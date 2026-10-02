package record

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SYSCALLS are learnt from the kernel's audit records. A recording
// session's filter allows what it would have refused and logs it (flong's
// `log` lines, grant.ApproveRecording), and the kernel writes each such
// call as an audit record of type 1326, SECCOMP, its action 0x7ffc0000,
// SECCOMP_RET_LOG. journald's audit socket reads them off the audit netlink
// (`_TRANSPORT=audit`), which no rate limit on the kernel's log reaches;
// reading them takes a user who may read the system journal, as one in
// systemd-journal or wheel may.
//
// A record names a process by its pid, which says nothing of whose session
// it is. So each is put down to a session by the process's cgroup, read
// as the record arrives -- flong runs every session's processes under
// flong-sessions.service/<container>/<machine> -- or by the pids seen in
// the session's own cgroup while it ran, polled for the ones gone before
// their record was read. One that neither places, gone too soon, is the
// session's only probably: by the time it was made, and only when no other
// recording ran beside it (Attribute).
//
// Collected here, in `chase record` itself, and not in a hook: the
// session's cgroup is killed before postStop runs, and what is read must be
// read while it lives.

// logged is SECCOMP_RET_LOG, the action a record's code= names for a call
// the filter allowed and logged.
const logged = "0x7ffc0000"

// Event is one logged call: when, by which process, and which call, by
// its audit arch and number; and the process's cgroup when its record was
// read, or "" when it was already gone.
type Event struct {
	Time    time.Time
	PID     int
	Arch    string
	Syscall int64
	Cgroup  string
}

// ParseAudit is the logged call one journal entry holds, in journalctl's
// `-o json`, made by uid; false for anything else. journald gives an audit
// record's fields as _AUDIT_FIELD_* beside its _PID and _UID; the message,
// the record as the kernel wrote it, is read for any it does not.
func ParseAudit(b []byte, uid int) (Event, bool) {
	var j map[string]any
	if json.Unmarshal(b, &j) != nil {
		return Event{}, false
	}
	str := func(k string) string { s, _ := j[k].(string); return s }
	fields := auditFields(str("MESSAGE"))
	field := func(journal, audit string) string {
		if v := str(journal); v != "" {
			return v
		}
		return fields[audit]
	}
	if t := str("_AUDIT_TYPE"); t != "" && t != "1326" {
		return Event{}, false
	}
	if field("_AUDIT_FIELD_CODE", "code") != logged {
		return Event{}, false
	}
	if u, err := strconv.Atoi(field("_UID", "uid")); err != nil || u != uid {
		return Event{}, false
	}
	pid, err := strconv.Atoi(field("_PID", "pid"))
	if err != nil || pid <= 0 {
		return Event{}, false
	}
	nr, err := strconv.ParseInt(field("_AUDIT_FIELD_SYSCALL", "syscall"), 10, 64)
	if err != nil || nr < 0 {
		return Event{}, false
	}
	arch := strings.ToLower(field("_AUDIT_FIELD_ARCH", "arch"))
	if arch == "" {
		return Event{}, false
	}
	e := Event{PID: pid, Arch: arch, Syscall: nr}
	if us, err := strconv.ParseInt(str("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
		e.Time = time.UnixMicro(us)
	}
	return e, true
}

// auditFields is an audit record's key=value words, a quoted value's
// quotes off.
func auditFields(msg string) map[string]string {
	out := map[string]string{}
	for _, w := range strings.Fields(msg) {
		k, v, ok := strings.Cut(w, "=")
		if !ok {
			continue
		}
		out[k] = strings.Trim(v, `"`)
	}
	return out
}

// Collector follows the journal's logged calls while a session runs.
type Collector struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	done   chan struct{}
	// cgroup is a process's cgroup as /proc says it, "" when it is gone.
	cgroup func(pid int) string

	mu     sync.Mutex
	events []Event
	pids   map[int]bool
	err    error
}

// Collect follows journalctl for uid's logged calls from since. journalctl
// is put in a process group of its own, so the ^C a person types at the
// session reaches the session and never the follower.
func Collect(journalctl string, uid int, since time.Time) (*Collector, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, journalctl, "--follow", "--no-pager", "-o", "json",
		fmt.Sprintf("--since=@%d", since.Unix()),
		"_TRANSPORT=audit", "_AUDIT_TYPE=1326", fmt.Sprintf("_UID=%d", uid))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	c := &Collector{cmd: cmd, cancel: cancel, done: make(chan struct{}), cgroup: procCgroup, pids: map[int]bool{}}
	go func() {
		defer close(c.done)
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			e, ok := ParseAudit(sc.Bytes(), uid)
			if !ok {
				continue
			}
			// At once, before the process can go.
			e.Cgroup = c.cgroup(e.PID)
			c.mu.Lock()
			c.events = append(c.events, e)
			c.mu.Unlock()
		}
		c.mu.Lock()
		c.err = sc.Err()
		c.mu.Unlock()
	}()
	return c, nil
}

// procCgroup is /proc/<pid>/cgroup, or "" for a process that is gone.
func procCgroup(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	return string(b)
}

// Watch adds every pid in the cgroup tree at dir to the session's, now
// and every interval until ctx ends: a process that has gone by the time
// its record is read is still known by its pid.
func (c *Collector) Watch(ctx context.Context, dir string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		pids := cgroupPids(dir)
		c.mu.Lock()
		for _, p := range pids {
			c.pids[p] = true
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// cgroupPids is every process in the cgroup tree at dir.
func cgroupPids(dir string) []int {
	var out []int
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "cgroup.procs" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, f := range bytes.Fields(b) {
			if n, err := strconv.Atoi(string(f)); err == nil {
				out = append(out, n)
			}
		}
		return nil
	})
	return out
}

// Stop ends the follower after drain, the time journald may still take to
// deliver what the kernel has written, and is what it collected: the
// logged calls, and the pids seen in the session's cgroup.
func (c *Collector) Stop(drain time.Duration) ([]Event, map[int]bool, error) {
	time.Sleep(drain)
	c.cancel()
	c.cmd.Wait()
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.events), c.pids, c.err
}

// SessionCgroup is the cgroup flong runs the session named machine in,
// under the user's flong-sessions.service, its holder: <container>/<machine>
// below it, in whichever slice the user's manager put the holder; "" when
// none is there.
func SessionCgroup(root string, uid int, machine string) string {
	for _, pattern := range []string{
		"%s/user.slice/user-%d.slice/user@%d.service/*/flong-sessions.service/*/%s",
		"%s/user.slice/user-%d.slice/user@%d.service/flong-sessions.service/*/%s",
	} {
		m, _ := filepath.Glob(fmt.Sprintf(pattern, root, uid, uid, machine))
		if len(m) == 1 {
			return m[0]
		}
	}
	return ""
}

// Placed is where a cgroup puts a process: in the session, in another
// session or elsewhere on the host, or nowhere, for one that was gone.
type Placed int

const (
	Gone Placed = iota
	InSession
	Elsewhere
)

// Place is where cgroup, as /proc/<pid>/cgroup says it, puts a process
// against the session named machine: below flong-sessions.service, the
// container, then the machine.
func Place(cgroup, machine string) Placed {
	if strings.TrimSpace(cgroup) == "" {
		return Gone
	}
	for _, line := range strings.Split(cgroup, "\n") {
		// cgroup v2's one line, 0::/path.
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		segs := strings.Split(path, "/")
		i := slices.Index(segs, "flong-sessions.service")
		if i >= 0 && i+2 < len(segs) && segs[i+2] == machine {
			return InSession
		}
	}
	return Elsewhere
}

// Attributed is the logged calls put down to a session: Sure, by its
// cgroup or a pid seen in it; Probable, by when it was made alone; and how
// many were someone else's, or could not be placed at all.
type Attributed struct {
	Sure, Probable    []Event
	Elsewhere, Unsure int
}

// Attribute puts each event down to the session named machine, or not:
// by the cgroup its process was in when its record was read, and failing
// that by its pid, seen in the session's cgroup while it ran. A process
// gone before either is the session's probably -- made between from and
// to, while sole, when no other recording ran beside it -- and otherwise
// counted as unsure. A cgroup read says more than a pid seen earlier,
// which may since have been reused.
func Attribute(events []Event, machine string, pids map[int]bool, from, to time.Time, sole bool) Attributed {
	var a Attributed
	for _, e := range events {
		switch Place(e.Cgroup, machine) {
		case InSession:
			a.Sure = append(a.Sure, e)
			continue
		case Elsewhere:
			a.Elsewhere++
			continue
		}
		switch {
		case pids[e.PID]:
			a.Sure = append(a.Sure, e)
		case sole && !e.Time.Before(from) && !e.Time.After(to):
			a.Probable = append(a.Probable, e)
		default:
			a.Unsure++
		}
	}
	return a
}

// Syscall is one call the session made that its filter would have
// refused: its name, how many times it was logged, and whether it was put
// down to the session only probably.
type Syscall struct {
	Name     string
	Count    int
	Probable bool
}

// resolver names a call by its audit arch and number, with flong's own
// tables (`flong-seccomp resolve ARCH NR`), each once.
type resolver struct {
	seccomp string
	names   map[string]string
}

func (r *resolver) name(arch string, nr int64) (string, error) {
	k := arch + " " + strconv.FormatInt(nr, 10)
	if n, ok := r.names[k]; ok {
		return n, nil
	}
	var out, errb bytes.Buffer
	cmd := exec.Command(r.seccomp, "resolve", arch, strconv.FormatInt(nr, 10))
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("syscall %d on arch %s: %s", nr, arch, strings.TrimSpace(errb.String()))
	}
	n := strings.TrimSpace(out.String())
	r.names[k] = n
	return n, nil
}

// Summarise is the calls attributed, by name, each counted, sorted by
// name; one only probable is marked so, unless it was also surely made.
// What could not be named is said, each once.
func Summarise(a Attributed, name func(arch string, nr int64) (string, error)) (calls []Syscall, unnamed []string) {
	by := map[string]*Syscall{}
	said := map[string]bool{}
	add := func(e Event, probable bool) {
		n, err := name(e.Arch, e.Syscall)
		if err != nil {
			if !said[err.Error()] {
				said[err.Error()] = true
				unnamed = append(unnamed, err.Error())
			}
			return
		}
		s, ok := by[n]
		if !ok {
			s = &Syscall{Name: n, Probable: true}
			by[n] = s
		}
		s.Count++
		s.Probable = s.Probable && probable
	}
	for _, e := range a.Sure {
		add(e, false)
	}
	for _, e := range a.Probable {
		add(e, true)
	}
	for _, n := range slices.Sorted(maps.Keys(by)) {
		calls = append(calls, *by[n])
	}
	return calls, unnamed
}
