package record

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/term"
)

// Config is what the module tells `chase record`: the tools it runs, by
// absolute path, and what each recording tier's filter allows.
type Config struct {
	// Journalctl is systemd's, which the logged calls, and frisket's lines
	// when its sink cannot be read, are read with.
	Journalctl string `json:"journalctl"`
	// Seccomp is flong's flong-seccomp, whose `resolve` names a call by
	// its audit arch and number.
	Seccomp string `json:"seccomp"`
	// Names are each recording tier's names file, flong's seccompProject
	// names: the calls its filter allows, one a line, its seccomp.deny
	// already taken out. A recording from scratch, which logs every call,
	// does not propose these.
	Names map[string]string `json:"names,omitempty"`
}

// Validate holds c's paths to being absolute, as the module writes them.
func (c Config) Validate() error {
	for _, p := range []struct{ name, path string }{{"journalctl", c.Journalctl}, {"seccomp", c.Seccomp}} {
		if !filepath.IsAbs(p.path) {
			return fmt.Errorf("%s is %q, which is not an absolute path", p.name, p.path)
		}
	}
	for tier, p := range c.Names {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("names of %s is %q, which is not an absolute path", tier, p)
		}
	}
	return nil
}

// Usage is `chase record`'s.
const Usage = `usage: chase record [--default allow|ask|refuse] [--base tier|none] [--] AGENT [ARG...]
       chase record apply [--last | MACHINE]`

// Args are `chase record`'s: how to record, and the agent -- claude,
// codex or shell -- with its own arguments, which are never read as
// chase's.
type Args struct {
	Options
	Agent string
	Args  []string
}

// ParseArgs reads `chase record`'s arguments: its own flags, up to `--`
// or the agent's name, whichever is first; everything after the agent is
// the agent's.
func ParseArgs(args []string) (Args, error) {
	a := Args{Options: Options{Base: "tier"}}
	for len(args) > 0 {
		arg := args[0]
		if arg == "--" {
			args = args[1:]
			break
		}
		if !strings.HasPrefix(arg, "-") {
			break
		}
		name, value, inline := strings.Cut(arg, "=")
		if name != "--default" && name != "--base" {
			return Args{}, fmt.Errorf("unknown flag %s", arg)
		}
		if !inline {
			if len(args) < 2 {
				return Args{}, fmt.Errorf("%s needs a value", name)
			}
			value, args = args[1], args[1:]
		}
		args = args[1:]
		switch name {
		case "--default":
			if !slices.Contains(grant.Answers, value) {
				return Args{}, fmt.Errorf("--default is %q, not one of %s", value, strings.Join(grant.Answers, ", "))
			}
			a.Default = value
		case "--base":
			if value != "tier" && value != "none" {
				return Args{}, fmt.Errorf("--base is %q, not tier or none", value)
			}
			a.Base = value
		}
	}
	if a.Default == "refuse" && a.Base == "none" {
		// What is refused now is refused by the filter, which then logs
		// nothing: from scratch, every call but the few every process makes.
		return Args{}, errors.New("--default refuse learns no syscalls, so --base none would only refuse every call the session makes")
	}
	if len(args) == 0 || args[0] == "" || strings.HasPrefix(args[0], "-") {
		return Args{}, errors.New("no agent: name claude, codex or shell")
	}
	a.Agent, a.Args = args[0], args[1:]
	return a, nil
}

// Session is one recording, as `chase record` starts it: the checkout's
// tier, decided as the wrapper decides it, its workspace, and the tier's
// record launcher.
type Session struct {
	Grant     grant.Config
	Config    Config
	Tier      string
	Workspace string
	Launcher  string
	Args      Args
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
}

// drain is how long after the session ends its logged calls are still
// read: journald delivers the kernel's records a little after they are
// made.
const drain = 1500 * time.Millisecond

// Run records a session: runs the tier's record launcher as a child, with
// what it is to record in its environment, and waits for it -- a ^C or a
// ^\ typed at the terminal reaches the session through the terminal's own
// process group, and is not this process's to act on; a SIGTERM or SIGHUP
// sent to this process is passed on -- following the logged calls while
// it runs; then, a ^C its own again, harvests what it needed, writes the
// recording and its proposal, says what it found, and exits as the session
// did.
func Run(s Session) int {
	uid := os.Getuid()
	say := func(format string, args ...any) { term.Say(s.Stderr, format, args...) }

	tokens := grant.RecordTokens(s.Grant)
	if err := os.MkdirAll(tokens, 0o700); err != nil {
		say("%v", err)
		return 1
	}
	var raw [16]byte
	rand.Read(raw[:])
	tok := hex.EncodeToString(raw[:])
	pidFile, machineFile := tokens+"/"+tok+".pid", tokens+"/"+tok+".machine"
	if err := files.WriteAtomic(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		say("%v", err)
		return 1
	}
	defer os.Remove(pidFile)
	defer os.Remove(machineFile)

	var notes []string
	start := time.Now()
	// A recording that refuses everything leaves the filter as it is
	// (grant.Recording's learning): nothing is logged, and nothing read.
	var col *Collector
	if s.Args.Default == "refuse" {
		notes = append(notes, "syscalls were not recorded: --default refuse leaves the tier's filter as it is, refusing what it refuses")
	} else if c, err := Collect(s.Config.Journalctl, uid, start.Add(-2*time.Second)); err != nil {
		notes = append(notes, fmt.Sprintf("no syscalls were collected: %v", err))
	} else {
		col = c
	}

	env := slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "CHASE_RECORD_") })
	env = append(env, grant.EnvDefault+"="+s.Args.Default, grant.EnvBase+"="+s.Args.Base, grant.EnvToken+"="+tok)
	cmd := exec.Command(s.Launcher, append([]string{s.Args.Agent}, s.Args.Args...)...)
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, s.Stdin, s.Stdout, s.Stderr

	// Caught, not ignored: an ignored signal stays ignored through exec,
	// and the session would never see the ^C meant for it.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		if col != nil {
			col.Stop(0)
		}
		say("%s: %v", s.Launcher, err)
		return 126
	}
	go func() {
		for sig := range sigs {
			if sig == syscall.SIGTERM || sig == syscall.SIGHUP {
				cmd.Process.Signal(sig)
			}
		}
	}()

	// The session's name, once approve has said it; its cgroup, once flong
	// has made it; and whether any other recording ran beside it.
	var mu sync.Mutex
	machine, sole := "", true
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		watching := false
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			if others(tokens, tok) {
				mu.Lock()
				sole = false
				mu.Unlock()
			}
			if !watching {
				if b, err := os.ReadFile(machineFile); err == nil {
					m := strings.TrimSpace(string(b))
					mu.Lock()
					machine = m
					mu.Unlock()
					if dir := SessionCgroup("/sys/fs/cgroup", uid, m); dir != "" && col != nil {
						watching = true
						go col.Watch(ctx, dir, 100*time.Millisecond)
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	werr := cmd.Wait()
	end := time.Now()
	cancel()
	// The session is over, and a ^C now is meant for this process: what
	// follows reads files the session could write, and a person must be
	// able to stop it.
	signal.Stop(sigs)
	close(sigs)
	exit := status(cmd, werr)

	var events []Event
	var pids map[int]bool
	if col != nil {
		var cerr error
		if events, pids, cerr = col.Stop(drain); cerr != nil {
			notes = append(notes, fmt.Sprintf("reading the journal's logged calls: %v", cerr))
		}
	}
	if b, err := os.ReadFile(machineFile); err == nil {
		mu.Lock()
		machine = strings.TrimSpace(string(b))
		mu.Unlock()
	}
	mu.Lock()
	m, alone := machine, sole
	mu.Unlock()
	if m == "" {
		say("the session did not start, so nothing was recorded")
		return exit
	}

	h := harvest{s: s, machine: m, start: start, end: end, sole: alone, exit: exit, notes: notes}
	h.run(events, pids)
	return exit
}

// others is whether a `chase record` other than tok's is running: its
// pid file there, and its process alive.
func others(tokens, tok string) bool {
	entries, _ := os.ReadDir(tokens)
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".pid")
		if !ok || name == tok {
			continue
		}
		b, err := os.ReadFile(filepath.Join(tokens, e.Name()))
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err == nil && pid > 0 && syscall.Kill(pid, 0) != syscall.ESRCH {
			return true
		}
	}
	return false
}

// status is the launcher's exit status, as a shell would give it: 128+n
// for a signal.
func status(cmd *exec.Cmd, err error) int {
	if cmd.ProcessState == nil {
		return 1
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	if err != nil && cmd.ProcessState.ExitCode() < 0 {
		return 1
	}
	return cmd.ProcessState.ExitCode()
}

// harvest is what a recording does once its session has ended.
type harvest struct {
	s          Session
	machine    string
	start, end time.Time
	sole       bool
	exit       int
	notes      []string
}

func (h *harvest) run(events []Event, pids map[int]bool) {
	s := h.s
	ctx := context.Background()
	lines, sinkRead := h.lines(ctx)
	if slices.Contains(s.Grant.Ungranted, s.Tier) {
		h.notes = append(h.notes, s.Tier+" reads no checkout's grant: what is proposed applies once it takes grants")
	}

	if len(events) == 0 && h.s.Config.Journalctl != "" && s.Args.Default != "refuse" {
		h.notes = append(h.notes, "no logged call was read: right if the session needed no call its filter refuses, and otherwise a sign you cannot read the system journal (systemd-journal) or journald's audit socket is off")
	}
	a := Attribute(events, h.machine, pids, h.start, h.end, h.sole)
	res := &resolver{seccomp: s.Config.Seccomp, names: map[string]string{}}
	calls, unnamed := Summarise(a, res.name)
	for _, u := range unnamed {
		h.notes = append(h.notes, "could not name "+u)
	}

	path := filepath.Join(s.Workspace, grant.FileName)
	current, _, err := readGrant(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		h.notes = append(h.notes, fmt.Sprintf("%s could not be read: %v", path, err))
	}
	against := h.against(current)
	o := s.Args.Options
	p := Propose(lines, calls, o, against)
	header := []string{
		fmt.Sprintf("chase record: what %s, a session of %s in %s, needed beyond its grant.", h.machine, s.Tier, s.Workspace),
		"Each entry is in the list its answer says, with what it was made from above it.",
		"Edit it as you like: `chase record apply " + h.machine + "` adds each entry here to the",
		"checkout's chase.jsonc, and the changed grant is put to you at the next launch.",
	}
	proposal := p.JSONC(header)

	diff := ""
	if len(p.Entries) > 0 {
		if merged, _, err := Merge(current, proposal); err != nil {
			h.notes = append(h.notes, fmt.Sprintf("the proposal could not be merged: %v", err))
		} else {
			diff = unified(s.Grant.Diff, grant.FileName, grant.FileName+", proposed", current, merged)
		}
	}

	all := slices.Clone(lines)
	for _, c := range calls {
		all = append(all, Line{Session: h.machine, Kind: "syscall", Name: c.Name, Count: c.Count, Probable: c.Probable, Would: "refuse", Answer: "allow", Source: "default"})
	}
	meta := Meta{
		Machine: h.machine, Tier: s.Tier, Workspace: s.Workspace, Agent: s.Args.Agent,
		Options: o, Started: h.start, Ended: h.end, Exit: h.exit, Sole: h.sole,
	}
	dir := RecordsDir(s.Grant)
	at, err := save(dir, meta, all, proposal)
	if err != nil {
		term.Say(h.s.Stderr, "the recording could not be kept: %v", err)
	}
	// Kept now in the user's own state; frisket's copy, the user's too, is
	// not needed again.
	if sink := grant.RecordSink(s.Grant, h.machine); sink != "" && sinkRead && err == nil {
		os.Remove(sink)
	}
	Report{
		Meta: meta, Lines: lines, Calls: calls, Proposal: p, Granted: against.Granted,
		Elsewhere: a.Elsewhere, Unsure: a.Unsure, Notes: h.notes, Dir: at, Diff: diff,
	}.Write(s.Stdout)
	Prune(dir, time.Now(), Keep, KeepFor)
}

// lines is frisket's lines of the session: its sink, and, when that
// cannot be read, its journal.
func (h *harvest) lines(ctx context.Context) ([]Line, bool) {
	sink := grant.RecordSink(h.s.Grant, h.machine)
	if sink != "" {
		lines, skipped, truncated, err := readSink(sink, h.machine)
		if err == nil {
			if skipped > 0 {
				h.notes = append(h.notes, fmt.Sprintf("%d line%s of %s were not frisket's", skipped, plural(skipped), sink))
			}
			if truncated {
				h.notes = append(h.notes, sink+" filled, and what came after is in frisket's journal alone")
			}
			return lines, true
		}
		h.notes = append(h.notes, fmt.Sprintf("frisket's sink could not be read (%v), so its journal was", err))
	}
	lines, err := journalRecords(ctx, h.s.Config.Journalctl, h.start.Add(-2*time.Second), h.machine)
	if err != nil {
		h.notes = append(h.notes, fmt.Sprintf("frisket's journal: %v", err))
	}
	return lines, false
}

// against is what a proposal is made against: the machines the
// checkout's grant names, and the calls it allows; and for a recording
// from scratch, the calls the tier's filter allows.
func (h *harvest) against(current []byte) Against {
	a := Against{Hosts: map[string]bool{}, Allowed: map[string]bool{}, Granted: map[string]bool{}}
	if current != nil {
		if b, err := grant.ParseFile(slices.Clone(current)); err != nil {
			h.notes = append(h.notes, fmt.Sprintf("%s is not a grant chase reads: %v", grant.FileName, err))
		} else {
			var f grant.File
			if json.Unmarshal(b, &f) == nil {
				if f.Apps.SSH != nil {
					for name := range f.Apps.SSH.Hosts {
						a.Hosts[name] = true
					}
				}
				if f.Seccomp != nil {
					for _, n := range f.Seccomp.Allow {
						a.Allowed[n], a.Granted[n] = true, true
					}
				}
			}
		}
	}
	if h.s.Args.Base == "none" {
		if p := h.s.Config.Names[h.s.Tier]; p == "" {
			h.notes = append(h.notes, "the tier's own calls are not known, so every call seen is proposed")
		} else if b, err := os.ReadFile(p); err != nil {
			h.notes = append(h.notes, fmt.Sprintf("the tier's own calls could not be read, so every call seen is proposed: %v", err))
		} else {
			for _, n := range strings.Fields(string(b)) {
				if !strings.HasPrefix(n, "-") {
					a.Allowed[n] = true
				}
			}
		}
	}
	return a
}

// maxGrant is the most of a checkout's chase.jsonc a recording reads:
// far more than any grant a person reads before approving it.
const maxGrant = 1 << 20

// readGrant is the checkout's chase.jsonc at path, and what it is, read as
// approve takes it: a plain file, and not a link -- the session could
// write it, and a link to a file of the user's, or to /dev/zero, a pipe
// that blocks the read forever, is none. It is opened without following a
// link or waiting on a pipe, and read no further than maxGrant.
func readGrant(path string) ([]byte, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, nil, fmt.Errorf("%s is a link, not a grant", path)
	}
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a plain file, so not a grant", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxGrant+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > maxGrant {
		return nil, nil, fmt.Errorf("%s is larger than %d bytes, so not a grant", path, maxGrant)
	}
	return b, fi, nil
}

// RecordsDir is where recordings are kept: <state>/records.
func RecordsDir(c grant.Config) string { return grant.StateDir(c) + "/records" }

// unified is `diff -u` of two texts, labelled, as diffutils' diff at path
// gives it; "" when it cannot be run.
func unified(path, labelA, labelB string, a, b []byte) string {
	dir, err := os.MkdirTemp("", "chase-record-")
	if err != nil {
		return ""
	}
	defer os.RemoveAll(dir)
	if os.WriteFile(dir+"/a", a, 0o600) != nil || os.WriteFile(dir+"/b", b, 0o600) != nil {
		return ""
	}
	var out bytes.Buffer
	cmd := exec.Command(path, "-u", "--label", labelA, "--label", labelB, dir+"/a", dir+"/b")
	cmd.Stdout = &out
	cmd.Run()
	return out.String()
}

// Apply is `chase record apply [--last | MACHINE]`: the recording's
// proposal merged into its checkout's chase.jsonc, what changed shown, and
// the recording marked applied. Applying one twice adds nothing the second
// time.
func Apply(c grant.Config, args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		term.Say(stderr, "%s", Usage)
		return 2
	}
	which := ""
	if len(args) == 1 {
		which = args[0]
	}
	at, m, err := find(RecordsDir(c), which)
	if err != nil {
		term.Say(stderr, "%v", err)
		return 1
	}
	proposal, err := os.ReadFile(filepath.Join(at, proposalFile))
	if err != nil {
		term.Say(stderr, "%v", err)
		return 1
	}
	path := filepath.Join(m.Workspace, grant.FileName)
	mode := os.FileMode(0o644)
	current, fi, err := readGrant(path)
	switch {
	case err == nil:
		mode = fi.Mode().Perm()
	case errors.Is(err, os.ErrNotExist):
		current = nil
	default:
		term.Say(stderr, "%v", err)
		return 1
	}
	merged, changes, err := Merge(current, proposal)
	if err != nil {
		term.Say(stderr, "%s: %v", m.Machine, err)
		return 1
	}
	var b strings.Builder
	added := 0
	for _, ch := range changes {
		where := strings.Join(ch.Path, ".")
		switch {
		case ch.Kept:
			fmt.Fprintf(&b, "  %s is in %s already\n", ch.Value, where)
		case ch.From != "":
			added++
			fmt.Fprintf(&b, "  %s moved to %s from %s\n", ch.Value, where, ch.From)
		case ch.Widened:
			added++
			fmt.Fprintf(&b, "  %s widened in %s\n", ch.Value, where)
		default:
			added++
			fmt.Fprintf(&b, "  %s added to %s\n", ch.Value, where)
		}
	}
	if added == 0 {
		io.WriteString(stdout, term.Clean(b.String()))
		term.Say(stdout, "%s: nothing to add to %s", m.Machine, path)
		return 0
	}
	diff := unified(c.Diff, grant.FileName, grant.FileName+", with "+m.Machine, current, merged)
	if err := files.WriteAtomic(path, merged, mode); err != nil {
		term.Say(stderr, "%v", err)
		return 1
	}
	now := time.Now()
	m.Applied = &now
	writeMeta(at, m)
	io.WriteString(stdout, term.Clean(diff+b.String()))
	term.Say(stdout, "%s's proposal is in %s: its grant is put to you at the next launch, once git tracks the file", m.Machine, path)
	return 0
}
