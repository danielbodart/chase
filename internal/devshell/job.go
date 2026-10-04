package devshell

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// job is one checkout's realisation: what is evaluated, and how.
type job struct {
	n    session.Nix
	r    Request
	kind string
	// dir is <Dir>/devshell.
	dir    string
	stderr io.Writer

	// files are the digests of what the cache is keyed on, by name.
	files map[string]string
	// args are nix's, after c0, and key what the cache is keyed on: the
	// one run that realises it, or, offline, the run that evaluates it.
	args []string
	key  string
	// env is the store path the profile pointed to when it was realised.
	env string
	// binds are what of the checkout nix is shown, at their own paths:
	// its directory, or the checkout it is in, and that checkout's git
	// directories.
	binds []string
}

// c0 is what every nix run is given first: flakes, and nothing the flake
// says of nix's own configuration, which would be the checkout's say over
// what the caller's nix trusts and fetches from; and lazy trees, which on
// Determinate Nix keep the checkout out of the world-readable store unless
// a derivation refers to it -- another nix warns of the setting it does
// not know and copies what git tracks in, as its own `nix develop` does.
var c0 = []string{
	"--extra-experimental-features", "nix-command flakes",
	"--option", "accept-flake-config", "false",
	"--option", "lazy-trees", "true",
}

// shellURIs is what a shell.nix's evaluation reaches: anything over https,
// as a session with direct egress could. Never a path or a file, which
// restrict-eval would otherwise be asked to let through.
var shellURIs = []string{"https://", "tarball+https://", "file+https://", "git+https://", "github:", "gitlab:", "sourcehut:"}

// offlineEval is what an offline evaluation is given beyond c0:
// substitution, which nix turns off when it finds no network, back on --
// the daemon's, from the machine's own binary caches, on the host's
// network, their signatures checked -- and nothing built while it
// evaluates, nor imported from what would be.
var offlineEval = []string{"--option", "substitute", "true", "--max-jobs", "0", "--option", "allow-import-from-derivation", "false"}

// plan is what the job evaluates and how: the digests of the files keyed
// on, nix's arguments, and the key of them all.
//
// A flake is evaluated as `nix develop` evaluates one, purely, its lock
// never written: what it does not lock is fetched for this launch alone. A
// shell.nix is evaluated restricted, as nix-shell evaluates none: <nixpkgs>
// is the system's, the rest of its NIX_PATH the checkout, and what it
// fetches https alone.
//
// Offline, what is evaluated first is the devShell's derivation alone,
// with no network: a flake's inputs are what the store has, and a
// shell.nix fetches nothing at all (realiseOffline).
func (j *job) plan() error {
	j.files = map[string]string{}
	names := []string{j.kind}
	if j.kind == flake {
		names = append(names, lock)
	}
	for _, name := range names {
		b, err := readPlain(j.r.Workspace + "/" + name)
		switch {
		case errors.Is(err, os.ErrNotExist) && name == lock:
			j.files[name] = ""
			continue
		case err != nil:
			return fmt.Errorf("%s: %v", name, err)
		}
		d := sha256.Sum256(b)
		j.files[name] = hex.EncodeToString(d[:])
	}
	attr, uris := "", strings.Join(shellURIs, " ")
	j.args = []string{"print-dev-env", "--json", "--profile", j.dir + "/profile"}
	if j.n.Offline {
		attr, uris = ".drvPath", ""
		j.args = append([]string{"eval", "--raw"}, offlineEval...)
	}
	if j.kind == flake {
		j.args = append(j.args, "--no-write-lock-file", j.r.Workspace+"#devShells."+j.n.System+".default"+attr)
	} else {
		j.args = append(j.args, "--option", "restrict-eval", "true", "--option", "allowed-uris", uris,
			"--arg", "inNixShell", "true", "-f", j.r.Workspace+"/"+shell)
		if j.n.Offline {
			j.args = append(j.args, "drvPath")
		}
	}
	b, err := json.Marshal(struct {
		Version int               `json:"version"`
		Kind    string            `json:"kind"`
		Files   map[string]string `json:"files"`
		System  string            `json:"system"`
		Nix     string            `json:"nix"`
		Nixpkgs string            `json:"nixpkgs"`
		Bwrap   string            `json:"bwrap"`
		Binds   []string          `json:"binds"`
		Args    []string          `json:"args"`
		Offline bool              `json:"offline,omitempty"`
	}{2, j.kind, j.files, j.n.System, j.n.Nix, j.n.Nixpkgs, j.n.Bwrap, j.binds, append(append([]string{}, c0...), j.args...), j.n.Offline})
	if err != nil {
		return err
	}
	d := sha256.Sum256(b)
	j.key = hex.EncodeToString(d[:])
	return nil
}

// readPlain is the file at p, a plain file and never a link: a link would
// key the cache on a file nix may not read the same.
func readPlain(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, errors.New("a link, not a file of the checkout's")
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a plain file")
	}
	return io.ReadAll(f)
}

// state is what is kept of a checkout's last realisation, written last.
//
// Env is the store path the profile pointed to when it was realised: the
// profile is switched before state.json is written, so a launch killed
// between the two leaves a profile of another key's, which is not taken
// for this one's.
type state struct {
	Key       string `json:"key"`
	Workspace string `json:"workspace"`
	Result    string `json:"result"`
	Reason    string `json:"reason,omitempty"`
	Env       string `json:"env,omitempty"`
	At        string `json:"at"`
}

// record writes what the realisation came to.
func (j *job) record(result, reason string) {
	b, err := json.Marshal(state{Key: j.key, Workspace: j.r.Workspace, Result: result, Reason: reason, Env: j.env, At: now().UTC().Format(time.RFC3339)})
	if err == nil {
		files.WriteAtomic(j.dir+"/state.json", b, 0o600)
	}
}

// cached is the devShell the last realisation kept, when it is of what is
// evaluated now: its environment, read through the profile that roots it;
// none; or a failure less than failedFor old, said as it was. hit is false
// for anything else, which is realised again.
func (j *job) cached() (ds *session.DevShell, err error, hit bool) {
	b, err := os.ReadFile(j.dir + "/state.json")
	if err != nil {
		return nil, nil, false
	}
	var s state
	if json.Unmarshal(b, &s) != nil || s.Key != j.key {
		return nil, nil, false
	}
	switch s.Result {
	case "env":
		// A profile that is gone, is not the one recorded, or no longer
		// reads, is realised again.
		if env, err := filepath.EvalSymlinks(j.dir + "/profile"); err != nil || s.Env == "" || env != s.Env {
			return nil, nil, false
		}
		ds, err := j.load()
		if err != nil {
			return nil, nil, false
		}
		return ds, nil, true
	case "none":
		return nil, &none{line: s.Reason, quiet: true}, true
	case "failed":
		at, err := time.Parse(time.RFC3339, s.At)
		if err != nil || now().Sub(at) >= failedFor {
			return nil, nil, false
		}
		return nil, fmt.Errorf("(as at %s) %s", s.At, s.Reason), true
	}
	return nil, nil, false
}

// load is the environment the profile roots, as the session is given it.
func (j *job) load() (*session.DevShell, error) {
	b, err := os.ReadFile(j.dir + "/profile")
	if err != nil {
		return nil, err
	}
	ds, dropped, err := parse(b)
	if err != nil {
		return nil, err
	}
	if len(dropped) > 0 {
		term.Say(j.stderr, "%s: the devShell's %s %s not given to the agent", j.r.Workspace, strings.Join(dropped, ", "), plural(len(dropped), "is", "are"))
	}
	return ds, nil
}

// realise is nix's runs, and the environment that comes of them, rooted
// in dir: given apps.nix.timeout between them, and then a failure.
func (j *job) realise(ctx context.Context) (*session.DevShell, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(j.n.Timeout)*time.Second)
	defer cancel()
	args := j.args
	var err error
	if j.n.Offline {
		args, err = j.realiseOffline(ctx)
	}
	if err == nil {
		err = j.run(ctx, args, io.Discard)
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("it took more than %d s", j.n.Timeout)
		}
		var f *failure
		if j.kind == flake && errors.As(err, &f) && strings.Contains(f.said, "does not provide attribute") {
			return nil, &none{line: fmt.Sprintf("%s: flake.nix has no devShells.%s.default", j.r.Workspace, j.n.System)}
		}
		return nil, err
	}
	prune(j.dir)
	if j.env, err = filepath.EvalSymlinks(j.dir + "/profile"); err != nil {
		return nil, err
	}
	return j.load()
}

// realiseOffline is everything of the devShell but the record of its
// environment, with no network, and the arguments of the run that makes
// that record: in a tier whose egress is not direct and unfiltered, what
// an evaluation reaches is neither the host's network nor a build of the
// checkout's.
//
// So the devShell's derivation is evaluated alone (plan), and read: one
// that asks for what a sandboxed build is not given is refused. Each of
// its inputs, as the outputs it takes, is substituted from the machine's
// binary caches with no local build allowed, and one that is in none of
// them refuses it, before anything is built. What is left is nix's own
// derivation that records the environment, of the devShell's attributes
// and with every input already there, which print-dev-env builds, the
// one local build, sandboxed by the daemon.
func (j *job) realiseOffline(ctx context.Context) ([]string, error) {
	var out bytes.Buffer
	if err := j.run(ctx, j.args, &out); err != nil {
		var f *failure
		if errors.As(err, &f) && fetching.MatchString(f.reason) {
			return nil, &failure{reason: f.reason + offlineHint, said: f.said}
		}
		return nil, err
	}
	drv := strings.TrimSpace(out.String())
	if !strings.HasPrefix(drv, "/nix/store/") || !drvName.MatchString(strings.TrimPrefix(drv, "/nix/store/")) {
		return nil, fmt.Errorf("its derivation is %q, which is not one in the store", drv)
	}
	out.Reset()
	if err := j.run(ctx, []string{"derivation", "show", "--option", "substitute", "true", drv}, &out); err != nil {
		return nil, err
	}
	inputs, err := inputsOf(drv, out.Bytes())
	if err != nil {
		return nil, err
	}
	if len(inputs) > 0 {
		build := append([]string{"build", "--no-link", "--option", "substitute", "true", "--max-jobs", "0"}, inputs...)
		if err := j.run(ctx, build, io.Discard); err != nil {
			var f *failure
			if ctx.Err() == nil && errors.As(err, &f) {
				return nil, fmt.Errorf("what it needs is not all in the machine's binary caches, and nothing of a devShell is built in this tier but nix's record of its environment: %s", f.reason)
			}
			return nil, err
		}
	}
	return []string{"print-dev-env", "--json", "--option", "substitute", "true", "--max-jobs", "1", "--profile", j.dir + "/profile", drv + "^*"}, nil
}

// fetching is what an evaluation with no network says of a fetch, and
// offlineHint what it is told.
var (
	fetching    = regexp.MustCompile(`access to URI|unable to download|resolve host|fetch`)
	offlineHint = "; a devShell is realised with no network in this tier: a flake's inputs are taken from the store alone, and a shell.nix has the system's <nixpkgs> and nothing to fetch"
)

// failure is a nix run that did not succeed, and what it said.
type failure struct {
	reason, said string
}

func (f *failure) Error() string { return f.reason }

// home is nix's HOME, chase's own and every checkout's: its fetcher and
// evaluation caches, and nothing of the caller's. Offline, one of its
// own, so nothing an evaluation of someone else's code leaves in nix's
// caches is read by an evaluation of one's own.
func (j *job) home() string {
	if j.n.Offline {
		return j.r.State + "/devshell/offline-home"
	}
	return j.r.State + "/devshell/home"
}

// confine is nix's argument list, in a bubblewrap of its own: nothing of
// the host but the store, the daemon's socket, the machine's nix
// configuration and resolver, the checkout's binds, read-only, nix's HOME,
// and the devshell directory, at its own path, for the profile nix roots
// there by that path; the host's network, as the tier's egress is direct,
// and none at all offline, where the daemon alone reaches the machine's
// binary caches;
// and none of the caller's environment but what is set here -- that HOME,
// a PATH of nix and git alone, the git a fetch shells out to, the daemon,
// the machine's CA bundle, and, for a shell.nix, its NIX_PATH. So
// NIXPKGS_ALLOW_UNFREE, an editor's or a terminal's variables never reach
// it, and a devShell is the same from wherever it is launched.
//
// nix's own restrictions do not hold what it reads -- builtins.getFlake
// in a shell.nix, a flake's path: or git+file input, is any file of the
// caller's -- and the checkout is what a session writes. So what is
// evaluated reads no file of the host's the session cannot -- the user's
// home, ~/.ssh, another checkout, chase's state -- and hands nothing of
// theirs to the session, nor to the world-readable store. /tmp is a tmpfs
// first, so what is bound later is not hidden under it.
func (j *job) confine(args []string) []string {
	argv := []string{j.n.Bwrap, "--unshare-all"}
	if !j.n.Offline {
		argv = append(argv, "--share-net")
	}
	argv = append(argv, "--die-with-parent", "--new-session", "--clearenv",
		"--tmpfs", "/tmp",
		"--ro-bind", "/nix/store", "/nix/store",
		"--bind", "/nix/var/nix/daemon-socket", "/nix/var/nix/daemon-socket",
		"--ro-bind-try", "/etc/nix", "/etc/nix",
		"--ro-bind-try", "/etc/static", "/etc/static",
		"--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
		"--ro-bind-try", "/etc/hosts", "/etc/hosts")
	for _, b := range j.binds {
		argv = append(argv, "--ro-bind", b, b)
	}
	argv = append(argv, "--bind", j.home(), j.home(), "--bind", j.dir, j.dir,
		"--dev", "/dev", "--proc", "/proc",
		"--setenv", "HOME", j.home(),
		"--setenv", "PATH", filepath.Dir(j.n.Nix)+":"+filepath.Dir(j.n.Git),
		"--setenv", "NIX_REMOTE", "daemon",
		"--setenv", "NIX_SSL_CERT_FILE", j.n.CABundle)
	if j.kind == shell {
		argv = append(argv, "--setenv", "NIX_PATH", "nixpkgs="+j.n.Nixpkgs+":"+j.r.Workspace)
	}
	argv = append(argv, "--", j.n.Nix)
	argv = append(argv, c0...)
	return append(argv, args...)
}

// run is nix, run with args, as the caller, confined: its environment
// confine's, its stdin /dev/null, its stdout stdout, and its process
// group killed when ctx is done -- bubblewrap's, that is, which puts nix
// in a session of its own (--new-session, so nothing in it can push input
// to a terminal), and nix, and all it started, die with it
// (--die-with-parent). What it says goes to the launcher's stderr,
// cleaned, as it comes; offline, but its warning that it has no network,
// which is the point.
func (j *job) run(ctx context.Context, args []string, stdout io.Writer) error {
	if err := os.MkdirAll(j.home(), 0o700); err != nil {
		return err
	}
	argv := j.confine(args)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	var said bytes.Buffer
	lines := &cleanLines{w: j.stderr}
	if j.n.Offline {
		lines.skip = "you don't have Internet access"
	}
	cmd.Stdout = stdout
	cmd.Stderr = io.MultiWriter(lines, &said)
	err := cmd.Run()
	lines.flush()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &failure{reason: reasonOf(said.String(), err), said: said.String()}
	}
	return nil
}

// reasonOf is what nix said of why it failed, as one line: its last
// error, or its last line, or how it exited.
func reasonOf(said string, err error) string {
	lines := strings.Split(strings.TrimSpace(said), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if _, after, ok := strings.Cut(lines[i], "error:"); ok && strings.TrimSpace(after) != "" {
			return strings.TrimSpace(after)
		}
	}
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		return last
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return fmt.Sprintf("nix exited with status %d", exit.ExitCode())
	}
	return err.Error()
}

// cleanLines writes what it is given to w a line at a time, each cleaned
// (term.Clean): nix's output carries what the checkout named. A line with
// skip in it is not written.
type cleanLines struct {
	w    io.Writer
	buf  []byte
	skip string
}

func (c *cleanLines) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	for {
		i := bytes.IndexByte(c.buf, '\n')
		if i < 0 {
			break
		}
		if line := string(c.buf[:i+1]); c.skip == "" || !strings.Contains(line, c.skip) {
			io.WriteString(c.w, term.Clean(line))
		}
		c.buf = c.buf[i+1:]
	}
	return len(p), nil
}

func (c *cleanLines) flush() {
	if len(c.buf) > 0 && (c.skip == "" || !strings.Contains(string(c.buf), c.skip)) {
		io.WriteString(c.w, term.Clean(string(c.buf))+"\n")
	}
	c.buf = nil
}

// plural is one when n is 1, and many otherwise.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
