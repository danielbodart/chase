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
	// args are nix's, after c0, and key what the cache is keyed on.
	args []string
	key  string
	// env is the store path the profile pointed to when it was realised.
	env string
}

// c0 is what every nix run is given first: flakes, and nothing the flake
// says of nix's own configuration, which would be the checkout's say over
// what the caller's nix trusts and fetches from; and lazy trees, which
// keep the checkout out of the world-readable store unless a derivation
// refers to it.
var c0 = []string{
	"--extra-experimental-features", "nix-command flakes",
	"--option", "accept-flake-config", "false",
	"--option", "lazy-trees", "true",
}

// shellURIs is what a shell.nix's evaluation reaches: anything over https,
// as a session with direct egress could. Never a path or a file, which
// restrict-eval would otherwise be asked to let through.
var shellURIs = []string{"https://", "tarball+https://", "file+https://", "git+https://", "github:", "gitlab:", "sourcehut:"}

// plan is what the job evaluates and how: the digests of the files keyed
// on, nix's arguments, and the key of them all.
//
// A flake is evaluated as `nix develop` evaluates one, purely, its lock
// never written: what it does not lock is fetched for this launch alone. A
// shell.nix is evaluated restricted, as nix-shell evaluates none: <nixpkgs>
// is the system's, the rest of its NIX_PATH the checkout, and what it
// fetches https alone.
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
	j.args = []string{"print-dev-env", "--json", "--profile", j.dir + "/profile"}
	if j.kind == flake {
		j.args = append(j.args, "--no-write-lock-file", j.r.Workspace+"#devShells."+j.n.System+".default")
	} else {
		j.args = append(j.args, "--option", "restrict-eval", "true", "--option", "allowed-uris", strings.Join(shellURIs, " "),
			"--arg", "inNixShell", "true", "-f", j.r.Workspace+"/"+shell)
	}
	b, err := json.Marshal(struct {
		Version int               `json:"version"`
		Kind    string            `json:"kind"`
		Files   map[string]string `json:"files"`
		System  string            `json:"system"`
		Nix     string            `json:"nix"`
		Nixpkgs string            `json:"nixpkgs"`
		Args    []string          `json:"args"`
	}{1, j.kind, j.files, j.n.System, j.n.Nix, j.n.Nixpkgs, append(append([]string{}, c0...), j.args...)})
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
		term.Say(j.stderr, "%s: the devShell's %s are not given to the agent", j.r.Workspace, strings.Join(dropped, ", "))
	}
	return ds, nil
}

// realise is nix's run, and the environment that comes of it, rooted in
// dir: given apps.nix.timeout, and then a failure.
func (j *job) realise(ctx context.Context) (*session.DevShell, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(j.n.Timeout)*time.Second)
	defer cancel()
	if err := j.run(ctx); err != nil {
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
	var err error
	if j.env, err = filepath.EvalSymlinks(j.dir + "/profile"); err != nil {
		return nil, err
	}
	return j.load()
}

// failure is a nix run that did not succeed, and what it said.
type failure struct {
	reason, said string
}

func (f *failure) Error() string { return f.reason }

// environ is all of the environment nix is given: the caller's HOME, for
// its own configuration, its fetcher cache and its access tokens; a PATH of
// nix and git alone, the git a fetch shells out to; the daemon; the
// machine's CA bundle; and, for a shell.nix, its NIX_PATH. Nothing else of
// the caller's -- NIXPKGS_ALLOW_UNFREE, an editor's or a terminal's
// variables -- so a devShell is the same from wherever it is launched.
func (j *job) environ() []string {
	env := []string{
		"HOME=" + j.r.Home,
		"PATH=" + filepath.Dir(j.n.Nix) + ":" + filepath.Dir(j.n.Git),
		"NIX_REMOTE=daemon",
		"NIX_SSL_CERT_FILE=" + j.n.CABundle,
	}
	if j.kind == shell {
		env = append(env, "NIX_PATH=nixpkgs="+j.n.Nixpkgs+":"+j.r.Workspace)
	}
	return env
}

// run is nix, as the caller: its environment environ's, its stdin
// /dev/null, and its process group killed when ctx is done, so nothing it
// started outlives the launch. What it says goes to the launcher's
// stderr, cleaned, as it comes.
func (j *job) run(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, j.n.Nix, append(append([]string{}, c0...), j.args...)...)
	cmd.Env = j.environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	var said bytes.Buffer
	lines := &cleanLines{w: j.stderr}
	cmd.Stdout = io.Discard
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
// (term.Clean): nix's output carries what the checkout named.
type cleanLines struct {
	w   io.Writer
	buf []byte
}

func (c *cleanLines) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	for {
		i := bytes.IndexByte(c.buf, '\n')
		if i < 0 {
			break
		}
		io.WriteString(c.w, term.Clean(string(c.buf[:i+1])))
		c.buf = c.buf[i+1:]
	}
	return len(p), nil
}

func (c *cleanLines) flush() {
	if len(c.buf) > 0 {
		io.WriteString(c.w, term.Clean(string(c.buf))+"\n")
		c.buf = nil
	}
}
