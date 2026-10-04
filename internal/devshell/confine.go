package devshell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/danielbodart/chase/internal/term"
)

// dnsForward is the address a networked step's resolver is told, which
// pasta answers with the host's own resolver.
const dnsForward = "169.254.1.1"

// step is one nix run: its name, P, A, B or C; whether it has a network;
// whether the devshell directory is bound, at its own path, for the GC
// roots nix registers by that path; whether what it says on stderr is
// kept rather than shown as it comes; and its arguments after c0.
type step struct {
	name     string
	network  bool
	devshell bool
	capture  bool
	args     []string
}

// stepFailure is a step that did not succeed, and what it said.
type stepFailure struct {
	name, reason, said string
}

func (f *stepFailure) Error() string { return f.reason }

// confine is s's argument list: nix, in a bubblewrap of its own, with
// nothing of the host but the store, the daemon's socket, nix's own
// configuration, the snapshot, nix's HOME, and the devshell directory for
// the steps that root what they make; none of the caller's environment; and
// a network, through pasta, only where s has one -- pasta's, which keeps
// the host's loopback and gateway out, and answers DNS from the host's
// resolver. /tmp is a tmpfs first, so what is bound later is not hidden
// under it.
//
// So what is evaluated reads no host file outside the store -- the user's
// home, another checkout, ~/.ssh, ~/.config/nix, a netrc -- whatever nix's
// own restrictions let through, as getFlake, a registry, a path: or
// git+file input would; and reaches no network but the one the step is
// given.
func (j *job) confine(s step) []string {
	var argv []string
	if s.network {
		argv = append(argv, j.n.Pasta, "--quiet", "--config-net", "--no-map-gw",
			"-t", "none", "-u", "none", "-T", "none", "-U", "none",
			"--dns-forward", dnsForward, "--")
	}
	argv = append(argv, j.n.Bwrap, "--unshare-all")
	if s.network {
		argv = append(argv, "--share-net")
	}
	argv = append(argv, "--die-with-parent", "--new-session", "--clearenv",
		"--tmpfs", "/tmp",
		"--ro-bind", "/nix/store", "/nix/store",
		"--bind", "/nix/var/nix/daemon-socket", "/nix/var/nix/daemon-socket",
		"--ro-bind", "/etc/nix", "/etc/nix",
		"--ro-bind", "/etc/static", "/etc/static")
	if s.network {
		argv = append(argv, "--ro-bind", j.r.State+"/nix/resolv.conf", "/etc/resolv.conf")
	}
	argv = append(argv, "--ro-bind", j.snap, j.src, "--bind", j.home(), "/home/nix")
	if s.devshell {
		argv = append(argv, "--bind", j.dir, j.dir)
	}
	argv = append(argv, "--dev", "/dev", "--proc", "/proc",
		"--setenv", "HOME", "/home/nix",
		"--setenv", "PATH", filepath.Dir(j.n.Nix),
		"--setenv", "NIX_REMOTE", "daemon",
		"--setenv", "NIX_SSL_CERT_FILE", j.n.CABundle)
	if j.kind == shell {
		argv = append(argv, "--setenv", "NIX_PATH", "nixpkgs="+j.n.Nixpkgs+":"+j.src)
	}
	argv = append(argv, "--", j.n.Nix)
	argv = append(argv, c0...)
	return append(argv, s.args...)
}

// run is s, confined: what it printed on stdout, or why it failed. Its
// environment is empty, its stdin /dev/null, and its process group is
// killed when ctx is done: pasta and bubblewrap, that is, since bubblewrap
// puts nix in a session of its own (--new-session, so nothing in it can
// push input to a terminal), and nix, and all it started, die with
// bubblewrap (--die-with-parent). What it says goes to the launcher's
// stderr, cleaned, as it comes, or is kept when s captures it.
func (j *job) run(ctx context.Context, s step) ([]byte, error) {
	argv := j.confine(s)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	var out, said bytes.Buffer
	cmd.Stdout = &out
	var lines *cleanLines
	if s.capture {
		cmd.Stderr = &said
	} else {
		lines = &cleanLines{w: j.stderr}
		cmd.Stderr = io.MultiWriter(lines, &said)
	}
	err := cmd.Run()
	if lines != nil {
		lines.flush()
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &stepFailure{name: s.name, reason: reasonOf(said.String(), err), said: said.String()}
	}
	return out.Bytes(), nil
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
