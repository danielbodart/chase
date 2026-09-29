// Package gitsafe is git, on the host, of a repository a session wrote.
//
// The selector and what finds a checkout run as the user, unsandboxed, on
// every launch, against a checkout whose .git -- config, HEAD, refs, objects,
// all of it -- a session, the strict tier's included, may have written. A
// repository's config names commands for git to run (core.fsmonitor on any
// read of the index, hook.<name>.command, filter drivers, a pager,
// gpg.program, core.sshCommand, credential.helper, and more with each
// release), and files for it to read (include.path,
// objects/info/alternates). Turning each off by name is a list that is never
// finished: hook.<name> and filter.<name> are named by the repository.
//
// So git here never reads the repository's config at all. Every call is
// Git.Run, so a call added later is made the same way:
//
//   - no environment but its own: no GIT_* of the caller's, no system or
//     global config (the user's own is not needed to sort a directory: only
//     origin's URL and the root commits' authors are read, and neither takes
//     anything from it), HOME an empty directory, no prompt, no lazy fetch,
//     no optional locks, no replace objects, no pager;
//
//   - GIT_DIR an empty repository of its own, not the checkout's: `git
//     config --file F --no-includes` reads F and only F, and `git log` of a
//     commit id resolved here reads the checkout's objects through
//     GIT_OBJECT_DIRECTORY and nothing else of it -- no config, index,
//     hooks, attributes, grafts, replace refs, shallow file or promisor
//     remote. It was a store path; it is now made by this package, in a
//     directory of the process's own that nothing else is told of;
//
//   - every config-driven command git has for the reads made here
//     overridden besides, for a call added later that reads more;
//
//   - bounded: objects a session wrote can be a delta cycle, or a zlib
//     bomb, that git would chase with no end to its time or memory, and a
//     config file can be sparse and a hundred gigabytes long. So each call
//     has an address-space limit, small pack windows to fit it, and a
//     timeout, and a call cut short is one that failed: nothing found, which
//     falls to the fallback like any other miss.
//
// And what git is given to read is looked at first: a config file, a ref or
// HEAD is read only as a plain file (not a link, not a pipe) no larger than
// such a file ever is, and objects only where nothing in them is a link and
// no alternates borrow any from elsewhere. Files read here without git are
// held to the same sizes.
package gitsafe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// Timeout is how long one call of git is given, as `timeout 20` gave it.
	Timeout = 20 * time.Second
	// KillAfter is how long a call told to stop is given before it is
	// killed, as `timeout -k 1` gave it.
	KillAfter = time.Second
	// AddressSpace is each call's address-space limit, `ulimit -v 1048576`:
	// 1 GiB, which the pack windows below are sized to fit.
	AddressSpace = 1 << 30
)

// Exit statuses as the shell reported them, which callers compare against:
// `timeout` gives 124 for a command it stopped, 128+9 for one it had to
// kill, and `env` 126 or 127 for one it could not run.
const (
	StatusTimedOut = 124
	StatusKilled   = 128 + 9
	StatusCannot   = 126
	StatusNotFound = 127
)

// overrides is every config-driven command git has for the reads made here,
// turned off, and the pack windows sized to fit AddressSpace. They come
// after the repository's config would, so they win over it -- though no
// repository's config is read.
var overrides = []string{
	"--no-pager", "--no-replace-objects",
	"-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
	"-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
	"-c", "core.pager=cat", "-c", "core.editor=false", "-c", "sequence.editor=false",
	"-c", "core.askPass=", "-c", "credential.helper=", "-c", "core.sshCommand=false",
	"-c", "core.gitProxy=", "-c", "core.alternateRefsCommand=", "-c", "protocol.allow=never",
	"-c", "diff.external=", "-c", "log.showSignature=false", "-c", "gpg.program=false",
	"-c", "gpg.ssh.program=false", "-c", "gpg.x509.program=false",
	"-c", "log.mailmap=false", "-c", "mailmap.file=", "-c", "mailmap.blob=",
	"-c", "uploadpack.packObjectsHook=", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
	"-c", "core.packedGitWindowSize=16m", "-c", "core.packedGitLimit=128m",
	"-c", "core.deltaBaseCacheLimit=32m", "-c", "core.bigFileThreshold=16m",
}

// assignable is what a call may set in git's environment, given as leading
// NAME=VALUE arguments, as the shell function took them: which repository,
// which objects, which index. Nothing else of the caller's reaches git.
var assignable = []string{"GIT_DIR=", "GIT_OBJECT_DIRECTORY=", "GIT_INDEX_FILE="}

// Config is what the NixOS module tells chase of git.
type Config struct {
	// Git is the absolute path of the git binary every call runs,
	// ${pkgs.git}/bin/git: never looked up on PATH, which is the caller's.
	Git string `json:"git"`
}

// Git runs git as described in the package comment. Its empty repositories
// are made on first use, in a directory only the user can read, and removed
// by Close.
type Git struct {
	path string
	self string

	// timeout and killAfter are Timeout and KillAfter, and a test's to
	// shorten.
	timeout   time.Duration
	killAfter time.Duration

	once  sync.Once
	dir   string
	dirOK error
}

// New is git at c.Git, which must be an absolute path to an executable file.
// Each call re-executes this process's own binary to set its address-space
// limit before git starts, so that binary must call MaybeExec first thing in
// main.
func New(c Config) (*Git, error) {
	if !filepath.IsAbs(c.Git) {
		return nil, fmt.Errorf("git is %q, which is not an absolute path", c.Git)
	}
	fi, err := os.Stat(c.Git)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("git is %s, which is not an executable file", c.Git)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("finding this binary to limit git with: %w", err)
	}
	return &Git{path: c.Git, self: self, timeout: Timeout, killAfter: KillAfter}, nil
}

// Close removes the empty repositories, if any were made.
func (g *Git) Close() error {
	if g.dir == "" {
		return nil
	}
	return os.RemoveAll(g.dir)
}

// Empty is the empty repository of an object format, sha1 or sha256, made
// here once: a bare repository with no objects, no refs, a HEAD naming a
// branch that does not exist, and a config that says only its format. It is
// both GIT_DIR and HOME of every call, so git finds neither a repository nor
// a user's config of anybody's.
//
// It is made under $XDG_RUNTIME_DIR when there is one, which no session sees,
// and the temporary directory otherwise, in a directory of its own that only
// the user can read.
func (g *Git) Empty(format string) (string, error) {
	if format != "sha1" && format != "sha256" {
		return "", fmt.Errorf("no empty repository of object format %q", format)
	}
	g.once.Do(func() { g.dir, g.dirOK = makeEmpties() })
	if g.dirOK != nil {
		return "", g.dirOK
	}
	return filepath.Join(g.dir, format), nil
}

func makeEmpties() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(base) {
		base = ""
	} else if fi, err := os.Stat(base); err != nil || !fi.IsDir() {
		base = ""
	}
	dir, err := os.MkdirTemp(base, "chase-git-")
	if err != nil {
		return "", err
	}
	for _, format := range []string{"sha1", "sha256"} {
		d := filepath.Join(dir, format)
		for _, sub := range []string{"objects", "refs"} {
			if err := os.MkdirAll(filepath.Join(d, sub), 0o700); err != nil {
				os.RemoveAll(dir)
				return "", err
			}
		}
		head := "ref: refs/heads/none\n"
		config := fmt.Sprintf("[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tobjectFormat = %s\n", format)
		if err := os.WriteFile(filepath.Join(d, "HEAD"), []byte(head), 0o600); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
		if err := os.WriteFile(filepath.Join(d, "config"), []byte(config), 0o600); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

// Result is what a call of git gave: everything it wrote, and its exit
// status as the shell would have seen it. Err is set, and Status is not 0,
// when git could not be run at all.
type Result struct {
	Stdout []byte
	Stderr []byte
	Status int
	Err    error
}

// OK is whether git exited 0.
func (r Result) OK() bool { return r.Status == 0 }

// Run runs git with args, as the shell function did:
//
//	git [GIT_DIR=D] [GIT_OBJECT_DIRECTORY=D] [GIT_INDEX_FILE=F] ARG...
//
// Leading arguments that set one of those three are git's environment, not
// its arguments; any other argument, and every one after it, is git's.
//
// git runs in /, in an environment of nothing but its own, in a process
// group of its own that is stopped after Timeout and killed KillAfter later,
// under an address-space limit of AddressSpace, with every override. It is
// never given the caller's stdin.
func (g *Git) Run(ctx context.Context, args ...string) Result {
	var set []string
	for len(args) > 0 && isAssignment(args[0]) {
		set = append(set, args[0])
		args = args[1:]
	}
	empty, err := g.Empty("sha1")
	if err != nil {
		return Result{Status: StatusCannot, Err: err}
	}
	env := map[string]string{}
	order := []string{}
	put := func(kv string) {
		k, v, _ := strings.Cut(kv, "=")
		if _, ok := env[k]; !ok {
			order = append(order, k)
		}
		env[k] = v
	}
	for _, kv := range []string{
		"PATH=" + filepath.Dir(g.path), "HOME=" + empty, "LC_ALL=C",
		"GIT_DIR=" + empty, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1",
		"GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_PAGER=cat", "PAGER=cat",
	} {
		put(kv)
	}
	// Later wins, as env -i gave the call's own assignments over the
	// defaults: GIT_DIR above all.
	for _, kv := range set {
		put(kv)
	}
	environ := make([]string, 0, len(order))
	for _, k := range order {
		environ = append(environ, k+"="+env[k])
	}

	argv := append([]string{trampolineArg, g.path}, overrides...)
	argv = append(argv, args...)
	cmd := exec.Command(g.self, argv...)
	cmd.Env = environ
	cmd.Dir = "/"
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Once git is gone, what it left holding its output is not waited on
	// for long.
	cmd.WaitDelay = g.killAfter
	if err := cmd.Start(); err != nil {
		return Result{Status: StatusCannot, Err: err}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timer := time.NewTimer(g.timeout)
	defer timer.Stop()
	var werr error
	stopped, killed := false, false
	select {
	case werr = <-done:
	case <-timer.C:
		stopped = true
	case <-ctx.Done():
		stopped = true
	}
	if stopped {
		// The whole group, as timeout signals it: git and anything it ran.
		syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		grace := time.NewTimer(g.killAfter)
		select {
		case werr = <-done:
		case <-grace.C:
			killed = true
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			werr = <-done
		}
		grace.Stop()
	}
	r := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	switch {
	case killed:
		r.Status = StatusKilled
	case stopped:
		r.Status = StatusTimedOut
	default:
		r.Status = status(cmd.ProcessState, werr)
	}
	if werr != nil && !errors.As(werr, new(*exec.ExitError)) {
		r.Err = werr
	}
	return r
}

func status(ps *os.ProcessState, err error) int {
	if ps == nil {
		if err != nil {
			return StatusCannot
		}
		return 0
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

func isAssignment(arg string) bool {
	for _, p := range assignable {
		if strings.HasPrefix(arg, p) {
			return true
		}
	}
	return false
}
