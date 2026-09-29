package gitsafe_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
)

// The test binary is the trampoline, as the chase binary is.
func TestMain(m *testing.M) {
	gitsafe.MaybeExec()
	os.Exit(m.Run())
}

// sh is a git alias that runs a shell command, which is how a test sees what
// git's own environment is: git runs it with /bin/sh as it was built with.
func sh(g *gitsafe.Git, cmd string, pre ...string) gitsafe.Result {
	args := append(pre, "-c", "alias.t=!"+cmd, "t")
	return g.Run(context.Background(), args...)
}

func TestGitIsGivenNoEnvironmentButItsOwn(t *testing.T) {
	g := gitsafetest.Safe(t)
	t.Setenv("CHASE_TEST_LEAK", "leaked")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'alias.pwned'='!echo pwned'")
	r := sh(g, `echo "$CHASE_TEST_LEAK|$LC_ALL|$GIT_CONFIG_NOSYSTEM|$GIT_CONFIG_GLOBAL|$GIT_TERMINAL_PROMPT|$GIT_NO_LAZY_FETCH|$GIT_OPTIONAL_LOCKS|$GIT_NO_REPLACE_OBJECTS|$GIT_PAGER|$PAGER|$GIT_ATTR_NOSYSTEM|$(pwd)"`)
	if !r.OK() {
		t.Fatalf("status %d: %s %v", r.Status, r.Stderr, r.Err)
	}
	if got, want := strings.TrimSpace(string(r.Stdout)), "|C|1|/dev/null|0|1|0|1|cat|cat|1|/"; got != want {
		t.Errorf("git's environment is %q, want %q", got, want)
	}
	if r := g.Run(context.Background(), "pwned"); r.OK() || strings.Contains(string(r.Stdout), "pwned") {
		t.Errorf("the caller's GIT_CONFIG_PARAMETERS reached git: %s", r.Stdout)
	}

	r = sh(g, `echo "$HOME|$GIT_DIR|$PATH"`)
	f := strings.Split(strings.TrimSpace(string(r.Stdout)), "|")
	empty, _ := g.Empty("sha1")
	// git puts its exec-path before the PATH it is given, and nothing else.
	if len(f) != 3 || f[0] != empty || f[1] != empty || !strings.HasSuffix(f[2], ":"+filepath.Dir(gitsafetest.GitPath(t))) || strings.Count(f[2], ":") != 1 {
		t.Errorf("HOME|GIT_DIR|PATH is %q, want HOME and GIT_DIR %s and PATH git's own", r.Stdout, empty)
	}
}

func TestOnlyLeadingAssignmentsAreGitsEnvironment(t *testing.T) {
	g := gitsafetest.Safe(t)
	empty, _ := g.Empty("sha256")
	r := sh(g, `echo "$GIT_INDEX_FILE|$GIT_OBJECT_DIRECTORY|$GIT_DIR"`, "GIT_INDEX_FILE=/i", "GIT_OBJECT_DIRECTORY=/o", "GIT_DIR="+empty)
	if got, want := strings.TrimSpace(string(r.Stdout)), "/i|/o|"+empty; got != want {
		t.Errorf("assignments gave %q, want %q (%s)", got, want, r.Stderr)
	}
	// After an argument, NAME=VALUE is git's argument.
	r = g.Run(context.Background(), "version", "GIT_DIR=/x")
	if !r.OK() || !strings.HasPrefix(string(r.Stdout), "git version") {
		t.Errorf("git version GIT_DIR=/x: %d %s %s", r.Status, r.Stdout, r.Stderr)
	}
}

// made is a git with no empty repositories given, so it makes its own under
// a $XDG_RUNTIME_DIR of the test's.
func made(t *testing.T) (*gitsafe.Git, string) {
	t.Helper()
	runtime := gitsafetest.Dir(t)
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	g, err := gitsafe.New(gitsafe.Config{Git: gitsafetest.GitPath(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g, runtime
}

func TestTheEmptyRepositoriesAreOfTheirFormatPrivateAndReadOnly(t *testing.T) {
	g, runtime := made(t)
	for _, format := range []string{"sha1", "sha256"} {
		d, err := g.Empty(format)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(filepath.Dir(d)) != runtime {
			t.Errorf("%s is not made in $XDG_RUNTIME_DIR %s", d, runtime)
		}
		r := g.Run(context.Background(), "GIT_DIR="+d, "rev-parse", "--show-object-format", "--is-bare-repository")
		if got := string(r.Stdout); got != format+"\ntrue\n" {
			t.Errorf("%s: %q %s", format, got, r.Stderr)
		}
		for p, want := range map[string]os.FileMode{
			filepath.Dir(d): 0o500, d: 0o500, d + "/objects": 0o500, d + "/refs": 0o500,
			d + "/HEAD": 0o400, d + "/config": 0o400,
		} {
			fi, err := os.Stat(p)
			if err != nil || fi.Mode().Perm() != want {
				t.Errorf("%s is %v (%v), want %v", p, fi.Mode().Perm(), err, want)
			}
		}
	}
	if _, err := g.Empty("md5"); err == nil {
		t.Error("an empty repository of an unknown format was made")
	}
	d, _ := g.Empty("sha1")
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Errorf("Close left %s", d)
	}
	// Used again after Close, it makes them again.
	if r := g.Run(context.Background(), "version"); !r.OK() {
		t.Errorf("git after Close: %d %s %v", r.Status, r.Stderr, r.Err)
	}
	g.Close()
	if left, _ := os.ReadDir(runtime); len(left) != 0 {
		t.Errorf("Close left %v", left)
	}
}

// Not in the temporary directory, which a session may share: with no
// $XDG_RUNTIME_DIR and none given, git is not run at all.
func TestWithNowherePrivateGitIsNotRun(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	g, err := gitsafe.New(gitsafe.Config{Git: gitsafetest.GitPath(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	r := g.Run(context.Background(), "version")
	if r.OK() || !errors.Is(r.Err, gitsafe.ErrNoPrivateDir) {
		t.Errorf("git ran with no private directory: %d %v", r.Status, r.Err)
	}
}

// The module's empty repositories are used as they are, and never removed.
func TestTheModulesEmptyRepositoriesAreUsedAndKept(t *testing.T) {
	c := gitsafetest.Config(t)
	g, err := gitsafe.New(c)
	if err != nil {
		t.Fatal(err)
	}
	for format, want := range map[string]string{"sha1": c.EmptySHA1, "sha256": c.EmptySHA256} {
		if d, err := g.Empty(format); err != nil || d != want {
			t.Errorf("Empty(%s) = %s %v, want %s", format, d, err, want)
		}
	}
	r := g.Run(context.Background(), "rev-parse", "--show-object-format")
	if string(r.Stdout) != "sha1\n" {
		t.Errorf("the given sha1 repository is not git's: %q %s", r.Stdout, r.Stderr)
	}
	g.Close()
	if _, err := os.Stat(c.EmptySHA1 + "/HEAD"); err != nil {
		t.Errorf("Close removed the module's repository: %v", err)
	}
	for _, bad := range []gitsafe.Config{
		{Git: c.Git, EmptySHA1: c.EmptySHA1},
		{Git: c.Git, EmptySHA256: c.EmptySHA256},
		{Git: c.Git, EmptySHA1: "sha1", EmptySHA256: c.EmptySHA256},
		{Git: c.Git, EmptySHA1: c.EmptySHA1, EmptySHA256: "/nonexistent"},
	} {
		if _, err := gitsafe.New(bad); err == nil {
			t.Errorf("%+v was taken", bad)
		}
	}
}

// Something git started that still holds its output once git has exited is
// not waited on for long, and what was read then is not taken for all of it.
func TestOutputHeldPastGitIsAFailure(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal("no sleep on PATH")
	}
	g := gitsafetest.Safe(t)
	gitsafe.SetTimeout(g, 10*time.Second, 300*time.Millisecond)
	start := time.Now()
	r := sh(g, sleep+" 5 & echo partial")
	if r.OK() {
		t.Errorf("a call whose output was held open succeeded: %q", r.Stdout)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("the held output was waited on for %s", d)
	}
}

// The limit reaches git through the trampoline, though the Go process that
// sets it is already over it.
func TestGitRunsUnderTheAddressSpaceLimit(t *testing.T) {
	g := gitsafetest.Safe(t)
	r := sh(g, "ulimit -v")
	if got := strings.TrimSpace(string(r.Stdout)); got != "1048576" {
		t.Errorf("ulimit -v in git is %q (%s), want 1048576", got, r.Stderr)
	}
	status, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, l := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(l, "VmPeak:") {
				t.Logf("this test binary: %s", strings.Join(strings.Fields(l), " "))
			}
		}
	}
}

func TestACallThatRunsTooLongIsStoppedAndFails(t *testing.T) {
	g := gitsafetest.Safe(t)
	gitsafe.SetTimeout(g, 300*time.Millisecond, 300*time.Millisecond)
	start := time.Now()
	r := sh(g, "while :; do :; done")
	if r.Status != gitsafe.StatusTimedOut {
		t.Errorf("status %d, want %d", r.Status, gitsafe.StatusTimedOut)
	}
	// Told to stop and ignoring it, what git ran is killed with the rest of
	// its group, and the call still ends.
	r = sh(g, `trap "" TERM; while :; do :; done`)
	if r.OK() {
		t.Error("a call that ignored being stopped succeeded")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("two calls cut short took %s", d)
	}
}

func TestGitIsNeverLookedUpOnPath(t *testing.T) {
	if _, err := gitsafe.New(gitsafe.Config{Git: "git"}); err == nil {
		t.Error("a relative git was taken")
	}
	if _, err := gitsafe.New(gitsafe.Config{Git: "/nonexistent/git"}); err == nil {
		t.Error("a git that is not there was taken")
	}
}

// realpath is coreutils' own, to hold Realpath to.
func realpath(t *testing.T, p string) (string, bool) {
	out, err := exec.Command("realpath", "-e", "--", p).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(string(out), "\n"), true
}

func TestRealpathIsRealpathE(t *testing.T) {
	if _, err := exec.LookPath("realpath"); err != nil {
		t.Fatal("no realpath on PATH")
	}
	d := gitsafetest.Dir(t)
	for _, p := range []string{"real/sub", "real/sub/deep"} {
		os.MkdirAll(filepath.Join(d, p), 0o755)
	}
	os.WriteFile(filepath.Join(d, "real/file"), nil, 0o644)
	os.Symlink(filepath.Join(d, "real/sub"), filepath.Join(d, "abs"))
	os.Symlink("real/sub", filepath.Join(d, "rel"))
	os.Symlink("nowhere", filepath.Join(d, "dangling"))
	os.Symlink("loop", filepath.Join(d, "loop"))
	os.Symlink("../file", filepath.Join(d, "real/sub/up"))
	for _, p := range []string{
		"", ".", "/", "//", d, d + "/", d + "/real/sub/..", d + "/abs/..", d + "/rel/..", d + "/abs/../file",
		d + "/abs/deep/../..", d + "/real/file", d + "/real/file/", d + "/real/file/..", d + "/real/file/.",
		d + "/dangling", d + "/loop", d + "/missing", d + "/missing/..", d + "/real/sub/up", d + "/real/sub/up/",
		d + "//real///sub/./deep", "/..", "/../" + d[1:],
	} {
		got, gotOK := gitsafe.Realpath(p)
		want, wantOK := realpath(t, p)
		if gotOK != nil {
			got = ""
		}
		if (gotOK == nil) != wantOK || got != want {
			t.Errorf("Realpath(%q) = %q, %v; realpath -e gives %q, %v", p, got, gotOK, want, wantOK)
		}
	}
	t.Chdir(filepath.Join(d, "abs"))
	for _, p := range []string{"..", "deep/..", "../file", "."} {
		got, err := gitsafe.Realpath(p)
		want, wantOK := realpath(t, p)
		if (err == nil) != wantOK || got != want {
			t.Errorf("in abs, Realpath(%q) = %q, %v; realpath -e gives %q", p, got, err, want)
		}
	}
}

func TestSmallIsAPlainFileNoLargerThanItsKind(t *testing.T) {
	d := gitsafetest.Dir(t)
	f := filepath.Join(d, "f")
	os.WriteFile(f, make([]byte, 10), 0o644)
	os.Symlink(f, filepath.Join(d, "link"))
	if !gitsafe.Small(f, 10) || gitsafe.Small(f, 9) {
		t.Error("a 10-byte file is not held to 10 bytes")
	}
	if gitsafe.Small(filepath.Join(d, "link"), 10) || gitsafe.Regular(filepath.Join(d, "link")) {
		t.Error("a link to a plain file is taken as one")
	}
	if gitsafe.Small(d, 1<<30) {
		t.Error("a directory is taken as a plain file")
	}
	if !gitsafe.Exists(filepath.Join(d, "link")) || gitsafe.ExistsFollowing(filepath.Join(d, "nope")) {
		t.Error("existence is wrong")
	}
}
