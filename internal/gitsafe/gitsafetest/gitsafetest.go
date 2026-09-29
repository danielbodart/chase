// Package gitsafetest is what the tests of gitsafe, checkout and selector
// share: the git they build real repositories with, which is the one on PATH
// and reads what those repositories say, and gitsafe's own, which must not.
package gitsafetest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/gitsafe"
)

// GitPath is the absolute path of the git on PATH, which the devShell and
// the flake's checks provide.
func GitPath(t testing.TB) string {
	t.Helper()
	p, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git on PATH")
	}
	p, err = filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Safe is gitsafe's git, closed when the test ends.
func Safe(t testing.TB) *gitsafe.Git {
	t.Helper()
	g, err := gitsafe.New(gitsafe.Config{Git: GitPath(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g
}

// Dir is a fresh directory for the test with every link in its path
// resolved: what is compared is a resolved path.
func Dir(t testing.TB) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Fixture is a git that builds a test's repositories: the one on PATH, with
// a HOME of its own and no system or global config, so what it makes is the
// same wherever the test runs. It reads what the repositories it is run in
// say, commands included -- which is what the tests hold gitsafe's git to
// not doing.
type Fixture struct {
	t    testing.TB
	path string
	home string
}

// NewFixture is a Fixture with its own HOME under the test's directory.
func NewFixture(t testing.TB) *Fixture {
	t.Helper()
	home := Dir(t)
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return &Fixture{t: t, path: GitPath(t), home: home}
}

func (f *Fixture) env() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") || strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HOME="+f.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+filepath.Join(f.home, ".gitconfig"))
}

// Run is git ARGS, which must succeed; it is what git printed on stdout.
func (f *Fixture) Run(args ...string) string {
	f.t.Helper()
	out, err := f.Try(args...)
	if err != nil {
		f.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// Try is git ARGS, which may fail.
func (f *Fixture) Try(args ...string) (string, error) {
	f.t.Helper()
	cmd := exec.Command(f.path, args...)
	cmd.Env = f.env()
	cmd.Stdin = strings.NewReader("")
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return out.String() + errb.String(), err
	}
	return out.String(), nil
}

// Stdin is git ARGS given stdin, which must succeed.
func (f *Fixture) Stdin(stdin string, args ...string) string {
	f.t.Helper()
	cmd := exec.Command(f.path, args...)
	cmd.Env = f.env()
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		f.t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

// Repo is `repo DIR REMOTE AUTHOR` of the flake's checks: a repository at
// dir, with one empty commit by author, and origin at remote.
func (f *Fixture) Repo(dir, remote, author string) {
	f.t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	f.Run("-C", dir, "init", "-q")
	f.Run("-C", dir, "-c", "user.name=x", "-c", "user.email="+author, "commit", "-q", "--allow-empty", "-m", "first")
	f.Run("-C", dir, "remote", "add", "origin", remote)
}
