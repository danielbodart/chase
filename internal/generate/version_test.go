package generate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gitRepo is a repository with VERSION holding major and commits commits.
func gitRepo(t *testing.T, major string, commits int) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "trunk")
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(major), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < commits; i++ {
		git(t, dir, "add", "-A")
		git(t, dir, "commit", "-q", "--allow-empty", "-m", "commit")
	}
	return dir
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@example.invalid",
		"GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@example.invalid",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestVersion(t *testing.T) {
	dir := gitRepo(t, " 0\n\t\v\f\r", 3)
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	for _, c := range []struct {
		run, want string
	}{
		// PATCH is the CI run number...
		{"42", "0.3.42\n"},
		// ...or, without one, the time in UTC.
		{"", "0.3.20260102020405\n"},
	} {
		got, err := Version(VersionOptions{
			Dir:    sub,
			Getenv: func(k string) string { return map[string]string{"GITHUB_RUN_NUMBER": c.run}[k] },
			Now:    func() time.Time { return at },
		})
		if err != nil || got != c.want {
			t.Errorf("run %q: %q, %v; want %q", c.run, got, err, c.want)
		}
	}
}

// A shallow clone's commit count is not the history's, so its version
// would be wrong: it is refused, saying how CI should check out.
func TestVersionRefusesAShallowClone(t *testing.T) {
	dir := gitRepo(t, "1\n", 2)
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, dir, "clone", "-q", "--depth", "1", "file://"+dir, clone)
	_, err := Version(VersionOptions{Dir: clone, Getenv: func(string) string { return "1" }})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Fatalf("a shallow clone was not refused: %v", err)
	}
	want := "version: shallow clone, so the commit count and the version are wrong.\n         In Actions, check out with `fetch-depth: 0`."
	if err.Error() != want {
		t.Fatalf("refused as %q", err)
	}
}

func TestVersionOutsideARepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	if _, err := os.Stat("/VERSION"); err == nil {
		t.Skip("/VERSION exists, which the script would have read")
	}
	_, err := Version(VersionOptions{Dir: t.TempDir()})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 1 || !strings.HasPrefix(err.Error(), "version: git rev-parse --show-toplevel: ") {
		t.Fatalf("outside a repository, not refused with status 1 as the script's failed redirect was: %v", err)
	}
}
