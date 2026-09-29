package checkout_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
)

func TestMain(m *testing.M) {
	gitsafe.MaybeExec()
	os.Exit(m.Run())
}

func call(t *testing.T, g *gitsafe.Git, f func(context.Context, *gitsafe.Git, []string, *bytes.Buffer, *bytes.Buffer) int, args ...string) (string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := f(context.Background(), g, args, &out, &errb)
	return out.String(), rc
}

func checkoutCmd(ctx context.Context, g *gitsafe.Git, a []string, o, e *bytes.Buffer) int {
	return checkout.RunCheckout(ctx, g, a, o, e)
}
func originCmd(ctx context.Context, g *gitsafe.Git, a []string, o, e *bytes.Buffer) int {
	return checkout.RunOrigin(ctx, g, a, o, e)
}
func lsFilesCmd(ctx context.Context, g *gitsafe.Git, a []string, o, e *bytes.Buffer) int {
	return checkout.RunLsFiles(ctx, g, a, o, e)
}

// What chase-checkout prints, for each kind of checkout, is the line its
// callers split on tabs.
func TestACheckoutIsPrintedAsItsCallersReadIt(t *testing.T) {
	g := gitsafetest.Safe(t)
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Repo(r+"/c", "git@github.com:example/shop.git", "a@example.com")
	fx.Repo(r+"/lib", "git@github.com:example/lib.git", "a@example.com")
	fx.Run("-C", r+"/c", "worktree", "add", "-q", r+"/c/.claude/worktrees/w")
	fx.Run("-C", r+"/c", "-c", "protocol.file.allow=always", "submodule", "add", "-q", "file://"+r+"/lib", "vendor/lib")
	os.MkdirAll(r+"/c/deep/er", 0o755)
	os.MkdirAll(r+"/plain", 0o755)

	for _, c := range []struct {
		args []string
		out  string
		rc   int
	}{
		{[]string{r + "/c"}, r + "/c\t" + r + "/c\tcheckout\t" + r + "/c/.git\t" + r + "/c/.git\n", 0},
		{[]string{r + "/c/deep/er"}, r + "/c\t" + r + "/c\tcheckout\t" + r + "/c/.git\t" + r + "/c/.git\n", 0},
		{[]string{r + "/c/.claude/worktrees/w"}, r + "/c/.claude/worktrees/w\t" + r + "/c\tworktree\t" + r + "/c/.git\t" + r + "/c/.git/worktrees/w\n", 0},
		{[]string{r + "/c/vendor/lib"}, r + "/c/vendor/lib\t" + r + "/c\tsubmodule\t" + r + "/c/.git/modules/vendor/lib\t" + r + "/c/.git/modules/vendor/lib\n", 0},
		// Asked as if the submodule's .git were gone: a directory inside a
		// submodule of the checkout above it.
		{[]string{"--ignoring", r + "/c/vendor/lib", r + "/c/vendor/lib"}, r + "/c/vendor/lib is inside " + r + "/c/vendor/lib, a submodule with no .git of its own\n", 1},
		{[]string{"--ignoring", r + "/c/.claude/worktrees/w", r + "/c/.claude/worktrees/w"}, r + "/c\t" + r + "/c\tcheckout\t" + r + "/c/.git\t" + r + "/c/.git\n", 0},
		{[]string{r + "/plain"}, "not a git repository\n", 1},
		{[]string{r + "/nonexistent"}, "no such directory\n", 1},
		{[]string{"--ignoring", r + "/nonexistent", r + "/c"}, "no such directory\n", 1},
	} {
		out, rc := call(t, g, checkoutCmd, c.args...)
		if out != c.out || rc != c.rc {
			t.Errorf("chase-checkout %q: %q %d, want %q %d", c.args, out, rc, c.out, c.rc)
		}
	}

	t.Chdir(r + "/c/deep")
	if out, rc := call(t, g, checkoutCmd); rc != 0 || !strings.HasPrefix(out, r+"/c\t") {
		t.Errorf("chase-checkout in a directory of it: %q %d", out, rc)
	}
	// Every variable that could redirect git is said, set even empty.
	t.Setenv("GIT_CONFIG_COUNT", "")
	t.Setenv("GIT_INDEX_FILE", "/x")
	if out, rc := call(t, g, checkoutCmd, r+"/c"); rc != 1 || out != "git is redirected by the environment: GIT_INDEX_FILE GIT_CONFIG_COUNT\n" {
		t.Errorf("a redirected environment: %q %d", out, rc)
	}
}

// A refusal carries what a session wrote, so it reaches a terminal cleaned.
func TestARefusalIsCleanedForTheTerminal(t *testing.T) {
	g := gitsafetest.Safe(t)
	r := gitsafetest.Dir(t)
	os.MkdirAll(r+"/x", 0o755)
	os.WriteFile(r+"/x/.git", []byte("gitdir: \x1b]0;PWNED\x07\n"), 0o644)
	out, rc := call(t, g, checkoutCmd, r+"/x")
	if rc != 1 || strings.ContainsAny(out, "\x1b\x07") || !strings.Contains(out, "?]0;PWNED?") {
		t.Errorf("an escape reached the terminal: %q", out)
	}
}

func TestOriginIsEveryURLTheConfigFilesGive(t *testing.T) {
	g := gitsafetest.Safe(t)
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Repo(r+"/c", "git@github.com:example/shop.git", "a@example.com")
	os.MkdirAll(r+"/c/sub", 0o755)
	head := r + "/c\t" + r + "/c\tcheckout\t" + r + "/c/.git\n"
	if out, rc := call(t, g, originCmd, r+"/c/sub"); rc != 0 || out != head+"git@github.com:example/shop.git\n" {
		t.Errorf("chase-origin: %q %d", out, rc)
	}
	fx.Run("-C", r+"/c", "config", "--add", "remote.origin.url", "https://github.com/example/billing")
	if out, rc := call(t, g, originCmd, r+"/c"); rc != 0 || out != head+"git@github.com:example/shop.git\nhttps://github.com/example/billing\n" {
		t.Errorf("chase-origin of two URLs: %q %d", out, rc)
	}
	fx.Run("-C", r+"/c", "remote", "remove", "origin")
	if out, rc := call(t, g, originCmd, r+"/c"); rc != 0 || out != head {
		t.Errorf("chase-origin of none: %q %d", out, rc)
	}
	os.MkdirAll(r+"/plain", 0o755)
	if out, rc := call(t, g, originCmd, r+"/plain"); rc != 1 || out != "not a git repository\n" {
		t.Errorf("chase-origin of no checkout: %q %d", out, rc)
	}
	if out, rc := call(t, g, originCmd); rc != 2 || out != "usage: chase-origin DIR\n" {
		t.Errorf("chase-origin with nothing: %q %d", out, rc)
	}
}

func TestLsFilesListsTheIndexWithoutRunningWhatTheCheckoutNames(t *testing.T) {
	g := gitsafetest.Safe(t)
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	pwned := r + "/PWNED"
	fx.Repo(r+"/c", "git@github.com:example/shop.git", "a@example.com")
	os.MkdirAll(r+"/c/sub/deep", 0o755)
	for _, f := range []string{"top", "sub/one", "sub/deep/two", "subway"} {
		os.WriteFile(r+"/c/"+f, []byte(f), 0o644)
	}
	fx.Run("-C", r+"/c", "add", ".")
	os.WriteFile(r+"/c/untracked", nil, 0o644)
	fx.Run("-C", r+"/c", "config", "core.fsmonitor", "touch "+pwned+"; false")
	os.MkdirAll(r+"/hooks", 0o755)
	os.WriteFile(r+"/hooks/post-index-change", []byte("#!/bin/sh\ntouch "+pwned+"\n"), 0o755)
	fx.Run("-C", r+"/c", "config", "core.hooksPath", r+"/hooks")
	// The same config does run each when git is asked plainly.
	fx.Try("-C", r+"/c", "ls-files")
	if _, err := os.Stat(pwned); err != nil {
		t.Fatal("core.fsmonitor is not run by a plain git ls-files, so this proves nothing")
	}
	os.Remove(pwned)

	for dir, want := range map[string]string{
		r + "/c":          "sub/deep/two\x00sub/one\x00subway\x00top\x00",
		r + "/c/sub":      "deep/two\x00one\x00",
		r + "/c/sub/deep": "two\x00",
	} {
		if out, rc := call(t, g, lsFilesCmd, dir); rc != 0 || out != want {
			t.Errorf("chase-ls-files %s: %q %d, want %q", dir, out, rc, want)
		}
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Error("chase-ls-files ran the checkout's core.fsmonitor or core.hooksPath")
	}

	// No index yet tracks nothing; no checkout is said.
	fx.Run("init", "-q", r+"/new")
	if out, rc := call(t, g, lsFilesCmd, r+"/new"); rc != 0 || out != "" {
		t.Errorf("a checkout with no index: %q %d", out, rc)
	}
	os.MkdirAll(r+"/nogit", 0o755)
	if out, rc := call(t, g, lsFilesCmd, r+"/nogit"); rc != 1 || out != "not a git repository\n" {
		t.Errorf("no checkout: %q %d", out, rc)
	}
	if out, rc := call(t, g, lsFilesCmd); rc != 2 || out != "usage: chase-ls-files DIR\n" {
		t.Errorf("chase-ls-files with nothing: %q %d", out, rc)
	}
}

// An index that needs more than itself is not read: a split index's shared
// part would be read from beside the index, which the session writes, and a
// sparse index would leave out what is under its sparse directories without
// a word.
func TestLsFilesRefusesAnIndexThatIsNotWhole(t *testing.T) {
	g := gitsafetest.Safe(t)
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Repo(r+"/split", "git@github.com:example/split.git", "a@example.com")
	os.WriteFile(r+"/split/f", nil, 0o644)
	fx.Run("-C", r+"/split", "add", "f")
	fx.Run("-C", r+"/split", "update-index", "--split-index")
	shared, _ := filepath.Glob(r + "/split/.git/sharedindex.*")
	if len(shared) == 0 {
		t.Fatal("the split index has no shared part, so it proves nothing")
	}
	if out, rc := call(t, g, lsFilesCmd, r+"/split"); rc != 1 || out != "the index of "+r+"/split cannot be read on its own, as a split index cannot\n" {
		t.Errorf("a split index: %q %d", out, rc)
	}

	fx.Repo(r+"/sparse", "git@github.com:example/sparse.git", "a@example.com")
	for _, f := range []string{"keep/f", "away/f"} {
		os.MkdirAll(filepath.Dir(r+"/sparse/"+f), 0o755)
		os.WriteFile(r+"/sparse/"+f, nil, 0o644)
	}
	fx.Run("-C", r+"/sparse", "add", ".")
	fx.Run("-C", r+"/sparse", "-c", "user.name=x", "-c", "user.email=a@example.com", "commit", "-qm", "x")
	fx.Run("-C", r+"/sparse", "sparse-checkout", "set", "--cone", "--sparse-index", "keep")
	if out, rc := call(t, g, lsFilesCmd, r+"/sparse"); rc != 1 || out != "the index of "+r+"/sparse is sparse, or cannot be read on its own\n" {
		t.Errorf("a sparse index: %q %d", out, rc)
	}

	// Not a plain file of an index's size: a link, and a pipe.
	fx.Repo(r+"/linked", "git@github.com:example/linked.git", "a@example.com")
	os.WriteFile(r+"/linked/f", nil, 0o644)
	fx.Run("-C", r+"/linked", "add", "f")
	os.Rename(r+"/linked/.git/index", r+"/index")
	os.Symlink(r+"/index", r+"/linked/.git/index")
	if out, rc := call(t, g, lsFilesCmd, r+"/linked"); rc != 1 || out != r+"/linked/.git/index is not a plain file of an index's size\n" {
		t.Errorf("a linked index: %q %d", out, rc)
	}
	// An object format git does not have.
	fx.Repo(r+"/odd", "git@github.com:example/odd.git", "a@example.com")
	os.WriteFile(r+"/odd/f", nil, 0o644)
	fx.Run("-C", r+"/odd", "add", "f")
	fx.Run("config", "--file", r+"/odd/.git/config", "extensions.objectFormat", "md5")
	if out, rc := call(t, g, lsFilesCmd, r+"/odd"); rc != 1 || out != r+"/odd has an object format of md5\n" {
		t.Errorf("an unknown object format: %q %d", out, rc)
	}
}

// A sha256 repository's index is read by the empty repository of its own
// format.
func TestLsFilesReadsASha256Index(t *testing.T) {
	g := gitsafetest.Safe(t)
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Run("init", "-q", "--object-format=sha256", r+"/c")
	os.WriteFile(r+"/c/f", nil, 0o644)
	fx.Run("-C", r+"/c", "add", "f")
	if out, rc := call(t, g, lsFilesCmd, r+"/c"); rc != 0 || out != "f\x00" {
		t.Errorf("a sha256 index: %q %d", out, rc)
	}
}
