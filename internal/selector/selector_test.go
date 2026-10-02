package selector_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
	"github.com/danielbodart/chase/internal/selector"
)

func TestMain(m *testing.M) {
	gitsafe.MaybeExec()
	os.Exit(m.Run())
}

// world is the selector check's: its rules are the example's shape at paths
// under the test's own directory, since `chase tier` compares resolved paths.
type world struct {
	t   *testing.T
	r   string
	git *gitsafetest.Fixture
	s   *selector.Selector
}

func newWorld(t *testing.T) *world {
	r := filepath.Join(gitsafetest.Dir(t), "root")
	cfg := selector.Config{
		Config:   gitsafetest.Config(t),
		Order:    []string{"host", "strict", "trusted"},
		Fallback: "strict",
		Tiers: map[string]selector.Tier{
			"host": {Bare: true, Match: []selector.Rule{
				{Paths: []string{r + "/home"}},
				{Checkouts: map[string]string{"alice/nix-config": r + "/p/nix-config"}},
				{Checkouts: map[string]string{"alice/bare": r + "/p/bare"}},
			}},
			"strict": {Launcher: "/launchers/chase-strict", Match: []selector.Rule{
				{Repos: []string{"alice/nix-config"}},
			}},
			"trusted": {Launcher: "/launchers/chase-trusted", Match: []selector.Rule{
				{Owners: []string{"alice"}, RootAuthorDomains: []string{"example.com"}},
			}},
		},
	}
	s, err := selector.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &world{t: t, r: r, git: gitsafetest.NewFixture(t), s: s}
}

func (w *world) repo(dir, remote, author string) { w.t.Helper(); w.git.Repo(dir, remote, author) }

func (w *world) mkdir(dirs ...string) {
	w.t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			w.t.Fatal(err)
		}
	}
}

func (w *world) write(path, content string) {
	w.t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

// tier is `chase tier ARGS`, as it prints.
func (w *world) tier(args ...string) string {
	w.t.Helper()
	var out, errb bytes.Buffer
	if rc := selector.RunTier(context.Background(), w.s, args, &out, &errb); rc != 0 {
		w.t.Fatalf("chase tier %q: %d %s", args, rc, errb.String())
	}
	return out.String()
}

// expect is the check's: DIR's tier, and a substring of --dry-run's reason.
func (w *world) expect(dir, tier, reason string) {
	w.t.Helper()
	lines := strings.Split(strings.TrimSuffix(w.tier("--dry-run", dir), "\n"), "\n")
	got := lines[len(lines)-1]
	if have := strings.TrimSuffix(w.tier(dir), "\n"); have != tier {
		w.t.Errorf("%s is '%s', not '%s': %s", dir, have, tier, got)
	}
	if !strings.Contains(got, reason) {
		w.t.Errorf("%s: expected '%s' in: %s", dir, reason, got)
	}
}

func (w *world) ifGone(dir string) string {
	w.t.Helper()
	return strings.TrimSuffix(w.tier("--if-gone", dir), "\n")
}

// workspace is the module's workspace snippet, run in dir.
func (w *world) workspace(dir string) string {
	return (&checkout.Finder{Git: w.s.Git()}).Workspace(context.Background(), dir)
}

// guard is the strict tier's guard, as flong runs it: no binds.
func (w *world) guard(ws string) (string, error) {
	var errb bytes.Buffer
	err := w.s.Guard(context.Background(), "strict", ws, "", &errb)
	if err != nil {
		fmt.Fprintln(&errb, err)
	}
	return errb.String(), err
}

// THE SELECTOR, run against real repositories, as the flake's selector check
// ran `chase tier`.
func TestTheSelectorAgainstRealRepositories(t *testing.T) {
	w := newWorld(t)
	r := w.r
	git := w.git.Run

	w.mkdir(r+"/home", r+"/plain")
	w.repo(r+"/p/nix-config", "git@github.com:alice/nix-config.git", "a@example.com")
	w.repo(r+"/p/nix-config/nested", "https://github.com/alice/nix-config", "a@example.com")
	w.repo(r+"/elsewhere/nix-config", "git@github.com:alice/nix-config.git", "a@example.com")
	w.repo(r+"/p/mine", "git@github.com:Alice/Mine.git", "a@Example.com")
	w.repo(r+"/p/fork", "https://github.com/alice/fork.git", "x@upstream.org")
	w.repo(r+"/p/other", "ssh://git@github.com/bob/thing", "a@example.com")
	git("clone", "-q", "--depth", "1", "file://"+r+"/p/mine", r+"/p/shallow")

	w.expect(r+"/home", "host", "path "+r+"/home")
	w.expect(r+"/p/nix-config", "host", "alice/nix-config at "+r+"/p/nix-config")
	// A repository nested inside the pinned checkout is not it, remote or
	// no: its own session writes its .git.
	w.expect(r+"/p/nix-config/nested", "strict", "repo alice/nix-config")
	// Its remote, anywhere else: strict, because strict is asked before
	// trusted and lists it.
	w.expect(r+"/elsewhere/nix-config", "strict", "repo alice/nix-config")
	w.expect(r+"/p/mine", "trusted", "owner alice, first commit by a@Example.com")
	w.expect(r+"/p/fork", "strict", "first commit by x@upstream.org")
	w.expect(r+"/p/other", "strict", "owner bob is not listed")
	w.expect(r+"/plain", "strict", "not a git repository")
	git("-C", r+"/p/shallow", "remote", "set-url", "origin", "git@github.com:alice/mine.git")
	w.expect(r+"/p/shallow", "strict", "shallow clone")

	// WHAT A SESSION COULD WRITE TO BE RUN ON THE HOST NEXT TIME. Each
	// claims the pinned checkout's remote, so only the layout stands between
	// it and host: none of them may get there, and each says why.
	forged := func(dir string) { w.repo(dir, "git@github.com:alice/nix-config.git", "a@example.com") }
	// core.worktree, in the repository's own config.
	forged(r + "/forge")
	git("-C", r+"/forge", "config", "core.worktree", r+"/p/nix-config")
	w.expect(r+"/forge", "strict", "core.worktree sends git to "+r+"/p/nix-config")
	// ... by an include, and by an includeIf on its gitdir: the included
	// file is never read, so a config that includes one is not sorted.
	forged(r + "/inc")
	w.write(r+"/inc.cfg", fmt.Sprintf("[core]\n\tworktree = %s\n", r+"/p/nix-config"))
	git("-C", r+"/inc", "config", "include.path", r+"/inc.cfg")
	w.expect(r+"/inc", "strict", r+"/inc/.git/config includes another file")
	forged(r + "/incif")
	git("-C", r+"/incif", "config", "includeIf.gitdir:"+r+"/incif/.path", r+"/inc.cfg")
	w.expect(r+"/incif", "strict", r+"/incif/.git/config includes another file")
	// A .git file pointing into the pinned checkout from outside it.
	w.mkdir(r + "/evil")
	w.write(r+"/evil/.git", "gitdir: "+r+"/p/nix-config/.git\n")
	w.expect(r+"/evil", "strict", "which is not a worktree's")
	// A .git that is a link to it.
	w.mkdir(r + "/link")
	os.Symlink(r+"/p/nix-config/.git", r+"/link/.git")
	w.expect(r+"/link", "strict", "is a symbolic link")
	// The environment.
	t.Setenv("GIT_DIR", r+"/p/nix-config/.git")
	t.Setenv("GIT_WORK_TREE", r+"/p/nix-config")
	w.expect(r+"/plain", "strict", "redirected by the environment: GIT_DIR GIT_WORK_TREE")
	w.expect(r+"/p/nix-config", "strict", "redirected by the environment")
	os.Unsetenv("GIT_DIR")
	os.Unsetenv("GIT_WORK_TREE")

	// WORKTREES, as work inside a checkout is done: one under the pinned
	// path holds, as Claude Code keeps them and anywhere else under it, and
	// so does a directory inside one.
	pinned := r + "/p/nix-config"
	git("-C", pinned, "worktree", "add", "-q", pinned+"/.claude/worktrees/feat")
	git("-C", pinned, "worktree", "add", "-q", pinned+"/tree")
	w.mkdir(pinned+"/.claude/worktrees/feat/deep/er", pinned+"/sub/deep")
	w.expect(pinned+"/.claude/worktrees/feat", "host", "alice/nix-config at "+pinned+", a worktree of "+pinned)
	w.expect(pinned+"/.claude/worktrees/feat/deep/er", "host", "a worktree of "+pinned)
	w.expect(pinned+"/tree", "host", "a worktree of "+pinned)
	w.expect(pinned+"/sub/deep", "host", "alice/nix-config at "+pinned)
	w.expect(pinned, "host", "alice/nix-config at "+pinned)
	// One kept elsewhere is its remote anywhere else.
	git("-C", pinned, "worktree", "add", "-q", r+"/elsewhere/away")
	w.expect(r+"/elsewhere/away", "strict", "repo alice/nix-config")
	// One inside the pinned path, of a checkout that is not: its remote
	// anywhere else, too.
	git("-C", r+"/elsewhere/nix-config", "worktree", "add", "-q", pinned+"/.claude/worktrees/intruder")
	w.expect(pinned+"/.claude/worktrees/intruder", "strict", "repo alice/nix-config")
	// A .git file naming a genuine worktree's gitdir from outside: that
	// gitdir names its own worktree back, not this one.
	w.mkdir(r + "/evil2")
	w.write(r+"/evil2/.git", "gitdir: "+pinned+"/.git/worktrees/feat\n")
	w.expect(r+"/evil2", "strict", "belongs to "+pinned+"/.claude/worktrees/feat/.git")
	// A worktree's own config, which git reads with worktreeConfig.
	git("-C", pinned, "worktree", "add", "-q", pinned+"/.claude/worktrees/bent")
	git("-C", pinned, "config", "extensions.worktreeConfig", "true")
	git("-C", pinned+"/.claude/worktrees/bent", "config", "--worktree", "core.worktree", r+"/elsewhere")
	w.expect(pinned+"/.claude/worktrees/bent", "strict", "core.worktree sends git to "+r+"/elsewhere")
	w.expect(pinned+"/.claude/worktrees/feat", "host", "a worktree of "+pinned)

	// THE WORKSPACE a launch mounts is the root the selector sorted, and a
	// layout it would not sort is the directory alone.
	for dir, want := range map[string]string{
		pinned + "/sub/deep":                    pinned,
		pinned + "/.claude/worktrees/feat/deep": pinned + "/.claude/worktrees/feat",
		r + "/forge":                            r + "/forge",
		r + "/evil":                             r + "/evil",
	} {
		w.mkdir(dir)
		if got := w.workspace(dir); got != want {
			t.Errorf("workspace of %s: %s, want %s", dir, got, want)
		}
	}

	// SUBMODULES are sorted as the repositories they are, and a directory
	// inside one mounts all of it.
	w.repo(r+"/lib-src", "git@github.com:alice/lib.git", "a@example.com")
	git("-C", r+"/p/mine", "-c", "protocol.file.allow=always", "submodule", "add", "-q", "file://"+r+"/lib-src", "vendor/lib")
	sub := r + "/p/mine/vendor/lib"
	git("-C", sub, "remote", "set-url", "origin", "git@github.com:alice/lib.git")
	w.mkdir(sub + "/deep")
	w.expect(sub, "trusted", "owner alice, first commit by a@example.com")
	w.expect(sub+"/deep", "trusted", "owner alice")
	if got := w.workspace(sub + "/deep"); got != sub {
		t.Errorf("workspace of a submodule: %s", got)
	}
	// Its gitdir, named from somewhere it is not checked out.
	w.mkdir(r + "/evil3")
	w.write(r+"/evil3/.git", "gitdir: "+r+"/p/mine/.git/modules/vendor/lib\n")
	w.expect(r+"/evil3", "strict", "which is not above it")
	w.mkdir(r + "/p/mine/other")
	w.write(r+"/p/mine/other/.git", "gitdir: "+r+"/p/mine/.git/modules/vendor/lib\n")
	w.expect(r+"/p/mine/other", "strict", "is checked out in")
	// Its core.worktree, moved, or joined by another from an include.
	git("-C", sub, "config", "core.worktree", r+"/p/mine/other")
	w.expect(sub, "strict", "is checked out in "+r+"/p/mine/other")
	git("-C", sub, "config", "core.worktree", "../../../../vendor/lib")
	w.expect(sub, "trusted", "owner alice")
	git("-C", sub, "config", "include.path", r+"/inc.cfg")
	w.expect(sub, "strict", "includes another file")
	git("-C", sub, "config", "--unset", "include.path")
	w.expect(sub, "trusted", "owner alice")
	// A worktree of a submodule: not sorted, and said so.
	git("-C", sub, "worktree", "add", "-q", r+"/p/mine/libwt")
	w.expect(r+"/p/mine/libwt", "strict", "a worktree of a submodule of "+r+"/p/mine")

	// WORKTREES OF A BARE REPOSITORY kept beside it, as some lay a checkout
	// out: pinned when the bare repository is under the path.
	git("clone", "-q", "--bare", "file://"+r+"/p/mine", r+"/p/bare/.bare")
	git("-C", r+"/p/bare/.bare", "remote", "set-url", "origin", "git@github.com:alice/bare.git")
	git("-C", r+"/p/bare/.bare", "worktree", "add", "-q", r+"/p/bare/trunk")
	w.expect(r+"/p/bare/trunk", "host", "alice/bare at "+r+"/p/bare, a worktree of "+r+"/p/bare/.bare")
	if got := w.workspace(r + "/p/bare/trunk"); got != r+"/p/bare/trunk" {
		t.Errorf("workspace of a bare worktree: %s", got)
	}
	// One whose bare repository is elsewhere is not.
	git("clone", "-q", "--bare", "file://"+r+"/p/mine", r+"/elsewhere/bare.git")
	git("-C", r+"/elsewhere/bare.git", "remote", "set-url", "origin", "git@github.com:alice/bare.git")
	git("-C", r+"/elsewhere/bare.git", "worktree", "add", "-q", r+"/p/bare/intruder")
	w.expect(r+"/p/bare/intruder", "trusted", "owner alice")
	// A directory that says it is bare and is not a repository.
	w.mkdir(r+"/fake/worktrees/w", r+"/fakewt")
	w.write(r+"/fake/config", "[core]\n\tbare = true\n")
	w.write(r+"/fakewt/.git", "gitdir: "+r+"/fake/worktrees/w\n")
	w.expect(r+"/fakewt", "strict", "is not a repository of its own")

	// A REPOSITORY NESTED IN A PINNED CHECKOUT, in a sandbox of its own,
	// and what its session can make of its .git. Each rewrite claims the
	// pinned remote; none may reach host.
	w.repo(r+"/opus-src", "https://github.com/xiph/opus.git", "a@xiph.org")
	git("-C", pinned, "-c", "protocol.file.allow=always", "submodule", "add", "-q", "file://"+r+"/opus-src", "vendor/opus")
	git("-C", pinned, "-c", "user.name=x", "-c", "user.email=a@example.com", "commit", "-q", "-m", "opus")
	opus := pinned + "/vendor/opus"
	git("-C", opus, "remote", "set-url", "origin", "https://github.com/xiph/opus.git")
	w.expect(opus, "strict", "owner xiph is not listed")
	// Swapped for a repository of its own.
	must(t, os.Rename(opus+"/.git", r+"/opus.gitfile"))
	git("-C", opus, "init", "-q")
	git("-C", opus, "remote", "add", "origin", "git@github.com:alice/nix-config.git")
	w.expect(opus, "strict", "repo alice/nix-config")
	git("-C", opus, "remote", "set-url", "origin", "git@github.com:alice/bare.git")
	w.mkdir(r + "/p/bare/opus")
	git("-C", r+"/p/bare/opus", "init", "-q")
	git("-C", r+"/p/bare/opus", "remote", "add", "origin", "git@github.com:alice/bare.git")
	w.expect(r+"/p/bare/opus", "strict", r+"/p/bare/opus is a checkout of its own, not "+r+"/p/bare")
	// Deleted: a directory inside a submodule, not of the checkout.
	must(t, os.RemoveAll(opus+"/.git"))
	w.expect(opus, "strict", "inside "+pinned+"/vendor/opus, a submodule with no .git of its own")
	w.mkdir(opus + "/deep")
	w.expect(opus+"/deep", "strict", "a submodule with no .git of its own")
	if got := w.workspace(opus + "/deep"); got != opus+"/deep" {
		t.Errorf("workspace of a gutted submodule: %s", got)
	}
	must(t, os.Rename(r+"/opus.gitfile", opus+"/.git"))
	w.expect(opus, "strict", "owner xiph is not listed")
	// A clone kept untracked in it, its remote rewritten.
	git("clone", "-q", "file://"+r+"/opus-src", pinned+"/scratch")
	git("-C", pinned+"/scratch", "remote", "set-url", "origin", "https://github.com/xiph/opus.git")
	w.expect(pinned+"/scratch", "strict", "owner xiph is not listed")
	git("-C", pinned+"/scratch", "remote", "set-url", "origin", "git@github.com:alice/nix-config.git")
	w.expect(pinned+"/scratch", "strict", "repo alice/nix-config")

	// ... and what a deleted .git would leave, which the selector cannot
	// tell from a directory of the checkout: the guard asks it before the
	// session starts, and refuses a sandbox there.
	if got := w.ifGone(pinned + "/scratch"); got != "host" {
		t.Errorf("scratch without its .git is not host: %s", got)
	}
	if got := w.ifGone(opus); got != "strict" {
		t.Errorf("a submodule without its .git is not strict: %s", got)
	}
	if got := w.ifGone(r + "/p/other"); got != "strict" {
		t.Errorf("p/other without its .git is not strict: %s", got)
	}
	if said, err := w.guard(pinned + "/scratch"); err == nil {
		t.Error("the guard let a clone nested in a host checkout into a sandbox")
	} else if !strings.Contains(said, "would be 'host' without its .git") {
		t.Errorf("guard: %s", said)
	}
	if said, err := w.guard(opus); err != nil {
		t.Errorf("the guard refused a submodule: %s", said)
	}
	if said, err := w.guard(r + "/p/other"); err != nil {
		t.Errorf("the guard refused p/other: %s", said)
	}
	// A worktree of another checkout, kept in the pinned one.
	if _, err := w.guard(pinned + "/.claude/worktrees/intruder"); err == nil {
		t.Error("the guard let a foreign worktree nested in a host checkout into a sandbox")
	}
	// A strict clone nested in a trusted checkout: deleting its .git would
	// make it trusted, and mount the checkout above it.
	git("clone", "-q", "file://"+r+"/opus-src", r+"/p/mine/nested")
	git("-C", r+"/p/mine/nested", "remote", "set-url", "origin", "https://github.com/bob/evil.git")
	w.expect(r+"/p/mine/nested", "strict", "owner bob is not listed")
	if got := w.ifGone(r + "/p/mine/nested"); got != "trusted" {
		t.Errorf("p/mine/nested without its .git is not trusted: %s", got)
	}
	if said, err := w.guard(r + "/p/mine/nested"); err == nil {
		t.Error("the guard let a strict clone nested in a trusted checkout into a sandbox")
	} else if !strings.Contains(said, "would be 'trusted' without its .git, not 'strict'") {
		t.Errorf("guard: %s", said)
	}
	// ... and a worktree of the trusted checkout, which stays trusted.
	git("-C", r+"/p/mine", "worktree", "add", "-q", r+"/p/mine/.claude/worktrees/w")
	if said, err := w.guard(r + "/p/mine/.claude/worktrees/w"); err != nil {
		t.Errorf("the guard refused a worktree of its own checkout: %s", said)
	}

	w.hostileCommands()
	w.hostileFiles()
	w.boundedFiles()
	w.branches()
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// COMMANDS A SESSION NAMES IN ITS REPOSITORY, which git would run on the
// host, as the user, as the selector reads it: every key git reads as a
// command, a hooks directory, a filter the checkout's .gitattributes asks
// for, set in a checkout, in a worktree's own config and in a submodule's,
// and in a file a repository includes. Each is asked of from the root, a
// directory below it, the worktree and the submodule, as the selector, the
// workspace and the guard ask. None may run.
func (w *world) hostileCommands() {
	t, r, git := w.t, w.r, w.git.Run
	ran := r + "/ran"
	w.write(r+"/cmd", fmt.Sprintf("#!/bin/sh\necho \"$0 $*\" >> %s\nexit 1\n", ran))
	must(t, os.Chmod(r+"/cmd", 0o755))
	w.mkdir(r + "/hooks")
	hooks := []string{"applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
		"prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge",
		"pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
		"reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite",
		"sendemail-validate", "fsmonitor-watchman", "post-index-change"}
	for _, h := range hooks {
		must(t, os.Symlink(r+"/cmd", r+"/hooks/"+h))
	}
	cmd := r + "/cmd"
	arm := func(file string) { // every command it can name, the marker
		for _, kv := range [][2]string{
			{"core.fsmonitor", cmd}, {"core.hooksPath", r + "/hooks"},
			{"core.pager", cmd}, {"pager.log", cmd}, {"pager.config", cmd},
			{"pager.ls-files", cmd}, {"pager.rev-parse", cmd}, {"pager.remote", cmd},
			{"diff.external", cmd}, {"diff.x.textconv", cmd}, {"diff.x.command", cmd},
			{"filter.x.process", cmd}, {"filter.x.clean", cmd}, {"filter.x.smudge", cmd},
			{"filter.x.required", "true"}, {"merge.x.driver", cmd},
			{"core.sshCommand", cmd}, {"core.gitProxy", cmd}, {"core.askPass", cmd},
			{"credential.helper", "!" + cmd}, {"uploadpack.packObjectsHook", cmd},
			{"core.alternateRefsCommand", cmd}, {"gc.recentObjectsHook", cmd},
			{"gpg.program", cmd}, {"gpg.ssh.program", cmd}, {"log.showSignature", "true"},
			{"core.editor", cmd}, {"sequence.editor", cmd},
			{"core.untrackedCache", "true"}, {"gc.auto", "1"}, {"gc.autoDetach", "false"},
			{"hook.chase.command", cmd}, {"hook.chase.event", "post-index-change"},
			{"remote.origin.receivepack", cmd}, {"remote.origin.uploadpack", cmd},
		} {
			git("config", "--file", file, "--add", kv[0], kv[1])
		}
		for _, e := range []string{"post-checkout", "reference-transaction", "pre-auto-gc", "pre-commit"} {
			git("config", "--file", file, "--add", "hook.chase.event", e)
		}
	}

	armed := r + "/p/armed"
	w.repo(armed, "git@github.com:alice/armed.git", "a@example.com")
	w.mkdir(armed + "/sub/deep")
	w.write(armed+"/sub/deep/f", "")
	w.write(armed+"/.gitattributes", "* filter=x diff=x merge=x\n")
	w.repo(r+"/armlib-src", "git@github.com:alice/armlib.git", "a@example.com")
	git("-C", armed, "-c", "protocol.file.allow=always", "submodule", "add", "-q", "file://"+r+"/armlib-src", "vendor/lib")
	git("-C", armed, "-c", "protocol.file.allow=always", "submodule", "add", "-q", "file://"+r+"/armlib-src", "vendor/inc")
	git("-C", armed, "add", "sub/deep/f", ".gitattributes")
	git("-C", armed, "-c", "user.name=x", "-c", "user.email=a@example.com", "commit", "-q", "-m", "armed")
	armlib := armed + "/vendor/lib"
	arminc := armed + "/vendor/inc"
	git("-C", armlib, "remote", "set-url", "origin", "git@github.com:alice/armlib.git")
	git("-C", arminc, "remote", "set-url", "origin", "git@github.com:alice/armlib.git")
	w.mkdir(armlib + "/deep")
	git("-C", armed, "worktree", "add", "-q", armed+"/.claude/worktrees/w")
	armwt := armed + "/.claude/worktrees/w"
	w.mkdir(armwt + "/deep")
	// A root commit that says it is signed, as a session can write, and
	// every ref packed, so HEAD is read through packed-refs.
	root := strings.TrimSpace(git("-C", armed, "rev-list", "--max-parents=0", "HEAD"))
	var signed strings.Builder
	for _, l := range strings.SplitAfter(git("-C", armed, "cat-file", "commit", root), "\n") {
		signed.WriteString(l)
		if strings.HasPrefix(l, "committer ") {
			signed.WriteString("gpgsig -----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----\n")
		}
	}
	signedID := strings.TrimSpace(w.git.Stdin(signed.String(), "-C", armed, "hash-object", "-t", "commit", "-w", "--stdin"))
	git("-C", armed, "replace", root, signedID)
	git("-C", armed, "pack-refs", "--all")
	git("-C", armed, "config", "extensions.worktreeConfig", "true")
	arm(armed + "/.git/config")
	arm(armed + "/.git/worktrees/w/config.worktree")
	arm(armed + "/.git/modules/vendor/lib/config")
	for _, h := range hooks {
		os.Remove(armed + "/.git/hooks/" + h)
		must(t, os.Symlink(cmd, armed+"/.git/hooks/"+h))
	}
	// ... and a file a repository includes, which names them all.
	arm(r + "/attack.cfg")
	git("-C", armed+"/.git/modules/vendor/inc", "config", "include.path", r+"/attack.cfg")
	w.repo(r+"/p/included", "git@github.com:alice/included.git", "a@example.com")
	w.mkdir(r + "/p/included/sub/deep")
	git("-C", r+"/p/included", "worktree", "add", "-q", r+"/p/included/.claude/worktrees/w")
	git("-C", r+"/p/included", "config", "include.path", r+"/attack.cfg")

	// They do run, for a git that is not the selector's.
	for what, dir := range map[string]string{
		"the checkout's": armed, "the worktree's": armwt, "the submodule's": armlib, "the included": r + "/p/included",
	} {
		w.git.Try("-C", dir, "status")
		if fi, err := os.Stat(ran); err != nil || fi.Size() == 0 {
			t.Fatalf("%s commands never run, so their absence proves nothing", what)
		}
		os.Remove(ran)
	}

	w.expect(armed, "trusted", "owner alice, first commit by a@example.com")
	w.expect(armed+"/sub/deep", "trusted", "owner alice, first commit by a@example.com")
	w.expect(armwt, "trusted", "owner alice, first commit by a@example.com")
	w.expect(armwt+"/deep", "trusted", "owner alice, first commit by a@example.com")
	w.expect(armlib, "trusted", "owner alice, first commit by a@example.com")
	w.expect(armlib+"/deep", "trusted", "owner alice, first commit by a@example.com")
	w.expect(arminc, "strict", armed+"/.git/modules/vendor/inc/config includes another file")
	w.expect(r+"/p/included", "strict", "includes another file")
	w.expect(r+"/p/included/sub/deep", "strict", "includes another file")
	w.expect(r+"/p/included/.claude/worktrees/w", "strict", "includes another file")
	for _, d := range []string{armed + "/sub/deep", armwt + "/deep", armlib + "/deep", arminc,
		r + "/p/included/sub/deep", r + "/p/included/.claude/worktrees/w"} {
		w.workspace(d)
		w.ifGone(d)
		w.guard(d)
	}
	if got := w.workspace(armed + "/sub/deep"); got != armed {
		t.Errorf("workspace of armed/sub/deep: %s", got)
	}
	if got := w.workspace(armlib + "/deep"); got != armlib {
		t.Errorf("workspace of an armed submodule: %s", got)
	}
	if b, err := os.ReadFile(ran); err == nil {
		t.Errorf("the selector ran a command the repository named: %s", b)
	}

	// A submodule of a worktree: not sorted, and said so.
	git("-C", armwt, "-c", "protocol.file.allow=always", "submodule", "update", "--init", "-q", "vendor/lib")
	w.expect(armwt+"/vendor/lib", "strict", "a submodule of a worktree of "+armed)
}

// FILES A SESSION NAMES for git to read, or wait on, in its stead: a config
// that is a pipe or a link, objects borrowed from elsewhere, a HEAD that is
// a link. None is read.
func (w *world) hostileFiles() {
	t, r, git := w.t, w.r, w.git.Run
	w.repo(r+"/p/piped", "git@github.com:alice/piped.git", "a@example.com")
	must(t, os.Remove(r+"/p/piped/.git/config"))
	must(t, mkfifo(r+"/p/piped/.git/config"))
	w.expect(r+"/p/piped", "strict", "is not a plain file")
	w.repo(r+"/p/linked", "git@github.com:alice/linked.git", "a@example.com")
	must(t, os.Rename(r+"/p/linked/.git/config", r+"/linked.cfg"))
	must(t, os.Symlink(r+"/linked.cfg", r+"/p/linked/.git/config"))
	w.expect(r+"/p/linked", "strict", "is not a plain file")
	git("clone", "-q", "--shared", r+"/p/mine", r+"/p/borrowed")
	git("-C", r+"/p/borrowed", "remote", "set-url", "origin", "git@github.com:alice/borrowed.git")
	w.expect(r+"/p/borrowed", "strict", "alternates")
	w.repo(r+"/p/headlink", "git@github.com:alice/headlink.git", "a@example.com")
	must(t, os.Rename(r+"/p/headlink/.git/HEAD", r+"/headlink.HEAD"))
	must(t, os.Symlink(r+"/headlink.HEAD", r+"/p/headlink/.git/HEAD"))
	w.expect(r+"/p/headlink", "strict", r+"/p/headlink/.git/HEAD is not a plain file the size of a ref")
}

// FILES NO LARGER THAN THEIR KIND, and history read in bounded time and
// memory: a sparse gitdir file, config or ref, and a pack whose objects are
// deltas of each other.
func (w *world) boundedFiles() {
	t, r, git := w.t, w.r, w.git.Run
	w.mkdir(r + "/huge/x")
	must(t, truncate(r+"/huge/.git", 1<<30))
	w.expect(r+"/huge/x", "strict", "is too large to be a gitdir file")
	w.repo(r+"/p/hugecfg", "git@github.com:alice/hugecfg.git", "a@example.com")
	git("-C", r+"/p/hugecfg", "config", "extensions.worktreeConfig", "true")
	must(t, truncate(r+"/p/hugecfg/.git/config.worktree", 1<<30))
	w.expect(r+"/p/hugecfg", "strict", "config.worktree is too large to be a config")
	w.repo(r+"/p/hugeref", "git@github.com:alice/hugeref.git", "a@example.com")
	must(t, truncate(r+"/p/hugeref/.git/"+strings.TrimSpace(git("-C", r+"/p/hugeref", "symbolic-ref", "HEAD")), 1<<30))
	w.expect(r+"/p/hugeref", "strict", "is not a plain file the size of a ref")

	w.mkdir(r + "/p/cyclic")
	git("-C", r+"/p/cyclic", "init", "-q")
	git("-C", r+"/p/cyclic", "remote", "add", "origin", "git@github.com:alice/cyclic.git")
	a := strings.Repeat("1", 40)
	cyclicPack(t, a, strings.Repeat("2", 40), r+"/p/cyclic/.git/objects/pack")
	w.write(r+"/p/cyclic/.git/"+strings.TrimSpace(git("-C", r+"/p/cyclic", "symbolic-ref", "HEAD")), a+"\n")
	start := time.Now()
	w.tier(r + "/p/cyclic")
	if d := time.Since(start); d > 60*time.Second {
		t.Errorf("a cyclic pack was not given up on: %s", d)
	}
	w.expect(r+"/p/cyclic", "strict", "the history of "+a+" cannot be read")
}

// BRANCHES are any name git would give one, whatever the locale; a name it
// would not is said to be one. Refs kept as reftable are not read.
func (w *world) branches() {
	r, git := w.r, w.git.Run
	w.repo(r+"/p/branchy", "git@github.com:alice/branchy.git", "a@example.com")
	for _, b := range []string{"issue#12", "wip,1", "fix/ümlaut"} {
		git("-C", r+"/p/branchy", "checkout", "-q", "-b", b)
		w.t.Setenv("LC_ALL", "C.UTF-8")
		w.expect(r+"/p/branchy", "trusted", "owner alice, first commit by a@example.com")
		w.t.Setenv("LC_ALL", "C")
		w.expect(r+"/p/branchy", "trusted", "owner alice, first commit by a@example.com")
	}
	w.write(r+"/p/branchy/.git/HEAD", "ref: refs/heads/a..b\n")
	w.expect(r+"/p/branchy", "strict", "HEAD names refs/heads/a..b, which is not a branch that is read")
	w.mkdir(r + "/p/reftable")
	git("-C", r+"/p/reftable", "init", "-q", "--ref-format=reftable")
	git("-C", r+"/p/reftable", "-c", "user.name=x", "-c", "user.email=a@example.com", "commit", "-q", "--allow-empty", "-m", "first")
	git("-C", r+"/p/reftable", "remote", "add", "origin", "git@github.com:alice/reftable.git")
	w.expect(r+"/p/reftable", "strict", "refs kept as reftable, which is not read")
}
