// Package checkout is WHICH CHECKOUT A DIRECTORY IS IN, found from where the
// directory really is and never from what git says of it. git's answer is
// the repository's to steer: core.worktree, a gitdir file, GIT_DIR and the
// rest all move --show-toplevel, and any session can write its own
// checkout's .git/config. A `checkouts` rule, and the workspace a launch
// mounts, both stand on this answer, so it is a walk up from the resolved
// path to the nearest .git, and a layout that would send git anywhere else
// is not sorted at all -- a path cannot be forged only if nothing else is
// asked.
//
// Three kinds of redirection are let through, because they are how work is
// done inside a checkout, and each is let through only in its own shape,
// checked from both ends:
//
//	a linked worktree (`git worktree add`, Claude Code's
//	.claude/worktrees/<name>): its .git is a file naming
//	<common>/.git/worktrees/<name>, <common> is itself a checkout, and
//	that gitdir shares <common>'s repository and names this .git back;
//
//	the same, of a bare repository (<bare>/worktrees/<name>, with <bare>
//	holding core.bare = true), the layout some keep a checkout's
//	worktrees side by side in;
//
//	a submodule: its .git is a file naming <super>/.git/modules/<path>,
//	<super> is a checkout above it, and the one core.worktree git
//	wrote there names this directory back.
//
// Where the repository is kept -- <common>, <bare>, <super> -- is the rule's
// to judge: the selector asks it be the pinned checkout itself. Anything
// else a .git file names is not sorted: a submodule of a linked worktree
// among them (<common>/.git/worktrees/<name>/modules/<path>), which is
// strict, a cost taken for a layout that would need a worktree and a
// submodule each checked from both ends.
//
// Its config is read by no git but `git config --file --no-includes` of each
// file, and one that includes another file is not sorted: what the include
// says is not read, so what the repository means is not known. Nor is one
// owned by someone else, as git itself refuses one.
//
// A directory with no .git of its own, inside one of the checkout's
// submodules, is not sorted either: its session could write only that
// submodule, and deleting its .git would otherwise leave a plain directory
// of the checkout above it. The checkout's .gitmodules says which paths are
// submodules -- read as a file, not from the index, which git reads only
// with fsmonitor and the rest of its machinery -- and no session below the
// checkout can write it. A gitlink .gitmodules does not list is not
// recognised: gutted, it is a directory of the checkout, and the guard,
// asking the same question before a session there starts, refuses that
// session a sandbox when the checkout's tier is a bare one.
//
// This was the chase-checkout script, and each of its checks, its order and
// its words are kept: what it printed is parsed, and what it refused is
// shown to a person as the reason a checkout went to the fallback.
package checkout

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/term"
)

// Checkout is where a directory's repository is, as chase-checkout printed
// it: ROOT<TAB>HOLDER<TAB>KIND<TAB>GITCOMMON<TAB>GITDIR.
type Checkout struct {
	// Root is the checkout's own directory: the nearest .git above the
	// directory asked about.
	Root string
	// Holder is the checkout the repository is kept in: Root for a
	// checkout of its own, the bare repository for a bare one's worktree.
	Holder string
	// Kind is checkout, worktree or submodule.
	Kind string
	// GitCommon is the repository's own directory; GitDir this checkout's
	// (its HEAD, its config.worktree).
	GitCommon string
	GitDir    string
}

// Line is the checkout as chase-checkout printed it, without the newline.
func (c Checkout) Line() string {
	return c.Root + "\t" + c.Holder + "\t" + c.Kind + "\t" + c.GitCommon + "\t" + c.GitDir
}

// Repo is the repository's directories, for reading its config.
func (c Checkout) Repo() gitsafe.Repo { return gitsafe.Repo{GitDir: c.GitDir, GitCommon: c.GitCommon} }

// ReadLine is a Checkout as a caller of chase-checkout read it back: `IFS=$'\t'
// read -r root common kind gitcommon gitdir <<< "$out"`. For a checkout found
// here it is the same Checkout; it is kept as the shell had it for the one
// whose holder has a tab or a newline in its path, which only the root is
// refused for.
func ReadLine(out string) Checkout {
	f := gitsafe.Read(out, gitsafe.Tab, 5)
	return Checkout{Root: f[0], Holder: f[1], Kind: f[2], GitCommon: f[3], GitDir: f[4]}
}

// Unsortable is a directory that cannot be sorted, and why, as
// chase-checkout printed it before it failed.
type Unsortable struct{ Reason string }

func (u *Unsortable) Error() string { return u.Reason }

func unsortable(format string, args ...any) error {
	return &Unsortable{Reason: fmt.Sprintf(format, args...)}
}

// Redirects is every variable of the caller's that can point git somewhere,
// in the order they are named when one is set. The git asked here never sees
// them, but the agent would be started into them, so a directory is not
// sorted while any is set, even empty.
var Redirects = []string{
	"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
	"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
}

// Finder finds checkouts.
type Finder struct {
	Git *gitsafe.Git
	// Env is the caller's environment; nil is this process's own.
	Env func(string) (string, bool)
}

func (f *Finder) lookup(k string) (string, bool) {
	if f.Env != nil {
		return f.Env(k)
	}
	return os.LookupEnv(k)
}

// Query is what chase-checkout was asked: `chase-checkout [--ignoring ROOT]
// [DIR]`.
type Query struct {
	// Dir is the directory, resolved; a relative one against the working
	// directory.
	Dir string
	// Ignoring, when set, asks what Dir would be with Ignoring's own .git
	// gone, which is what a session there could make it by deleting it.
	Ignoring *string
}

var (
	submoduleOfWorktree = regexp.MustCompile(`(?s)^(/.*)/\.git/worktrees/[^/]+/modules/.+$`)
	worktreeOfSubmodule = regexp.MustCompile(`(?s)^(/.*)/\.git/modules/.+/worktrees/[^/]+$`)
	worktreeGitdir      = regexp.MustCompile(`(?s)^(/.*)/\.git/worktrees/[^/]+$`)
	submoduleGitdir     = regexp.MustCompile(`(?s)^(/.*)/\.git/modules/.+$`)
	bareWorktreeGitdir  = regexp.MustCompile(`(?s)^(/.*)/worktrees/[^/]+$`)
)

// errAbort is a failure the script died of rather than refused with: it
// printed nothing, and its callers said only that it could not find the
// checkout.
var errAbort = errors.New("chase-checkout stopped")

// Find is the checkout q.Dir is in, or an *Unsortable saying why there is
// none to be sorted, or another error when finding it failed outright.
func (f *Finder) Find(ctx context.Context, q Query) (Checkout, error) {
	var redirects []string
	for _, v := range Redirects {
		if _, ok := f.lookup(v); ok {
			redirects = append(redirects, v)
		}
	}
	if len(redirects) > 0 {
		return Checkout{}, unsortable("git is redirected by the environment: %s", strings.Join(redirects, " "))
	}

	ignoring := ""
	if q.Ignoring != nil {
		r, ok := gitsafe.Resolve(*q.Ignoring)
		if !ok {
			return Checkout{}, unsortable("no such directory")
		}
		ignoring = r
	}
	abs, ok := gitsafe.Resolve(q.Dir)
	if !ok {
		return Checkout{}, unsortable("no such directory")
	}

	// The nearest .git, of whatever kind: which kind is decided below.
	root := abs
	for !(gitsafe.Exists(root+"/.git") && root != ignoring) {
		if root == "/" {
			return Checkout{}, unsortable("not a git repository")
		}
		root = dirname(root)
	}
	if strings.ContainsAny(root, "\t\n") {
		return Checkout{}, unsortable("a checkout whose path has a tab or a newline")
	}
	dotgit := strings.TrimSuffix(root, "/") + "/.git"

	g := f.Git
	var gitdir, common, gitcommon string
	// The one core.worktree a submodule may carry; none for anything else.
	allowedWorktree := ""
	kind := "checkout"
	switch {
	case gitsafe.IsLink(dotgit):
		return Checkout{}, unsortable("%s is a symbolic link", dotgit)
	case gitsafe.IsDir(dotgit):
		gitdir, common, gitcommon = dotgit, root, dotgit
		// A commondir file makes a .git directory a worktree's in disguise.
		if gitsafe.Exists(gitdir + "/commondir") {
			return Checkout{}, unsortable("%s shares another repository (commondir)", dotgit)
		}
	case gitsafe.Regular(dotgit):
		if !gitsafe.Small(dotgit, gitsafe.LineSize) {
			return Checkout{}, unsortable("%s is too large to be a gitdir file", dotgit)
		}
		line, err := gitsafe.FirstLine(dotgit)
		if err != nil {
			return Checkout{}, errAbort
		}
		if !strings.HasPrefix(line, "gitdir: ") {
			return Checkout{}, unsortable("%s is a file that names no gitdir", dotgit)
		}
		target := strings.TrimPrefix(line, "gitdir: ")
		if !strings.HasPrefix(target, "/") {
			target = root + "/" + target
		}
		gitdir, ok = gitsafe.Resolve(target)
		if !ok {
			return Checkout{}, unsortable("%s points at %s, which does not exist", dotgit, target)
		}
		if !gitsafe.IsDir(gitdir) {
			return Checkout{}, unsortable("%s points at %s, which is not a directory", dotgit, gitdir)
		}
		if m := submoduleOfWorktree.FindStringSubmatch(gitdir); m != nil {
			return Checkout{}, unsortable("%s is a submodule of a worktree of %s, which is not sorted", dotgit, m[1])
		} else if m := worktreeOfSubmodule.FindStringSubmatch(gitdir); m != nil {
			return Checkout{}, unsortable("%s is a worktree of a submodule of %s, which is not sorted", dotgit, m[1])
		} else if m := worktreeGitdir.FindStringSubmatch(gitdir); m != nil {
			kind, common, gitcommon = "worktree", m[1], m[1]+"/.git"
			if !(gitsafe.IsDir(gitcommon) && !gitsafe.IsLink(gitcommon) && !gitsafe.ExistsFollowing(gitcommon+"/commondir")) {
				return Checkout{}, unsortable("%s is a worktree of %s, which is not a checkout", dotgit, common)
			}
		} else if m := submoduleGitdir.FindStringSubmatch(gitdir); m != nil {
			kind, common, gitcommon = "submodule", m[1], gitdir
			if !(gitsafe.IsDir(common+"/.git") && !gitsafe.IsLink(common+"/.git") && !gitsafe.ExistsFollowing(common+"/.git/commondir")) {
				return Checkout{}, unsortable("%s is a submodule of %s, which is not a checkout", dotgit, common)
			}
			if !strings.HasPrefix(root, common+"/") {
				return Checkout{}, unsortable("%s is a submodule of %s, which is not above it", dotgit, common)
			}
			if gitsafe.Exists(gitdir + "/commondir") {
				return Checkout{}, unsortable("%s shares another repository (commondir)", gitdir)
			}
			// git writes core.worktree into a submodule's gitdir itself, to
			// name the directory it is checked out in: one, and this one.
			if !gitsafe.Small(gitdir+"/config", gitsafe.ConfigSize) {
				return Checkout{}, unsortable("%s/config is not a plain file of a config's size", gitdir)
			}
			if res := g.Run(ctx, "config", "--file", gitdir+"/config", "--no-includes", "--get-all", "core.worktree"); res.OK() {
				allowedWorktree = gitsafe.Output(res.Stdout)
			}
			if allowedWorktree == "" || strings.Contains(allowedWorktree, "\n") {
				return Checkout{}, unsortable("%s does not name one directory it is checked out in", gitdir)
			}
			to := allowedWorktree
			if !strings.HasPrefix(to, "/") {
				to = gitdir + "/" + to
			}
			if r, _ := gitsafe.Resolve(to); r != root {
				return Checkout{}, unsortable("%s is checked out in %s, not %s", gitdir, allowedWorktree, root)
			}
		} else if m := bareWorktreeGitdir.FindStringSubmatch(gitdir); m != nil && f.isBare(ctx, m[1]) {
			kind, common, gitcommon = "worktree", m[1], m[1]
			if !(gitsafe.IsDir(common+"/objects") && gitsafe.ExistsFollowing(common+"/HEAD") && !gitsafe.ExistsFollowing(common+"/commondir")) {
				return Checkout{}, unsortable("%s is a worktree of %s, which is not a repository of its own", dotgit, common)
			}
		} else {
			return Checkout{}, unsortable("%s points at %s, which is not a worktree's or a submodule's", dotgit, gitdir)
		}
		if kind == "worktree" {
			if names(gitdir, "commondir") != gitcommon {
				return Checkout{}, unsortable("%s does not share %s", gitdir, gitcommon)
			}
			if names(gitdir, "gitdir") != dotgit {
				owner := "nothing"
				if gitsafe.Small(gitdir+"/gitdir", gitsafe.LineSize) {
					if l, err := gitsafe.FirstLine(gitdir + "/gitdir"); err == nil {
						owner = l
					}
				}
				return Checkout{}, unsortable("%s belongs to %s, not %s", gitdir, owner, dotgit)
			}
		}
	default:
		return Checkout{}, unsortable("%s is neither a directory nor a gitdir file", dotgit)
	}

	// Owned by the user, as git itself insists (safe.directory): a checkout
	// someone else can write is theirs to sort.
	me := os.Getuid()
	for _, d := range []string{root, dotgit, gitdir, gitcommon} {
		if uid, ok := owner(d); !ok || uid != me {
			return Checkout{}, unsortable("%s is owned by someone else", d)
		}
	}

	// The layout is a checkout's. Its configuration can still send git
	// elsewhere: core.worktree, beyond the one a submodule is allowed, in
	// the repository's config or a worktree's config.worktree. Each file is
	// read alone and must say all it means itself: one that includes
	// another is not sorted, since that other is not read.
	repo := gitsafe.Repo{GitDir: gitdir, GitCommon: gitcommon}
	for _, file := range repo.ConfigFiles(ctx, g) {
		if !gitsafe.Exists(file) {
			continue
		}
		if !gitsafe.Regular(file) {
			return Checkout{}, unsortable("%s is not a plain file", file)
		}
		if !gitsafe.Small(file, gitsafe.ConfigSize) {
			return Checkout{}, unsortable("%s is too large to be a config", file)
		}
		if !g.Run(ctx, "config", "--file", file, "--no-includes", "--list").OK() {
			return Checkout{}, unsortable("%s cannot be read", file)
		}
		if g.Run(ctx, "config", "--file", file, "--no-includes", "--name-only", "--get-regexp", `^include(if)?\.`).OK() {
			return Checkout{}, unsortable("%s includes another file", file)
		}
	}
	worktree, err := repo.Config(ctx, g, "core.worktree")
	if err != nil {
		return Checkout{}, unsortable("the config of %s cannot be read", root)
	}
	worktree = gitsafe.Output([]byte(worktree))
	if worktree != "" && worktree != allowedWorktree {
		return Checkout{}, unsortable("core.worktree sends git to %s", strings.ReplaceAll(worktree, "\n", ", "))
	}

	// A directory below the root: not inside a submodule of it, as the
	// root's .gitmodules lists them.
	modules := root + "/.gitmodules"
	if abs != root && gitsafe.Exists(modules) {
		if !gitsafe.Regular(modules) {
			return Checkout{}, unsortable("%s is not a plain file", modules)
		}
		if !gitsafe.Small(modules, gitsafe.ConfigSize) {
			return Checkout{}, unsortable("%s is too large to be read", modules)
		}
		if !g.Run(ctx, "config", "--file", modules, "--no-includes", "--list").OK() {
			return Checkout{}, unsortable("%s cannot be read", modules)
		}
		rel := strings.TrimPrefix(abs, strings.TrimSuffix(root, "/")+"/")
		res := g.Run(ctx, "config", "--file", modules, "--no-includes", "-z", "--get-regexp", `^submodule\..*\.path$`)
		entries := strings.Split(string(res.Stdout), "\x00")
		// read -d "" reads only what a NUL ends.
		for _, entry := range entries[:len(entries)-1] {
			path := entry
			if _, v, ok := strings.Cut(entry, "\n"); ok {
				path = v
			}
			path = strings.TrimPrefix(path, "./")
			path = strings.TrimSuffix(path, "/")
			if path == "" {
				continue
			}
			if rel == path || strings.HasPrefix(rel, path+"/") {
				return Checkout{}, unsortable("%s is inside %s/%s, a submodule with no .git of its own", abs, root, path)
			}
		}
	}

	return Checkout{Root: root, Holder: common, Kind: kind, GitCommon: gitcommon, GitDir: gitdir}, nil
}

// isBare is whether dir's config is a plain file of a config's size that
// says core.bare is true.
func (f *Finder) isBare(ctx context.Context, dir string) bool {
	if !gitsafe.Small(dir+"/config", gitsafe.ConfigSize) {
		return false
	}
	res := f.Git.Run(ctx, "config", "--file", dir+"/config", "--no-includes", "--type=bool", "--get", "core.bare")
	return gitsafe.Output(res.Stdout) == "true"
}

// names is where a gitdir's own file naming another -- commondir, or the
// gitdir back-pointer -- points, read as git reads it: relative to that
// gitdir, and resolved. Nothing when it is not a plain file of a line's
// size, or points nowhere.
func names(gitdir, file string) string {
	p := gitdir + "/" + file
	if !gitsafe.Small(p, gitsafe.LineSize) {
		return ""
	}
	to, err := gitsafe.FirstLine(p)
	if err != nil {
		return ""
	}
	if !strings.HasPrefix(to, "/") {
		to = gitdir + "/" + to
	}
	r, _ := gitsafe.Resolve(to)
	return r
}

// dirname is `$(dirname -- P)` of a path Realpath gave: absolute, clean.
func dirname(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return gitsafe.TrimNL(p[:i])
}

// owner is the uid that owns p itself, not what a link at p points to.
func owner(p string) (int, bool) {
	fi, err := os.Lstat(p)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// RunCheckout is `chase-checkout [--ignoring ROOT] [DIR]`: the checkout DIR
// (the working directory without one) is in, as one line of
// ROOT<TAB>HOLDER<TAB>KIND<TAB>GITCOMMON<TAB>GITDIR on stdout, and 0; or why
// it cannot be sorted, as a line on stdout, and 1. It closes g before it
// returns, as every entry point does: see gitsafe.Git.Close.
func RunCheckout(ctx context.Context, g *gitsafe.Git, args []string, stdout, stderr io.Writer) int {
	defer g.Close()
	var q Query
	if len(args) > 0 && args[0] == "--ignoring" {
		if len(args) < 2 {
			term.Say(stderr, "chase-checkout: --ignoring needs a directory")
			return 1
		}
		q.Ignoring = &args[1]
		args = args[2:]
	}
	if len(args) > 0 {
		q.Dir = args[0]
	} else {
		wd, err := os.Getwd()
		if err != nil {
			term.Say(stderr, "chase-checkout: %v", err)
			return 1
		}
		q.Dir = wd
	}
	c, err := (&Finder{Git: g}).Find(ctx, q)
	return report(err, stdout, stderr, func() { fmt.Fprintln(stdout, c.Line()) })
}

// report prints a found checkout by ok, or why there is none: an
// Unsortable's reason on stdout, cleaned for the terminal it reaches, as
// the one line the script printed, and anything else on stderr.
func report(err error, stdout, stderr io.Writer, ok func()) int {
	var u *Unsortable
	switch {
	case err == nil:
		ok()
		return 0
	case errors.As(err, &u):
		fmt.Fprintln(stdout, term.Clean(u.Reason))
	default:
		term.Say(stderr, "%v", err)
	}
	return 1
}
