// Package selector is `chase tier`: which tier a directory's checkout is
// sorted into, by the rules chase.tiers.<name>.match declares, asked in
// chase.order, and chase.fallback for whatever none of them claims or the
// selector cannot sort. It is also the two things that act on its answer:
// the guard each sandbox runs before a session starts, and the wrapper
// (`claude`, `codex`, `chase shell`) that picks what to run.
//
// How far each predicate is believed is the tier's author's to judge, not
// the selector's. A path is the one signal a checkout cannot forge; a
// remote, an owner and a first commit's author are strings any checkout can
// claim. What the selector owes every predicate is to read what the checkout
// says without doing what it says: its checkout found by package checkout,
// from where the directory is, and its config, refs and objects read by
// package gitsafe, never by a git that reads the checkout's config itself.
package selector

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/gitsafe"
)

// Selector sorts directories into tiers.
type Selector struct {
	cfg   Config
	rules []rule
	git   *gitsafe.Git
	// Env is the caller's environment, which what finds a checkout refuses
	// to sort under when it would redirect git; nil is this process's own.
	Env func(string) (string, bool)
}

// New is a Selector of c, which is validated first.
func New(c Config) (*Selector, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	g, err := gitsafe.New(c.Config)
	if err != nil {
		return nil, err
	}
	return &Selector{cfg: c, rules: compile(c), git: g}, nil
}

// Close releases what the selector's git made. RunTier, RunGuard and
// Launch close it themselves; any other caller closes it before it exits or
// execs, as gitsafe.Git.Close says.
func (s *Selector) Close() error { return s.git.Close() }

// Git is the selector's git, for what else is asked of a checkout in the same
// process.
func (s *Selector) Git() *gitsafe.Git { return s.git }

// Fallback is chase.fallback.
func (s *Selector) Fallback() string { return s.cfg.Fallback }

// asking is one decide: the directory, and what has been found of it, once
// and only if a rule needs it.
type asking struct {
	s        *Selector
	ctx      context.Context
	dir      string
	abs      string
	ignoring string

	checkoutState string
	originState   string
	c             checkout.Checkout
	slug, owner   string

	// found is what the rule being asked has found, and misses why the
	// rules asked so far did not hold: --dry-run's reasons. A predicate
	// that does not hold for a reason worth telling -- not "some other
	// path" -- says it with miss.
	found  []string
	misses []string
}

func (a *asking) miss(m string) bool {
	if m != "" {
		a.misses = append(a.misses, m)
	}
	return false
}

// Decide is the tier of dir and why: the first rule to hold, and what it
// found, or the fallback and why nothing held, each reason once. With
// ignoring, dir's checkout is found as if ignoring's own .git were deleted,
// as a session working there could.
func (s *Selector) Decide(ctx context.Context, dir, ignoring string) (tier, reason string) {
	a := &asking{s: s, ctx: ctx, dir: dir, ignoring: ignoring}
	if abs, ok := physical(dir); ok {
		a.abs = abs
	} else {
		a.abs = dir
	}
	for _, r := range s.rules {
		a.found = nil
		if a.holds(r) {
			return r.tier, strings.Join(a.found, ", ")
		}
	}
	// Why nothing held, each reason once.
	joined := ""
	for _, m := range a.misses {
		if strings.Contains("; "+joined+"; ", "; "+m+"; ") {
			continue
		}
		if joined != "" {
			joined += "; "
		}
		joined += m
	}
	if joined == "" {
		joined = "no rule holds"
	}
	return s.cfg.Fallback, joined
}

// holds is one rule: each predicate it sets, and all of them to hold.
func (a *asking) holds(r rule) bool {
	if r.paths != nil && !a.atPath(*r.paths) {
		return false
	}
	if r.checkouts != nil && !a.inCheckout(*r.checkouts) {
		return false
	}
	if r.repos != nil && !a.inRepos(*r.repos) {
		return false
	}
	if r.owners != nil && !a.byOwner(*r.owners) {
		return false
	}
	if r.domains != nil && !a.firstCommitBy(*r.domains) {
		return false
	}
	return true
}

// needCheckout is the checkout the directory is in, found once and only if a
// rule needs it, by package checkout: from where the directory is, not from
// what git says. What it cannot sort, no rule that asks git can place.
func (a *asking) needCheckout() bool {
	if a.checkoutState == "" {
		q := checkout.Query{Dir: a.dir}
		if a.ignoring != "" {
			q.Ignoring = &a.ignoring
		}
		f := &checkout.Finder{Git: a.s.git, Env: a.s.Env}
		c, err := f.Find(a.ctx, q)
		if err == nil {
			a.c = checkout.ReadLine(gitsafe.TrimNL(c.Line()))
			a.checkoutState = "ok"
		} else {
			a.checkoutState = "cannot find its checkout"
			if u, ok := err.(*checkout.Unsortable); ok {
				if out := gitsafe.Output([]byte(u.Reason)); out != "" {
					a.checkoutState = out
				}
			}
		}
	}
	return a.checkoutState == "ok" || a.miss(a.checkoutState)
}

// needOrigin is origin's first URL, as `git remote get-url` gives it, read
// from the config files alone, and owner/repo parsed from it; the user's
// url.<base>.insteadOf is not applied, and needs not be: owner/repo is
// parsed from either.
func (a *asking) needOrigin() bool {
	if !a.needCheckout() {
		return false
	}
	if a.originState == "" {
		remote, err := a.c.Repo().Config(a.ctx, a.s.git, "remote.origin.url")
		remote = gitsafe.FirstOf(gitsafe.Output([]byte(remote)))
		switch {
		case err != nil:
			a.originState = "cannot read the config of " + a.c.Root
		case remote == "":
			a.originState = "no origin remote"
		default:
			// git@host:owner/repo.git | https://host/owner/repo.git | ssh://git@host/owner/repo
			slug := strings.TrimSuffix(remote, ".git")
			if i := strings.LastIndexByte(slug, ':'); i >= 0 {
				slug = slug[i+1:]
			}
			if strings.HasPrefix(slug, "//") {
				if i := strings.IndexByte(slug[2:], '/'); i >= 0 {
					slug = slug[2+i+1:]
				}
			}
			slug = lowerASCII(strings.TrimPrefix(slug, "/"))
			if !strings.Contains(slug, "/") || strings.Count(slug, "/") >= 2 {
				a.originState = "cannot parse owner/repo from " + remote
			} else {
				a.slug = slug
				a.owner, _, _ = strings.Cut(slug, "/")
				a.originState = "ok"
			}
		}
	}
	return a.originState == "ok" || a.miss(a.originState)
}

// THE PREDICATES, each given its list one entry per line.

func (a *asking) atPath(list string) bool {
	for _, p := range gitsafe.HereLines(list) {
		if a.abs == p {
			a.found = append(a.found, "path "+p)
			return true
		}
	}
	return false
}

// inCheckout is the checkout at the path, or a worktree or submodule of it
// under the path, as .claude/worktrees are: the repository has to be kept in
// the checkout at the path itself, or in its .bare. Not merely somewhere
// under it: a repository nested inside, a clone or a submodule, has its own
// session, which can write its own .git and would claim the path's remote
// the moment it did.
func (a *asking) inCheckout(list string) bool {
	if !a.needOrigin() {
		return false
	}
	c := a.c
	for _, line := range gitsafe.HereLines(list) {
		f := gitsafe.Fields(line, gitsafe.Tab, 2)
		s, p := f[0], f[1]
		if s != a.slug {
			continue
		}
		if c.Root != p && !strings.HasPrefix(c.Root, p+"/") {
			return a.miss(a.slug + " is declared at " + p + ", not " + c.Root)
		}
		if c.Holder != p && c.GitCommon != p+"/.bare" {
			if c.Holder == c.Root {
				return a.miss(c.Root + " is a checkout of its own, not " + p)
			}
			return a.miss(c.Root + " is a " + c.Kind + " of " + c.Holder + ", not of " + p)
		}
		if c.Holder == c.Root {
			a.found = append(a.found, a.slug+" at "+p)
		} else {
			a.found = append(a.found, a.slug+" at "+p+", a "+c.Kind+" of "+c.Holder)
		}
		return true
	}
	return false
}

func (a *asking) inRepos(list string) bool {
	if !a.needOrigin() {
		return false
	}
	if listed(list, a.slug) {
		a.found = append(a.found, "repo "+a.slug)
		return true
	}
	return false
}

func (a *asking) byOwner(list string) bool {
	if !a.needOrigin() {
		return false
	}
	if listed(list, a.owner) {
		a.found = append(a.found, "owner "+a.owner)
		return true
	}
	return a.miss("owner " + a.owner + " is not listed")
}

// listed is whether x is one of the list's lines, as `grep -qxF X <<< LIST`
// was meant to ask. See the package's behaviour notes: grep read an X that
// began with '-' as its own options, and this does not.
func listed(list, x string) bool {
	for _, l := range gitsafe.HereLines(list) {
		if l == x {
			return true
		}
	}
	return false
}

var commitID = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// headCommit is the commit HEAD names, resolved here rather than by git,
// which would read the checkout's config to find it: HEAD in the checkout's
// own gitdir, a branch in refs/heads/ or packed-refs of the repository, each
// a plain file inside it. A branch is any name git would give one, as git
// itself checks it. It is the commit, or why HEAD was not read -- nothing
// when there is simply no commit -- and false.
func (a *asking) headCommit() (string, bool) {
	c := a.c
	ref := "HEAD"
	for range 5 {
		var file string
		switch {
		case ref == "HEAD":
			file = c.GitDir + "/HEAD"
		case strings.HasPrefix(ref, "refs/heads/") && len(ref) > len("refs/heads/") &&
			a.s.git.Run(a.ctx, "check-ref-format", ref).OK():
			file = c.GitCommon + "/" + ref
		default:
			return "HEAD names " + gitsafe.Quote(ref) + ", which is not a branch that is read", false
		}
		line := ""
		if gitsafe.Exists(file) {
			if r, _ := gitsafe.Resolve(file); !gitsafe.Small(file, gitsafe.LineSize) || r != file {
				return file + " is not a plain file the size of a ref, so HEAD is not read", false
			}
			l, full, err := gitsafe.ReadLine(file)
			if err != nil || (!full && l == "") {
				return "", false
			}
			line = l
			if strings.HasPrefix(line, "ref: ") {
				ref = strings.TrimPrefix(line, "ref: ")
				continue
			}
		} else if packed := c.GitCommon + "/packed-refs"; ref != "HEAD" && gitsafe.ExistsFollowing(packed) {
			if !gitsafe.Small(packed, gitsafe.PackedRefsSize) {
				return packed + " is not a plain file of a size that is read", false
			}
			line = packedRef(packed, ref)
		}
		if !commitID.MatchString(line) {
			return "", false
		}
		return line, true
	}
	return "HEAD names refs through more than five links, which are not followed", false
}

// packedRef is the object packed-refs gives ref: of the lines that have " ref"
// in them, as `grep -F` finds them, the first whose second field is ref. A
// file with a NUL in it is one grep calls binary and prints no line of.
//
// It was looked at before -- a plain file of at most PackedRefsSize -- but a
// session can write its .git while this runs, and swap in a link, a pipe or
// a sparse file of a hundred gigabytes after that look. grep streamed the
// file; this process has no address-space limit of its own and no timeout
// here. So it is opened without following a link or waiting on a pipe, must
// still be a plain file, and is read a line at a time and no further than
// PackedRefsSize: a file that has grown past it since is one not read.
func packedRef(packed, ref string) string {
	fd, err := unix.Open(packed, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	f := os.NewFile(uintptr(fd), packed)
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	limited := &io.LimitedReader{R: f, N: gitsafe.PackedRefsSize + 1}
	r := bufio.NewReader(limited)
	found, matched := "", false
	for {
		l, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return ""
		}
		if limited.N == 0 || strings.IndexByte(l, 0) >= 0 {
			return ""
		}
		// grep ends the last line with a newline if the file does not. The
		// first match is the answer, but the rest is still read: a NUL
		// anywhere makes the whole file one grep prints nothing of.
		l = strings.TrimSuffix(l, "\n")
		if !matched && strings.Contains(l, " "+ref) {
			if fields := gitsafe.Fields(l, gitsafe.Blank, 2); fields[1] == ref {
				found, matched = fields[0], true
			}
		}
		if err == io.EOF {
			return found
		}
	}
}

// firstCommitBy is every root commit's author at one of the domains, since a
// history can have more than one. A shallow clone's first commit is its
// boundary, not the real root. The commits are read from the repository's
// objects alone, by a git whose repository is otherwise an empty one of its
// own.
func (a *asking) firstCommitBy(list string) bool {
	if !a.needCheckout() {
		return false
	}
	c := a.c
	if gitsafe.Exists(c.GitCommon + "/shallow") {
		return a.miss("shallow clone, first commit unknowable")
	}
	repo := c.Repo()
	refs, err := repo.Config(a.ctx, a.s.git, "extensions.refStorage")
	if err != nil {
		refs = "unreadable"
	}
	refs = gitsafe.LastOf(gitsafe.Output([]byte(refs)))
	if refs != "" && refs != "files" {
		return a.miss("refs kept as " + refs + ", which is not read")
	}
	format, err := repo.Config(a.ctx, a.s.git, "extensions.objectFormat")
	if err != nil {
		format = "unreadable"
	}
	format = gitsafe.LastOf(gitsafe.Output([]byte(format)))
	if format == "" {
		format = "sha1"
	}
	if format != "sha1" && format != "sha256" {
		return a.miss("objects kept as " + format + ", which are not read")
	}
	empty, err := a.s.git.Empty(format)
	if err != nil {
		return a.miss("objects kept as " + format + ", which are not read")
	}
	objects := c.GitCommon + "/objects"
	if !gitsafe.IsDir(objects) || gitsafe.IsLink(objects) {
		return a.miss("no objects to read")
	}
	if gitsafe.Exists(objects + "/info/alternates") {
		return a.miss("objects borrowed from elsewhere (alternates), which are not read")
	}
	if notPlain(objects) {
		return a.miss("objects that are links or pipes, which are not read")
	}
	oid, ok := a.headCommit()
	if !ok {
		if oid != "" {
			return a.miss(oid)
		}
		oid = ""
	}
	authors := ""
	if oid != "" {
		res := a.s.git.Run(a.ctx, "GIT_DIR="+empty, "GIT_OBJECT_DIRECTORY="+objects,
			"log", "--no-mailmap", "--max-parents=0", "--format=%ae", oid, "--")
		if !res.OK() {
			return a.miss("the history of " + oid + " cannot be read")
		}
		authors = gitsafe.Output(res.Stdout)
	}
	if authors == "" {
		return a.miss("no commits, no provenance to check")
	}
	for _, author := range gitsafe.HereLines(authors) {
		domain := author
		if i := strings.LastIndexByte(author, '@'); i >= 0 {
			domain = author[i+1:]
		}
		if !listed(list, lowerASCII(domain)) {
			return a.miss("first commit by " + author)
		}
	}
	a.found = append(a.found, "first commit by "+gitsafe.FirstOf(authors))
	return true
}

// notPlain is whether anything under objects, which is not followed if it is
// a link, is neither a plain file nor a directory: `find -P OBJECTS ! -type f
// ! -type d -print -quit`. What cannot be read is passed over, as find
// passed over it.
func notPlain(objects string) bool {
	found := false
	var walk func(dir string)
	walk = func(dir string) {
		f, err := os.Open(dir)
		if err != nil {
			return
		}
		entries, _ := f.ReadDir(-1)
		f.Close()
		for _, e := range entries {
			if found {
				return
			}
			p := dir + "/" + e.Name()
			fi, err := os.Lstat(p)
			if err != nil {
				continue
			}
			switch {
			case fi.IsDir():
				walk(p)
			case fi.Mode().IsRegular():
			default:
				found = true
				return
			}
		}
	}
	walk(objects)
	return found
}
