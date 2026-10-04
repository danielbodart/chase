// Package devshell is a checkout's Nix devShell, realised on the host before
// its session starts, and given to the session as the least of its
// environment (PLAN.md, decision 21): flake.nix's
// devShells.<system>.default, or shell.nix's, flake.nix's when it has both.
//
// The files are not the problem -- flong binds the whole of /nix/store into
// every session -- the environment is: a session starts clean, so PATH,
// PKG_CONFIG_PATH and the rest of `nix develop` never reach it. So the
// launcher, as the caller, has nix print the devShell's environment, keeps
// a GC root for it in chase's state, and hands it to the payload
// (session.DevShell), whose wrapper orders PATH and runs the shellHook in
// the session.
//
// In every tier, only where the checkout's approved grant turns it on
// (apps.nix.devShell), as `direnv allow` does: no checkout's Nix is
// evaluated unless it asks, and one that does not costs a launch nothing
// but a look for a shell.nix or a flake.nix, which, when it has one, is
// told in a line how to turn it on. One the grant turned on that cannot be
// realised refuses the launch, as a grant applied whole or not at all
// does.
//
// In a tier of one's own code, whose egress is direct and unfiltered, what
// is evaluated is the checkout itself, as `nix develop` would evaluate it,
// by the caller's nix: a flake purely, never taking its nixConfig or
// writing its lock; a shell.nix under restrict-eval, its NIX_PATH the
// system's nixpkgs and the checkout. nix's own settings do not hold what it reads, and the checkout
// is what a session writes, so nix runs in a bubblewrap that shows it
// nothing of the host's but the store, the daemon's socket, the machine's
// nix configuration and the checkout (job.confine): no environment of the
// caller's, and no file the session could not read itself.
//
// In any other tier -- someone else's code -- offline: nix in the same
// bubblewrap with no network at all, its derivation evaluated alone, its
// inputs substituted from the machine's binary caches by the daemon, with
// nothing built but nix's record of its environment (job.realiseOffline);
// one that needs a fetch or a build cannot be realised. What needs a fetch
// waits on a store of the session's own, where the session evaluates it
// itself, through frisket (flong's PLAN §3); the design that fetched
// through frisket on the host is kept on the branch devshell-confined.
//
// The result is cached on what was evaluated -- flake.nix and flake.lock,
// or shell.nix, and every setting the evaluation is run with -- under
// <state>/checkouts/<key>/devshell, bound into no session, the realised
// environment its GC root there; a change to the files takes effect at the
// next launch.
package devshell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// Request is one launch's: the checkout; chase's state directory, where
// nix's HOME is kept; the checkout's own directory there
// (<state>/checkouts/<key>), bound into no session; and whether its
// approved grant turns its devShell on, without which there is none.
type Request struct {
	Workspace, State, Dir string
	Granted               bool
}

// The kinds of devShell, by the file that has it.
const (
	flake = "flake.nix"
	shell = "shell.nix"
	lock  = "flake.lock"
)

// failedFor is how long a devShell that could not be realised is taken to
// still be so: a broken flake does not cost every launch its seconds.
const failedFor = time.Hour

// now is the clock, a test's to move.
var now = time.Now

// none is a checkout with no devShell to give, and what is said of it,
// unless quiet -- as it is when it was said at the launch that found it.
type none struct {
	line  string
	quiet bool
}

func (n *none) Error() string { return n.line }

// Realise is the checkout's devShell for a session, realised on the host as
// the caller, or nil for none: none where its grant does not turn it on
// (ungranted). The error is a launch stopped while it was realised, which
// is stopped, never launched without it; or a devShell the grant turned on
// that cannot be realised, which refuses the launch, as any part of a
// grant that cannot be applied does (PLAN.md, decision 4), saying how to
// launch without it.
func Realise(ctx context.Context, n session.Nix, r Request, stderr io.Writer) (*session.DevShell, error) {
	if !r.Granted {
		ungranted(r, stderr)
		return nil, nil
	}
	sweep(r.State)
	ds, err := realise(ctx, n, r, stderr)
	var no *none
	switch {
	case err == nil:
		return ds, nil
	case ctx.Err() != nil:
		// The launch was stopped, not the devShell refused: nothing is
		// kept of it, and nothing more is launched.
		return nil, fmt.Errorf("%s: the devShell was not realised: the launch was stopped", r.Workspace)
	case errors.As(err, &no):
		if no.line != "" && !no.quiet {
			term.Say(stderr, "%s", no.line)
		}
		return nil, nil
	}
	return nil, fmt.Errorf("%s: the devShell its grant turns on could not be realised, and the session is not started: %s; %s", r.Workspace, hinted(err.Error()), without)
}

// without is how a launch is had without the devShell its grant turns on.
const without = `to launch without it, set "apps": {"nix": {"devShell": false}} in the checkout's grant, or remove it, and approve that`

// ungranted is a checkout whose grant does not turn its devShell on:
// nothing of it is evaluated, what an earlier grant kept is let go, and
// one that looks to have a devShell -- a shell.nix, or a flake.nix that
// names devShells -- is told, in a line, what turns it on.
func ungranted(r Request, stderr io.Writer) {
	os.RemoveAll(r.Dir + "/devshell")
	if exists(r.Workspace+"/"+shell) || namesDevShells(r.Workspace+"/"+flake) {
		term.Say(stderr, `%s: its devShell is not given: the checkout's grant turns it on, with "apps": {"nix": {"devShell": true}}`, r.Workspace)
	}
}

// namesDevShells is whether the flake.nix at p, a plain file, says
// devShells: read, never evaluated.
func namesDevShells(p string) bool {
	b, err := readPlain(p)
	return err == nil && bytes.Contains(b, []byte("devShells"))
}

// hint is what most devShells that work with `nix develop` and not here
// have in common, and so what a reason matching hintable is told.
var (
	hintable = regexp.MustCompile(`unfree|--impure|getEnv|ssh`)
	hint     = "; the evaluation sees none of your environment, nor your home: set config.allowUnfree in the import, and give private inputs access-tokens in the machine's nix configuration"
)

func hinted(reason string) string {
	if hintable.MatchString(reason) {
		return reason + hint
	}
	return reason
}

// realise is Realise's devShell, a *none for none, or why it could not be
// realised.
//
// A flake.nix is taken where git tracks it, as nix develop takes it from a
// git checkout, and one that is not tracked is said rather than evaluated,
// the checkout's shell.nix taken instead when it has one; in a directory
// that is no git checkout, as it is, as nix develop takes it there. A
// shell.nix is taken as nix-shell takes it, tracked or not.
func realise(ctx context.Context, n session.Nix, r Request, stderr io.Writer) (*session.DevShell, error) {
	ws := r.Workspace
	if !exists(ws+"/"+flake) && !exists(ws+"/"+shell) {
		os.RemoveAll(r.Dir + "/devshell")
		return nil, &none{}
	}
	kind, untracked := "", ""
	var c checkout.Checkout
	if exists(ws + "/" + flake) {
		var files []string
		var err error
		c, files, err = tracked(ctx, n, ws)
		var u *checkout.Unsortable
		switch {
		case errors.As(err, &u) && u.Reason == "not a git repository":
			kind = flake
		case err != nil:
			return nil, fmt.Errorf("what %s tracks cannot be read, and a flake is what git tracks: %v", ws, err)
		case slices.Contains(files, flake):
			kind = flake
		default:
			untracked = fmt.Sprintf("%s: flake.nix is not tracked by git, and nix evaluates what git tracks: `git add` it", ws)
		}
	}
	if kind == "" && exists(ws+"/"+shell) {
		kind = shell
	}
	dir := r.Dir + "/devshell"
	if kind == "" {
		// Nothing to root: what was kept for it is let go.
		os.RemoveAll(dir)
		return nil, &none{line: untracked}
	}
	if untracked != "" {
		term.Say(stderr, "%s", untracked)
	}
	if strings.ContainsAny(ws, "#?") {
		return nil, fmt.Errorf("nix would read the # or ? in %s as part of a flake reference", ws)
	}
	if kind == shell && strings.ContainsAny(ws, ":=") {
		return nil, fmt.Errorf("nix would read the : or = in %s as part of NIX_PATH, which restrict-eval allows", ws)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	binds := []string{ws}
	if kind == flake {
		binds = bindsOf(ws, c)
	}
	j := &job{n: n, r: r, kind: kind, dir: dir, stderr: stderr, binds: binds}
	if err := j.plan(); err != nil {
		return nil, err
	}
	if ds, err, hit := j.cached(); hit {
		return ds, err
	}
	unlock, err := lockDir(dir, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// The launch that held the lock before this one may have realised it.
	if ds, err, hit := j.cached(); hit {
		return ds, err
	}
	if n.Offline {
		term.Say(stderr, "%s: realising the devShell of %s, with no network", ws, kind)
	} else {
		term.Say(stderr, "%s: realising the devShell of %s", ws, kind)
	}
	ds, err := j.realise(ctx)
	var no *none
	switch {
	case ctx.Err() != nil:
		// Stopped, not failed: what the next launch finds is what was
		// there before this one.
		return nil, ctx.Err()
	case errors.As(err, &no):
		os.Remove(dir + "/profile")
		prune(dir)
		j.record("none", no.line)
	case err != nil:
		j.record("failed", err.Error())
	default:
		j.record("env", "")
	}
	return ds, err
}

// tracked is the checkout ws is in, and what of ws it tracks, relative to
// it, read by checkout.Finder from the index alone: never by a git in the
// checkout, whose config a session writes. ws in no checkout is an
// *checkout.Unsortable, "not a git repository".
func tracked(ctx context.Context, n session.Nix, ws string) (checkout.Checkout, []string, error) {
	g, err := gitsafe.New(n.Config)
	if err != nil {
		return checkout.Checkout{}, nil, err
	}
	defer g.Close()
	f := &checkout.Finder{Git: g}
	c, err := f.Find(ctx, checkout.Query{Dir: ws})
	if err != nil {
		return checkout.Checkout{}, nil, err
	}
	list, err := f.LsFiles(ctx, ws)
	if err != nil {
		return checkout.Checkout{}, nil, err
	}
	paths := strings.Split(string(list), "\x00")
	if paths[len(paths)-1] == "" {
		paths = paths[:len(paths)-1]
	}
	return c, paths, nil
}

// bindsOf is what of the host nix is shown of a flake at ws, at their own
// paths: the checkout it is in, whose git nix reads it from, and that
// checkout's git directories, which a worktree's or a submodule's are not
// under it; or ws alone, in no checkout. A shell.nix is shown ws alone,
// all restrict-eval lets it read. Each is bound after any it is under, so
// none is hidden.
func bindsOf(ws string, c checkout.Checkout) []string {
	if c.Root == "" {
		return []string{ws}
	}
	var binds []string
	for _, p := range []string{c.Root, c.GitCommon, c.GitDir} {
		if p != "" && !slices.Contains(binds, p) {
			binds = append(binds, p)
		}
	}
	slices.SortStableFunc(binds, func(a, b string) int { return len(a) - len(b) })
	return binds
}

// exists is whether anything is at p, a link included.
func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
