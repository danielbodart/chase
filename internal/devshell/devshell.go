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
// What is evaluated is the checkout's, which a session writes: someone
// else's, in a tier for other people's code. nix's own restrictions are not
// enough to hold it -- builtins.getFlake ignores allowed-uris, a registry
// names any flake, path:, git+file and ?host= inputs and a redirect all
// get past it -- so every nix run is confined as well (confine): bubblewrap
// with nothing of the host but the store, the daemon's socket and nix's own
// configuration, a snapshot of what the checkout tracks, and a HOME of
// chase's; none of the caller's environment; and a network, through pasta,
// only for the steps that need one, with the host's loopback kept out.
// restrict-eval holds for every kind in every tier, with allowed-uris
// beside it as a second layer.
//
// In a tier whose egress is frisket's, the evaluation has no network at
// all: the flake.lock's inputs are fetched first (prefetch), by chase, from
// URLs it builds from the lock's own fields and only from names the
// session's allowlist holds, and the daemon builds nothing of the
// devShell's inputs, which only binary caches give (--max-jobs 0). In a
// tier with direct egress, the evaluation reaches the network as the
// session would, and the daemon builds locally, a fixed-output build on
// the host's own network: the cost of local builds where nothing is
// filtered.
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
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/snapshot"
	"github.com/danielbodart/chase/internal/term"
)

// Request is one launch's: the checkout; chase's state directory; the
// checkout's own directory there (<state>/checkouts/<key>), bound into no
// session; the frisket document whose allow list bounds the evaluation;
// what the approved grant said, nil for nothing; and whether the session
// records (PLAN.md, decision 20).
type Request struct {
	Tier, Workspace, State, Dir, Policy string
	Asked                               *bool
	Recording                           bool
}

// The kinds of devShell, by the file that has it.
const (
	flake = "flake.nix"
	shell = "shell.nix"
	lock  = "flake.lock"
)

// failedFor is how long a devShell that could not be realised is taken to
// still be so, where the tier gives it automatically: a broken flake does
// not cost every launch its seconds. One a grant asks for is always tried
// again.
const failedFor = time.Hour

// now is the clock, a test's to move.
var now = time.Now

// none is a checkout with no devShell to give, and what is said of it: a
// refusal's words, where a grant asked for one, and otherwise said unless
// quiet -- as it is when it was said at the launch that found it.
type none struct {
	line  string
	quiet bool
}

func (n *none) Error() string { return n.line }

// Realise is the checkout's devShell for a session of r.Tier, realised on
// the host as the caller inside a confinement of its own, or nil for none.
//
// Whether one is wanted is the tier's devShell setting, automatic or
// granted, unless the grant says: true turns it on, and makes one that
// cannot be realised a refusal (PLAN.md, decision 4), the error returned;
// false leaves out one the tier would give. A recording is never refused
// for its devShell: it finds what a session needs, and a devShell that
// cannot be realised is something it says. Otherwise, one that cannot be
// realised is said, and the session starts without it.
func Realise(ctx context.Context, n session.Nix, r Request, stderr io.Writer) (*session.DevShell, error) {
	want, required := n.DevShell == "automatic", false
	if r.Asked != nil {
		want, required = *r.Asked, *r.Asked
	}
	if r.Recording {
		required = false
	}
	if !want {
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
		if required {
			return nil, errors.New(no.line)
		}
		if no.line != "" && !no.quiet {
			term.Say(stderr, "%s", no.line)
		}
		return nil, nil
	}
	reason := hinted(err.Error())
	if required {
		return nil, fmt.Errorf("%s: the devShell the grant asks for could not be realised: %s", r.Workspace, reason)
	}
	term.Say(stderr, "%s: the devShell could not be realised, and the session starts without it: %s", r.Workspace, reason)
	return nil, nil
}

// hint is what most devShells that work with `nix develop` and not here
// have in common, and so what a reason matching hintable is told.
var (
	hintable = regexp.MustCompile(`unfree|--impure|getEnv|ssh|Permission denied`)
	hint     = "; the evaluation sees no environment, no ~/.config and no network but its own: set config.allowUnfree in the import, and lock what it fetches"
)

func hinted(reason string) string {
	if hintable.MatchString(reason) {
		return reason + hint
	}
	return reason
}

// realise is Realise's devShell, a *none for none, or why it could not be
// realised.
func realise(ctx context.Context, n session.Nix, r Request, stderr io.Writer) (*session.DevShell, error) {
	ws := r.Workspace
	asked := r.Asked != nil && *r.Asked
	files, err := tracked(ctx, n, ws)
	if err != nil {
		if r.Asked == nil && !exists(ws+"/"+flake) && !exists(ws+"/"+shell) {
			return nil, &none{}
		}
		if err.Error() == "not a git repository" {
			return nil, fmt.Errorf("what is evaluated is what git tracks, and %s is not a git checkout", ws)
		}
		return nil, fmt.Errorf("what is evaluated is what git tracks, and what %s tracks cannot be read: %v", ws, err)
	}
	// What the index lists and the work tree no longer has -- deleted and
	// not yet removed, or outside a sparse checkout -- is left out, as nix
	// develop leaves it out of a git flake.
	files = slices.DeleteFunc(files, func(f string) bool { return !exists(ws + "/" + f) })
	kind := ""
	switch {
	case slices.Contains(files, flake):
		kind = flake
	case slices.Contains(files, shell):
		kind = shell
	}
	// A flake.nix git does not track is not evaluated, nor taken over a
	// shell.nix it does: said, as nix develop says it, rather than left
	// for the person to wonder at.
	var untracked string
	for _, f := range []string{flake, shell} {
		if kind == f {
			break
		}
		if !slices.Contains(files, f) && exists(ws+"/"+f) {
			untracked = fmt.Sprintf("%s: %s is not tracked by git, and what is evaluated is what git tracks: `git add` it", ws, f)
			break
		}
	}
	dir := r.Dir + "/devshell"
	if kind == "" {
		// Nothing to root: what was kept for it is let go.
		os.RemoveAll(dir)
		if untracked != "" {
			return nil, &none{line: untracked}
		}
		if asked {
			return nil, &none{line: fmt.Sprintf("%s: the grant asks for a devShell, and the checkout tracks no flake.nix or shell.nix", ws)}
		}
		return nil, &none{}
	}
	if untracked != "" {
		term.Say(stderr, "%s", untracked)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	snap, err := os.MkdirTemp(r.Dir, "devshell-snapshot.")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(snap)
	keyed := []string{kind}
	if kind == flake && slices.Contains(files, lock) {
		keyed = append(keyed, lock)
	}
	if err := copyTracked(ws, snap, keyed); err != nil {
		return nil, err
	}
	j := &job{n: n, r: r, kind: kind, dir: dir, snap: snap, src: "/src/" + sourceName(ws), stderr: stderr}
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
	staleSnapshots(r.Dir, snap, 2*time.Duration(n.Timeout)*time.Second)
	// The launch that held the lock before this one may have realised it.
	if ds, err, hit := j.cached(); hit {
		return ds, err
	}
	if err := copyTracked(ws, snap, slices.DeleteFunc(slices.Clone(files), func(f string) bool { return slices.Contains(keyed, f) })); err != nil {
		return nil, err
	}
	term.Say(stderr, "%s: realising the devShell of %s", ws, kind)
	for _, said := range j.said {
		term.Say(stderr, "%s", said)
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

// tracked is what the checkout tracks, relative to it, read by
// checkout.RunLsFiles from the index alone: never by a git in the
// checkout, whose config a session writes.
func tracked(ctx context.Context, n session.Nix, ws string) ([]string, error) {
	g, err := gitsafe.New(n.Config)
	if err != nil {
		return nil, err
	}
	var list, why bytes.Buffer
	if rc := checkout.RunLsFiles(ctx, g, []string{ws}, &list, &why); rc != 0 {
		return nil, errors.New(gitsafe.Output(list.Bytes()))
	}
	paths := strings.Split(list.String(), "\x00")
	if paths[len(paths)-1] == "" {
		paths = paths[:len(paths)-1]
	}
	return paths, nil
}

// copyTracked is each of paths, as the checkout has them now, copied into
// snap following no link at any component (internal/snapshot).
func copyTracked(ws, snap string, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	err := snapshot.CopyTracked(ws, snap, paths)
	var refused *snapshot.Refused
	if errors.As(err, &refused) {
		return errors.New(refused.Reason)
	}
	return err
}

// exists is whether anything is at p, a link included.
func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// sourceName is what the snapshot is called in the confinement, /src/NAME:
// the checkout's own name, so ./. is the same store name at every launch,
// with anything that would be read as part of a flake reference or a
// NIX_PATH made a '-'.
var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func sourceName(ws string) string {
	name := unsafeName.ReplaceAllString(filepath.Base(ws), "-")
	if name == "" || strings.Trim(name, ".") == "" {
		return "source"
	}
	return name
}
