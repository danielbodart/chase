package devshell

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/danielbodart/chase/internal/nixstore"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// SessionRequest is one launch's, in a tier whose store is the session's
// own: the checkout, the machine its store is kept by, flong's $binds,
// which shows whether binds made the store, what the approved grant says
// of Nix, and whether the launch is a recording.
type SessionRequest struct {
	Workspace, Machine, Binds string
	Asked                     *session.NixAsked
	Recording                 bool
}

// Refusal is a launch the grant's devShell ends before the agent starts.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

// InSession is what a session whose store is its own is given of Nix, at
// exec (internal/nixstore): the store, which binds made and its nix is
// told of, and, where the checkout has a devShell, chase-devshell ahead of
// the agent, which evaluates it inside the session, over that store, its
// fetches the session's own; or nil for no store at all. Nothing of the
// checkout's Nix is evaluated on the host.
//
// When is the tier's and the grant's. Where the tier's devShell is
// automatic, the store and the devShell are every session's, unless the
// grant says devShell false; where it is granted, the store is a
// session's whose approved grant asks for it (apps.nix.store) or for the
// devShell (apps.nix.devShell), which brings the store with it. A devShell
// the grant asks for that cannot be had ends the launch, here or in the
// session, with what stopped it said, unless the launch is a recording,
// which is never ended for it; any other is said, and the session starts
// without it.
func InSession(ctx context.Context, n session.Nix, r SessionRequest, stderr io.Writer) (*session.InSession, error) {
	ws := r.Workspace
	store, devShell := !n.Granted(), !n.Granted()
	required := false
	if a := r.Asked; a != nil {
		if a.DevShell != nil {
			devShell = *a.DevShell
			store = store || devShell
			required = devShell && !r.Recording
		}
		if a.Store != nil && *a.Store {
			store = true
		}
	}
	if !store {
		return nil, nil
	}
	without := func(why string) (*session.InSession, error) {
		if required {
			return nil, &Refusal{fmt.Sprintf("%s: the grant asks for a devShell, and %s", ws, why)}
		}
		term.Say(stderr, "%s: %s, and the session starts without it", ws, why)
		return nil, nil
	}
	if !nixstore.Made(r.Binds) {
		// binds runs before the grant is approved, and made none because
		// the checkout's chase.jsonc did not ask for one then.
		return without("binds made the session no nix store of its own, as chase.jsonc did not ask for one when it ran: launch again")
	}
	env, err := nixstore.Env(n.Session, r.Machine)
	if err != nil {
		return nil, err
	}
	in := &session.InSession{Env: env}
	if !devShell {
		return in, nil
	}
	kind, _, untracked, err := kindOf(ctx, n, ws)
	if err == nil && kind == "" {
		switch {
		case untracked != "":
			err = fmt.Errorf("%s", untracked)
		case !required:
			// Nothing to evaluate, and nothing to say.
			return in, nil
		default:
			err = fmt.Errorf("the checkout has no flake.nix or shell.nix")
		}
	}
	if err == nil {
		if untracked != "" {
			term.Say(stderr, "%s", untracked)
		}
		err = readable(ws, kind)
	}
	if err != nil {
		if _, err := without(err.Error()); err != nil {
			return nil, err
		}
		return in, nil
	}
	mode := "automatic"
	if required {
		mode = "granted"
	}
	in.Devshell = []string{n.Session.Devshell,
		"-checkout", ws, "-kind", kind, "-nixpkgs", n.Nixpkgs, "-system", n.System,
		"-timeout", strconv.Itoa(n.Timeout), "-mode", mode, "-nix", n.Session.Nix, "-git", n.Git}
	return in, nil
}
