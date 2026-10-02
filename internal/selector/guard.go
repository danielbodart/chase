package selector

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/term"
)

// Refused is a guard's refusal: the session does not start, and Message says
// why, as chase: refusing a '<tier>' session, ....
type Refused struct{ Message string }

func (r *Refused) Error() string { return r.Message }

// Guard is what each sandbox tier's guard asks before a session of it starts
// in workspace, flong's $workspace, with binds, flong's $binds: the other
// members of the workspace's groups, one PATH[:MODE] a line. Each refusal is
// a *Refused; what is only reported is written to stderr.
//
// A consistency check first, not a gate: the launcher runs as the caller,
// who could run it with any workspace, or run bwrap without it. It catches
// the wrapper and the launcher disagreeing about a checkout -- a launcher
// started by hand, or a checkout whose remote changed since the wrapper
// sorted it -- before a session is built around the wrong tier. What gates
// a checkout's own changes to its session is chase.approver. Not the
// fallback's: it is where anything the selector could not place goes, so it
// takes any checkout. The one refusal after it is everyone's.
func (s *Selector) Guard(ctx context.Context, tier, workspace, binds string, stderr io.Writer) error {
	if tier != s.cfg.Fallback {
		// `$(chase tier "$workspace") || tier=unknown`: chase tier has no
		// failure of its own left to fall back from.
		now := s.Tier(ctx, workspace)
		if now != tier {
			return &Refused{fmt.Sprintf("chase: refusing a '%s' session, this checkout is '%s'", tier, now)}
		}
	}

	// A checkout the rules would put in another tier with its own .git gone
	// -- one nested in a checkout of that tier, not a submodule of it -- is
	// refused a sandbox: its session could delete that .git, and its next
	// launch would be that tier's, with the checkout above it mounted. Tiers
	// have no order of privilege to say which way is up, so any change is
	// refused but one to the fallback, which is where anything unsorted goes
	// already. This one is a gate, and every sandbox's, the fallback's too:
	// it guards against the session, which cannot reach the launcher, not
	// against the caller.
	if gitsafe.Exists(workspace + "/.git") {
		now := s.Tier(ctx, workspace)
		gone := s.IfGone(ctx, workspace)
		if gone != now && gone != s.cfg.Fallback {
			return &Refused{fmt.Sprintf("chase: refusing a '%s' session, %s is nested in a '%s' checkout, and would be '%s' without its .git, not '%s'; clone it elsewhere, or make it a submodule",
				tier, workspace, gone, gone, now)}
		}
	}

	// Group members are reported, not refused: vendoring the same code into
	// the workspace would bypass a refusal anyway. Only checkouts: the state
	// directories apps bind are not code, and have no tier.
	for _, bind := range gitsafe.HereLines(binds) {
		if bind == "" {
			continue
		}
		extra, mode := bind, bind
		if i := strings.LastIndexByte(bind, ':'); i >= 0 {
			extra, mode = bind[:i], bind[i+1:]
		}
		if !gitsafe.ExistsFollowing(extra + "/.git") {
			continue
		}
		fmt.Fprintln(stderr, term.Clean(fmt.Sprintf("chase: mounting %s (%s, %s)", extra, s.Tier(ctx, extra), mode)))
	}
	return nil
}

// RunGuard is the guard flong runs for a sandbox tier, `chase guard TIER`,
// with workspace and binds in the environment as flong sets them: 0, or a
// refusal on stderr and 1. An unset workspace or binds stops it, as it
// stopped the script under set -u. It closes s before it returns.
func RunGuard(ctx context.Context, s *Selector, args []string, env func(string) (string, bool), stderr io.Writer) int {
	defer s.Close()
	if len(args) != 1 {
		term.Say(stderr, "usage: chase guard TIER")
		return 2
	}
	workspace, ok := env("workspace")
	if !ok {
		term.Say(stderr, "guard: workspace: unbound variable")
		return 1
	}
	binds, bok := env("binds")
	var err error
	if bok {
		err = s.Guard(ctx, args[0], workspace, binds, stderr)
	} else {
		err = s.Guard(ctx, args[0], workspace, "", io.Discard)
		if err == nil {
			term.Say(stderr, "guard: binds: unbound variable")
			return 1
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, term.Clean(err.Error()))
		return 1
	}
	return 0
}
