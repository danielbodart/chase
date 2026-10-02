package grant

import (
	"context"
	"io"
	"os"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/dockerproject"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// Exec is `chase hook exec TIER`, flong's exec for a sandbox tier: the
// payload, printed on stdout as flong reads it, for the launcher's
// arguments args, and its status. e is the grant's configuration when
// tier takes grants, nil when it takes none; a nil registry is
// DefaultApps'. binds is flong's $binds.
//
// In order:
//
//   - the agent, judged first (session.Agent), so a launch that was always
//     going to be refused -- no agent, or one the tier does not run -- is
//     refused before anything is done for it: no stage consumed, no secret
//     decrypted, no token minted with a real key, no unit started;
//   - what earlier versions left on the host that nothing reads now
//     (forget), gone;
//   - for a tier that takes grants, what seccompPolicy approved,
//     applied (Launch) -- its secrets decrypted, its apps prepared, the
//     session's policy document written for frisket -- and what it exports
//     and seeds handed to the payload, with nothing written for a session
//     to source;
//   - the payload itself (session.Payload), printed.
//
// Anything that goes wrong ends the launch with nothing on stdout, flong's
// postStop releasing what was made; stdout is the payload's alone, and
// everything said goes to stderr.
func Exec(ctx context.Context, s session.Config, e *Config, registry map[string]apps.App, tier, ws, machine, binds string, args []string, stdout, stderr io.Writer) int {
	return execute(ctx, s, e, registry, nil, tier, ws, machine, binds, args, stdout, stderr)
}

// execute is Exec, for a recording session when rec is not nil
// (ExecRecording).
func execute(ctx context.Context, s session.Config, e *Config, registry map[string]apps.App, rec *Recording, tier, ws, machine, binds string, args []string, stdout, stderr io.Writer) int {
	if err := session.Agent(s, tier, args); err != nil {
		term.Say(stderr, "%s: %v", ws, err)
		return 1
	}
	forget(s, e, stderr)
	var given session.Given
	if e != nil {
		if registry == nil {
			registry = DefaultApps(*e, stderr)
		}
		var err error
		if given, err = launch(ctx, *e, registry, rec, tier, ws, machine, stderr); err != nil {
			term.Say(stderr, "%v", err)
			return 1
		}
	}
	if e != nil {
		given.Project = sessionProject(ctx, *e, tier, ws, given)
		// A recording session has no network of flong's, whatever the
		// tier's -- frisket's "all" set takes every connection -- so no
		// ports to publish: flong refuses a forward with no network to
		// forward from.
		if t, ok := s.Tiers[tier]; ok && t.Forward && rec == nil && given.Project != "" {
			if p, err := dockerproject.Of(given.Project); err == nil {
				given.Forward = p.Address
			}
		}
	}
	p, err := session.Payload(s, tier, ws, binds, args, given, stderr)
	if err != nil {
		term.Say(stderr, "%s: %v", ws, err)
		return 1
	}
	if err := p.Write(stdout); err != nil {
		term.Say(stderr, "%s: %v", ws, err)
		return 1
	}
	return 0
}

// forget removes what the session's shell script and its postStart left on
// the host, which nothing reads or binds any more, so that it does not sit
// there unowned until a person finds it:
//
//   - <state>/env, each checkout's environment directory, bound read-only
//     into its sessions: an `env` file of the Docker addresses and names a
//     launch exported, and Google Cloud's session keys, RSA private keys
//     each, which are kept in <state>/checkouts now, where no session sees
//     them;
//   - ~/.local/state/agents/cloudflare, where each tier's copy of the
//     Cloudflare account id was made to be bound in, which is read on the
//     host at each launch now;
//   - ~/.local/state/agents itself, once it is empty: codex's homes, the
//     one thing of chase's kept there that is still wanted, are moved to
//     ~/.local/state/chase/codex by codex (internal/apps/codex), and
//     whatever else is there is the user's.
//
// Removing a directory that is not there is nothing, so it is done at
// every launch rather than tracked. What cannot be removed is said, and
// does not end the launch: nothing of it reaches a session. Once no host
// is left that ran the script, this can go.
func forget(s session.Config, e *Config, stderr io.Writer) {
	if s.Home == "" {
		return
	}
	state := s.Home + "/.local/state/chase"
	if e != nil {
		state = e.state()
	}
	agents := s.Home + "/.local/state/agents"
	for _, dir := range []string{state + "/env", agents + "/cloudflare"} {
		if err := os.RemoveAll(dir); err != nil {
			term.Say(stderr, "%s is left from an earlier chase, and could not be removed: %v", dir, err)
		}
	}
	// Removes only an empty directory, and says nothing of one that is not.
	os.Remove(agents)
}

// sessionProject is the project the session is of: the approved Docker
// project's when it has one, otherwise the one its origin names, said
// nothing of, since a checkout with none is still launched; "" for none.
// Its address is where the session's published ports are bound, so two
// projects' dev servers on one port do not meet, and its repo names the
// session in the terminal's header.
func sessionProject(ctx context.Context, c Config, tier, ws string, given session.Given) string {
	for _, v := range given.Env {
		if v.Name == "CHASE_DOCKER_PROJECT" {
			return v.Value
		}
	}
	slug, err := Project(ctx, c, ws, tier, io.Discard)
	if err != nil {
		return ""
	}
	return slug
}
