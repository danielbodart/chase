// Package session is what a tier's session is given on the host before it
// starts, so that nothing a session needs is made, and nothing at all is
// run, inside it but the agent:
//
//   - the directories bound into it beside the workspace (Binds, flong's
//     binds hook), made or refreshed as the caller;
//   - the payload itself (Payload, flong's exec hook): the agent's argument
//     list, the variables added to its environment, and the files seeded
//     into its home, printed in flong's tagged fields.
//
// The payload was a bash script the module wrote and flong ran as the
// session's command, inside it. Everything it worked out -- which agent, with
// which flags, the directories it may write, the placeholder logins, the
// stores a tier keeps, a Cloudflare account, a grant's environment -- is worked
// out here instead, on the host, where a test can hold it, and the session
// runs the agent's own program with nothing between.
package session

import "path/filepath"

// Config is the session section of chase's configuration.
type Config struct {
	// Home is chase.home, the user's home on both sides of the boundary,
	// and so the home every seeded file is written under: flong does not
	// tell exec the home, which it reads from the container only after
	// exec has run, so the files are written against the one the module
	// declared for the user, and one outside the home the container turns
	// out to have refuses the launch.
	Home string `json:"home"`
	// Runtime is the user's runtime directory, /run/user/<chase.uid>.
	Runtime string `json:"runtime"`
	// Placeholder is chase.placeholder, what a session holds in place of
	// every credential: Claude Code's placeholder login is made of it.
	Placeholder string `json:"placeholder"`
	// WorkspaceGroups is chase.workspaceGroups: checkouts worked on
	// together, each member bound beside the others, read-write.
	WorkspaceGroups [][]string `json:"workspaceGroups,omitempty"`
	// Tiers is what each sandbox tier binds and runs, by tier name.
	Tiers map[string]Tier `json:"tiers"`
}

// Tier is what one sandbox tier's apps bind and run.
type Tier struct {
	// Claude is Claude Code in the tier, nil for none.
	Claude *Claude `json:"claude,omitempty"`
	// Codex is codex in the tier, nil for none.
	Codex *Codex `json:"codex,omitempty"`
	// Cloudflare is the account the tier's sessions are told, when it has
	// one.
	Cloudflare *Cloudflare `json:"cloudflare,omitempty"`
	// Stores are what the tier's sessions keep beyond themselves, by name:
	// a directory on the host per workspace or per tier, bound in, that
	// the session's tools are pointed at (see Store).
	Stores map[string]Store `json:"stores,omitempty"`
	// Environment is what the tier's container sets in every session's
	// environment, as flong's module computed it from the container's
	// options and wrote it into the declaration: what /etc/set-environment
	// would set, one final value per name, `${HOME}` for a reference to
	// the launch's own. flong refuses a launch whose exec sets any name of
	// it, so Payload is told them, to judge what it would add first (see
	// Payload).
	Environment map[string]string `json:"environment,omitempty"`
}

// Store is a directory a tier's sessions keep, made on the host and bound
// in read-write at its own path. Which tool keeps what in it is the
// module's to say, in Env; chase knows nothing of any tool.
type Store struct {
	// Scope is "workspace", a directory for each workspace the tier
	// opens, or "tier", one for all of them. A scope that keeps nothing
	// past the session, or keeps the host's own, is no store.
	Scope string `json:"scope"`
	// Root is where the tier's directories are made: Root/<tier>/all for
	// the tier, Root/<tier>/<Munge(workspace)> for a workspace, which
	// always begins with '-' and so is never "all".
	Root string `json:"root"`
	// Env names, for each variable, the path in the directory it is set
	// to, "" for the directory itself; set unless the container sets it.
	Env map[string]string `json:"env,omitempty"`
	// Files are installed in the directory afresh at every launch, each
	// its path in the directory and the host file it is a copy of, so
	// nothing a session left in their place is what the next reads.
	Files map[string]string `json:"files,omitempty"`
}

// dir is s's directory for a session of workspace in tier.
func (s Store) dir(tier, workspace string) string {
	if s.Scope == "tier" {
		return filepath.Join(s.Root, tier, "all")
	}
	return filepath.Join(s.Root, tier, Munge(workspace))
}

// Claude is Claude Code in a tier.
type Claude struct {
	// Scope is apps.claude.scope: "host", its sessions, history and
	// plugins the host's; "workspace", its settings alone and this
	// workspace's transcripts, kept where the host's Claude Code finds
	// them; or "session", its settings alone and nothing kept.
	Scope string `json:"scope"`
	// Settings is the tier's settings file, in the store, given as
	// --settings, which outranks the user's and the project's.
	Settings string `json:"settings"`
	// Connectors is apps.claude.connectors: whether the placeholder login
	// carries the scopes claude.ai's connectors need.
	Connectors bool `json:"connectors,omitempty"`
}

// scope is c's Scope, or "" for no Claude Code.
func (c *Claude) scope() string {
	if c == nil {
		return ""
	}
	return c.Scope
}

// Codex is codex in a tier. Its CODEX_HOME, at a workspace's or the tier's
// scope, is a store of the module's with the placeholder login among its
// files; at the host's it is the host's ~/.codex, bound by the container.
type Codex struct {
	// Scope is apps.codex.scope: "session", "workspace", "tier" or "host".
	Scope string `json:"scope"`
	// Placeholder is the placeholder login, which a session's own
	// ~/.codex is seeded with.
	Placeholder string `json:"placeholder"`
}

// Cloudflare is the account a tier's sessions use: the user's own file
// holding its id, read on the host at each launch and given to the session
// as CLOUDFLARE_ACCOUNT_ID. Not a credential -- it names the account, it does
// not open it -- but it is kept beside the token, so the file itself is
// never bound in.
type Cloudflare struct {
	AccountIDFile string `json:"accountIdFile"`
}
