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
// which flags, the directories it may write, the placeholder logins, a
// codex home, a Cloudflare account, an envelope's environment -- is worked
// out here instead, on the host, where a test can hold it, and the session
// runs the agent's own program with nothing between.
package session

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
	// Environment is what the tier's container sets in every session's
	// environment, its environment.variables as the module evaluated them.
	// flong computes the payload's environment from the same options and
	// refuses a launch whose exec sets any name it already sets, so
	// Payload is told them, to judge what it would add first (see
	// Payload).
	Environment map[string]string `json:"environment,omitempty"`
}

// Claude is Claude Code in a tier.
type Claude struct {
	// State is apps.claude.state: "shared", its sessions, history and
	// plugins the host's; or "isolated", its settings alone and this
	// workspace's transcripts.
	State string `json:"state"`
	// Settings is the tier's settings file, in the store, given as
	// --settings, which outranks the user's and the project's.
	Settings string `json:"settings"`
	// Connectors is apps.claude.connectors: whether the placeholder login
	// carries the scopes claude.ai's connectors need.
	Connectors bool `json:"connectors,omitempty"`
}

// state is c's State, or "" for no Claude Code.
func (c *Claude) state() string {
	if c == nil {
		return ""
	}
	return c.State
}

// Codex is codex in a tier: its state, and for an isolated tier where each
// workspace's CODEX_HOME is made and what login it is given.
type Codex struct {
	State string `json:"state"`
	// StateDir is where each workspace's CODEX_HOME is made.
	StateDir string `json:"stateDir"`
	// Placeholder is the placeholder login each home is given afresh.
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
