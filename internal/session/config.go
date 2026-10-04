// Package session is what a tier's session is given on the host before it
// starts, so that nothing a session needs is made, and nothing at all is
// run, inside it but the agent -- and, where the checkout's devShell is
// given (internal/devshell), the bash that orders its PATH, runs its
// shellHook and execs the agent, found on the container's PATH:
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

import (
	"fmt"
	"path/filepath"

	"github.com/danielbodart/chase/internal/gitsafe"
)

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
	// TrustEnv are the variables set to the workspace, each an app's list
	// of the paths it trusts without asking -- mise's
	// MISE_TRUSTED_CONFIG_PATHS -- for an app whose tier trusts its
	// checkouts.
	TrustEnv []string `json:"trustEnv,omitempty"`
	// Environment is what the tier's container sets in every session's
	// environment, as flong's module computed it from the container's
	// options and wrote it into the declaration: what /etc/set-environment
	// would set, one final value per name, `${HOME}` for a reference to
	// the launch's own. flong refuses a launch whose exec sets any name of
	// it, so Payload is told them, to judge what it would add first (see
	// Payload).
	Environment map[string]string `json:"environment,omitempty"`
	// Forward is whether the tier's sessions have a network whose
	// published ports exec may put on an address of its own: the
	// project's, which flong is given as `forward:ADDRESS`.
	Forward bool `json:"forward,omitempty"`
	// Nix is the tier's apps.nix, nil for none: a checkout's devShell,
	// realised on the host before the session starts, or evaluated by the
	// session over a store of its own (internal/devshell).
	Nix *Nix `json:"nix,omitempty"`
	// PathFront are the entries of the container's PATH that a devShell's
	// go behind: /run/wrappers/bin, and an app's that must find a tool
	// before a devShell does -- mise's shims, so the toolchain a checkout
	// pins is the one found, and a shim with nothing pinned falls through
	// to the devShell's.
	PathFront []string `json:"pathFront,omitempty"`
}

// Nix is a tier's apps.nix: how a checkout's devShell is given to its
// sessions -- realised on the host, as the caller (internal/devshell), or
// by the session itself, over a store of its own (Session).
type Nix struct {
	// Git lists what a checkout tracks, from its index alone
	// (internal/gitsafe).
	gitsafe.Config
	// Timeout is how many seconds a realisation may take.
	Timeout int `json:"timeout"`
	// Nix is the host's nix, absolute: never looked up on PATH, which is
	// the caller's. It realises the devShell where the store is the
	// host's, and roots and promotes what a session's store looks at
	// where it is the session's.
	Nix string `json:"nix"`
	// Nixpkgs is what <nixpkgs> is to a checkout's shell.nix: the
	// system's own, a store path.
	Nixpkgs string `json:"nixpkgs"`
	// System is the devShells.<system> a flake's is taken from.
	System string `json:"system"`
	// Bwrap confines nix's run on the host: bubblewrap, showing it nothing
	// of the host's but the store, the daemon and the checkout. The host's
	// store's alone.
	Bwrap string `json:"bwrap,omitempty"`
	// CABundle is the machine's, for the evaluation's https on the host.
	// The host's store's alone.
	CABundle string `json:"caBundle,omitempty"`
	// Store is apps.nix.store: "host", "" too, where the launcher realises
	// the devShell and the session has no nix of its own; or "session",
	// where the session runs nix itself over a store of its own, made at
	// binds and gone at postStop, and evaluates the devShell there.
	Store string `json:"store,omitempty"`
	// DevShell is apps.nix.devShell: "automatic", a devShell whenever the
	// checkout has one, "" too; or "granted", only when the approved
	// grant asks.
	DevShell string `json:"devShell,omitempty"`
	// Session is the session's own store, for Store "session".
	Session *NixSession `json:"session,omitempty"`
}

// NixSession is a tier's store of the session's own (internal/nixstore):
// an overlay of the host's store, its upper a directory of the caller's
// kept for one launch, where the session runs nix single-user.
type NixSession struct {
	// Root is where each session's directory is made, by its machine:
	// ~/.cache/chase/nix/sessions.
	Root string `json:"root"`
	// Nix is the nix the session runs, absolute: the one whose read-only
	// local store reads the host's database as any other reader does.
	Nix string `json:"nix"`
	// Devshell is chase-devshell, which runs ahead of the agent, inside the
	// session, to evaluate the checkout's devShell there.
	Devshell string `json:"devshell"`
	// NixStore is the host's nix-store, which promotes what a session
	// substituted.
	NixStore string `json:"nixStore"`
	// Sqlite is the sqlite3 that reads a session's database, read-only and
	// defensively, for the names it holds.
	Sqlite string `json:"sqlite"`
	// SystemdRun starts the promotion, a unit of the user's own.
	SystemdRun string `json:"systemdRun"`
	// ConfDir is the container's nix configuration, which the session's
	// nix reads: never the user's.
	ConfDir string `json:"confDir"`
	// MaxBytes and MaxInodes bound the upper: past either, the session is
	// stopped.
	MaxBytes  int64 `json:"maxBytes"`
	MaxInodes int64 `json:"maxInodes"`
	// MaxRoots caps the host's paths rooted for one session.
	MaxRoots int `json:"maxRoots"`
	// Promote is whether what a session's store holds of the binary
	// caches' is realised on the host after it, by name, from the host's
	// own substituters.
	Promote bool `json:"promote,omitempty"`
}

// InSession is whether the store is the session's own.
func (n *Nix) InSession() bool { return n != nil && n.Store == "session" }

// Granted is whether the devShell waits on the grant.
func (n *Nix) Granted() bool { return n != nil && n.DevShell == "granted" }

// Validate refuses a Nix the module did not write, rather than half obey
// it: a tool named without a slash would be looked up on the caller's
// PATH, and a path left out would be read as the working directory.
func (n Nix) Validate() error {
	paths := []struct{ name, path string }{{"git", n.Git}, {"nix", n.Nix}, {"nixpkgs", n.Nixpkgs}}
	switch n.Store {
	case "", "host":
		paths = append(paths, struct{ name, path string }{"bwrap", n.Bwrap}, struct{ name, path string }{"caBundle", n.CABundle})
	case "session":
		s := n.Session
		if s == nil {
			return fmt.Errorf("nix.store is session, and nix.session is missing")
		}
		paths = append(paths, []struct{ name, path string }{
			{"session.root", s.Root}, {"session.nix", s.Nix}, {"session.devshell", s.Devshell},
			{"session.nixStore", s.NixStore}, {"session.sqlite", s.Sqlite}, {"session.systemdRun", s.SystemdRun},
			{"session.confDir", s.ConfDir},
		}...)
		if s.MaxBytes <= 0 || s.MaxInodes <= 0 || s.MaxRoots <= 0 {
			return fmt.Errorf("nix.session's limits are %d bytes, %d inodes and %d roots: a store is given some of each", s.MaxBytes, s.MaxInodes, s.MaxRoots)
		}
	default:
		return fmt.Errorf("nix.store is %q, neither host nor session", n.Store)
	}
	for _, p := range paths {
		if !filepath.IsAbs(p.path) {
			return fmt.Errorf("nix.%s is %q, which is not an absolute path", p.name, p.path)
		}
	}
	switch {
	case n.Timeout <= 0:
		return fmt.Errorf("nix.timeout is %d: a realisation is given some seconds", n.Timeout)
	case n.System == "":
		return fmt.Errorf("nix.system is empty")
	case n.DevShell != "" && n.DevShell != "automatic" && n.DevShell != "granted":
		return fmt.Errorf("nix.devShell is %q, neither automatic nor granted", n.DevShell)
	case n.DevShell == "granted" && n.Store != "session":
		return fmt.Errorf("nix.devShell is granted, and the store is the host's: a tier that takes grants for its devShell evaluates it in the session")
	}
	return nil
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
	// Trust is apps.claude.trust: whether the workspace is trusted, so its
	// folder-trust dialog is not raised.
	Trust bool `json:"trust,omitempty"`
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
	// Trust is apps.codex.trust: whether the workspace is trusted, so codex
	// does not ask.
	Trust bool `json:"trust,omitempty"`
}

// Cloudflare is the account a tier's sessions use: the user's own file
// holding its id, read on the host at each launch and given to the session
// as CLOUDFLARE_ACCOUNT_ID. Not a credential -- it names the account, it does
// not open it -- but it is kept beside the token, so the file itself is
// never bound in.
type Cloudflare struct {
	AccountIDFile string `json:"accountIdFile"`
}
