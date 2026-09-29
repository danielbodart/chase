// Package session is what a tier's session is given on the host before it
// starts: the directories bound into it beside the workspace (Binds, flong's
// binds hook), made or refreshed as the caller, so that nothing a session
// needs is left to be made inside it.
package session

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/term"
)

// Config is the session section of chase's configuration.
type Config struct {
	// Home is chase.home, the user's home on both sides of the boundary.
	Home string `json:"home"`
	// Runtime is the user's runtime directory, /run/user/<chase.uid>.
	Runtime string `json:"runtime"`
	// WorkspaceGroups is chase.workspaceGroups: checkouts worked on
	// together, each member bound beside the others, read-write.
	WorkspaceGroups [][]string `json:"workspaceGroups,omitempty"`
	// Tiers is what each sandbox tier binds, by tier name.
	Tiers map[string]Tier `json:"tiers"`
}

// Tier is what one sandbox tier's apps bind.
type Tier struct {
	// Claude is the tier's apps.claude.state: "shared", "isolated", or
	// empty for no Claude Code.
	Claude string `json:"claude,omitempty"`
	// Codex is the tier's apps.codex.state, as Claude is.
	Codex *Codex `json:"codex,omitempty"`
	// Cloudflare is the tier's account-id directory, when it has one.
	Cloudflare *Cloudflare `json:"cloudflare,omitempty"`
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

// Cloudflare is the account id a tier's sessions read: copied from the
// user's own file into a directory of the tier's, bound read-only.
type Cloudflare struct {
	Dir           string `json:"dir"`
	AccountIDFile string `json:"accountIdFile"`
}

// Binds is flong's binds hook for tier, as the caller: each directory the
// session is given beside its workspace, one PATH or PATH:rw a line on out,
// the directories it needs made first. A failure ends the launch: flong
// refuses a session whose bind source is missing anyway.
func Binds(c Config, tier, workspace string, out io.Writer) error {
	t := c.Tiers[tier]
	var lines []string

	// The other members of every group the workspace is in, read-write:
	// not transitive, sorted, each once, and only those that exist.
	var peers []string
	for _, g := range c.WorkspaceGroups {
		if !slices.Contains(g, workspace) {
			continue
		}
		for _, m := range g {
			if m != workspace && !slices.Contains(peers, m) {
				peers = append(peers, m)
			}
		}
	}
	slices.Sort(peers)
	for _, p := range peers {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			lines = append(lines, p+":rw")
		}
	}

	claudeDir := filepath.Join(c.Home, ".claude")
	switch t.Claude {
	case "isolated":
		// This workspace's transcripts only, written to the host so
		// `claude --resume` finds them later, where Claude Code itself keeps
		// them.
		dir := filepath.Join(claudeDir, "projects", Munge(workspace))
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return err
		}
		lines = append(lines, dir+":rw")
	case "shared":
		// Bound by the container's own mounts, which flong refuses a
		// session over if a source is missing -- and Claude Code's own
		// cleanup deletes plans/ once it empties.
		for _, d := range []string{"projects", "plugins", "file-history", "plans", "paste-cache", "sessions"} {
			if err := os.MkdirAll(filepath.Join(claudeDir, d), 0o777); err != nil {
				return err
			}
		}
		h, err := os.OpenFile(filepath.Join(claudeDir, "history.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o666)
		if err != nil {
			return err
		}
		h.Close()
		// Made by the host's Claude Code only once a session starts there.
		socks := filepath.Join(c.Runtime, "cc-socks")
		if err := os.Mkdir(socks, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
	}

	if cx := t.Codex; cx != nil && cx.State == "isolated" {
		// A home per workspace, given the placeholder login afresh, so
		// nothing a session left behind is what the next authenticates
		// with; replaced rather than written, so a link a session planted
		// at auth.json is not written through.
		home := filepath.Join(cx.StateDir, Munge(workspace))
		if err := os.MkdirAll(home, 0o777); err != nil {
			return err
		}
		if err := install(cx.Placeholder, filepath.Join(home, "auth.json")); err != nil {
			return err
		}
		lines = append(lines, home+":rw")
	}

	if cf := t.Cloudflare; cf != nil {
		if err := os.MkdirAll(cf.Dir, 0o777); err != nil {
			return err
		}
		if err := install(cf.AccountIDFile, filepath.Join(cf.Dir, "account-id")); err != nil {
			return err
		}
		lines = append(lines, cf.Dir)
	}

	for _, l := range lines {
		if strings.ContainsAny(l, "\n") {
			return fmt.Errorf("%s: a bind with a newline in it", term.Clean(l))
		}
		if _, err := fmt.Fprintln(out, l); err != nil {
			return err
		}
	}
	return nil
}

// install copies src to dst at 0600 as `install -m 0600` did: a new file
// renamed over whatever was at dst, a link included, never written through.
func install(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return files.WriteAtomic(dst, b, 0o600)
}

// Munge is a path as Claude Code names its directory under
// ~/.claude/projects: every UTF-16 code unit that is not an ASCII letter or
// digit made a '-', as its JavaScript does. The transcripts bound in have to
// be where Claude Code in the session writes them, which is there.
func Munge(path string) string {
	var b strings.Builder
	for _, u := range utf16.Encode([]rune(path)) {
		if 'a' <= u && u <= 'z' || 'A' <= u && u <= 'Z' || '0' <= u && u <= '9' {
			b.WriteRune(rune(u))
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}
