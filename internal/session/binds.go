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
	switch t.Claude.state() {
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
