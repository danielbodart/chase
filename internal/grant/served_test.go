package grant

import (
	"strings"
	"testing"
)

// servedAs: a checkout is its own project; a linked worktree is
// <worktree>.<repo>, its directory made one label and cut to fit.
func TestServedAs(t *testing.T) {
	long := strings.Repeat("a", 90)
	for _, c := range []struct{ slug, kind, root, want string }{
		{"acme/app", "checkout", "/p/app", "acme/app"},
		{"acme/app", "submodule", "/p/app/sub", "acme/app"},
		{"acme/app", "worktree", "/p/app/.claude/worktrees/fix-login", "acme/fix-login.app"},
		{"acme/app", "worktree", "/p/app/.claude/worktrees/Fix Login.v2", "acme/fix-login-v2.app"},
		{"acme/app", "worktree", "/p/app/.claude/worktrees/--x_y", "acme/x_y.app"},
		{"acme/app", "worktree", "/w/" + strings.Repeat("b", 70), "acme/" + strings.Repeat("b", 63) + ".app"},
		{"acme/" + long, "worktree", "/w/feature", "acme/feature." + long},
		{"acme/" + long + "1234", "worktree", "/w/feature", "acme/featu." + long + "1234"},
	} {
		got, err := servedAs(c.slug, c.kind, c.root)
		if err != nil || got != c.want {
			t.Errorf("servedAs(%q, %q, %q) = %q, %v; want %q", c.slug, c.kind, c.root, got, err, c.want)
		}
	}
	for _, root := range []string{"/w/---", "/w/x"} {
		slug := "acme/app"
		if root == "/w/x" {
			slug = "acme/" + strings.Repeat("a", 99)
		}
		if got, err := servedAs(slug, "worktree", root); err == nil {
			t.Errorf("servedAs(%q, worktree, %q) = %q, not refused", slug, root, got)
		}
	}
}
