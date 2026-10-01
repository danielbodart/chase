package selector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A bare tier trusts its checkout in the apps it says, and only for the
// agent being run: Claude Code in the host's file, codex by an override
// between the host command and the person's words, and a variable with the
// checkout ahead of what it held.
func TestABareTierTrustsItsCheckoutOnTheHost(t *testing.T) {
	file := filepath.Join(t.TempDir(), ".claude.json")
	os.WriteFile(file, []byte(`{}`), 0o600)
	all := Trust{Claude: true, Codex: true, Env: []string{"MISE_TRUSTED_CONFIG_PATHS"}}
	env := []string{"A=1", "MISE_TRUSTED_CONFIG_PATHS=/old"}

	argv, got, err := all.OnHost("codex", file, 1, "/w/shop", []string{"/bin/codex", "exec", "hi"}, env)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/bin/codex", "-c", `projects."/w/shop".trust_level="trusted"`, "exec", "hi"}; !slices.Equal(argv, want) {
		t.Errorf("argv is %q", argv)
	}
	if want := []string{"A=1", "MISE_TRUSTED_CONFIG_PATHS=/w/shop:/old"}; !slices.Equal(got, want) {
		t.Errorf("env is %q", got)
	}
	if !slices.Equal(env, []string{"A=1", "MISE_TRUSTED_CONFIG_PATHS=/old"}) {
		t.Errorf("the caller's env was changed: %q", env)
	}
	if b, _ := os.ReadFile(file); string(b) != `{}` {
		t.Errorf("codex trusted Claude Code: %s", b)
	}

	argv, got, _ = all.OnHost("claude", file, 2, "/w/shop", []string{"/bin/claude", "--x", "p"}, []string{"A=1"})
	if !slices.Equal(argv, []string{"/bin/claude", "--x", "p"}) || !slices.Equal(got, []string{"A=1", "MISE_TRUSTED_CONFIG_PATHS=/w/shop"}) {
		t.Errorf("claude: %q %q", argv, got)
	}
	if b, _ := os.ReadFile(file); !strings.Contains(string(b), `"/w/shop"`) {
		t.Errorf("Claude Code was not trusted: %s", b)
	}

	// Nothing trusted, nothing changed.
	argv, got, _ = Trust{}.OnHost("codex", file, 1, "/w/other", []string{"/bin/codex"}, []string{"A=1"})
	if !slices.Equal(argv, []string{"/bin/codex"}) || !slices.Equal(got, []string{"A=1"}) {
		t.Errorf("an untrusting tier: %q %q", argv, got)
	}
}
