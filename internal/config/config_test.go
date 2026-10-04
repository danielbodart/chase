package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/config"
)

// file is a config with one sandbox tier whose apps.nix is nix, as the
// module writes it, with change made to it first.
func file(t *testing.T, change func(nix map[string]any)) string {
	t.Helper()
	nix := map[string]any{
		"git": "/nix/store/git/bin/git", "timeout": 1200,
		"nix": "/nix/store/nix/bin/nix", "nixpkgs": "/nix/store/nixpkgs", "system": "x86_64-linux",
		"caBundle": "/etc/ssl/certs/ca-certificates.crt",
	}
	change(nix)
	doc := map[string]any{
		"selector": map[string]any{"git": "/nix/store/git/bin/git", "fallback": "own", "tiers": map[string]any{"own": map[string]any{"launcher": "/nix/store/flong/bin/flong.chase-own"}}},
		"session":  map[string]any{"home": "/home/alice", "runtime": "/run/user/1000", "placeholder": "p", "tiers": map[string]any{"own": map[string]any{"nix": nix}}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A tool chase runs to realise a devShell, or what it is given, named
// without a slash would be looked up on the caller's PATH or read from the
// working directory: refused when the file is read, naming it.
func TestLoadRefusesARelativeNixNixpkgsOrCABundle(t *testing.T) {
	if _, err := config.Load(file(t, func(map[string]any) {})); err != nil {
		t.Fatalf("the module's own was refused: %v", err)
	}
	for _, key := range []string{"nix", "nixpkgs", "caBundle", "git"} {
		_, err := config.Load(file(t, func(n map[string]any) { n[key] = "relative/" + key }))
		if err == nil || !strings.Contains(err.Error(), "nix."+key+` is "relative/`+key+`", which is not an absolute path`) {
			t.Errorf("a relative %s: %v", key, err)
		}
	}
}

// No time at all, no system, and a setting chase does not know are each
// one that would not apply as written.
func TestLoadRefusesNoTimeoutNoSystemOrAnUnknownSetting(t *testing.T) {
	for _, c := range []struct {
		key  string
		v    any
		said string
	}{
		{"timeout", 0, "nix.timeout is 0"},
		{"system", "", "nix.system is empty"},
		{"devShell", "automatic", `unknown field "devShell"`},
	} {
		_, err := config.Load(file(t, func(n map[string]any) { n[c.key] = c.v }))
		if err == nil || !strings.Contains(err.Error(), c.said) {
			t.Errorf("%s = %v: %v", c.key, c.v, err)
		}
	}
}
