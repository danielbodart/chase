package selector_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
	"github.com/danielbodart/chase/internal/selector"
)

// Each entry point leaves nothing of its own git behind, though what calls
// it exits or execs without running a deferred call: with no empty
// repositories given, the ones it made are gone when it returns.
func TestEntryPointsLeaveNoEmptyRepositoryBehind(t *testing.T) {
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Repo(r+"/c", "git@github.com:example/shop.git", "a@example.com")
	runtime := gitsafetest.Dir(t)
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	s, err := selector.New(selector.Config{
		Config: gitsafe.Config{Git: gitsafetest.GitPath(t)},
		Order:  []string{"host", "strict"}, Fallback: "strict",
		Tiers: map[string]selector.Tier{
			"host":   {Bare: true, Match: []selector.Rule{{Owners: []string{"example"}, RootAuthorDomains: []string{"example.com"}}}},
			"strict": {Launcher: "/l"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	left := func(what string) {
		t.Helper()
		if es, _ := os.ReadDir(runtime); len(es) != 0 {
			t.Errorf("%s left %v in $XDG_RUNTIME_DIR", what, es)
		}
	}
	var out, errb bytes.Buffer
	if code := selector.RunAgentTier(ctx, s, []string{r + "/c"}, &out, &errb); code != 0 || out.String() != "host\n" {
		t.Fatalf("agent-tier: %d %q %q", code, out.String(), errb.String())
	}
	left("agent-tier")
	selector.RunAgentTier(ctx, s, []string{"--dry-run", r + "/c"}, &out, &errb)
	left("agent-tier --dry-run")
	env := map[string]string{"workspace": r + "/c", "binds": ""}
	selector.RunGuard(ctx, s, []string{"strict"}, func(k string) (string, bool) { v, ok := env[k]; return v, ok }, &errb)
	left("the guard")
	w := selector.Wrapper{Agent: "claude", HostCommand: []string{"/bin/claude"}}
	if got := s.Launch(ctx, r+"/c", w, nil); len(got) != 1 || got[0] != "/bin/claude" {
		t.Errorf("launch: %q", got)
	}
	left("the wrapper")
}
