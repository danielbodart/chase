package selector_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
	"github.com/danielbodart/chase/internal/selector"
)

func newSelector(t *testing.T, c selector.Config) *selector.Selector {
	t.Helper()
	c.Config = gitsafetest.Config(t)
	s, err := selector.New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// origin's owner/repo is parsed from each form a remote takes, lower-cased,
// and a URL it cannot be parsed from is said.
func TestOwnerAndRepoAreParsedFromOrigin(t *testing.T) {
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Repo(r+"/c", "git@github.com:example/shop.git", "a@example.com")
	s := newSelector(t, selector.Config{
		Order: []string{"strict"}, Fallback: "strict",
		Tiers: map[string]selector.Tier{"strict": {Launcher: "/l", Match: []selector.Rule{
			{Owners: []string{"nobody-listed"}},
		}}},
	})
	for url, want := range map[string]string{
		"git@github.com:example/shop.git":         "owner example is not listed",
		"https://github.com/Example/Shop.git":     "owner example is not listed",
		"ssh://git@github.com/acme/app":           "owner acme is not listed",
		"file:///srv/acme/app":                    "cannot parse owner/repo from file:///srv/acme/app",
		"ssh://git@github.com:22/acme/app":        "cannot parse owner/repo from ssh://git@github.com:22/acme/app",
		"https://github.com/acme/app.git.git":     "owner acme is not listed",
		"acme/app":                                "owner acme is not listed",
		"/acme/app":                               "owner acme is not listed",
		"-ealice/app":                             "owner -ealice is not listed",
		"https://github.com/example":              "cannot parse owner/repo from https://github.com/example",
		"https://github.com/example/shop/tree/x":  "cannot parse owner/repo from https://github.com/example/shop/tree/x",
		"git@github.com:ÉXAMPLE/shop.git":         "owner Éxample is not listed",
		"https://user:pass@github.com/evil/x.git": "cannot parse owner/repo from https://user:pass@github.com/evil/x.git",
	} {
		fx.Run("-C", r+"/c", "config", "--", "remote.origin.url", url)
		if tier, why := s.Decide(context.Background(), r+"/c", ""); tier != "strict" || why != want {
			t.Errorf("%s: %s %q, want %q", url, tier, why, want)
		}
	}
	fx.Run("-C", r+"/c", "remote", "remove", "origin")
	if _, why := s.Decide(context.Background(), r+"/c", ""); why != "no origin remote" {
		t.Errorf("no origin: %q", why)
	}
	// The first URL is origin's, and an empty one is none.
	fx.Run("-C", r+"/c", "config", "--add", "remote.origin.url", "")
	fx.Run("-C", r+"/c", "config", "--add", "remote.origin.url", "git@github.com:acme/app.git")
	if _, why := s.Decide(context.Background(), r+"/c", ""); why != "no origin remote" {
		t.Errorf("an empty first URL: %q", why)
	}
}

// A listed owner or domain is one line of the list, exactly. The script
// asked grep, which read an owner beginning with '-' as its own options:
// "-ealice" was the pattern "alice", and "-V" matched anything. Here it is
// only itself.
func TestAnOwnerIsNeverAnOption(t *testing.T) {
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Repo(r+"/c", "git@github.com:acme/app.git", "a@-eexample.com")
	s := newSelector(t, selector.Config{
		Order: []string{"trusted"}, Fallback: "strict",
		Tiers: map[string]selector.Tier{
			"trusted": {Launcher: "/l", Match: []selector.Rule{{Owners: []string{"alice"}}, {Owners: []string{"acme"}, RootAuthorDomains: []string{"example.com"}}}},
			"strict":  {Launcher: "/l"},
		},
	})
	for _, url := range []string{"-ealice/app", "-V/app", "--version/app"} {
		fx.Run("-C", r+"/c", "config", "--", "remote.origin.url", url)
		if tier, why := s.Decide(context.Background(), r+"/c", ""); tier != "strict" {
			t.Errorf("%s is %s: %s", url, tier, why)
		}
	}
	fx.Run("-C", r+"/c", "config", "--", "remote.origin.url", "acme/app")
	if tier, why := s.Decide(context.Background(), r+"/c", ""); tier != "strict" || !strings.Contains(why, "first commit by a@-eexample.com") {
		t.Errorf("a first commit at -eexample.com is %s: %s", tier, why)
	}
}

// A path rule is the exact directory, links resolved, never a prefix; and
// the reasons nothing held are each said once, in the order found.
func TestPathsAreExactAndReasonsAreSaidOnce(t *testing.T) {
	r := gitsafetest.Dir(t)
	for _, d := range []string{"home/sub", "real"} {
		os.MkdirAll(filepath.Join(r, d), 0o755)
	}
	os.Symlink(r+"/home", r+"/link")
	s := newSelector(t, selector.Config{
		Order: []string{"host", "trusted"}, Fallback: "strict",
		Tiers: map[string]selector.Tier{
			"host":    {Bare: true, Match: []selector.Rule{{Paths: []string{r + "/home"}}}},
			"trusted": {Launcher: "/l", Match: []selector.Rule{{Owners: []string{"acme"}}, {Repos: []string{"acme/app"}}}},
			"strict":  {Launcher: "/l"},
		},
	})
	ctx := context.Background()
	for dir, want := range map[string]string{
		r + "/home":        "host",
		r + "/home/":       "host",
		r + "/link":        "host",
		r + "/link/sub/..": "host",
		r + "/home/sub":    "strict",
		r + "/real":        "strict",
	} {
		if tier, why := s.Decide(ctx, dir, ""); tier != want {
			t.Errorf("%s is %s (%s), want %s", dir, tier, why, want)
		}
	}
	t.Chdir(r)
	if tier, _ := s.Decide(ctx, "home", ""); tier != "host" {
		t.Errorf("a relative path is %s", tier)
	}
	if tier, _ := s.Decide(ctx, "link/..", ""); tier != "strict" {
		t.Errorf("link/.. is read logically, as cd reads it, and is %s", tier)
	}
	// Two rules, each missing for the same reason: said once.
	if _, why := s.Decide(ctx, r+"/real", ""); why != "not a git repository" {
		t.Errorf("reasons: %q", why)
	}
	if _, why := s.Decide(ctx, r+"/nonexistent", ""); why != "no such directory" {
		t.Errorf("reasons: %q", why)
	}
}

func TestDryRunIsATableAndIfGoneNeedsADirectory(t *testing.T) {
	r := gitsafetest.Dir(t)
	os.MkdirAll(r+"/home", 0o755)
	os.MkdirAll(r+"/é-plain", 0o755)
	s := newSelector(t, selector.Config{
		Order: []string{"host"}, Fallback: "strict",
		Tiers: map[string]selector.Tier{
			"host":   {Bare: true, Match: []selector.Rule{{Paths: []string{r + "/home"}}}},
			"strict": {Launcher: "/l"},
		},
	})
	var out, errb bytes.Buffer
	if rc := selector.RunAgentTier(context.Background(), s, []string{"--dry-run", r + "/home/", r + "/é-plain"}, &out, &errb); rc != 0 {
		t.Fatal(errb.String())
	}
	want := "DIRECTORY" + strings.Repeat(" ", 18) + "TIER" + strings.Repeat(" ", 6) + "REASON\n" +
		"home" + strings.Repeat(" ", 23) + "host" + strings.Repeat(" ", 6) + "path " + r + "/home\n" +
		// Padded by bytes, as printf pads under LC_ALL=C: é is two.
		"é-plain" + strings.Repeat(" ", 19) + "strict    no rule holds\n"
	if out.String() != want {
		t.Errorf("--dry-run:\n%q\nwant\n%q", out.String(), want)
	}
	out.Reset()
	if rc := selector.RunAgentTier(context.Background(), s, []string{"--dry-run"}, &out, &errb); rc != 0 || out.String() != "DIRECTORY                  TIER      REASON\n" {
		t.Errorf("--dry-run of nothing: %q", out.String())
	}
	if rc := selector.RunAgentTier(context.Background(), s, []string{"--if-gone"}, &out, &errb); rc != 1 {
		t.Errorf("--if-gone with no directory: %d", rc)
	}
	out.Reset()
	t.Chdir(r + "/home")
	if rc := selector.RunAgentTier(context.Background(), s, nil, &out, &errb); rc != 0 || out.String() != "host\n" {
		t.Errorf("agent-tier in the working directory: %q", out.String())
	}
}

func TestTheGuardChecksTheTierAndReportsGroupMembers(t *testing.T) {
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Repo(r+"/mine", "git@github.com:acme/app.git", "a@example.com")
	fx.Repo(r+"/theirs", "git@github.com:evil/x.git", "a@example.com")
	os.MkdirAll(r+"/state", 0o755)
	s := newSelector(t, selector.Config{
		Order: []string{"trusted"}, Fallback: "strict",
		Tiers: map[string]selector.Tier{
			"trusted": {Launcher: "/l/trusted", Match: []selector.Rule{{Owners: []string{"acme"}}}},
			"strict":  {Launcher: "/l/strict"},
		},
	})
	ctx := context.Background()
	var said bytes.Buffer
	err := s.Guard(ctx, "trusted", r+"/theirs", "", &said)
	if err == nil || err.Error() != "chase: refusing a 'trusted' session, this checkout is 'strict'" {
		t.Errorf("the trusted guard of a strict checkout: %v", err)
	}
	// The fallback takes any checkout.
	if err := s.Guard(ctx, "strict", r+"/mine", "", &said); err != nil {
		t.Errorf("the fallback's guard refused: %v", err)
	}
	said.Reset()
	binds := r + "/theirs:rw\n\n" + r + "/state:rw\n" + r + "/mine"
	if err := s.Guard(ctx, "trusted", r+"/mine", binds, &said); err != nil {
		t.Fatal(err)
	}
	want := "chase: mounting " + r + "/theirs (strict, rw)\nchase: mounting " + r + "/mine (trusted, " + r + "/mine)\n"
	if said.String() != want {
		t.Errorf("the guard reported\n%q\nwant\n%q", said.String(), want)
	}

	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	var errb bytes.Buffer
	if rc := selector.RunGuard(ctx, s, []string{"trusted"}, env(map[string]string{"workspace": r + "/mine", "binds": ""}), &errb); rc != 0 {
		t.Errorf("guard: %d %s", rc, errb.String())
	}
	if rc := selector.RunGuard(ctx, s, []string{"trusted"}, env(map[string]string{"workspace": r + "/mine"}), &errb); rc != 1 {
		t.Errorf("guard with binds unset: %d", rc)
	}
	errb.Reset()
	if rc := selector.RunGuard(ctx, s, []string{"trusted"}, env(map[string]string{"workspace": r + "/theirs", "binds": ""}), &errb); rc != 1 || errb.String() != "chase: refusing a 'trusted' session, this checkout is 'strict'\n" {
		t.Errorf("guard refusing: %d %q", rc, errb.String())
	}
}

func TestTheWrapperRunsTheTiersCommand(t *testing.T) {
	r := gitsafetest.Dir(t)
	os.MkdirAll(r+"/home", 0o755)
	os.MkdirAll(r+"/else", 0o755)
	s := newSelector(t, selector.Config{
		Order: []string{"host"}, Fallback: "strict",
		Tiers: map[string]selector.Tier{
			"host":    {Bare: true, Match: []selector.Rule{{Paths: []string{r + "/home"}}}},
			"strict":  {Launcher: "/l/strict"},
			"trusted": {Launcher: "/l/trusted"},
		},
	})
	w := selector.Wrapper{Agent: "claude", HostCommand: []string{"/bin/claude", "--allow-dangerously-skip-permissions"}}
	ctx := context.Background()
	if got := s.Launch(ctx, r+"/home", w, []string{"-p", "x"}); !slices.Equal(got, []string{"/bin/claude", "--allow-dangerously-skip-permissions", "-p", "x"}) {
		t.Errorf("a bare tier runs %q", got)
	}
	if got := s.Launch(ctx, r+"/else", w, nil); !slices.Equal(got, []string{"/l/strict", "claude"}) {
		t.Errorf("a sandbox runs %q", got)
	}
	t.Setenv("SHELL", "")
	if got := selector.ShellHostCommand(); !slices.Equal(got, []string{"bash"}) {
		t.Errorf("an empty SHELL is %q", got)
	}
}

func TestAConfigIsWhatTheModuleAsserts(t *testing.T) {
	git := gitsafetest.GitPath(t)
	good := selector.Config{
		Config: gitsafe.Config{Git: git}, Order: []string{"host", "strict"}, Fallback: "strict",
		Tiers: map[string]selector.Tier{
			"host":   {Bare: true, Match: []selector.Rule{{Checkouts: map[string]string{"Acme/App": "/p/app", "acme/app": "/q/app"}}}},
			"strict": {Launcher: "/l"},
		},
	}
	b, _ := json.Marshal(good)
	path := filepath.Join(t.TempDir(), "selector.json")
	os.WriteFile(path, b, 0o600)
	c, err := selector.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Git != git || c.Tiers["host"].Match[0].Checkouts["Acme/App"] != "/p/app" {
		t.Errorf("the config did not round-trip: %+v", c)
	}
	for name, bad := range map[string]func(c *selector.Config){
		"relative git":      func(c *selector.Config) { c.Git = "git" },
		"missing fallback":  func(c *selector.Config) { c.Fallback = "nope" },
		"bare fallback":     func(c *selector.Config) { c.Fallback = "host" },
		"unknown in order":  func(c *selector.Config) { c.Order = append(c.Order, "nope") },
		"twice in order":    func(c *selector.Config) { c.Order = []string{"host", "host", "strict"} },
		"rules not ordered": func(c *selector.Config) { c.Order = []string{"strict"} },
		"no launcher":       func(c *selector.Config) { c.Tiers["strict"] = selector.Tier{} },
		"empty rule": func(c *selector.Config) {
			c.Tiers["strict"] = selector.Tier{Launcher: "/l", Match: []selector.Rule{{}}}
		},
	} {
		c := good
		c.Tiers = map[string]selector.Tier{}
		for k, v := range good.Tiers {
			c.Tiers[k] = v
		}
		bad(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: validated", name)
		}
	}
}

// Two checkouts entries that lower-case alike are asked in the order Nix
// gave an attribute set's names: "Acme/App" before "acme/app".
func TestCheckoutsAreAskedInNixsOrder(t *testing.T) {
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Repo(r+"/q/app", "git@github.com:acme/app.git", "a@example.com")
	s := newSelector(t, selector.Config{
		Order: []string{"host"}, Fallback: "strict",
		Tiers: map[string]selector.Tier{
			"host":   {Bare: true, Match: []selector.Rule{{Checkouts: map[string]string{"acme/app": r + "/q/app", "Acme/App": r + "/p/app"}}}},
			"strict": {Launcher: "/l"},
		},
	})
	tier, why := s.Decide(context.Background(), r+"/q/app", "")
	if tier != "strict" || !strings.Contains(why, "acme/app is declared at "+r+"/p/app, not "+r+"/q/app") {
		t.Errorf("%s: %s", tier, why)
	}
}
