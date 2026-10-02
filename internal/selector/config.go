package selector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/danielbodart/chase/internal/gitsafe"
)

// Config is what the NixOS module tells the selector: chase.order,
// chase.fallback and chase.tiers, as they were spliced into the selector script's text,
// and the paths of what it runs. The module writes it as JSON.
type Config struct {
	// Git is the absolute path of the git binary every git call runs.
	gitsafe.Config

	// Order is chase.order: the tiers asked, first to last. The first with
	// a rule in its match that holds is the checkout's.
	Order []string `json:"order"`

	// Fallback is chase.fallback: the tier a checkout goes to when no
	// tier's rules hold, and whenever sorting it fails at all. Never a bare
	// one.
	Fallback string `json:"fallback"`

	// Tiers is chase.tiers, by name: each tier's rules, whether it is bare,
	// and what launches a session of it.
	Tiers map[string]Tier `json:"tiers"`
}

// Tier is one of chase.tiers.
type Tier struct {
	// Bare is chase.tiers.<name>.bare: run with no sandbox at all, as the
	// host command a wrapper names.
	Bare bool `json:"bare"`

	// Match is chase.tiers.<name>.match: any one of these rules, each
	// holding only when every predicate it sets does.
	Match []Rule `json:"match"`

	// Launcher is the absolute path of a sandbox tier's launcher, `lib.getExe
	// config.flong."chase-<name>".launcher`, which a wrapper execs with the
	// agent's name and its arguments. Empty for a bare tier.
	Launcher string `json:"launcher,omitempty"`

	// Trust is what a bare tier trusts its checkouts in, on the host, before
	// the agent starts; nil for nothing, and for a sandbox tier, whose
	// session trusts them itself (internal/session).
	Trust *Trust `json:"trust,omitempty"`
}

// Trust is the apps a bare tier trusts its checkouts in, each its
// apps.<app>.trust.
type Trust struct {
	// Claude is whether the checkout is trusted in the host's
	// ~/.claude.json.
	Claude bool `json:"claude,omitempty"`
	// Codex is whether codex is told to trust it.
	Codex bool `json:"codex,omitempty"`
	// Env are the variables the checkout is added to, each an app's list
	// of the paths it trusts without asking.
	Env []string `json:"env,omitempty"`
}

// Rule is one of chase.tiers.<name>.match, as the module's ruleType has it.
// A predicate that is empty is not asked; a rule holds when every predicate
// it sets holds.
type Rule struct {
	// Paths are directories, matched exactly against the one asked about,
	// with its links resolved.
	Paths []string `json:"paths,omitempty"`
	// Checkouts are repositories keyed by "owner/name", valued by where
	// their checkout lives.
	Checkouts map[string]string `json:"checkouts,omitempty"`
	// Repos are repositories by "owner/name" alone.
	Repos []string `json:"repos,omitempty"`
	// Owners are repository owners, the first half of origin's owner/name.
	Owners []string `json:"owners,omitempty"`
	// RootAuthorDomains are email domains every first commit was authored
	// at one of.
	RootAuthorDomains []string `json:"rootAuthorDomains,omitempty"`
}

// LoadConfig reads a Config from a JSON file the module wrote.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.Validate()
}

// Validate holds a Config to what the module asserts of it, so a file that
// was not written by the module is refused rather than half obeyed.
func (c Config) Validate() error {
	if !filepath.IsAbs(c.Git) {
		return fmt.Errorf("git is %q, which is not an absolute path", c.Git)
	}
	fb, ok := c.Tiers[c.Fallback]
	if !ok {
		return fmt.Errorf("the fallback %q is not one of the tiers", c.Fallback)
	}
	if fb.Bare {
		return fmt.Errorf("the fallback %q is bare: what no rule vouched for must run in a sandbox", c.Fallback)
	}
	seen := map[string]bool{}
	for _, name := range c.Order {
		if _, ok := c.Tiers[name]; !ok || seen[name] {
			return fmt.Errorf("the order must name each tier at most once, and nothing else: %q", c.Order)
		}
		seen[name] = true
	}
	for name, t := range c.Tiers {
		if !t.Bare && !filepath.IsAbs(t.Launcher) {
			return fmt.Errorf("tier %q is a sandbox with no launcher", name)
		}
		if len(t.Match) > 0 && !seen[name] {
			return fmt.Errorf("tier %q has rules but is not in the order", name)
		}
		for _, r := range t.Match {
			if len(r.Paths) == 0 && len(r.Checkouts) == 0 && len(r.Repos) == 0 && len(r.Owners) == 0 && len(r.RootAuthorDomains) == 0 {
				return fmt.Errorf("tier %q has a rule that sets no predicate", name)
			}
		}
	}
	return nil
}

// rule is one rule as the shell function the module generated for it: the
// tier it is of, and each predicate it sets with its list as one string, an
// entry a line, as the function was given it.
type rule struct {
	tier                                     string
	paths, checkouts, repos, owners, domains *string
}

// compile is every tier's rules, first to last as the order asks them.
// Remotes and owners are compared lower-cased, as the remote is read, and a
// checkout's entries are in the order Nix gave an attribute set's names.
func compile(c Config) []rule {
	lines := func(xs []string) *string {
		if len(xs) == 0 {
			return nil
		}
		s := strings.Join(xs, "\n")
		return &s
	}
	lower := func(xs []string) []string {
		out := make([]string, len(xs))
		for i, x := range xs {
			out[i] = lowerASCII(x)
		}
		return out
	}
	var rules []rule
	for _, tier := range c.Order {
		for _, r := range c.Tiers[tier].Match {
			var pins []string
			names := make([]string, 0, len(r.Checkouts))
			for s := range r.Checkouts {
				names = append(names, s)
			}
			sort.Strings(names)
			for _, s := range names {
				pins = append(pins, lowerASCII(s)+"\t"+r.Checkouts[s])
			}
			rules = append(rules, rule{
				tier:      tier,
				paths:     lines(r.Paths),
				checkouts: lines(pins),
				repos:     lines(lower(r.Repos)),
				owners:    lines(lower(r.Owners)),
				domains:   lines(lower(r.RootAuthorDomains)),
			})
		}
	}
	return rules
}

// lowerASCII is Nix's lib.toLower and C's tr '[:upper:]' '[:lower:]': A to Z
// alone.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
