// Package grant is a project's grant, applied at launch (PLAN.md, decisions
// 7, 10, 11 and 17): what the checkout's own chase.jsonc asks for beyond its
// tier, once a person has approved it. Its steps:
//
//	approve   seccompPolicy, before the session is built: snapshots the
//	          checkout's chase.jsonc, and the sops file it names, checks
//	          what it says against what a grant may say, has a person
//	          approve it if it is not what they last approved, stages the
//	          approved grant for this launch, and prints its syscall
//	          loosenings for flong
//	launch    exec, after seccompPolicy and before the session is built:
//	          decrypts the secrets the staged grant binds, prepares each
//	          bound app, writes the session's policy document where frisket
//	          reads it, and gives the payload its environment and files
//	project   a checkout's Docker project, as approve derives it
//	docker    `chase docker`: a checkout's project, address, names and ports
//
// and postStop: each app's Stop, then the session's run directory and
// anything staged for it removed.
//
// All of it runs as the user who launched: a launcher has no privilege of
// its own (PLAN.md, decision 2). The approval is split from the rest because
// a syscall filter is installed before anything in the session runs, so what
// loosens it has to be known, and approved, before flong starts bwrap.
//
// A checkout with no chase.jsonc is the tier as it is. Anything that goes
// wrong on the way ends the launch: a grant is applied whole or the session
// does not start.
package grant

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/apps/docker"
	appsgcloud "github.com/danielbodart/chase/internal/apps/gcloud"
	appsssh "github.com/danielbodart/chase/internal/apps/ssh"
	"github.com/danielbodart/chase/internal/gitsafe"
)

// Config is what grant.nix writes for the grant, as JSON. A test gives its own, which is
// what the harness's rewriting of the script's lines was.
type Config struct {
	// Git is the git that finds a checkout, reads its origin and lists
	// what it tracks, never the checkout's own (see internal/gitsafe).
	gitsafe.Config

	// UID is chase.uid, the user every step runs as: Runtime's default.
	UID int `json:"uid"`
	// Home is chase.home, the user's home, and a session's at the same
	// path, where an app's files are seeded: a snapshot is taken under
	// Home/.cache/chase, and State defaults to Home/.local/state/chase.
	Home string `json:"home"`
	// State is where chase keeps what it approved (approved/<key>), each
	// checkout's own directory (checkouts/<key>). Empty is
	// Home/.local/state/chase.
	State string `json:"state,omitempty"`
	// Runtime is the user's runtime directory, where a launch stages its
	// approval (chase/.grant/<machine>.json) and keeps its session's own
	// directory (chase/<machine>), which no session sees. Empty is
	// /run/user/<UID>.
	Runtime string `json:"runtime,omitempty"`
	// Policies is the directory of the tiers' own policy documents,
	// /etc/frisket/policies, one <tier>.json each.
	Policies string `json:"policies"`

	// DockerTiers are the tiers apps/docker.nix gives Docker: not bare, with
	// apps.docker.enable, which it asserts take grants.
	DockerTiers []string `json:"dockerTiers"`
	// Checkouts is every tier's pinned checkouts, as the selector holds
	// them: each owner/repo, and every path any tier pins it at. What names
	// a checkout's Docker project is held to these both ways. The module
	// lower-cases each owner/repo and sorts its paths, and they are read as
	// if it had, whether or not it did: a pin written Example/Billing is
	// example/billing's, as the script's baked file always had it.
	Checkouts map[string][]string `json:"checkouts"`
	// Apps is chase.internal.projectApps, what an app becomes when a
	// project binds it, by name. An app whose routes are made at launch --
	// Docker, Google Cloud, SSH -- is also in the registry the launch is given,
	// which is what its `prepare` was; its entry here says only whether it
	// has a credential, and may be left out when it does.
	Apps map[string]App `json:"apps"`
	// Approver is chase.approver: the program that asks a person to
	// approve a checkout's grant. Empty is none, and nothing is
	// approved.
	Approver string `json:"approver,omitempty"`
	// Sops and Diff are the absolute paths of the tools run: sops to
	// decrypt, and diffutils' diff to show a person what changed. Neither
	// is looked up on PATH, which is the caller's.
	Sops string `json:"sops"`
	Diff string `json:"diff"`

	// Docker, Gcloud and SSH are the apps whose routes are made at launch,
	// as their own packages take them. Nil is an app the module does not
	// have.
	Docker *docker.Config     `json:"docker,omitempty"`
	Gcloud *appsgcloud.Config `json:"gcloud,omitempty"`
	SSH    *appsssh.Config    `json:"ssh,omitempty"`
}

// App is one of chase.internal.projectApps whose routes the module writes:
// its frisket routes by tier, the names it adds to allow, the session's env,
// and envFromGrant, variables taken from the binding's other fields.
type App struct {
	// Routes is by tier: a route, or a list of them, as a policy document
	// holds one but for credentialFile, which is the project's decrypted
	// secret.
	Routes map[string]json.RawMessage `json:"routes,omitempty"`
	Allow  []string                   `json:"allow,omitempty"`
	Env    map[string]string          `json:"env,omitempty"`
	// EnvFromGrant names, for each variable, the binding's field it is
	// taken from.
	EnvFromGrant map[string]string `json:"envFromGrant,omitempty"`
	// Credential, true when absent, says the app is bound only with the
	// project's secret, named by the binding's credential.secret, and not
	// at all without one. False: the app has no credential, and is made by
	// its code from the binding alone, whenever the binding says anything.
	Credential *bool `json:"credential,omitempty"`
}

func (a App) hasCredential() bool { return a.Credential == nil || *a.Credential }

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
	return c, c.paths()
}

// paths holds every path the script had spliced in to being one: absolute,
// as a store path or the module's own is. A tool named without a slash is
// looked up by exec on PATH, which is the caller's, and a path left out of
// a hand-written file is "", which would be read as the working directory's
// own. So a file the module did not write is refused, rather than half obeyed, as
// the selector's is.
func (c Config) paths() error {
	for _, p := range []struct{ name, path string }{
		{"home", c.Home}, {"policies", c.Policies},
		{"sops", c.Sops}, {"diff", c.Diff},
	} {
		if !filepath.IsAbs(p.path) {
			return fmt.Errorf("%s is %q, which is not an absolute path", p.name, p.path)
		}
	}
	// Empty is a default, or, for the approver, none: nothing is approved.
	for _, p := range []struct{ name, path string }{
		{"state", c.State}, {"runtime", c.Runtime}, {"approver", c.Approver},
	} {
		if p.path != "" && !filepath.IsAbs(p.path) {
			return fmt.Errorf("%s is %q, which is neither empty nor an absolute path", p.name, p.path)
		}
	}
	return nil
}

// Validate is what the module refused when it built the script -- an app
// with no credential is made from its binding alone, which only its code
// can do, so one without code is refused here rather than at a launch --
// and every path in c an absolute one.
func Validate(c Config, registry map[string]apps.App) error {
	if err := c.paths(); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(c.Apps)) {
		if _, code := registry[name]; !c.Apps[name].hasCredential() && !code {
			return fmt.Errorf("chase.internal.projectApps.%s has no credential and no prepare, so nothing could be made of what a grant says for it", name)
		}
	}
	return nil
}

// DefaultApps is the registry of apps whose routes are made at launch, as
// the module has them: Docker, Google Cloud and SSH, each from its own Config,
// saying what it says to stderr.
func DefaultApps(c Config, stderr io.Writer) map[string]apps.App {
	r := map[string]apps.App{}
	if c.Docker != nil {
		r["docker"] = &docker.App{Config: *c.Docker, Stderr: stderr}
	}
	if c.Gcloud != nil {
		r["gcloud"] = appsgcloud.New(*c.Gcloud, stderr)
	}
	if c.SSH != nil {
		r["ssh"] = &appsssh.App{Config: *c.SSH, Stderr: stderr}
	}
	return r
}

// checkouts is Checkouts as the module baked it: `lib.zipAttrsWith (_:
// paths: lib.unique (lib.sort lib.lessThan paths))` of each pin under
// `lib.toLower s` -- every owner/repo lower-cased, ASCII only, as
// lib.toLower is, with the paths of each spelling of it together, sorted,
// each once. Read as given, a Config with a tier's own spelling would refuse
// the repository at its own pinned path, as pinned there under another
// name, and leave a pin elsewhere unenforced.
func (c Config) checkouts() map[string][]string {
	out := map[string][]string{}
	for s, paths := range c.Checkouts {
		l := lowerASCII(s)
		out[l] = append(out[l], paths...)
	}
	for s, paths := range out {
		slices.Sort(paths)
		out[s] = slices.Compact(paths)
	}
	return out
}

func (c Config) state() string {
	if c.State != "" {
		return c.State
	}
	// As the script had it, "$home/.local/state/chase": what is printed of
	// it is what the module's own lines derive the same way.
	return c.Home + "/.local/state/chase"
}

func (c Config) runtime() string {
	if c.Runtime != "" {
		return c.Runtime
	}
	return "/run/user/" + strconv.Itoa(c.UID)
}
