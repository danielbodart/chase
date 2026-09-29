// Package envelope is a project's envelope, applied at launch (PLAN.md,
// decisions 7, 10, 11 and 17). It was chase-envelope, the script
// project/default.nix built, and each of its steps is kept here, in its
// order and with its words:
//
//	env-dir   the checkout's environment directory, bound read-only
//	approve   seccompPolicy, before the session is built: snapshots the
//	          checkout, has a person approve its flake and then what its
//	          chaseModules.default evaluates to, stages the approved result
//	          for this launch, and prints its syscall loosenings for flong
//	launch    postStart, before frisket's steps: decrypts the secrets the
//	          staged result binds, prepares each bound app, and writes the
//	          session's policy document and its environment
//	policy    frisket steer's -policy: the session's document, or the tier's
//	project   a checkout's Docker project, as approve derives it
//	docker    `chase docker`: a checkout's project, address, names and ports
//
// and postStop, which was a script of the module's own: each app's Stop,
// then the session's run directory and anything staged for it removed.
//
// All of it runs as the user who launched: a launcher has no privilege of
// its own (PLAN.md, decision 2). The approval is split from the rest because
// a syscall filter is installed before anything in the session runs, so what
// loosens it has to be known, and approved, before flong starts bwrap.
//
// A checkout with no flake, or a flake with no `chaseModules.default`, is the
// tier as it is. Anything that goes wrong on the way ends the launch: an
// envelope is applied whole or the session does not start.
package envelope

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/apps/docker"
	appsgcloud "github.com/danielbodart/chase/internal/apps/gcloud"
	"github.com/danielbodart/chase/internal/gitsafe"
)

// Config is everything project/default.nix spliced into chase-envelope's
// text, as the module will write it, as JSON. A test gives its own, which is
// what the harness's rewriting of the script's lines was.
type Config struct {
	// Git is the git that finds a checkout, reads its origin and lists
	// what it tracks, never the checkout's own (see internal/gitsafe).
	gitsafe.Config

	// UID is chase.uid, the user every step runs as: Runtime's default.
	UID int `json:"uid"`
	// Home is chase.home, the user's home: a snapshot is taken under
	// Home/.cache/chase, and State defaults to Home/.local/state/chase.
	Home string `json:"home"`
	// State is where chase keeps what it approved (approved/<key>), each
	// checkout's environment directory (env/<key>), and the Docker
	// addresses already claimed (docker/addresses.json). Empty is
	// Home/.local/state/chase.
	State string `json:"state,omitempty"`
	// Runtime is the user's runtime directory, where a launch stages its
	// approval (chase/.envelope/<machine>.json) and keeps its session's own
	// directory (chase/<machine>), which no session sees. Empty is
	// /run/user/<UID>.
	Runtime string `json:"runtime,omitempty"`
	// Hosts is /etc/chase/docker-hosts.json, which nix-config writes with
	// /etc/hosts: which of a project's names the host carries, at which
	// address. Read as data; absent is none.
	Hosts string `json:"hosts"`
	// Policies is the directory of the tiers' own policy documents,
	// /etc/frisket/policies, one <tier>.json each.
	Policies string `json:"policies"`

	// DockerTiers are the tiers apps/docker.nix gives Docker: not bare, with
	// apps.docker.enable, which it asserts take envelopes.
	DockerTiers []string `json:"dockerTiers"`
	// Checkouts is every tier's pinned checkouts, as the selector holds
	// them: each owner/repo, lower-cased, and every path any tier pins it
	// at, sorted. What names a checkout's Docker project is held to these
	// both ways.
	Checkouts map[string][]string `json:"checkouts"`
	// Apps is chase.internal.projectApps, what an app becomes when a
	// project binds it, by name. An app whose routes are made at launch --
	// Docker, Google Cloud -- is also in the registry the launch is given,
	// which is what its `prepare` was; its entry here says only whether it
	// has a credential, and may be left out when it does.
	Apps map[string]App `json:"apps"`
	// Approver is chase.approver: the program that asks a person to
	// approve a checkout's envelope. Empty is none, and nothing is
	// approved.
	Approver string `json:"approver,omitempty"`
	// Evaluator is chase's envelope evaluator flake, in the store: its one
	// input is the checkout, given on the command line and evaluated
	// purely.
	Evaluator string `json:"evaluator"`

	// Nix, Sops and Diff are the absolute paths of the tools run: nix to
	// evaluate, sops to decrypt, and diffutils' diff to show a person
	// what changed. None is looked up on PATH, which is the caller's.
	Nix  string `json:"nix"`
	Sops string `json:"sops"`
	Diff string `json:"diff"`

	// Docker and Gcloud are the apps whose routes are made at launch, as
	// their own packages take them. Nil is an app the module does not
	// have.
	Docker *docker.Config     `json:"docker,omitempty"`
	Gcloud *appsgcloud.Config `json:"gcloud,omitempty"`
}

// App is one of chase.internal.projectApps whose routes the module writes:
// its frisket routes by tier, the names it adds to allow, the session's env,
// and envFromBinding, variables taken from the binding's other fields.
type App struct {
	// Routes is by tier: a route, or a list of them, as a policy document
	// holds one but for credentialFile, which is the project's decrypted
	// secret.
	Routes map[string]json.RawMessage `json:"routes,omitempty"`
	Allow  []string                   `json:"allow,omitempty"`
	Env    map[string]string          `json:"env,omitempty"`
	// EnvFromBinding names, for each variable, the binding's field it is
	// taken from.
	EnvFromBinding map[string]string `json:"envFromBinding,omitempty"`
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
	return c, nil
}

// Validate is what the module refused when it built the script: an app with
// no credential is made from its binding alone, which only its code can do,
// so one without code is refused here rather than at a launch.
func Validate(c Config, registry map[string]apps.App) error {
	for _, name := range slices.Sorted(maps.Keys(c.Apps)) {
		if _, code := registry[name]; !c.Apps[name].hasCredential() && !code {
			return fmt.Errorf("chase.internal.projectApps.%s has no credential and no prepare, so nothing could be made of its binding", name)
		}
	}
	return nil
}

// DefaultApps is the registry of apps whose routes are made at launch, as
// the module has them: Docker and Google Cloud, each from its own Config,
// saying what it says to stderr.
func DefaultApps(c Config, stderr io.Writer) map[string]apps.App {
	r := map[string]apps.App{}
	if c.Docker != nil {
		r["docker"] = &docker.App{Config: *c.Docker, Stderr: stderr}
	}
	if c.Gcloud != nil {
		r["gcloud"] = appsgcloud.New(*c.Gcloud, stderr)
	}
	return r
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
