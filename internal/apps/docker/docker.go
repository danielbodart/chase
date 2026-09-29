// Package docker is Docker through frisket (docs/docker.md): a project's
// containers, on the rootless daemon of the tier's user, reached by the
// session only through a route frisket judges request by request, and
// published only on the project's own loopback address. What the project is
// was approved with its envelope, from its checkout's origin; the route is
// made at launch, from that and the binding's images and ports.
//
// It was chase-docker-prepare, a script apps/docker.nix built, run by the
// launch as `prepare TIER WORKSPACE RUN ENVDIR` with the binding on stdin and
// the project in chase_project. It is the same judgement here, called in the
// launch's own process (PLAN.md, decision 2). Run and EnvDir are not needed:
// Docker has no secret, and nothing of the checkout's to keep.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/dockerproject"
	"github.com/danielbodart/chase/internal/term"
	"github.com/danielbodart/frisket/policy"
)

// Host is the name the session reaches the daemon by: frisket intercepts it,
// and it is the one name a Docker binding adds to the session's allowlist.
const Host = "docker.frisket.internal"

// Config is what the NixOS module gives the Docker app, as JSON. It was
// spliced into chase-docker-prepare's text as routeTemplates, a store file of
// each tier's route; it is the same data, computed by Nix as before.
type Config struct {
	// Routes is, for each tier with Docker enabled (not bare, with
	// apps.docker.enable and direct egress), everything of its route that
	// the launch does not decide, keyed by the tier's name. A tier not here
	// has no Docker, and a binding in it is said and adds nothing.
	//
	// Each is apps/docker.nix's `route`: name "docker", host
	// docker.frisket.internal, upstream unix:///run/user/<uid>/docker.sock,
	// unmatched "refuse", Docker's own JSON refusal, the paths
	// operations.json generates with each operation's description removed,
	// and a docker block of source.json's apiVersions, a maxBody of 262144
	// and the fields.json table of each body admit.json names. The launch
	// fills in the docker block's project, images, ports, address and
	// names, and nothing else; a template's own values of those are
	// replaced.
	Routes map[string]policy.Route `json:"routes"`
}

// LoadConfig reads a Config as the module writes it, refusing any field it
// does not know, as frisket refuses one in a policy: a misspelt key in a
// route is a rule that silently does not apply.
func LoadConfig(b []byte) (Config, error) {
	var c Config
	if err := policy.Decode(b, &c); err != nil {
		return Config{}, fmt.Errorf("docker config: %w", err)
	}
	return c, nil
}

// App is the Docker app. Its Prepare says to Stderr, through term, the one
// thing it says without refusing: that a tier has no Docker.
type App struct {
	Config Config
	Stderr io.Writer
}

var _ apps.App = (*App)(nil)

// Prepare is the route to the project's daemon, the name it is reached by,
// and the variables that point the CLI at it.
//
// A refusal is an error whose text is "<workspace>: docker: <why>", which the
// launch says as "chase: " and that, through term.Say, as the script's die
// did; the launch then ends, and nothing of the patch is used. The workspace
// is the checkout's path, and is only safe to print cleaned.
func (a *App) Prepare(_ context.Context, r apps.Request) (apps.Patch, error) {
	ws := r.Workspace
	die := func(format string, args ...any) (apps.Patch, error) {
		return apps.Patch{}, fmt.Errorf("%s: docker: %s", ws, fmt.Sprintf(format, args...))
	}

	tmpl, ok := a.Config.Routes[r.Tier]
	if !ok {
		term.Say(a.stderr(), "%s: docker ignored: %s has no docker", ws, r.Tier)
		return apps.Patch{}, nil
	}

	// The project approve derived from the checkout's origin, and was
	// approved as: never anything the envelope says, which would let a
	// project name another's containers as its own.
	if r.Project == "" {
		return die("no project was approved for it, so its containers could be nobody's")
	}
	b, err := readBinding(r.Binding)
	if err != nil {
		return die("%v", err)
	}
	if len(b.images) == 0 {
		return die("no images: say which the project's containers may run")
	}
	// As options.nix refuses it, again here, since every spelling below is
	// made from it: an image's ID, or sha256:<prefix>, which the daemon
	// answers with whatever local image has it.
	for _, img := range b.images {
		if !notAnID(img) {
			return die("an image named by its ID: name it by its repository and a tag or digest")
		}
	}
	who, err := dockerproject.Of(r.Project)
	if err != nil {
		return die("%s has no address", r.Project)
	}

	// frisket compares an image as the string a client sends, and the CLI
	// sends what it was given: every spelling that names the same image on
	// Docker Hub. The envelope allows only the shortest, so each is given
	// all of its own here.
	images := []string{}
	seen := map[string]bool{}
	for _, img := range b.images {
		for _, s := range Spellings(img) {
			if !seen[s] {
				seen[s] = true
				images = append(images, s)
			}
		}
	}

	route := tmpl
	var d policy.DockerRoute
	if tmpl.Docker != nil {
		d = *tmpl.Docker
	}
	d.Project = who.Project
	d.Images = images
	d.Ports = b.ports
	d.Address = who.Address
	d.Names = who.Names
	route.Docker = &d

	ports := make([]string, len(b.ports))
	for i, p := range b.ports {
		ports[i] = strconv.Itoa(p)
	}
	return apps.Patch{
		Routes: []policy.Route{route},
		Allow:  []string{Host},
		Env: map[string]string{
			"DOCKER_HOST":          "tcp://" + Host + ":2376",
			"DOCKER_TLS_VERIFY":    "1",
			"DOCKER_CERT_PATH":     "/etc/chase/docker",
			"CHASE_DOCKER_PROJECT": who.Project,
			"CHASE_DOCKER_ADDRESS": who.Address,
			"CHASE_DOCKER_NAMES":   strings.Join(who.Names, " "),
			"CHASE_DOCKER_PORTS":   strings.Join(ports, " "),
		},
	}, nil
}

// Stop has nothing to release: Prepare starts nothing.
func (a *App) Stop(context.Context, string) error { return nil }

func (a *App) stderr() io.Writer {
	if a.Stderr == nil {
		return io.Discard
	}
	return a.Stderr
}

// Spellings are every spelling the CLI could send of an image as the
// envelope names it, the image itself first: a Docker Hub image with no
// namespace is also library/, docker.io/ and docker.io/library/ it, one with
// a namespace also docker.io/ it, and one whose first component is a
// registry -- a '.' or ':' in it, or localhost -- is only itself.
func Spellings(image string) []string {
	if !strings.Contains(image, "/") {
		return []string{image, "library/" + image, "docker.io/" + image, "docker.io/library/" + image}
	}
	first, _, _ := strings.Cut(image, "/")
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return []string{image}
	}
	return []string{image, "docker.io/" + image}
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// notAnID is whether no /-separated part of an image, before its @digest
// and then its :tag, is sha256 or 64 hex, in any case.
//
// It is the script's jq, exactly, where frisket's docker.ValidImage has the
// same rule: split("@")[0] | split(":")[0] | ascii_downcase. jq splits an
// empty string into no parts, so a part that is empty, or empty before its
// '@', has no name, and jq failed on it; the script's `|| die` said that
// failure as this refusal, and so does this. options.nix and ValidImage
// both refuse such an image anyway.
func notAnID(image string) bool {
	for _, part := range strings.Split(image, "/") {
		name, _, _ := strings.Cut(part, "@")
		if name == "" {
			return false
		}
		name, _, _ = strings.Cut(name, ":")
		name = asciiLower(name)
		if name == "sha256" || hex64.MatchString(name) {
			return false
		}
	}
	return true
}

// asciiLower is jq's ascii_downcase: A-Z only.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// binding is what Prepare reads of a Docker binding: its images and ports.
type binding struct {
	images []string
	ports  []int
}

// errNoImages is a binding with nothing a container could run. It is also
// what a binding that is not a JSON object came to in the script, whose
// `jq -e '(.images // []) != []'` failed on one and said this.
var errNoImages = errors.New("no images: say which the project's containers may run")

// readBinding reads a binding as the script's jq did: by its exact keys, the
// last of a key given twice, and null or false for either as none.
// encoding/json would match "Images" to a field named images, which jq never
// did, so the keys are read from a map.
func readBinding(raw json.RawMessage) (binding, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return binding{}, errNoImages
	}
	var b binding
	if v := obj["images"]; !none(v) {
		if err := json.Unmarshal(v, &b.images); err != nil {
			// jq failed on images that were not a list of strings, in the ID
			// check, whose `|| die` said this; the options refuse them first.
			return binding{}, errors.New("an image named by its ID: name it by its repository and a tag or digest")
		}
	}
	b.ports = []int{}
	if v := obj["ports"]; !none(v) {
		if err := json.Unmarshal(v, &b.ports); err != nil {
			return binding{}, fmt.Errorf("ports are not a list of ports: %s", v)
		}
	}
	return b, nil
}

// none is whether a value is what jq's `// []` replaces: absent, null or
// false.
func none(v json.RawMessage) bool {
	s := strings.TrimSpace(string(v))
	return s == "" || s == "null" || s == "false"
}
