package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/frisket/policy"
	"pgregory.net/rapid"
)

const ws = "/root/p/shop"

// appDir is apps/docker, whose files the module builds each tier's route
// template from.
var appDir = filepath.Join("..", "..", "..", "apps", "docker")

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(appDir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// admitted is admit.json: each admitted operation's methods and docker
// block, as written.
func admitted(t *testing.T) map[string]struct {
	Methods []string        `json:"methods"`
	Docker  json.RawMessage `json:"docker"`
} {
	var admit map[string]struct {
		Methods []string        `json:"methods"`
		Docker  json.RawMessage `json:"docker"`
	}
	readJSON(t, "admit.json", &admit)
	return admit
}

// template is the route apps/docker.nix builds for a tier, from the same
// files, as the module will write it into Config: the paths operations.json
// generates with their descriptions removed, and the table of each body
// admit.json names. It goes through JSON and LoadConfig, strictly, as the
// module's file will.
func template(t *testing.T) Config {
	t.Helper()
	var paths []map[string]any
	readJSON(t, "operations.json", &paths)
	for _, p := range paths {
		delete(p["operation"].(map[string]any), "description")
	}
	var fields map[string]json.RawMessage
	readJSON(t, "fields.json", &fields)
	var source struct {
		APIVersions json.RawMessage `json:"apiVersions"`
	}
	readJSON(t, "source.json", &source)
	bodies := map[string]json.RawMessage{}
	for _, a := range admitted(t) {
		var d struct {
			Body string `json:"body"`
		}
		if err := json.Unmarshal(a.Docker, &d); err != nil {
			t.Fatal(err)
		}
		if d.Body != "" {
			bodies[d.Body] = fields[d.Body]
		}
	}
	route := map[string]any{
		"name":      "docker",
		"host":      "docker.frisket.internal",
		"upstream":  "unix:///run/user/1000/docker.sock",
		"unmatched": "refuse",
		"refusal":   map[string]any{"contentType": "application/json", "body": `{"message":"{{message}}"}`},
		"paths":     paths,
		"docker": map[string]any{
			"apiVersions": source.APIVersions,
			"maxBody":     262144,
			"bodies":      bodies,
		},
	}
	b, err := json.Marshal(map[string]any{"routes": map[string]any{"trusted": route}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(b)
	if err != nil {
		t.Fatalf("the module's config was not loaded: %v", err)
	}
	return c
}

func prepare(t *testing.T, c Config, tier, project, binding string) (apps.Patch, string, error) {
	t.Helper()
	var stderr bytes.Buffer
	a := &App{Config: c, Stderr: &stderr}
	p, err := a.Prepare(context.Background(), apps.Request{
		Tier: tier, Workspace: ws, Run: "run", Dir: "dir", Home: "/home/user",
		Project: project, Binding: json.RawMessage(binding),
	})
	return p, stderr.String(), err
}

// asJSON is v as jq would compare it: marshalled, and read back as plain
// values.
func asJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// requireFrisket is the variable that makes a missing frisket a failure
// rather than a skip. The build that gates chase sets it, with frisket among
// its check inputs, so that what frisket loads is always judged there.
const requireFrisket = "CHASE_REQUIRE_FRISKET"

// frisketCheck runs `frisket check` on a session's document, as the checks
// do. frisket's command is not a package chase can build from here: its
// loader is internal to frisket, and what it needs is not in chase's
// go.sum. So it is the binary on PATH, and a test that needs it is skipped
// without one, unless CHASE_REQUIRE_FRISKET is set, when it fails: a skip
// the build did not ask for is a check that silently never ran.
func frisketCheck(t *testing.T, doc any) (string, error) {
	t.Helper()
	bin, err := exec.LookPath("frisket")
	if err != nil {
		if os.Getenv(requireFrisket) != "" {
			t.Fatalf("frisket is not on PATH, and %s is set: %v", requireFrisket, err)
		}
		t.Skipf("frisket is not on PATH, so what it loads is not checked; set %s to fail instead", requireFrisket)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", f).CombinedOutput()
	return string(out), err
}

func document(p apps.Patch, allow ...string) policy.Document {
	return policy.Document{Name: "trusted", Policy: policy.Policy{Allow: append(slices.Clone(p.Allow), allow...), Routes: p.Routes}}
}

const shop = `{"images": ["postgres:18", "bitnami/redis:7", "ghcr.io/o/x:1"], "ports": [64320, 64321]}`

// docker-launch, THE ROUTE: its address and names are the project's, never
// the grant's, every spelling the CLI could send of each image is there,
// and the rest is the template's, which frisket loads.
func TestTheRouteIsTheProjects(t *testing.T) {
	c := template(t)
	p, said, err := prepare(t, c, "trusted", "example/shop", shop)
	if err != nil {
		t.Fatal(err)
	}
	if said != "" {
		t.Errorf("said %q", said)
	}
	if len(p.Routes) != 1 || p.Routes[0].Name != "docker" {
		t.Fatalf("there is not one docker route: %+v", p.Routes)
	}
	r := p.Routes[0]
	d := r.Docker
	if r.Host != "docker.frisket.internal" || r.Upstream != "unix:///run/user/1000/docker.sock" || r.Unmatched != "refuse" || r.CredentialFile != "" {
		t.Errorf("the route is not the template's: %s %s %s %q", r.Host, r.Upstream, r.Unmatched, r.CredentialFile)
	}
	if r.Refusal == nil || *r.Refusal != (policy.Refusal{ContentType: "application/json", Body: `{"message":"{{message}}"}`}) {
		t.Errorf("the refusal is not Docker's: %+v", r.Refusal)
	}
	if d.Project != "example/shop" || d.Address != "127.101.170.171" || !slices.Equal(d.Names, []string{"shop.example.internal"}) {
		t.Errorf("the route is not shop's: %s %s %q", d.Project, d.Address, d.Names)
	}
	wantImages := []string{"postgres:18", "library/postgres:18", "docker.io/postgres:18", "docker.io/library/postgres:18",
		"bitnami/redis:7", "docker.io/bitnami/redis:7", "ghcr.io/o/x:1"}
	if !slices.Equal(d.Images, wantImages) {
		t.Errorf("images %q, want %q", d.Images, wantImages)
	}
	if !slices.Equal(d.Ports, []int{64320, 64321}) {
		t.Errorf("ports %v", d.Ports)
	}
	if !reflect.DeepEqual(d.APIVersions, policy.APIVersions{Min: "1.55", Max: "1.56", Unversioned: []string{"/_ping"}}) {
		t.Errorf("apiVersions %+v", d.APIVersions)
	}
	if d.MaxBody != 262144 {
		t.Errorf("maxBody %d", d.MaxBody)
	}

	// The bodies are fields.json's tables of exactly the bodies admit.json
	// names.
	var fields map[string]json.RawMessage
	readJSON(t, "fields.json", &fields)
	keys := make([]string, 0, len(d.Bodies))
	for k, v := range d.Bodies {
		keys = append(keys, k)
		if !reflect.DeepEqual(asJSON(t, v), asJSON(t, fields[k])) {
			t.Errorf("the table of %s is not fields.json's", k)
		}
	}
	sort.Strings(keys)
	if !slices.Equal(keys, []string{"ContainerCreate", "ExecCreate", "ExecStart", "NetworkCreate", "VolumeCreate"}) {
		t.Errorf("bodies %q", keys)
	}

	// Every rule has its operation, without its description; the admitted
	// ones are admit.json's, exactly; and none asks.
	admit := admitted(t)
	got := map[string]bool{}
	for _, rule := range r.Paths {
		if rule.Operation == nil || rule.Operation.Description != "" {
			t.Errorf("a rule without its operation, or with its description: %+v", rule)
			continue
		}
		if rule.Ask {
			t.Errorf("%s asks", rule.Operation.ID)
		}
		if rule.Refuse {
			continue
		}
		// jq's from_entries kept one rule of each operation; two admitted
		// rules of one would have made its equality with admit.json fail.
		if got[rule.Operation.ID] {
			t.Errorf("%s is admitted twice", rule.Operation.ID)
		}
		got[rule.Operation.ID] = true
		a, ok := admit[rule.Operation.ID]
		if !ok {
			t.Errorf("%s is admitted, and not in admit.json", rule.Operation.ID)
			continue
		}
		if !slices.Equal(rule.Methods, a.Methods) || !reflect.DeepEqual(asJSON(t, rule.Docker), asJSON(t, a.Docker)) {
			t.Errorf("%s is not admit.json's: %v %s", rule.Operation.ID, rule.Methods, asJSON(t, rule.Docker))
		}
	}
	for id := range admit {
		if !got[id] {
			t.Errorf("%s is in admit.json, and not admitted", id)
		}
	}

	if !slices.Equal(p.Allow, []string{"docker.frisket.internal"}) {
		t.Errorf("allow %q", p.Allow)
	}

	// THE ENVIRONMENT: the CLI pointed at frisket, verifying it by the
	// session's CA, and the project said for a person to read.
	wantEnv := map[string]string{
		"DOCKER_HOST":           "tcp://docker.frisket.internal:2376",
		"DOCKER_TLS_VERIFY":     "1",
		"DOCKER_CERT_PATH":      "/etc/chase/docker",
		"CHASE_PROJECT":         "example/shop",
		"CHASE_PROJECT_ADDRESS": "127.101.170.171",
		"CHASE_PROJECT_NAMES":   "shop.example.internal",
		"CHASE_DOCKER_PORTS":    "64320 64321",
	}
	if !reflect.DeepEqual(p.Env, wantEnv) {
		t.Errorf("env %v, want %v", p.Env, wantEnv)
	}

	// The launch merges the tier's own allowlist after the patch's.
	if out, err := frisketCheck(t, document(p, "github.com")); err != nil {
		t.Errorf("frisket refused the document: %v: %s", err, out)
	}
}

// The patch is the one document the launch merges, as JSON: the route's
// project block is whole, and a template is not changed by a launch made
// from it.
func TestAPatchLeavesItsTemplateAlone(t *testing.T) {
	c := template(t)
	before := asJSON(t, c)
	if _, _, err := prepare(t, c, "trusted", "example/shop", shop); err != nil {
		t.Fatal(err)
	}
	p, _, err := prepare(t, c, "trusted", "example/billing", `{"images": ["redis:7"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(asJSON(t, c), before) {
		t.Error("the template was changed by a launch")
	}
	d := asJSON(t, p.Routes[0]).(map[string]any)["docker"].(map[string]any)
	if d["project"] != "example/billing" || !reflect.DeepEqual(d["images"], []any{"redis:7", "library/redis:7", "docker.io/redis:7", "docker.io/library/redis:7"}) {
		t.Errorf("billing's route is %v", d)
	}
}

// Images alone, with no ports, still route: no port is published, and
// nothing relayed.
func TestImagesAloneRouteWithNoPorts(t *testing.T) {
	for _, binding := range []string{`{"images": ["postgres:18"]}`, `{"images": ["postgres:18"], "ports": null}`, `{"images": ["postgres:18"], "ports": false}`} {
		p, _, err := prepare(t, template(t), "trusted", "example/shop", binding)
		if err != nil {
			t.Fatalf("%s: %v", binding, err)
		}
		d := asJSON(t, p.Routes[0]).(map[string]any)["docker"].(map[string]any)
		if !reflect.DeepEqual(d["ports"], []any{}) {
			t.Errorf("%s: no ports did not route with none: %v", binding, d["ports"])
		}
		if v, ok := p.Env["CHASE_DOCKER_PORTS"]; !ok || v != "" {
			t.Errorf("%s: no ports was not said as none: %q %v", binding, v, ok)
		}
	}
	p, _, _ := prepare(t, template(t), "trusted", "example/shop", `{"images": ["postgres:18"]}`)
	if out, err := frisketCheck(t, document(p, "github.com")); err != nil {
		t.Errorf("frisket refused a route with no ports: %v: %s", err, out)
	}
}

// The refusals, each said as the script's die said it once the launch puts
// "chase: " before it, and each with nothing of a patch.
func TestWhatIsRefused(t *testing.T) {
	id := "an image named by its ID: name it by its repository and a tag or digest"
	for _, v := range []struct{ why, project, binding, said string }{
		// Ports alone name nothing a container could run, so the launch ends
		// here rather than frisket refusing the document.
		{"ports alone", "example/shop", `{"ports": [64320]}`, "no images: say which the project's containers may run"},
		{"no images", "example/shop", `{"images": [], "ports": [64320]}`, "no images"},
		{"null images", "example/shop", `{"images": null}`, "no images"},
		{"false images", "example/shop", `{"images": false}`, "no images"},
		{"a null binding", "example/shop", `null`, "no images"},
		{"no binding at all", "example/shop", ``, "no images"},
		{"a binding that is a list", "example/shop", `["postgres:18"]`, "no images"},
		// NO PROJECT, NO ROUTE: approve always stages one for a Docker
		// binding, so this is the prepare run as launch would with none.
		{"no project", "", `{"images": ["postgres:18"]}`, "no project was approved for it, so its containers could be nobody's"},
		// AN IMAGE'S ID is refused by the prepare too, though the grant's
		// options refuse it first: every spelling the route gets is made
		// from what reaches it.
		{"an ID", "example/shop", `{"images": ["sha256:` + strings.Repeat("0123abcd", 8) + `"]}`, id},
		{"a prefix of an ID", "example/shop", `{"images": ["sha256:0123abcd"]}`, id},
		{"a bare ID, in capitals, tagged", "example/shop", `{"images": ["` + strings.Repeat("0123ABCD", 8) + `:1"]}`, id},
		{"sha256 as a repository", "example/shop", `{"images": ["o/sha256:1"]}`, id},
		{"SHA256 as a registry", "example/shop", `{"images": ["postgres:18", "SHA256/x@y"]}`, id},
		// jq's $ matched before a newline that ends the text, so an ID with
		// one after it was still an ID to the script.
		{"an ID and a newline", "example/shop", `{"images": ["` + strings.Repeat("0123abcd", 8) + `\n"]}`, id},
		{"an ID and a newline, tagged", "example/shop", `{"images": ["o/` + strings.Repeat("0123abcd", 8) + `\n:1"]}`, id},
		// What jq could not split, its `|| die` said as an ID.
		{"an empty component", "example/shop", `{"images": ["a//b:1"]}`, id},
		{"a component with no name before its digest", "example/shop", `{"images": ["@sha256:1"]}`, id},
		{"a null image", "example/shop", `{"images": ["postgres:18", null]}`, id},
		{"images that are one string", "example/shop", `{"images": "postgres:18"}`, id},
		{"images that are a number", "example/shop", `{"images": 1}`, id},
		// Not the script's: jq split "" into no parts, so the ID check held
		// and it routed "" and its spellings; and it read an object's values
		// as its images. Both are refused here.
		{"an empty image", "example/shop", `{"images": [""]}`, id},
		{"images that are an object", "example/shop", `{"images": {"a": "postgres:18"}}`, id},
		{"images that are an empty object", "example/shop", `{"images": {}}`, id},
		{"a project frisket would refuse", "not a slug", `{"images": ["postgres:18"]}`, "not a slug has no address"},
		{"ports that are not ports", "example/shop", `{"images": ["postgres:18"], "ports": ["x"]}`, `ports are not a list of ports: ["x"]`},
		// The script's own refusals come before the ports are read, whatever
		// they are, as its jq read them last.
		{"no images, and ports that are not ports", "example/shop", `{"images": [], "ports": ["x"]}`, "no images"},
		{"an ID, and ports that are not ports", "example/shop", `{"images": ["sha256:1"], "ports": ["x"]}`, id},
		{"no project, and ports that are not ports", "", `{"images": ["postgres:18"], "ports": ["x"]}`, "no project"},
		{"no address, and ports that are not ports", "not a slug", `{"images": ["postgres:18"], "ports": ["x"]}`, "not a slug has no address"},
	} {
		p, said, err := prepare(t, template(t), "trusted", v.project, v.binding)
		if err == nil {
			t.Errorf("%s: a route was prepared: %+v", v.why, p)
			continue
		}
		if !strings.HasPrefix(err.Error(), ws+": docker: "+v.said) {
			t.Errorf("%s: said %q, not %q", v.why, err, v.said)
		}
		if !reflect.DeepEqual(p, apps.Patch{}) || said != "" {
			t.Errorf("%s: the refusal gave the launch something: %+v %q", v.why, p, said)
		}
	}
}

// A TIER WITHOUT DOCKER says so, and adds nothing: the patch is {}.
func TestATierWithoutDockerSaysSo(t *testing.T) {
	p, said, err := prepare(t, template(t), "plain", "example/shop", shop)
	if err != nil {
		t.Fatal(err)
	}
	if said != "chase: "+ws+": docker ignored: plain has no docker\n" {
		t.Errorf("said %q", said)
	}
	b, _ := json.Marshal(p)
	if string(b) != "{}" {
		t.Errorf("a tier without Docker got %s", b)
	}
	// Even with no project or images: what the tier has is decided first.
	if _, _, err := prepare(t, template(t), "plain", "", `{}`); err != nil {
		t.Errorf("a tier without Docker refused: %v", err)
	}
	// What it says carries the checkout's path, cleaned.
	var stderr bytes.Buffer
	a := &App{Config: template(t), Stderr: &stderr}
	if _, err := a.Prepare(context.Background(), apps.Request{Tier: "pl\x1bain", Workspace: "/p/\x1b]0;x\x07"}); err != nil {
		t.Fatal(err)
	}
	if stderr.String() != "chase: /p/?]0;x?: docker ignored: pl?ain has no docker\n" {
		t.Errorf("said %q", stderr.String())
	}
}

// The project is folded to lower case, as `chase project-address` did.
func TestTheProjectIsLowerCased(t *testing.T) {
	p, _, err := prepare(t, template(t), "trusted", "Example/Shop", `{"images": ["postgres:18"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Routes[0].Docker.Project != "example/shop" || p.Env["CHASE_PROJECT"] != "example/shop" {
		t.Errorf("%s %s", p.Routes[0].Docker.Project, p.Env["CHASE_PROJECT"])
	}
}

// Each image's spellings, as jq's spellings made them, deduplicated in the
// order they are first made; and the binding read by its exact keys, as jq
// read it, the last of one given twice.
func TestEverySpellingOnce(t *testing.T) {
	for _, v := range []struct {
		binding string
		want    []string
	}{
		{`{"images": ["postgres:18", "library/postgres:18"]}`, []string{"postgres:18", "library/postgres:18", "docker.io/postgres:18", "docker.io/library/postgres:18"}},
		{`{"images": ["library/postgres:18", "postgres:18"]}`, []string{"library/postgres:18", "docker.io/library/postgres:18", "postgres:18", "docker.io/postgres:18"}},
		{`{"images": ["localhost/x:1", "host:5000/x:1", "eu.gcr.io/p/x:1", "o/x@sha256:` + strings.Repeat("ab", 32) + `"]}`,
			[]string{"localhost/x:1", "host:5000/x:1", "eu.gcr.io/p/x:1", "o/x@sha256:" + strings.Repeat("ab", 32), "docker.io/o/x@sha256:" + strings.Repeat("ab", 32)}},
		{`{"images": ["a:1"], "images": ["b:1"], "Images": ["c:1"]}`, []string{"b:1", "library/b:1", "docker.io/b:1", "docker.io/library/b:1"}},
	} {
		p, _, err := prepare(t, template(t), "trusted", "example/shop", v.binding)
		if err != nil {
			t.Errorf("%s: %v", v.binding, err)
			continue
		}
		if got := p.Routes[0].Docker.Images; !slices.Equal(got, v.want) {
			t.Errorf("%s: %q, want %q", v.binding, got, v.want)
		}
	}
	// "Ports" is not ports.
	p, _, err := prepare(t, template(t), "trusted", "example/shop", `{"images": ["a:1"], "Ports": [64320]}`)
	if err != nil || len(p.Routes[0].Docker.Ports) != 0 {
		t.Errorf("Ports was read as ports: %v %v", err, p.Routes)
	}
}

// Whatever the images, each is its own first spelling, and none is given
// twice.
func TestSpellingsAreEachImageFirstAndNoneTwice(t *testing.T) {
	c := template(t)
	part := rapid.StringMatching(`[a-z0-9.:]{1,6}`)
	rapid.Check(t, func(t *rapid.T) {
		images := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string {
			parts := rapid.SliceOfN(part, 1, 3).Draw(t, "parts")
			return strings.Join(parts, "/")
		}), 1, 4).Draw(t, "images")
		b, _ := json.Marshal(map[string]any{"images": images})
		a := &App{Config: c}
		p, err := a.Prepare(context.Background(), apps.Request{Tier: "trusted", Workspace: ws, Project: "example/shop", Binding: b})
		if err != nil {
			return // an image jq could not split, or an ID
		}
		got := p.Routes[0].Docker.Images
		seen := map[string]bool{}
		for _, s := range got {
			if seen[s] {
				t.Fatalf("%q given twice in %q", s, got)
			}
			seen[s] = true
		}
		for _, img := range images {
			if !seen[img] {
				t.Fatalf("%q is not among its spellings %q", img, got)
			}
		}
	})
}

// docker-fields' sample: the route this prepare writes for one project, with
// every rule operations.json generates and the table for each body
// admit.json names, carries shop's address and names and every table, and
// frisket loads it -- and not at another project's address or names.
func TestFrisketLoadsTheSampleAndNotAnotherProjects(t *testing.T) {
	p, _, err := prepare(t, template(t), "trusted", "example/shop", `{"images": ["postgres:18"], "ports": [64320, 64321]}`)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Routes[0].Docker
	if d.Address != "127.101.170.171" || !slices.Equal(d.Names, []string{"shop.example.internal"}) {
		t.Errorf("the sample is not shop's address and names: %s %q", d.Address, d.Names)
	}
	if !slices.Equal(d.Images, []string{"postgres:18", "library/postgres:18", "docker.io/postgres:18", "docker.io/library/postgres:18"}) {
		t.Errorf("the sample's images: %q", d.Images)
	}
	keys := make([]string, 0, len(d.Bodies))
	for k := range d.Bodies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !slices.Equal(keys, []string{"ContainerCreate", "ExecCreate", "ExecStart", "NetworkCreate", "VolumeCreate"}) {
		t.Errorf("the sample does not carry every admitted body's table: %q", keys)
	}
	if out, err := frisketCheck(t, document(p)); err != nil {
		t.Fatalf("the tables were not judged whole: %v: %s", err, out)
	}

	own := `are not ["shop.example.internal"], the project's own`
	for _, v := range []struct {
		why  string
		edit func(*policy.DockerRoute)
		said string
	}{
		{"names beyond what it derives", func(d *policy.DockerRoute) { d.Names = append(d.Names, "shop.internal") }, own},
		{"names short of what it derives", func(d *policy.DockerRoute) { d.Names = []string{} }, own},
		{"another project's names", func(d *policy.DockerRoute) { d.Names = []string{"billing.example.internal"} }, own},
		{"an address it does not derive", func(d *policy.DockerRoute) { d.Address = "127.101.170.172" }, "is not 127.101.170.171, the project's own"},
	} {
		bad, _, _ := prepare(t, template(t), "trusted", "example/shop", `{"images": ["postgres:18"], "ports": [64320, 64321]}`)
		v.edit(bad.Routes[0].Docker)
		out, err := frisketCheck(t, document(bad))
		if err == nil {
			t.Errorf("frisket loaded %s", v.why)
			continue
		}
		if !strings.Contains(out, v.said) {
			t.Errorf("%s, refused otherwise: %s", v.why, out)
		}
	}
}

// Config is read strictly: a misspelt key in a template is refused, not
// dropped.
func TestAConfigWithAKeyFrisketDoesNotKnowIsRefused(t *testing.T) {
	if _, err := LoadConfig([]byte(`{"routes": {"trusted": {"name": "docker", "hots": "x"}}}`)); err == nil {
		t.Error("a misspelt key was loaded")
	}
	if _, err := LoadConfig([]byte(`{"routes": {}, "extra": 1}`)); err == nil {
		t.Error("an unknown key was loaded")
	}
}
