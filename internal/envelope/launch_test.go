package envelope_test

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/apps/docker"
	"github.com/danielbodart/chase/internal/envelope"
)

// probe stands in for an app with no credential, as the project-launch
// check's did: it keeps what it was given, and adds a name and a variable.
type probe struct {
	requests []apps.Request
	stopped  []string
	// running is, at each Stop, whether the session's directory was still
	// there.
	running []bool
	runtime string
}

func (p *probe) Prepare(_ context.Context, r apps.Request) (apps.Patch, error) {
	p.requests = append(p.requests, r)
	return apps.Patch{Routes: []policy.Route{}, Allow: []string{"probe.example"}, Env: map[string]string{"PROBE": "1"}}, nil
}

func (p *probe) Stop(_ context.Context, machine string) error {
	p.stopped = append(p.stopped, machine)
	_, err := os.Stat(p.runtime + "/chase/" + machine)
	p.running = append(p.running, err == nil)
	return nil
}

func (h *harness) policyDoc(machine string) policy.Document {
	h.t.Helper()
	var d policy.Document
	if err := policy.Decode([]byte(read(h.t, h.dir+"/run/chase/"+machine+"/policy.json")), &d); err != nil {
		h.t.Fatalf("the session's document is not frisket's: %v", err)
	}
	return d
}

func lines(s string) []string { return strings.Split(s, "\n") }

func no() *bool { f := false; return &f }

// newProjectLaunch is the project-launch check's system: example/shop pinned
// in trusted, which has no Docker, and probe an app with no credential.
func newProjectLaunch(t *testing.T) (*harness, *probe, string) {
	h := newHarness(t)
	r := h.root()
	h.cfg.Checkouts["example/shop"] = []string{r + "/p/shop"}
	h.cfg.Apps["docker"] = envelope.App{Credential: no()}
	h.cfg.Apps["probe"] = envelope.App{Credential: no()}
	h.cfg.Apps["gcloud"] = envelope.App{}
	p := &probe{runtime: h.cfg.Runtime}
	h.cfg.Docker = &docker.Config{Routes: map[string]policy.Route{}}
	h.registry = map[string]apps.App{"probe": p}
	write(t, h.cfg.Policies+"/trusted.json", `{"name": "trusted", "allow": [], "routes": []}`)
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:example/shop.git")
	h.flake(ws)
	return h, p, ws
}

// The ported project-launch check: AN APP WITH NO CREDENTIAL (docs/docker.md),
// launched: its code is run from the binding alone, whenever the binding
// says anything, with nothing decrypted, and given the Docker project that
// approve staged -- never one derived again at launch, nor one the session
// has. An app with a credential is still bound only with one.
func TestAnAppWithNoCredentialIsMadeFromItsBinding(t *testing.T) {
	h, p, ws := newProjectLaunch(t)
	h.launched(ws, "m1", "trusted", `{"bindings": {"docker": {"images": ["postgres:18"], "ports": [64320]}, "probe": {"x": 1}, "gcloud": {"serviceAccount": "a@p.iam.gserviceaccount.com"}}}`)
	if len(p.requests) != 1 {
		t.Fatalf("probe was prepared %d times", len(p.requests))
	}
	r := p.requests[0]
	if string(r.Binding) != `{"x":1}` {
		t.Errorf("prepare was not given the binding: %s", r.Binding)
	}
	if r.Project != "example/shop" {
		t.Errorf("prepare was not given the approved project: %q", r.Project)
	}
	if r.Tier != "trusted" || r.Workspace != ws || r.Run != h.dir+"/run/chase/m1" || r.EnvDir != h.dir+"/state/env/"+key(ws) {
		t.Errorf("prepare was not given the session: %+v", r)
	}
	d := h.policyDoc("m1")
	if !slices.Equal(d.Allow, []string{"probe.example"}) || len(d.Routes) != 0 {
		t.Errorf("probe's patch was not merged: %+v", d)
	}
	env := read(t, h.envfile(ws))
	if !slices.Contains(lines(env), "export PROBE='1'") {
		t.Errorf("probe's env was not exported: %q", env)
	}
	if strings.Contains(env, "chase_project") {
		t.Errorf("the session was given chase_project: %q", env)
	}
	if !h.said("chase: " + ws + ": probe from no credential") {
		t.Errorf("where probe came from was not said: %s", h.err)
	}
	if strings.Contains(h.err, "gcloud from") {
		t.Errorf("gcloud was bound with no secret: %s", h.err)
	}
	if !h.said("chase: " + ws + ": docker ignored: trusted has no docker") {
		t.Errorf("a tier without Docker did not say so: %s", h.err)
	}
	if h.log("sops.log") != nil {
		t.Errorf("a secret was decrypted: %q", h.log("sops.log"))
	}
	if left, _ := os.ReadDir(h.dir + "/run/chase/m1/secrets"); len(left) != 0 {
		t.Errorf("a secret was kept: %v", left)
	}

	// Without probe, it is never prepared.
	h.launched(ws, "m2", "trusted", `{"bindings": {"docker": {"images": ["postgres:18"], "ports": [64320]}}}`)
	if len(p.requests) != 1 {
		t.Error("probe was prepared with no binding")
	}
	if strings.Contains(h.err, "probe from") {
		t.Errorf("probe was said with no binding: %s", h.err)
	}
	if d := h.policyDoc("m2"); len(d.Allow) != 0 {
		t.Errorf("probe's names were allowed with no binding: %q", d.Allow)
	}

	// Without Docker, there is no project to give, and it is empty.
	h.launched(ws, "m3", "trusted", `{"bindings": {"probe": {"x": 2}}}`)
	if r := p.requests[len(p.requests)-1]; r.Project != "" || string(r.Binding) != `{"x":2}` {
		t.Errorf("prepare was given a project with no Docker, or not the binding: %+v", r)
	}
	if h.log("sops.log") != nil {
		t.Errorf("a secret was decrypted: %q", h.log("sops.log"))
	}
}

// An app with neither a credential nor code is refused when the system is
// built, and, were it not, at the launch.
func TestAnAppWithNoCredentialAndNoCodeIsRefused(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	c := h.cfg
	c.Apps = map[string]envelope.App{"bad": {Credential: no()}, "fine": {}}
	err := envelope.Validate(c, nil)
	if err == nil || err.Error() != "chase.internal.projectApps.bad has no credential and no prepare, so nothing could be made of its binding" {
		t.Errorf("an app with no credential and no prepare was built: %v", err)
	}
	if err := envelope.Validate(c, map[string]apps.App{"bad": &probe{}}); err != nil {
		t.Errorf("an app with code was refused: %v", err)
	}

	h.cfg.Apps["bad"] = envelope.App{Credential: no()}
	h.approved(ws, "m1", "trusted", `{"bindings": {"bad": {"x": 1}}}`)
	if h.run("launch", "trusted", ws, "m1") == 0 {
		t.Error("an app with no credential and no prepare was launched")
	}
	h.mustSay("chase: " + ws + ": bad has no credential and no prepare")
}

// Every path the script had spliced in is an absolute one: a tool named
// without a slash would be looked up on the caller's PATH, and a path left
// out would be "", which is a Hosts never there and a flake ref of nothing.
// Empty is a default only where there is one, and no approver.
func TestAConfigsPathsAreAbsolute(t *testing.T) {
	h := newHarness(t)
	if err := envelope.Validate(h.cfg, nil); err != nil {
		t.Fatalf("the harness's Config was refused: %v", err)
	}
	for _, c := range []struct {
		name string
		set  func(*envelope.Config)
		want string
	}{
		{"nix", func(c *envelope.Config) { c.Nix = "nix" }, `nix is "nix", which is not an absolute path`},
		{"sops", func(c *envelope.Config) { c.Sops = "" }, `sops is "", which is not an absolute path`},
		{"diff", func(c *envelope.Config) { c.Diff = "bin/diff" }, `diff is "bin/diff", which is not an absolute path`},
		{"hosts", func(c *envelope.Config) { c.Hosts = "" }, `hosts is "", which is not an absolute path`},
		{"evaluator", func(c *envelope.Config) { c.Evaluator = "" }, `evaluator is "", which is not an absolute path`},
		{"policies", func(c *envelope.Config) { c.Policies = "policies" }, `policies is "policies", which is not an absolute path`},
		{"home", func(c *envelope.Config) { c.Home = "" }, `home is "", which is not an absolute path`},
		{"approver", func(c *envelope.Config) { c.Approver = "approver" }, `approver is "approver", which is neither empty nor an absolute path`},
		{"state", func(c *envelope.Config) { c.State = "state" }, `state is "state", which is neither empty nor an absolute path`},
	} {
		cfg := h.cfg
		c.set(&cfg)
		if err := envelope.Validate(cfg, nil); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, not %s", c.name, err, c.want)
		}
		b, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		write(t, h.dir+"/config.json", string(b))
		if _, err := envelope.LoadConfig(h.dir + "/config.json"); err == nil || err.Error() != c.want {
			t.Errorf("%s, loaded: %v, not %s", c.name, err, c.want)
		}
	}
	cfg := h.cfg
	cfg.Approver, cfg.State, cfg.Runtime = "", "", ""
	if err := envelope.Validate(cfg, nil); err != nil {
		t.Errorf("no approver, and the default state and runtime, were refused: %v", err)
	}
}

// dockerTemplate is the route apps/docker.nix builds for a tier, from the
// files it builds it from, as internal/apps/docker's tests make it.
func dockerTemplate(t *testing.T) policy.Route {
	t.Helper()
	dir := filepath.Join("..", "..", "apps", "docker")
	readJSON := func(name string, v any) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	var paths []map[string]any
	readJSON("operations.json", &paths)
	for _, p := range paths {
		delete(p["operation"].(map[string]any), "description")
	}
	var fields map[string]json.RawMessage
	readJSON("fields.json", &fields)
	var admit map[string]struct {
		Docker struct {
			Body string `json:"body"`
		} `json:"docker"`
	}
	readJSON("admit.json", &admit)
	var source struct {
		APIVersions json.RawMessage `json:"apiVersions"`
	}
	readJSON("source.json", &source)
	bodies := map[string]json.RawMessage{}
	for _, a := range admit {
		if a.Docker.Body != "" {
			bodies[a.Docker.Body] = fields[a.Docker.Body]
		}
	}
	b, err := json.Marshal(map[string]any{
		"name": "docker", "host": docker.Host, "upstream": "unix:///run/user/1000/docker.sock", "unmatched": "refuse",
		"refusal": map[string]any{"contentType": "application/json", "body": `{"message":"{{message}}"}`},
		"paths":   paths,
		"docker":  map[string]any{"apiVersions": source.APIVersions, "maxBody": 262144, "bodies": bodies},
	})
	if err != nil {
		t.Fatal(err)
	}
	var r policy.Route
	if err := policy.Decode(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// dockerRouteIsTheTemplates is the rest of docker-launch's judgement of the
// route, made of policy.json as it was written rather than as frisket's
// Document reads it back: the document is encoded from a policy.Document
// now, so a field lost on the way through Merge or the encoding shows here,
// and not only if `frisket check` happens to mind. The API versions and the
// admitted bodies' tables are the files', every path keeps its operation but
// not the operation's description, the paths not refused are admit.json's,
// exactly, none asks, and the route has no credentialFile at all.
func dockerRouteIsTheTemplates(t *testing.T, path string) {
	t.Helper()
	dir := filepath.Join("..", "..", "apps", "docker")
	readJSON := func(p string) any {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return v
	}
	admit := readJSON(filepath.Join(dir, "admit.json")).(map[string]any)
	fields := readJSON(filepath.Join(dir, "fields.json")).(map[string]any)
	doc := readJSON(path).(map[string]any)
	var route map[string]any
	for _, r := range doc["routes"].([]any) {
		if r := r.(map[string]any); r["name"] == "docker" {
			route = r
		}
	}
	if route == nil {
		t.Fatalf("%s has no docker route", path)
	}
	if _, has := route["credentialFile"]; has {
		t.Errorf("the docker route has a credentialFile: %v", route["credentialFile"])
	}
	d, _ := route["docker"].(map[string]any)
	want := map[string]any{"min": "1.55", "max": "1.56", "unversioned": []any{"/_ping"}}
	if !reflect.DeepEqual(d["apiVersions"], want) {
		t.Errorf("the route's apiVersions are %v, not %v", d["apiVersions"], want)
	}
	bodies := map[string]any{}
	for _, a := range admit {
		if b, ok := a.(map[string]any)["docker"].(map[string]any)["body"].(string); ok {
			bodies[b] = fields[b]
		}
	}
	if !reflect.DeepEqual(d["bodies"], bodies) {
		t.Error("the route's bodies are not the tables of the bodies admit.json names")
	}
	got, _ := d["bodies"].(map[string]any)
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, []string{"ContainerCreate", "ExecCreate", "ExecStart", "NetworkCreate", "VolumeCreate"}) {
		t.Errorf("the route's bodies are %q", keys)
	}
	admitted := map[string]any{}
	n := 0
	for _, p := range route["paths"].([]any) {
		p := p.(map[string]any)
		op, ok := p["operation"].(map[string]any)
		if !ok {
			t.Errorf("a path has no operation: %v", p)
			continue
		}
		if _, has := op["description"]; has {
			t.Errorf("%v kept its description", op["id"])
		}
		if ask, _ := p["ask"].(bool); ask {
			t.Errorf("%v asks", op["id"])
		}
		if refuse, _ := p["refuse"].(bool); refuse {
			continue
		}
		n++
		// `{methods, docker}`: each, or null when it is not there.
		admitted[op["id"].(string)] = map[string]any{"methods": p["methods"], "docker": p["docker"]}
	}
	if !reflect.DeepEqual(admitted, admit) {
		for id := range admit {
			if !reflect.DeepEqual(admitted[id], admit[id]) {
				t.Errorf("%s is admitted as %v, not as admit.json has it: %v", id, admitted[id], admit[id])
			}
		}
		for id := range admitted {
			if _, ok := admit[id]; !ok {
				t.Errorf("%s is admitted, and admit.json does not name it", id)
			}
		}
	}
	if n != len(admit) {
		t.Errorf("%d paths are not refused, and admit.json names %d", n, len(admit))
	}
}

// frisketCheck is `frisket check` of a session's document, as the checks
// ran it: the binary on PATH, skipped without one unless
// CHASE_REQUIRE_FRISKET is set, as internal/apps/docker's tests have it.
func frisketCheck(t *testing.T, path string) {
	t.Helper()
	bin, err := exec.LookPath("frisket")
	if err != nil {
		if os.Getenv("CHASE_REQUIRE_FRISKET") != "" {
			t.Fatalf("frisket is not on PATH, and CHASE_REQUIRE_FRISKET is set: %v", err)
		}
		t.Log("frisket is not on PATH, so what it loads is not checked")
		return
	}
	if out, err := exec.Command(bin, "check", path).CombinedOutput(); err != nil {
		t.Errorf("frisket refused %s: %v: %s", path, err, out)
	}
}

// The ported docker-launch check, as far as the launch goes (the prepare's
// own refusals are internal/apps/docker's): DOCKER, LAUNCHED. A checkout
// whose envelope binds Docker gets a route to the rootless daemon, as the
// project approve staged, and the variables that point the CLI at it. A
// checkout that binds nothing of Docker's gets no route, and a binding in a
// tier without Docker is said and adds nothing.
func TestDockerIsLaunchedAsTheApprovedProject(t *testing.T) {
	h := newHarness(t)
	r := h.root()
	h.cfg.Checkouts["example/shop"] = []string{r + "/p/shop"}
	h.cfg.DockerTiers = []string{"trusted"}
	h.cfg.Apps["docker"] = envelope.App{Credential: no()}
	h.cfg.Docker = &docker.Config{Routes: map[string]policy.Route{"trusted": dockerTemplate(t)}}
	for _, tier := range []string{"trusted", "plain"} {
		write(t, h.cfg.Policies+"/"+tier+".json", `{"name": "`+tier+`", "allow": ["github.com"], "routes": []}`)
	}
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:Example/Shop.git")
	h.flake(ws)
	launched := func(tier, machine, env string) {
		t.Helper()
		h.approved(ws, machine, tier, env)
		if got := h.stagedProject(machine); got != "example/shop" {
			t.Errorf("approve did not stage the project: %v", got)
		}
		if h.run("launch", tier, ws, machine) != 0 {
			t.Fatalf("%s was not launched: %s", machine, h.err)
		}
	}
	shop := `{"bindings": {"docker": {"images": ["postgres:18", "bitnami/redis:7", "ghcr.io/o/x:1"], "ports": [64320, 64321]}}}`

	launched("trusted", "m1", shop)
	if !h.said("chase: " + ws + ": docker from no credential") {
		t.Errorf("where docker came from was not said: %s", h.err)
	}
	d := h.policyDoc("m1")
	var routes []policy.Route
	for _, rt := range d.Routes {
		if rt.Name == "docker" {
			routes = append(routes, rt)
		}
	}
	if len(routes) != 1 {
		t.Fatalf("there is not one docker route: %+v", d.Routes)
	}
	rt := routes[0]
	if rt.Host != "docker.frisket.internal" || rt.Upstream != "unix:///run/user/1000/docker.sock" || rt.Unmatched != "refuse" || rt.CredentialFile != "" {
		t.Errorf("the route is not the template's: %+v", rt)
	}
	dr := rt.Docker
	if dr.Project != "example/shop" || dr.Address != "127.101.170.171" || !slices.Equal(dr.Names, []string{"shop.internal", "shop.example.internal"}) ||
		!slices.Equal(dr.Images, []string{"postgres:18", "library/postgres:18", "docker.io/postgres:18", "docker.io/library/postgres:18",
			"bitnami/redis:7", "docker.io/bitnami/redis:7", "ghcr.io/o/x:1"}) ||
		!slices.Equal(dr.Ports, []int{64320, 64321}) || dr.MaxBody != 262144 {
		t.Errorf("the route is not shop's: %+v", dr)
	}
	if !slices.Equal(d.Allow, []string{"docker.frisket.internal", "github.com"}) {
		t.Errorf("docker.frisket.internal was not allowed: %q", d.Allow)
	}
	dockerRouteIsTheTemplates(t, h.dir+"/run/chase/m1/policy.json")
	frisketCheck(t, h.dir+"/run/chase/m1/policy.json")
	env := lines(read(t, h.envfile(ws)))
	for _, line := range []string{
		"export DOCKER_HOST='tcp://docker.frisket.internal:2376'",
		"export DOCKER_TLS_VERIFY='1'",
		"export DOCKER_CERT_PATH='/etc/chase/docker'",
		"export CHASE_DOCKER_PROJECT='example/shop'",
		"export CHASE_DOCKER_ADDRESS='127.101.170.171'",
		"export CHASE_DOCKER_NAMES='shop.internal shop.example.internal'",
		"export CHASE_DOCKER_PORTS='64320 64321'",
	} {
		if !slices.Contains(env, line) {
			t.Errorf("the env file has no %s: %q", line, env)
		}
	}

	// Images alone, with no ports, still route.
	launched("trusted", "m2", `{"bindings": {"docker": {"images": ["postgres:18"]}}}`)
	for _, rt := range h.policyDoc("m2").Routes {
		if rt.Name == "docker" && len(rt.Docker.Ports) != 0 {
			t.Errorf("no ports did not route with none: %v", rt.Docker.Ports)
		}
	}
	if !slices.Contains(lines(read(t, h.envfile(ws))), "export CHASE_DOCKER_PORTS=''") {
		t.Errorf("no ports was not said as none: %s", read(t, h.envfile(ws)))
	}
	frisketCheck(t, h.dir+"/run/chase/m2/policy.json")

	// Ports alone name nothing a container could run, so the launch ends
	// there rather than frisket refusing the document.
	h.approved(ws, "m3", "trusted", `{"bindings": {"docker": {"ports": [64320]}}}`)
	if h.run("launch", "trusted", ws, "m3") == 0 {
		t.Error("Docker with no images was launched")
	}
	h.mustSay("chase: " + ws + ": docker: no images")
	h.mustSay("chase: " + ws + ": docker could not be prepared")

	// NO BINDING, NO ROUTE, and nothing of Docker's in the session.
	h.approved(ws, "m4", "trusted", `{"bindings": {"gcloud": {"serviceAccount": "a@p.iam.gserviceaccount.com"}}}`)
	if h.run("launch", "trusted", ws, "m4") != 0 {
		t.Fatalf("m4 was not launched: %s", h.err)
	}
	if d := h.policyDoc("m4"); len(d.Routes) != 0 || !slices.Equal(d.Allow, []string{"github.com"}) {
		t.Errorf("a checkout with no binding got a route: %+v", d)
	}
	if env := read(t, h.envfile(ws)); strings.Contains(env, "DOCKER") {
		t.Errorf("a checkout with no binding got Docker's variables: %q", env)
	}
	if strings.Contains(h.err, "docker") {
		t.Errorf("docker was said with no binding: %s", h.err)
	}

	// A TIER WITHOUT DOCKER says so, and adds nothing.
	launched("plain", "m5", shop)
	if !h.said("chase: " + ws + ": docker ignored: plain has no docker") {
		t.Errorf("the tier without Docker did not say so: %s", h.err)
	}
	if d := h.policyDoc("m5"); len(d.Routes) != 0 || !slices.Equal(d.Allow, []string{"github.com"}) {
		t.Errorf("a tier without Docker got a route: %+v", d)
	}
	if env := read(t, h.envfile(ws)); strings.Contains(env, "DOCKER") {
		t.Errorf("a tier without Docker got Docker's variables: %q", env)
	}
}

// A launch consumes its stage: a second launch of the same approval, or one
// seccompPolicy never approved, is refused. An approval of the tier as it is
// removes the environment an earlier launch wrote.
func TestALaunchAppliesOneApprovalOnce(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	h.launched(ws, "m1", "trusted", `{"bindings": {"probe": {"x": 1}}}`)
	if _, err := os.Stat(h.dir + "/run/chase/.envelope/m1.json"); err == nil {
		t.Error("the stage outlived its launch")
	}
	if h.run("launch", "trusted", ws, "m9") == 0 {
		t.Error("a launch nothing approved was applied")
	}
	if h.err != "chase: "+ws+": nothing was approved for this launch: the tier's seccompPolicy did not run\n" {
		t.Errorf("an unapproved launch said: %q", h.err)
	}
	if fi, err := os.Stat(h.envfile(ws)); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("the env file is not the session's to read: %v", fi)
	}
	if fi, err := os.Stat(h.dir + "/run/chase/m1/policy.json"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the policy document is not the user's alone: %v", fi)
	}
	write(t, ws+"/flake.nix", "{ outputs = _: { }; }\n")
	h.approved(ws, "m2", "trusted", "")
	if got := read(t, h.dir+"/run/chase/.envelope/m2.json"); got != "null\n" {
		t.Errorf("a flake without chaseModules was staged as %q", got)
	}
	if h.run("launch", "trusted", ws, "m2") != 0 {
		t.Fatalf("the tier as it is was not launched: %s", h.err)
	}
	if _, err := os.Stat(h.envfile(ws)); err == nil {
		t.Error("an earlier launch's environment was left")
	}
	if _, err := os.Stat(h.dir + "/run/chase/m2"); err == nil {
		t.Error("the tier as it is has a session directory")
	}
}

// The sops file launched is the one whose digest was approved, decrypted a
// secret at a time into the session's own directory, and gone once each
// app has its secret. One changed after the approval is refused.
func TestTheSecretsAreTheApprovedOnes(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	h.cfg.Apps["cloudflare"] = envelope.App{
		Routes: map[string]json.RawMessage{"trusted": json.RawMessage(`{"name": "cloudflare", "host": "api.cloudflare.com", "upstream": "https://api.cloudflare.com"}`)},
		Allow:  []string{"api.cloudflare.com"},
		Env:    map[string]string{"CLOUDFLARE_API_TOKEN": "proxy-injected"},
		EnvFromBinding: map[string]string{
			"CLOUDFLARE_ACCOUNT_ID": "accountId",
			"CLOUDFLARE_ZONE":       "zone",
		},
	}
	write(t, ws+"/secrets.json", `{"cloudflare-token": "the token"}`)
	h.fx.Run("-C", ws, "add", "secrets.json")
	env := `{"secrets": "secrets.json", "bindings": {"cloudflare": {"credential": {"secret": "cloudflare-token"}, "accountId": "it's 023e"}}}`
	h.launched(ws, "m1", "trusted", env)
	if !h.said("chase: " + ws + ": cloudflare from secrets.json:cloudflare-token") {
		t.Errorf("where cloudflare came from was not said: %s", h.err)
	}
	if got := read(t, h.dir+"/run/chase/m1/secrets/cloudflare"); got != "the token" {
		t.Errorf("the secret was not decrypted where frisket reads it: %q", got)
	}
	if fi, _ := os.Stat(h.dir + "/run/chase/m1/secrets/cloudflare"); fi.Mode().Perm() != 0o600 {
		t.Errorf("the secret is not the user's alone: %v", fi.Mode())
	}
	if left, _ := filepath.Glob(h.dir + "/run/chase/m1/sops.*"); len(left) != 0 {
		t.Errorf("the staged sops file outlived the launch: %v", left)
	}
	if log := h.log("sops.log"); len(log) != 1 || !strings.HasPrefix(log[0], `--decrypt --extract ["cloudflare-token"] `+h.dir+"/run/chase/m1/sops.") || !strings.HasSuffix(log[0], "/secrets.json") {
		t.Errorf("sops was not asked for the one secret: %q", log)
	}
	d := h.policyDoc("m1")
	if len(d.Routes) != 1 || d.Routes[0].CredentialFile != h.dir+"/run/chase/m1/secrets/cloudflare" || !slices.Equal(d.Allow, []string{"api.cloudflare.com"}) {
		t.Errorf("cloudflare's route was not bound with the project's secret: %+v", d)
	}
	if got := read(t, h.envfile(ws)); got != "export CLOUDFLARE_API_TOKEN='proxy-injected'\nexport CLOUDFLARE_ACCOUNT_ID='it'\\''s 023e'\n" {
		t.Errorf("the environment is not what the shell was given: %q", got)
	}

	// The staged copy, changed after its digest was approved.
	h.approved(ws, "m2", "trusted", env)
	p := h.dir + "/run/chase/.envelope/m2.json"
	var doc map[string]any
	json.Unmarshal([]byte(read(t, p)), &doc)
	doc["secrets"].(map[string]any)["text"] = `{"cloudflare-token": "another"}`
	b, _ := json.Marshal(doc)
	write(t, p, string(b))
	if h.run("launch", "trusted", ws, "m2") == 0 {
		t.Error("a changed sops file was launched")
	}
	if !h.said("chase: " + ws + ": the staged secrets.json is not the one approved") {
		t.Errorf("a changed sops file was not said: %s", h.err)
	}

	// A secret sops cannot give, and one it gives empty.
	h.approved(ws, "m3", "trusted", env)
	t.Setenv(sopsFails, "1")
	if h.run("launch", "trusted", ws, "m3") == 0 || !h.said("chase: "+ws+": could not decrypt 'cloudflare-token'") {
		t.Errorf("a secret sops could not decrypt: %s", h.err)
	}
	t.Setenv(sopsFails, "")
	write(t, ws+"/secrets.json", `{"cloudflare-token": ""}`)
	h.fx.Run("-C", ws, "add", "secrets.json")
	h.approved(ws, "m4", "trusted", env)
	if h.run("launch", "trusted", ws, "m4") == 0 || !h.said("chase: "+ws+": 'cloudflare-token' is empty") {
		t.Errorf("an empty secret: %s", h.err)
	}

	// A binding naming a secret, and no sops file.
	h.approved(ws, "m5", "trusted", `{"bindings": {"cloudflare": {"credential": {"secret": "cloudflare-token"}}}}`)
	if h.run("launch", "trusted", ws, "m5") == 0 || !h.said("chase: "+ws+": a binding names secret 'cloudflare-token', and chase.secrets names no file") {
		t.Errorf("a secret with no sops file: %s", h.err)
	}
}

// What the project names in an app's lists applies only to an app the tier
// has with a credential: to one it lacks, or has anonymously, they are said
// to be ignored.
func TestListsOfAnAppTheTierLacksOrHasAnonymouslyAreIgnored(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	write(t, h.cfg.Policies+"/trusted.json", `{"name": "trusted", "allow": ["github.com"], "routes": [{"name": "github", "host": "api.github.com", "upstream": "https://api.github.com"}]}`)
	h.launched(ws, "m1", "trusted", `{"bindings": {"github": {"allow": ["repos/delete"]}, "huggingface": {"ask": ["x"]}, "probe": {"x": 1}}}`)
	if !h.said("chase: " + ws + ": github's lists ignored: github is anonymous in trusted") {
		t.Errorf("an anonymous app's lists were not said to be ignored: %s", h.err)
	}
	if !h.said("chase: " + ws + ": huggingface's lists ignored: trusted has no huggingface") {
		t.Errorf("an absent app's lists were not said to be ignored: %s", h.err)
	}

	// An empty credentialFile is none: the route is written without one,
	// so it is anonymous in what frisket loads (a change from jq, whose
	// `.credentialFile` was true of "").
	write(t, h.cfg.Policies+"/trusted.json", `{"name": "trusted", "allow": ["github.com"], "routes": [{"name": "github", "host": "api.github.com", "upstream": "https://api.github.com", "credentialFile": ""}]}`)
	h.launched(ws, "m2", "trusted", `{"bindings": {"github": {"allow": ["repos/delete"]}}}`)
	if !h.said("chase: " + ws + ": github's lists ignored: github is anonymous in trusted") {
		t.Errorf("an empty credentialFile's lists were not said to be ignored: %s", h.err)
	}
}

// Two launches' envelopes, and each app's environment, one group of lines an
// app, as the script's exports were: an app with nothing to export is an
// empty line.
func TestTheEnvironmentIsAGroupOfLinesAnApp(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	h.cfg.Apps["docker"] = envelope.App{Credential: no(), Env: map[string]string{"A": "1"}}
	h.launched(ws, "m1", "trusted", `{"bindings": {"docker": {"images": ["postgres:18"]}, "probe": {"x": 1}}}`)
	if got := read(t, h.envfile(ws)); got != "export A='1'\nexport PROBE='1'\n" {
		t.Errorf("the env file is %q", got)
	}
	h.cfg.Apps["docker"] = envelope.App{Credential: no()}
	h.launched(ws, "m2", "trusted", `{"bindings": {"docker": {"images": ["postgres:18"]}, "probe": {"x": 1}}}`)
	if got := read(t, h.envfile(ws)); got != "\nexport PROBE='1'\n" {
		t.Errorf("the env file is %q", got)
	}
	env, err := envelope.Launch(context.Background(), h.cfg, h.registry, "trusted", ws, "m3", &strings.Builder{})
	if err == nil {
		t.Errorf("an unapproved launch gave %v", env)
	}
	h.approved(ws, "m3", "trusted", `{"bindings": {"probe": {"x": 1}}}`)
	env, err = envelope.Launch(context.Background(), h.cfg, h.registry, "trusted", ws, "m3", &strings.Builder{})
	if err != nil || len(env) != 1 || env[0] != (envelope.Var{Name: "PROBE", Value: "1"}) {
		t.Errorf("the launch's environment is %v: %v", env, err)
	}
}

// postStop: each app's Stop, while the session's directory is still there,
// and then the directory and anything staged for it, gone.
func TestTheSessionsEndStopsEachAppFirst(t *testing.T) {
	h, p, ws := newProjectLaunch(t)
	h.launched(ws, "m1", "trusted", `{"bindings": {"probe": {"x": 1}}}`)
	h.approved(ws, "m1", "trusted", `{"bindings": {"probe": {"x": 1}}}`)
	if rc := envelope.RunPostStop(context.Background(), h.cfg, h.registry, []string{"m1"}, nil, &strings.Builder{}, &strings.Builder{}); rc != 0 {
		t.Errorf("postStop failed: %d", rc)
	}
	if !slices.Equal(p.stopped, []string{"m1"}) || !slices.Equal(p.running, []bool{true}) {
		t.Errorf("probe was not stopped before its directory went: %v %v", p.stopped, p.running)
	}
	for _, gone := range []string{"/run/chase/m1", "/run/chase/.envelope/m1.json"} {
		if _, err := os.Lstat(h.dir + gone); err == nil {
			t.Errorf("%s outlived the session", gone)
		}
	}
}
