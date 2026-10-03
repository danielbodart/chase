package grant_test

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
	appsssh "github.com/danielbodart/chase/internal/apps/ssh"
	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/session"
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

func no() *bool { f := false; return &f }

// newProjectLaunch is the project-launch check's system: example/shop pinned
// in trusted, which has no Docker, and probe an app with no credential, bound
// as cloudflare, a name a grant may bind.
func newProjectLaunch(t *testing.T) (*harness, *probe, string) {
	h := newHarness(t)
	r := h.root()
	h.cfg.Checkouts["example/shop"] = []string{r + "/p/shop"}
	h.cfg.Apps["docker"] = grant.App{Credential: no()}
	h.cfg.Apps["cloudflare"] = grant.App{Credential: no()}
	h.cfg.Apps["gcloud"] = grant.App{}
	p := &probe{runtime: h.cfg.Runtime}
	h.cfg.Docker = &docker.Config{Routes: map[string]policy.Route{}}
	h.registry = map[string]apps.App{"cloudflare": p}
	write(t, h.cfg.Policies+"/trusted.json", `{"name": "trusted", "allow": [], "routes": []}`)
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:example/shop.git")
	return h, p, ws
}

// The ported project-launch check: AN APP WITH NO CREDENTIAL (docs/docker.md),
// launched: its code is run from the binding alone, whenever the binding
// says anything, with nothing decrypted, and given the Docker project that
// approve staged -- never one derived again at launch, nor one the session
// has. An app with a credential is still bound only with one.
func TestAnAppWithNoCredentialIsMadeFromItsBinding(t *testing.T) {
	h, p, ws := newProjectLaunch(t)
	h.launched(ws, "m1", "trusted", `{"apps": {"docker": {"images": ["postgres:18"], "ports": [64320]}, "cloudflare": {"accountId": "11111111111111111111111111111111"}, "gcloud": {"serviceAccount": "a@p.iam.gserviceaccount.com"}}}`)
	if len(p.requests) != 1 {
		t.Fatalf("probe was prepared %d times", len(p.requests))
	}
	r := p.requests[0]
	if string(r.Binding) != `{"accountId":"11111111111111111111111111111111"}` {
		t.Errorf("prepare was not given the binding: %s", r.Binding)
	}
	if r.Project != "example/shop" {
		t.Errorf("prepare was not given the approved project: %q", r.Project)
	}
	if r.Tier != "trusted" || r.Workspace != ws || r.Run != h.dir+"/run/chase/m1" || r.Dir != h.dir+"/state/checkouts/"+key(ws) || r.Home != h.dir+"/home" {
		t.Errorf("prepare was not given the session: %+v", r)
	}
	d := h.policyDoc("m1")
	if !slices.Equal(d.Allow, []string{"probe.example"}) || len(d.Routes) != 0 {
		t.Errorf("probe's patch was not merged: %+v", d)
	}
	if env := h.env(); !slices.Equal(env, []string{"PROBE=1"}) {
		t.Errorf("probe's env, and nothing else, was not given the session: %q", env)
	}
	if strings.Contains(h.err, "cloudflare from") {
		t.Errorf("an app with no credential said where it came from: %s", h.err)
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
	h.launched(ws, "m2", "trusted", `{"apps": {"docker": {"images": ["postgres:18"], "ports": [64320]}}}`)
	if len(p.requests) != 1 {
		t.Error("probe was prepared with no binding")
	}
	if strings.Contains(h.err, "cloudflare from") {
		t.Errorf("probe was said with no binding: %s", h.err)
	}
	if d := h.policyDoc("m2"); len(d.Allow) != 0 {
		t.Errorf("probe's names were allowed with no binding: %q", d.Allow)
	}

	// Without Docker, there is no project to give, and it is empty.
	h.launched(ws, "m3", "trusted", `{"apps": {"cloudflare": {"accountId": "22222222222222222222222222222222"}}}`)
	if r := p.requests[len(p.requests)-1]; r.Project != "" || string(r.Binding) != `{"accountId":"22222222222222222222222222222222"}` {
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
	c.Apps = map[string]grant.App{"bad": {Credential: no()}, "fine": {}}
	err := grant.Validate(c, nil)
	if err == nil || err.Error() != "chase.internal.projectApps.bad has no credential and no prepare, so nothing could be made of what a grant says for it" {
		t.Errorf("an app with no credential and no prepare was built: %v", err)
	}
	if err := grant.Validate(c, map[string]apps.App{"bad": &probe{}}); err != nil {
		t.Errorf("an app with code was refused: %v", err)
	}

	h.cfg.Apps["huggingface"] = grant.App{Credential: no()}
	h.approved(ws, "m1", "trusted", `{"apps": {"huggingface": {"ask": ["x"]}}}`)
	if h.launch("trusted", ws, "m1") == 0 {
		t.Error("an app with no credential and no prepare was launched")
	}
	h.mustSay("chase: " + ws + ": huggingface has no credential and no prepare")
}

// Every path the script had spliced in is an absolute one: a tool named
// without a slash would be looked up on the caller's PATH, and a path left
// out would be "", which is read as the working directory.
// Empty is a default only where there is one, and no approver.
func TestAConfigsPathsAreAbsolute(t *testing.T) {
	h := newHarness(t)
	if err := grant.Validate(h.cfg, nil); err != nil {
		t.Fatalf("the harness's Config was refused: %v", err)
	}
	for _, c := range []struct {
		name string
		set  func(*grant.Config)
		want string
	}{
		{"sops", func(c *grant.Config) { c.Sops = "" }, `sops is "", which is not an absolute path`},
		{"diff", func(c *grant.Config) { c.Diff = "bin/diff" }, `diff is "bin/diff", which is not an absolute path`},
		{"policies", func(c *grant.Config) { c.Policies = "policies" }, `policies is "policies", which is not an absolute path`},
		{"home", func(c *grant.Config) { c.Home = "" }, `home is "", which is not an absolute path`},
		{"approver", func(c *grant.Config) { c.Approver = "approver" }, `approver is "approver", which is neither empty nor an absolute path`},
		{"state", func(c *grant.Config) { c.State = "state" }, `state is "state", which is neither empty nor an absolute path`},
	} {
		cfg := h.cfg
		c.set(&cfg)
		if err := grant.Validate(cfg, nil); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, not %s", c.name, err, c.want)
		}
		b, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		write(t, h.dir+"/config.json", string(b))
		if _, err := grant.LoadConfig(h.dir + "/config.json"); err == nil || err.Error() != c.want {
			t.Errorf("%s, loaded: %v, not %s", c.name, err, c.want)
		}
	}
	cfg := h.cfg
	cfg.Approver, cfg.State, cfg.Runtime = "", "", ""
	if err := grant.Validate(cfg, nil); err != nil {
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

// SSH, LAUNCHED (docs/apps/ssh.md): each machine a grant names is an SSH
// route in the session's document, logging in with the machine's
// credential and answering commands by the catalogue, the tier and the
// project's lists, which frisket loads. A tier without SSH says so and adds
// none; a grant frisket would refuse, or the catalogue, is refused before
// anyone is asked, and one naming an operation the catalogue has since
// lost ends the launch.
func TestSSHIsLaunchedAsTheGrantNamesIt(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/p/ops"
	h.repo(ws, "git@github.com:Example/Ops.git")
	h.cfg.Apps["ssh"] = grant.App{Credential: no()}
	h.cfg.SSH = &appsssh.Config{
		Tiers:     map[string]appsssh.Tier{"trusted": {Writes: "ask", Guarded: "refuse", Unmatched: "ask", Env: []string{"LANG", "LC_*"}}},
		Catalogue: "../../apps/ssh/operations.json",
		Agent:     "/run/user/1000/gcr/ssh",
	}
	for _, tier := range []string{"trusted", "plain"} {
		write(t, h.cfg.Policies+"/"+tier+".json", `{"name": "`+tier+`", "allow": ["github.com"], "routes": []}`)
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl server"
	// ops is server with members merged over its own, so that none is
	// named twice, which is refused before any rule of the machine's.
	ops := func(members string) string {
		h := map[string]any{"address": "192.168.1.10", "user": "ops", "hostKeys": []string{key}}
		if members != "" {
			if err := json.Unmarshal([]byte(members), &h); err != nil {
				t.Fatal(err)
			}
		}
		b, err := json.Marshal(map[string]any{"apps": map[string]any{"ssh": map[string]any{"hosts": map[string]any{"server": h}}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	h.launched(ws, "m1", "trusted", ops(`{"refuse": ["category:packages"]}`))
	d := h.policyDoc("m1")
	if len(d.SSH) != 1 {
		t.Fatalf("there is not one SSH route: %+v", d.SSH)
	}
	r := d.SSH[0]
	if r.Name != "server" || r.Address != "192.168.1.10" || r.User != "ops" || !slices.Equal(r.HostKeys, []string{key}) ||
		r.Agent != "/run/user/1000/gcr/ssh" || r.KeyFile != "" || r.Unmatched != "ask" || !slices.Equal(r.Env, []string{"LANG", "LC_*"}) {
		t.Errorf("the route is not the grant's and the machine's: %+v", r)
	}
	answers := map[string]string{}
	for _, e := range r.Exec {
		if e.Arg == "" {
			answers[e.Command] = map[bool]string{true: "ask", false: "allow"}[e.Ask]
			if e.Refuse {
				answers[e.Command] = "refuse"
			}
		}
	}
	for command, want := range map[string]string{"ls **": "allow", "apt list **": "refuse", "systemctl restart **": "ask", "rm **": "refuse"} {
		if answers[command] != want {
			t.Errorf("%s is %q, not %s", command, answers[command], want)
		}
	}
	if !slices.Equal(d.Allow, []string{"github.com"}) || len(d.Routes) != 0 || len(h.env()) != 0 {
		t.Errorf("SSH added more than its route: %+v %q", d, h.env())
	}
	frisketCheck(t, h.dir+"/run/chase/m1/policy.json")

	h.launched(ws, "m2", "plain", ops(""))
	if d := h.policyDoc("m2"); len(d.SSH) != 0 {
		t.Errorf("a tier without SSH has a route: %+v", d.SSH)
	}
	h.mustSay("chase: " + ws + ": ssh ignored: plain has no ssh")

	asked := len(h.approvals())
	if h.approve(ws, "m3", "trusted", ops(`{"address": "server.lan"}`)) == 0 {
		t.Error("a machine named by a name was approved")
	}
	h.mustSay("apps.ssh.hosts.server.address")
	h.mustSay("a literal IP")
	if len(h.approvals()) != asked {
		t.Error("a grant frisket would refuse was put to a person")
	}

	// An operation the catalogue does not have, or a pattern it overrules,
	// is refused before anyone is asked, as a launch would refuse it.
	for _, tc := range []struct{ grant, said string }{
		{`{"allow": ["restart-everything"]}`, `apps.ssh.hosts.server: "restart-everything" is no operation of the catalogue's`},
		{`{"allow": ["systemctl restart *"]}`, `is as literal as the catalogue's "systemctl restart **" (service-restart)`},
		// Nor does a grant name a catalogue: its machine is the Linux
		// catalogue's, whose secrets a device's would take off it.
		{`{"catalogue": "zyxel-vmg4005", "unmatched": "allow"}`, `unknown field "catalogue"`},
	} {
		if h.approve(ws, "m4", "trusted", ops(tc.grant)) == 0 {
			t.Errorf("%s was approved", tc.grant)
		}
		h.mustSay(tc.said)
		if len(h.approvals()) != asked {
			t.Errorf("%s was put to a person", tc.grant)
		}
	}
	// In a tier without SSH it says nothing of the catalogue's: its
	// launches add no route.
	h.approved(ws, "m5", "plain", ops(`{"allow": ["restart-everything"]}`))

	// A grant approved under a catalogue that had an operation still ends
	// the launch once the catalogue has it no longer.
	ops0, err := os.ReadFile(h.cfg.SSH.Catalogue)
	if err != nil {
		t.Fatal(err)
	}
	wider := filepath.Join(t.TempDir(), "operations.json")
	write(t, wider, strings.Replace(string(ops0), "[", `[{"id": "restart-everything", "summary": "Restart everything", "class": "guarded", "category": "services", "commands": ["restart-everything"]},`, 1))
	narrower := h.cfg.SSH.Catalogue
	h.cfg.SSH.Catalogue = wider
	h.approved(ws, "m6", "trusted", ops(`{"allow": ["restart-everything"]}`))
	h.cfg.SSH.Catalogue = narrower
	if h.launch("trusted", ws, "m6") == 0 {
		t.Error("an operation the catalogue no longer has was launched")
	}
	h.mustSay(`chase: ` + ws + `: ssh: apps.ssh.hosts.server: "restart-everything" is no operation of the catalogue's`)
	h.mustSay("chase: " + ws + ": ssh could not be prepared")
}

// A TIER'S OWN MACHINES, LAUNCHED: each is an SSH route in every session of
// the tier, a checkout with no grant too, logging in with its own
// credential, which is a path in the session's document -- frisket's to
// read, at login -- and nothing the session is given. A grant adds its own machines beside them, never one of
// the same name, which is refused before anyone is asked. A tier that takes
// no grant is launched for its machines alone, and its checkouts'
// chase.jsonc is never read.
func TestATiersOwnMachinesAreInEverySessionOfIt(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/p/ops"
	h.repo(ws, "git@github.com:Example/Ops.git")
	h.cfg.Apps["ssh"] = grant.App{Credential: no()}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl modem"
	modem := appsssh.TierHost{
		Host:         appsssh.Host{Address: "192.168.1.1", User: "admin", HostKeys: []string{key}, Shell: true},
		PasswordFile: "/run/secrets/modem-password",
	}
	answers := appsssh.Tier{Writes: "ask", Guarded: "refuse", Unmatched: "ask", Hosts: map[string]appsssh.TierHost{"modem": modem}}
	h.cfg.SSH = &appsssh.Config{
		Tiers:     map[string]appsssh.Tier{"ops": answers, "fixed": answers},
		Catalogue: "../../apps/ssh/operations.json",
	}
	h.cfg.Ungranted = []string{"fixed"}
	for _, tier := range []string{"ops", "fixed"} {
		write(t, h.cfg.Policies+"/"+tier+".json", `{"name": "`+tier+`", "allow": ["github.com"], "routes": []}`)
	}

	// No chase.jsonc: the tier as it is, with its machine.
	h.launched(ws, "m1", "ops", "")
	d := h.policyDoc("m1")
	if len(d.SSH) != 1 || d.SSH[0].Name != "modem" || d.SSH[0].PasswordFile != "/run/secrets/modem-password" || !d.SSH[0].Shell || d.SSH[0].Agent != "" {
		t.Fatalf("the tier's machine is not in the session's document: %+v", d.SSH)
	}
	if len(h.env()) != 0 || len(h.given.Files) != 0 {
		t.Errorf("the session was given something of the tier's machine: %q %+v", h.env(), h.given.Files)
	}
	frisketCheck(t, h.dir+"/run/chase/m1/policy.json")

	// A grant's machine beside it, with no credential of the machine's to
	// log in with, is refused at launch; one of the tier's name, before
	// anyone is asked.
	server := func(name, address string) string {
		return `{"apps": {"ssh": {"hosts": {"` + name + `": {"address": "` + address + `", "user": "ops", "hostKeys": ["` + strings.Replace(key, "modem", "server", 1) + `"]}}}}}`
	}
	asked := len(h.approvals())
	if h.approve(ws, "m2", "ops", server("modem", "192.168.1.10")) == 0 {
		t.Error("a grant naming the tier's machine was approved")
	}
	h.mustSay("apps.ssh.hosts.modem is the tier's own machine")
	if len(h.approvals()) != asked {
		t.Error("a grant naming the tier's machine was put to a person")
	}
	h.cfg.SSH.Agent = "/run/user/1000/gcr/ssh"
	h.launched(ws, "m3", "ops", server("server", "192.168.1.10"))
	if d := h.policyDoc("m3"); len(d.SSH) != 2 || d.SSH[0].Name != "modem" || d.SSH[1].Name != "server" || d.SSH[1].Agent != "/run/user/1000/gcr/ssh" {
		t.Errorf("not the tier's machine and the grant's: %+v", d.SSH)
	}

	// A tier taking no grant: its machine, and nothing of the chase.jsonc
	// the checkout now has.
	asked = len(h.approvals())
	h.launched(ws, "m4", "fixed", server("modem", "192.168.1.10"))
	if d := h.policyDoc("m4"); len(d.SSH) != 1 || d.SSH[0].Name != "modem" {
		t.Errorf("not the ungranted tier's machine alone: %+v", d.SSH)
	}
	if len(h.approvals()) != asked {
		t.Error("a tier taking no grant asked about one")
	}

	// A tier's machine frisket would not log in with ends every launch.
	bad := h.cfg.SSH.Tiers["ops"]
	bad.Hosts = map[string]appsssh.TierHost{"modem": {Host: modem.Host, PasswordFile: "/tmp/p"}}
	h.cfg.SSH.Tiers["ops"] = bad
	h.approved(ws, "m5", "ops", server("server", "192.168.1.10"))
	if h.launch("ops", ws, "m5") == 0 {
		t.Error("a tier's machine with a password under /tmp was launched")
	}
	h.mustSay("chase: " + ws + ": ssh: chase.tiers.ops.apps.ssh.hosts.modem.passwordFile")
}

// The ported docker-launch check, as far as the launch goes (the prepare's
// own refusals are internal/apps/docker's): DOCKER, LAUNCHED. A checkout
// whose grant binds Docker gets a route to the rootless daemon, as the
// project approve staged, and the variables that point the CLI at it. A
// checkout that binds nothing of Docker's gets no route, and a binding in a
// tier without Docker is said and adds nothing.
func TestDockerIsLaunchedAsTheApprovedProject(t *testing.T) {
	h := newHarness(t)
	r := h.root()
	h.cfg.Checkouts["example/shop"] = []string{r + "/p/shop"}
	h.cfg.DockerTiers = []string{"trusted"}
	h.cfg.Apps["docker"] = grant.App{Credential: no()}
	h.cfg.Docker = &docker.Config{Routes: map[string]policy.Route{"trusted": dockerTemplate(t)}}
	for _, tier := range []string{"trusted", "plain"} {
		write(t, h.cfg.Policies+"/"+tier+".json", `{"name": "`+tier+`", "allow": ["github.com"], "routes": []}`)
	}
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:Example/Shop.git")
	launched := func(tier, machine, env string) {
		t.Helper()
		h.approved(ws, machine, tier, env)
		if got := h.stagedProject(machine); got != "example/shop" {
			t.Errorf("approve did not stage the project: %v", got)
		}
		if h.launch(tier, ws, machine) != 0 {
			t.Fatalf("%s was not launched: %s", machine, h.err)
		}
	}
	shop := `{"apps": {"docker": {"images": ["postgres:18", "bitnami/redis:7", "ghcr.io/o/x:1"], "ports": [64320, 64321]}}}`

	launched("trusted", "m1", shop)
	if strings.Contains(h.err, "docker from") {
		t.Errorf("docker, with no credential, said where it came from: %s", h.err)
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
	if dr.Project != "example/shop" || dr.Address != "127.101.170.171" || !slices.Equal(dr.Names, []string{"shop.example.internal"}) ||
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
	env := h.env()
	for _, line := range []string{
		"DOCKER_HOST=tcp://docker.frisket.internal:2376",
		"DOCKER_TLS_VERIFY=1",
		"DOCKER_CERT_PATH=/etc/chase/docker",
		"CHASE_PROJECT=example/shop",
		"CHASE_PROJECT_ADDRESS=127.101.170.171",
		"CHASE_PROJECT_NAMES=shop.example.internal",
		"CHASE_DOCKER_PORTS=64320 64321",
	} {
		if !slices.Contains(env, line) {
			t.Errorf("the session's environment has no %s: %q", line, env)
		}
	}

	// Images alone, with no ports, still route.
	launched("trusted", "m2", `{"apps": {"docker": {"images": ["postgres:18"]}}}`)
	for _, rt := range h.policyDoc("m2").Routes {
		if rt.Name == "docker" && len(rt.Docker.Ports) != 0 {
			t.Errorf("no ports did not route with none: %v", rt.Docker.Ports)
		}
	}
	if !slices.Contains(h.env(), "CHASE_DOCKER_PORTS=") {
		t.Errorf("no ports was not said as none: %q", h.env())
	}
	frisketCheck(t, h.dir+"/run/chase/m2/policy.json")

	// Ports alone name nothing a container could run, so the launch ends
	// there rather than frisket refusing the document.
	h.approved(ws, "m3", "trusted", `{"apps": {"docker": {"ports": [64320]}}}`)
	if h.launch("trusted", ws, "m3") == 0 {
		t.Error("Docker with no images was launched")
	}
	h.mustSay("chase: " + ws + ": docker: no images")
	h.mustSay("chase: " + ws + ": docker could not be prepared")

	// NO BINDING, NO ROUTE, and nothing of Docker's in the session.
	h.approved(ws, "m4", "trusted", `{"apps": {"gcloud": {"serviceAccount": "a@p.iam.gserviceaccount.com"}}}`)
	if h.launch("trusted", ws, "m4") != 0 {
		t.Fatalf("m4 was not launched: %s", h.err)
	}
	if d := h.policyDoc("m4"); len(d.Routes) != 0 || !slices.Equal(d.Allow, []string{"github.com"}) {
		t.Errorf("a checkout with no binding got a route: %+v", d)
	}
	if env := strings.Join(h.env(), "\n"); strings.Contains(env, "DOCKER") {
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
	if env := strings.Join(h.env(), "\n"); strings.Contains(env, "DOCKER") {
		t.Errorf("a tier without Docker got Docker's variables: %q", env)
	}
}

// A launch consumes its stage: a second launch of the same approval, or one
// seccompPolicy never approved, is refused. An approval of the tier as it is
// still writes the session's document, the tier's own, where frisket's
// policyFile names it for every session, and gives the session nothing of
// its own.
func TestALaunchAppliesOneApprovalOnce(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	h.launched(ws, "m1", "trusted", `{"apps": {"cloudflare": {"accountId": "11111111111111111111111111111111"}}}`)
	if _, err := os.Stat(h.dir + "/run/chase/.grant/m1.json"); err == nil {
		t.Error("the stage outlived its launch")
	}
	if fi, err := os.Stat(h.dir + "/run/chase/m1"); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the session's directory is not the user's alone: %v", fi)
	}
	if h.launch("trusted", ws, "m9") == 0 {
		t.Error("a launch nothing approved was applied")
	}
	if h.err != "chase: "+ws+": nothing was approved for this launch: the tier's seccompPolicy did not run\n" {
		t.Errorf("an unapproved launch said: %q", h.err)
	}
	if _, err := os.Stat(h.dir + "/run/chase/m9"); err == nil {
		t.Error("a launch nothing approved made a session directory")
	}
	if fi, err := os.Stat(h.dir + "/run/chase/m1/policy.json"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the policy document is not the user's alone: %v", fi)
	}
	write(t, h.cfg.Policies+"/trusted.json", `{"name": "trusted", "allow": ["api.github.com"], "routes": [{"name": "github", "host": "api.github.com", "upstream": "https://api.github.com", "credentialFile": "/run/secrets/gh", "placeholder": "proxy-injected", "paths": [{"methods": ["GET"], "prefix": "/"}]}]}`)
	os.Remove(ws + "/chase.jsonc")
	h.approved(ws, "m2", "trusted", "")
	if got := read(t, h.dir+"/run/chase/.grant/m2.json"); got != "null\n" {
		t.Errorf("a checkout without chase.jsonc was staged as %q", got)
	}
	if h.launch("trusted", ws, "m2") != 0 {
		t.Fatalf("the tier as it is was not launched: %s", h.err)
	}
	if len(h.given.Env) != 0 || len(h.given.Files) != 0 {
		t.Errorf("the tier as it is gave the session %+v", h.given)
	}
	if h.err != "" {
		t.Errorf("the tier as it is said %q", h.err)
	}
	d := h.policyDoc("m2")
	if d.Name != "trusted" || !slices.Equal(d.Allow, []string{"api.github.com"}) || len(d.Routes) != 1 || d.Routes[0].CredentialFile != "/run/secrets/gh" {
		t.Errorf("the tier as it is was not given the tier's own document: %+v", d)
	}
	if left, _ := os.ReadDir(h.dir + "/run/chase/m2"); len(left) != 1 {
		t.Errorf("the tier as it is left more than its document: %v", left)
	}
	frisketCheck(t, h.dir+"/run/chase/m2/policy.json")

	// A tier with no document of its own is no launch at all.
	if err := os.Remove(h.cfg.Policies + "/trusted.json"); err != nil {
		t.Fatal(err)
	}
	h.approved(ws, "m3", "trusted", "")
	if h.launch("trusted", ws, "m3") == 0 {
		t.Error("a tier with no document was launched")
	}
}

// The sops file launched is the one whose digest was approved, decrypted a
// secret at a time into the session's own directory, and gone once each
// app has its secret. One changed after the approval is refused.
func TestTheSecretsAreTheApprovedOnes(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	// The real Cloudflare, with its credential, in probe's place.
	delete(h.registry, "cloudflare")
	h.cfg.Apps["cloudflare"] = grant.App{
		Routes: map[string]json.RawMessage{"trusted": json.RawMessage(`{"name": "cloudflare", "host": "api.cloudflare.com", "upstream": "https://api.cloudflare.com"}`)},
		Allow:  []string{"api.cloudflare.com"},
		Env:    map[string]string{"CLOUDFLARE_API_TOKEN": "proxy-injected"},
		EnvFromGrant: map[string]string{
			"CLOUDFLARE_ACCOUNT_ID": "accountId",
			"CLOUDFLARE_ZONE":       "zone",
		},
	}
	write(t, ws+"/secrets.json", `{"cloudflare-token": "the token"}`)
	h.fx.Run("-C", ws, "add", "secrets.json")
	env := `{"secrets": "secrets.json", "apps": {"cloudflare": {"credential": {"secret": "cloudflare-token"}, "accountId": "023e105f4ecef8ad9ca31a8372d0c353"}}}`
	h.launched(ws, "m1", "trusted", env)
	if !h.said("chase: cloudflare from secrets.json:cloudflare-token") {
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
	if got := h.env(); !slices.Equal(got, []string{"CLOUDFLARE_API_TOKEN=proxy-injected", "CLOUDFLARE_ACCOUNT_ID=023e105f4ecef8ad9ca31a8372d0c353"}) {
		t.Errorf("the session's environment is %q", got)
	}

	// The staged copy, changed after its digest was approved.
	h.approved(ws, "m2", "trusted", env)
	p := h.dir + "/run/chase/.grant/m2.json"
	var doc map[string]any
	json.Unmarshal([]byte(read(t, p)), &doc)
	doc["secrets"].(map[string]any)["text"] = `{"cloudflare-token": "another"}`
	b, _ := json.Marshal(doc)
	write(t, p, string(b))
	if h.launch("trusted", ws, "m2") == 0 {
		t.Error("a changed sops file was launched")
	}
	if !h.said("chase: " + ws + ": the staged secrets.json is not the one approved") {
		t.Errorf("a changed sops file was not said: %s", h.err)
	}

	// A secret sops cannot give, and one it gives empty.
	h.approved(ws, "m3", "trusted", env)
	t.Setenv(sopsFails, "1")
	if h.launch("trusted", ws, "m3") == 0 || !h.said("chase: "+ws+": could not decrypt 'cloudflare-token'") {
		t.Errorf("a secret sops could not decrypt: %s", h.err)
	}
	t.Setenv(sopsFails, "")
	write(t, ws+"/secrets.json", `{"cloudflare-token": ""}`)
	h.fx.Run("-C", ws, "add", "secrets.json")
	h.approved(ws, "m4", "trusted", env)
	if h.launch("trusted", ws, "m4") == 0 || !h.said("chase: "+ws+": 'cloudflare-token' is empty") {
		t.Errorf("an empty secret: %s", h.err)
	}

	// A binding naming a secret, and no sops file.
	h.approved(ws, "m5", "trusted", `{"apps": {"cloudflare": {"credential": {"secret": "cloudflare-token"}}}}`)
	if h.launch("trusted", ws, "m5") == 0 || !h.said("chase: "+ws+": an app names secret 'cloudflare-token', and the grant names no secrets file") {
		t.Errorf("a secret with no sops file: %s", h.err)
	}
}

// What the project names in an app's lists applies only to an app the tier
// has with a credential: to one it lacks, or has anonymously, they are said
// to be ignored.
func TestListsOfAnAppTheTierLacksOrHasAnonymouslyAreIgnored(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	write(t, h.cfg.Policies+"/trusted.json", `{"name": "trusted", "allow": ["github.com"], "routes": [{"name": "github", "host": "api.github.com", "upstream": "https://api.github.com"}]}`)
	h.launched(ws, "m1", "trusted", `{"apps": {"github": {"allow": ["repos/delete"]}, "huggingface": {"ask": ["x"]}, "cloudflare": {"accountId": "11111111111111111111111111111111"}}}`)
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
	h.launched(ws, "m2", "trusted", `{"apps": {"github": {"allow": ["repos/delete"]}}}`)
	if !h.said("chase: " + ws + ": github's lists ignored: github is anonymous in trusted") {
		t.Errorf("an empty credentialFile's lists were not said to be ignored: %s", h.err)
	}
}

// seeder is an app with no credential that seeds a file into the session's
// home, as Google Cloud seeds its key.
type seeder struct{}

func (seeder) Prepare(_ context.Context, r apps.Request) (apps.Patch, error) {
	f := session.File{Path: r.Home + "/.config/seeder/key", Mode: 0o600, Content: "for " + r.Workspace}
	return apps.Patch{Env: map[string]string{"SEEDER_KEY": f.Path}, Files: []session.File{f}}, nil
}

func (seeder) Stop(context.Context, string) error { return nil }

// The session's environment is each bound app's variables, the apps in the
// order of their names, and its files each app's own, handed back to the
// payload rather than written anywhere a session would read them. An app
// with nothing to give adds nothing.
func TestTheSessionIsGivenEachAppsVariablesAndFiles(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	h.cfg.Apps["docker"] = grant.App{Credential: no(), Env: map[string]string{"A": "1"}}
	h.cfg.Apps["gcloud"] = grant.App{Credential: no()}
	h.registry["gcloud"] = seeder{}
	h.launched(ws, "m1", "trusted", `{"apps": {"docker": {"images": ["postgres:18"]}, "cloudflare": {"accountId": "11111111111111111111111111111111"}, "gcloud": {"serviceAccount": "s@p.iam.gserviceaccount.com"}}}`)
	if got := h.env(); !slices.Equal(got, []string{"PROBE=1", "A=1", "SEEDER_KEY=" + h.dir + "/home/.config/seeder/key"}) {
		t.Errorf("the session's environment is %q", got)
	}
	if got := h.given.Files; len(got) != 1 || got[0] != (session.File{Path: h.dir + "/home/.config/seeder/key", Mode: 0o600, Content: "for " + ws}) {
		t.Errorf("the session's files are %+v", got)
	}
	h.cfg.Apps["docker"] = grant.App{Credential: no()}
	h.launched(ws, "m2", "trusted", `{"apps": {"docker": {"images": ["postgres:18"]}, "cloudflare": {"accountId": "11111111111111111111111111111111"}}}`)
	if got := h.env(); !slices.Equal(got, []string{"PROBE=1"}) {
		t.Errorf("the session's environment is %q", got)
	}
	if len(h.given.Files) != 0 {
		t.Errorf("an unbound app's files were given: %+v", h.given.Files)
	}
	for _, left := range []string{h.dir + "/state/env", h.dir + "/home/.config"} {
		if _, err := os.Stat(left); err == nil {
			t.Errorf("the launch wrote %s, which is the payload's to be given", left)
		}
	}
	given, err := grant.Launch(context.Background(), h.cfg, h.registry, "trusted", ws, "m3", &strings.Builder{})
	if err == nil {
		t.Errorf("an unapproved launch gave %v", given)
	}
	h.approved(ws, "m3", "trusted", `{"apps": {"cloudflare": {"accountId": "11111111111111111111111111111111"}}}`)
	given, err = grant.Launch(context.Background(), h.cfg, h.registry, "trusted", ws, "m3", &strings.Builder{})
	if err != nil || len(given.Env) != 1 || given.Env[0] != (session.Var{Name: "PROBE", Value: "1"}) {
		t.Errorf("the launch's environment is %v: %v", given, err)
	}
}

// postStop: each app's Stop, while the session's directory is still there,
// and then the directory and anything staged for it, gone.
func TestTheSessionsEndStopsEachAppFirst(t *testing.T) {
	h, p, ws := newProjectLaunch(t)
	h.launched(ws, "m1", "trusted", `{"apps": {"cloudflare": {"accountId": "11111111111111111111111111111111"}}}`)
	h.approved(ws, "m1", "trusted", `{"apps": {"cloudflare": {"accountId": "11111111111111111111111111111111"}}}`)
	if rc := grant.RunPostStop(context.Background(), h.cfg, h.registry, []string{"m1"}, nil, &strings.Builder{}, &strings.Builder{}); rc != 0 {
		t.Errorf("postStop failed: %d", rc)
	}
	if !slices.Equal(p.stopped, []string{"m1"}) || !slices.Equal(p.running, []bool{true}) {
		t.Errorf("probe was not stopped before its directory went: %v %v", p.stopped, p.running)
	}
	for _, gone := range []string{"/run/chase/m1", "/run/chase/.grant/m1.json"} {
		if _, err := os.Lstat(h.dir + gone); err == nil {
			t.Errorf("%s outlived the session", gone)
		}
	}
}
