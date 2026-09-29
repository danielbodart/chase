package generate

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The operations check, as flake.nix had it: THE GENERATOR ON A SWAGGER 2.0
// SPEC (docs/docker.md, decision 4), offline, on a small spec shaped like
// the Engine API's: its basePath, its own HEAD, its bodies walked into
// known.json, and an app admitted rather than classed. What would make it
// generate for a spec it was not pinned to is refused. Then an OpenAPI 3
// fixture, and then Docker's own, and every other app's: what the pinned
// spec generates must be what is committed, so the operations.json and
// known.json a person reviews are the spec's and admit.json's and nothing
// else.

// repo is the checkout this test is in.
var repo = filepath.Join("..", "..")

// fixture is a fresh copy of the apps the check works on: the two fixtures
// and Docker's own.
type fixture struct {
	t    *testing.T
	apps string
	app  string // the app the helpers below act on
}

func fresh(t *testing.T) *fixture {
	t.Helper()
	apps := filepath.Join(t.TempDir(), "apps")
	copyDir(t, filepath.Join(repo, "tests", "operations", "demo"), filepath.Join(apps, "demo"))
	copyDir(t, filepath.Join(repo, "tests", "operations", "legacy"), filepath.Join(apps, "legacy"))
	copyDir(t, filepath.Join(repo, "apps", "docker"), filepath.Join(apps, "docker"))
	return &fixture{t: t, apps: apps, app: "demo"}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			copyDir(t, filepath.Join(from, e.Name()), filepath.Join(to, e.Name()))
			continue
		}
		data, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) path(name string) string { return filepath.Join(f.apps, f.app, name) }

// generate runs the generator on the app, as the check's generate() did:
// its error, and what it said.
func (f *fixture) generate(spec ...string) (error, string) {
	var stderr bytes.Buffer
	o := OperationsOptions{Apps: f.apps, Name: f.app, Stderr: &stderr}
	if len(spec) > 0 {
		o.Spec = spec[0]
	}
	err := Operations(context.Background(), o)
	if err != nil {
		stderr.WriteString(err.Error() + "\n")
	}
	return err, stderr.String()
}

func (f *fixture) mustGenerate(why string) {
	f.t.Helper()
	if err, said := f.generate(); err != nil {
		f.t.Fatalf("%s: %s", why, said)
	}
}

// refuses is the check's refuses(): the generator fails, saying want.
func (f *fixture) refuses(why, want string) {
	f.t.Helper()
	err, said := f.generate()
	if err == nil {
		f.t.Fatalf("generated anyway: %s", why)
	}
	if !strings.Contains(said, want) {
		f.t.Fatalf("%s, refused otherwise: %s", why, said)
	}
}

func (f *fixture) read(name string) string {
	f.t.Helper()
	data, err := os.ReadFile(f.path(name))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

func (f *fixture) write(name, text string) {
	f.t.Helper()
	if err := os.WriteFile(f.path(name), []byte(text), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// sed replaces the first match of re in the file, as the check's sed did.
func (f *fixture) sed(name, re, with string, all bool) {
	f.t.Helper()
	text := f.read(name)
	r := regexp.MustCompile(re)
	var out string
	if all {
		out = r.ReplaceAllString(text, with)
	} else {
		done := false
		out = r.ReplaceAllStringFunc(text, func(m string) string {
			if done {
				return m
			}
			done = true
			return r.ReplaceAllString(m, with)
		})
	}
	if out == text {
		f.t.Fatalf("%s: %s matched nothing", name, re)
	}
	f.write(name, out)
}

// edit is the check's edit(): a change to one JSON file.
func (f *fixture) edit(name string, change func(o *Object)) {
	f.t.Helper()
	o := f.value(name).(*Object)
	change(o)
	f.write(name, toJSON(o)+"\n")
}

func (f *fixture) value(name string) any {
	f.t.Helper()
	values, _, err := parseJSON([]byte(f.read(name)))
	if err != nil || len(values) != 1 {
		f.t.Fatalf("%s: %v", name, err)
	}
	return values[0]
}

// repin is the check's repin(): source.json pins what the file now is.
func (f *fixture) repin(name string) {
	f.t.Helper()
	sum := sha256Hex([]byte(f.read(name)))
	f.edit("source.json", func(o *Object) { o.Set("sha256", sum) })
}

func (f *fixture) rules() []*Object {
	f.t.Helper()
	var out []*Object
	for _, r := range f.value("operations.json").([]any) {
		out = append(out, r.(*Object))
	}
	return out
}

// rule is the check's rule(): the rules with exactly these methods and this
// path.
func (f *fixture) rule(methods, path string) []*Object {
	f.t.Helper()
	var out []*Object
	for _, r := range f.rules() {
		if equal(get(r, "methods"), strs(strings.Split(methods, ","))) && equal(get(r, "path"), path) {
			out = append(out, r)
		}
	}
	return out
}

func (f *fixture) one(methods, path string) *Object {
	f.t.Helper()
	rs := f.rule(methods, path)
	if len(rs) != 1 {
		f.t.Fatalf("%d rules for %s %s, not one", len(rs), methods, path)
	}
	return rs[0]
}

func get(v any, path ...string) any {
	for _, p := range path {
		o, ok := v.(*Object)
		if !ok {
			return nil
		}
		v, _ = o.Get(p)
	}
	return v
}

func obj(pairs ...any) *Object {
	o := NewObject()
	for i := 0; i < len(pairs); i += 2 {
		o.Set(pairs[i].(string), pairs[i+1])
	}
	return o
}

func TestOperationsAdmittedSwagger(t *testing.T) {
	f := fresh(t)
	f.mustGenerate("the fixture did not generate")

	for _, r := range f.rules() {
		if strings.HasPrefix(get(r, "path").(string), "/v1.2") {
			t.Fatalf("the basePath was not stripped from the templates: %s", toJSON(r))
		}
	}
	if len(f.rule("GET", "/things/*/json")) == 0 {
		t.Fatal("the basePath was not stripped from the templates")
	}
	if r := f.one("HEAD", "/_ping"); get(r, "operation", "id") != "PingHead" || get(r, "refuse") != nil {
		t.Fatalf("an explicit HEAD is not its own rule: %s", toJSON(r))
	}
	if r := f.one("GET", "/_ping"); get(r, "operation", "id") != "Ping" || get(r, "refuse") != true {
		t.Fatalf("a GET beside an explicit HEAD took HEAD too: %s", toJSON(r))
	}
	if r := f.one("GET,HEAD", "/things/json"); get(r, "operation", "id") != "ThingList" {
		t.Fatal("a refused GET with no HEAD of its own does not refuse HEAD too")
	}
	if get(f.one("GET", "/version"), "docker", "owned") != "none" || len(f.rule("GET,HEAD", "/version")) != 0 {
		t.Fatal("an admitted operation does not have exactly the methods admit.json lists")
	}
	r := f.one("DELETE", "/things/*")
	if got := toJSON([]any{get(r, "refuse"), get(r, "operation", "id"), get(r, "operation", "summary"), get(r, "operation", "class"), get(r, "docker")}); got != `[true,"ThingDelete","Remove a thing","guarded",null]` {
		t.Fatalf("an operation admit.json does not name is not refused, with its operation: %s", toJSON(r))
	}
	for _, r := range f.rules() {
		_, idOK := get(r, "operation", "id").(string)
		_, summaryOK := get(r, "operation", "summary").(string)
		classOK := slices.Contains(classes, interp(get(r, "operation", "class")))
		if !idOK || !summaryOK || !classOK || (get(r, "refuse") == true) == (get(r, "docker") != nil) {
			t.Fatalf("a rule is neither refused nor admitted, or has no operation or class: %s", toJSON(r))
		}
	}
	if toJSON(get(f.one("POST", "/things/create"), "docker")) != toJSON(get(f.value("admit.json"), "ThingCreate", "docker")) {
		t.Fatal("an admitted operation does not carry its docker block")
	}

	// A body's fields: through #/parameters, $ref and allOf, and not into
	// an array, a map, or a scalar's allOf.
	want := `{"ThingCreate":["Name","Labels","Mounts","Kind","Health","Health.Test","Host","Host.Memory","Host.Binds"]}`
	if got := toJSON(f.value("known.json")); got != want {
		t.Fatalf("known.json is not the body's fields: %s", got)
	}
	if n := strings.Count(f.read("known.json"), "\n"); n != 13 {
		t.Fatalf("known.json is not one field per line: %d lines", n)
	}
	admitted := f.read("operations.json")

	// The format from the url, where source.json does not say it.
	f.edit("source.json", func(o *Object) { o.Delete("format") })
	f.mustGenerate("a .yaml url was not read as YAML")
	if f.read("operations.json") != admitted {
		t.Fatal("the format from the url generated something else")
	}
}

// Without admit.json, an app is classed, as every app before Docker is,
// with no exceptions.json and a HEAD where a GET has none of its own.
func TestOperationsClassedSwagger(t *testing.T) {
	f := fresh(t)
	if err := os.Remove(f.path("admit.json")); err != nil {
		t.Fatal(err)
	}
	f.mustGenerate("an app with no admit.json did not generate")
	for _, r := range f.rules() {
		if get(r, "refuse") != nil || get(r, "docker") != nil {
			t.Fatalf("an app that is not admitted refused: %s", toJSON(r))
		}
	}
	if get(f.one("GET,HEAD", "/version"), "operation", "class") != "read" {
		t.Fatal("a GET with no HEAD of its own does not take HEAD")
	}
	if get(f.one("GET", "/_ping"), "operation", "id") != "Ping" || get(f.one("HEAD", "/_ping"), "operation", "id") != "PingHead" {
		t.Fatal("a GET beside an explicit HEAD took HEAD too")
	}
	if _, err := os.Stat(f.path("known.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("known.json was written for an app that is not admitted")
	}
}

func TestOperationsRefuses(t *testing.T) {
	for _, c := range []struct {
		why, want string
		change    func(f *fixture)
	}{
		{"an admitted operation the spec does not have", `not in the pinned spec: ["NoSuchThing"]`, func(f *fixture) {
			f.edit("admit.json", func(o *Object) {
				o.Set("NoSuchThing", obj("methods", []any{"GET"}, "docker", obj("owned", "none")))
			})
		}},
		{"HEAD admitted as a GET's where the spec has its own", "admit.json gives Ping", func(f *fixture) {
			f.edit("admit.json", func(o *Object) {
				o.Set("Ping", obj("methods", []any{"GET", "HEAD"}, "docker", obj("owned", "none")))
			})
		}},
		{"an admitted operation with no methods", "needs its methods and a docker block", func(f *fixture) {
			f.edit("admit.json", func(o *Object) { o.Set("Version", obj("docker", obj("owned", "none"))) })
		}},
		// A key given twice is refused wherever a person writes it: jq
		// would keep the last, and a reviewer may read the first.
		{"an operation admitted twice, the later one winning", "admit.json gives a key twice", func(f *fixture) {
			f.sed("admit.json", `(?m)^}$`, ",\"Version\": {\"methods\": [\"GET\"], \"docker\": {\"owned\": \"list\", \"query\": {\"all\": \"any\"}}}\n}", true)
		}},
		{"a docker block that gives a field twice", "admit.json gives a key twice", func(f *fixture) {
			f.sed("admit.json", `"owned": "container", "param": 1`, `"owned": "container", "param": 1, "owned": "none"`, true)
		}},
		{"a pin that gives a field twice", "source.json gives a key twice", func(f *fixture) {
			f.sed("source.json", `\{`, `{"basePath": "/v1.3",`, false)
		}},
		{"a body table for an operation with no body", "the spec gives it 0 bodies", func(f *fixture) {
			f.edit("admit.json", func(o *Object) {
				get(o, "ThingInspect", "docker").(*Object).Set("body", "ThingInspect")
			})
		}},
		{"a pin whose version is not the top of the range", "info.version is 1.2, not 1.3", func(f *fixture) {
			f.edit("source.json", func(o *Object) { get(o, "apiVersions").(*Object).Set("max", "1.3") })
		}},
		{"a spec whose basePath is not the one pinned", "basePath is /v1.2, not /v1.3", func(f *fixture) {
			f.edit("source.json", func(o *Object) { o.Set("basePath", "/v1.3") })
		}},
		{"a format that is not what source.json pins", "format openapi3-yaml, but a swagger2 spec", func(f *fixture) {
			f.edit("source.json", func(o *Object) { o.Set("format", "openapi3-yaml") })
		}},
		{"a spec that does not hash as pinned", "is not the pinned spec", func(f *fixture) {
			f.edit("source.json", func(o *Object) { o.Set("sha256", strings.Repeat("0", 64)) })
		}},
		{"YAML changed after it was pinned", "is not the pinned spec", func(f *fixture) {
			f.write("spec.yaml", f.read("spec.yaml")+"x: 1\n")
		}},
		{"a basePath spec that is not Swagger 2.0", "swagger is 1.2, not 2.0", func(f *fixture) {
			f.sed("spec.yaml", `(?m)^swagger: "2.0"$`, `swagger: "1.2"`, true)
			f.repin("spec.yaml")
		}},
		// In an admitted app, admit.json is all that admits: nothing
		// exceptions.json could add would carry a docker block.
		{"a hand-written rule in an admitted app", "an admitted app takes no hand-written rules", func(f *fixture) {
			f.write("exceptions.json", `{"rules": [{"methods": ["POST"], "prefix": "/things/*", "reason": "x", "class": "write", "operation": {"id": "Hand", "summary": "hand"}}]}`+"\n")
		}},
		{"a GraphQL endpoint in an admitted app", "an admitted app takes no hand-written rules", func(f *fixture) {
			f.write("exceptions.json", `{"graphql": [{"path": "/graphql", "reason": "x", "operation": {"id": "Q", "summary": "q"}}]}`+"\n")
		}},
		{"a reclassification in an admitted app", "an admitted app takes no hand-written rules", func(f *fixture) {
			f.write("exceptions.json", `{"write": {"Ping": "x"}}`+"\n")
		}},
	} {
		t.Run(c.why, func(t *testing.T) {
			f := fresh(t)
			c.change(f)
			f.refuses(c.why, c.want)
		})
	}
}

// OpenAPI 3, as the apps before Docker are: its spec vendored as
// openapi.json and nowhere else (its url does not resolve), and its
// templates under the servers url's path, whatever scheme.
func TestOperationsOpenAPI3(t *testing.T) {
	f := fresh(t)
	f.app = "legacy"
	f.mustGenerate("the OpenAPI 3 fixture did not generate from openapi.json")
	r := f.one("GET,HEAD", "/api/v3/items")
	if get(r, "operation", "id") != "listItems" || get(r, "operation", "class") != "read" {
		t.Fatalf("an OpenAPI 3 GET is not [GET,HEAD] under the server's path: %s", f.read("operations.json"))
	}
	if get(f.one("POST", "/api/v3/items"), "operation", "class") != "write" || get(f.one("DELETE", "/api/v3/items/*"), "operation", "class") != "guarded" {
		t.Fatalf("an OpenAPI 3 operation is not under the server's path, as its class: %s", f.read("operations.json"))
	}
	rules := f.rules()
	if len(rules) != 3 {
		t.Fatalf("the OpenAPI 3 fixture generated other rules: %s", f.read("operations.json"))
	}
	for _, r := range rules {
		if get(r, "refuse") != nil || get(r, "docker") != nil {
			t.Fatalf("the OpenAPI 3 fixture generated other rules: %s", f.read("operations.json"))
		}
	}
	legacy := f.read("operations.json")

	f = fresh(t)
	f.app = "legacy"
	for _, name := range []string{"openapi.json", "source.json"} {
		f.sed(name, `https://api\.example\.invalid/api/v3`, "http://api.example.invalid/api/v3", true)
	}
	f.repin("openapi.json")
	f.mustGenerate("an http server did not generate")
	if f.read("operations.json") != legacy {
		t.Fatal("an http server's path was not stripped as an https one's")
	}

	f = fresh(t)
	f.app = "legacy"
	f.edit("source.json", func(o *Object) { o.Set("server", "https://api.example.invalid/api/v4") })
	f.refuses("a server that is not the spec's", `servers is ["https://api.example.invalid/api/v3"], not https://api.example.invalid/api/v4`)
}

// pinned is the spec an app's source.json pins, fetched; the test is
// skipped where it cannot be, as the check had it from a fixed-output
// fetch and a test here has only the network.
func pinned(t *testing.T, url, sum, name string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("fetches the pinned spec")
	}
	path := filepath.Join(t.TempDir(), name)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := fetch(ctx, &http.Client{Timeout: 3 * time.Minute}, url, path); err != nil {
		t.Skipf("the pinned spec could not be fetched, so is not compared: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256Hex(data); got != sum {
		t.Fatalf("%s is not what is pinned: %s", url, got)
	}
	return path
}

// pinOf is what the committed app's source.json pins.
func pinOf(t *testing.T, app string, path ...string) (url, sum string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, "apps", app, "source.json"))
	if err != nil {
		t.Fatal(err)
	}
	values, _, err := parseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	v := get(values[0], path...)
	return get(v, "url").(string), get(v, "sha256").(string)
}

// Docker, from the pinned Engine API spec: what is committed is what it
// generates, byte for byte.
func TestOperationsDocker(t *testing.T) {
	url, sum := pinOf(t, "docker")
	spec := pinned(t, url, sum, "swagger.yaml")
	f := fresh(t)
	f.app = "docker"
	if err, said := f.generate(spec); err != nil {
		t.Fatalf("Docker did not generate from its pinned spec: %s", said)
	}
	for _, name := range []string{"operations.json", "known.json"} {
		committed, err := os.ReadFile(filepath.Join(repo, "apps", "docker", name))
		if err != nil {
			t.Fatal(err)
		}
		if f.read(name) != string(committed) {
			t.Fatalf("apps/docker/%s is not what the pinned spec generates: run chase-generate operations docker", name)
		}
	}

	// Each admitted operation is one rule, with exactly the methods and
	// docker block admit.json gives it; every other operation is a refusal
	// that names what it refused.
	admit := f.value("admit.json").(*Object)
	var ids []string
	for _, r := range f.rules() {
		if get(r, "docker") == nil {
			id, ok := get(r, "operation", "id").(string)
			if get(r, "refuse") != true || !ok || id == "" {
				t.Fatalf("an operation admit.json does not name is not refused with its operation id: %s", toJSON(r))
			}
			continue
		}
		id := get(r, "operation", "id").(string)
		ids = append(ids, id)
		want, _ := admit.Get(id)
		if !equal(want, obj("methods", get(r, "methods"), "docker", get(r, "docker"))) {
			t.Fatalf("an operation admit.json names is not exactly one rule with its methods and docker block: %s", toJSON(r))
		}
	}
	slices.Sort(ids)
	if !slices.Equal(ids, admit.SortedKeys()) {
		t.Fatalf("an operation admit.json names is not exactly one rule: %v", ids)
	}
	if get(f.one("HEAD", "/_ping"), "operation", "id") != "SystemPingHead" || get(f.one("GET", "/_ping"), "operation", "id") != "SystemPing" {
		t.Fatal("/_ping is not a HEAD rule and a GET rule of their own")
	}
	n := 0
	for _, r := range f.rules() {
		if get(r, "path") == "/_ping" {
			n++
		}
		if strings.HasPrefix(interp(alt(get(r, "path"), get(r, "prefix"))), "/v1.") {
			t.Fatalf("a template still carries the API version: %s", toJSON(r))
		}
	}
	if n != 2 {
		t.Fatalf("/_ping is not a HEAD rule and a GET rule of their own: %d rules", n)
	}
	if got := f.value("known.json").(*Object).SortedKeys(); !slices.Equal(got, []string{"ContainerCreate", "ExecCreate", "ExecStart", "NetworkCreate", "VolumeCreate"}) {
		t.Fatalf("known.json does not hold exactly the admitted body tables: %v", got)
	}
}

// What was compared above is admit.json as parsed, which keeps the last of
// a repeated key: so, apart from the generator's own refusal, the text
// itself names each admitted operation once, and no pinned or admitted
// field twice.
func TestDockerAdmitNamesEachOnce(t *testing.T) {
	for _, name := range []string{"admit.json", "source.json"} {
		data, err := os.ReadFile(filepath.Join(repo, "apps", "docker", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, dup, err := parseJSON(data); err != nil || dup {
			t.Fatalf("apps/docker/%s gives a key twice in one object (%v)", name, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(repo, "apps", "docker", "admit.json"))
	if err != nil {
		t.Fatal(err)
	}
	lines := len(regexp.MustCompile(`(?m)^"[A-Za-z]+": `).FindAllString(string(data), -1))
	values, _, _ := parseJSON(data)
	keys := values[0].(*Object).Len()
	if lines != keys || keys != 31 {
		t.Fatalf("admit.json does not name 31 operations, each once on its own line: %d lines, %d keys", lines, keys)
	}
}

// Every other app, from its pinned spec -- vendored, or fetched -- and, for
// GitHub, its pinned GraphQL schema: what is committed is what it
// generates, byte for byte.
func TestOperationsCommitted(t *testing.T) {
	for _, app := range []string{"huggingface", "cloudflare", "github"} {
		t.Run(app, func(t *testing.T) {
			apps := filepath.Join(t.TempDir(), "apps")
			copyDir(t, filepath.Join(repo, "apps", app), filepath.Join(apps, app))
			var spec string
			if !isFile(filepath.Join(apps, app, "openapi.json")) {
				url, sum := pinOf(t, app)
				spec = pinned(t, url, sum, "openapi.json")
			}
			if src, _ := os.ReadFile(filepath.Join(apps, app, "source.json")); strings.Contains(string(src), `"graphql"`) {
				url, sum := pinOf(t, app, "graphql")
				schema := pinned(t, url, sum, "schema.graphql")
				data, err := os.ReadFile(schema)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(apps, app, "schema.graphql"), data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var stderr bytes.Buffer
			if err := Operations(context.Background(), OperationsOptions{Apps: apps, Name: app, Spec: spec, Stderr: &stderr}); err != nil {
				t.Fatalf("%s did not generate from its pinned spec: %v", app, err)
			}
			got, err := os.ReadFile(filepath.Join(apps, app, "operations.json"))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(repo, "apps", app, "operations.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("apps/%s/operations.json is not what the pinned spec generates: run chase-generate operations %s", app, app)
			}
			if !strings.HasPrefix(stderr.String(), "operations: "+app+": ") {
				t.Fatalf("no summary: %q", stderr.String())
			}
		})
	}
}
