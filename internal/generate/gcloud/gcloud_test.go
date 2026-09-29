package gcloud

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GOOGLE CLOUD'S GENERATOR (docs/gcloud.md, decision 8), run on a small API
// of each kind: Discovery and protos, a proto-only API, a mixin. Every way
// the classification can be wrong is refused. The flake's gcloud check,
// ported: tests/gcloud is its fixture.

var fixtureEntries = []string{"demo/v1/demo.proto", "other/v1/other.proto", "other/v1beta1/other.proto", "whole/v1/whole.proto", "google/longrunning/operations.proto"}

type fixture struct {
	t                  *testing.T
	dir, entries, desc string
}

// newFixture is tests/gcloud copied, its protos compiled by protoc as the
// check compiled them.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	need(t, "protoc")
	f := &fixture{t: t, dir: filepath.Join(t.TempDir(), "t")}
	copyTree(t, filepath.Join("..", "..", "..", "tests", "gcloud"), f.dir)
	tmp := t.TempDir()
	f.entries, f.desc = filepath.Join(tmp, "entries"), filepath.Join(tmp, "d.pb")
	if err := os.WriteFile(f.entries, []byte(strings.Join(fixtureEntries, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("protoc", append([]string{"-I", ".", "--include_imports", "--include_source_info", "--descriptor_set_out=" + f.desc}, fixtureEntries...)...)
	cmd.Dir = filepath.Join(f.dir, "googleapis")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("protoc: %v: %s", err, out)
	}
	return f
}

// generate is `gcloud.py generate app discoveries googleapis d.pb entries`,
// as the Tool: its status and what it said.
func (f *fixture) generate() (int, string) {
	var stdout, stderr bytes.Buffer
	code := Tool([]string{"generate", filepath.Join(f.dir, "app"), filepath.Join(f.dir, "discoveries"), filepath.Join(f.dir, "googleapis"), f.desc, f.entries}, &stdout, &stderr)
	return code, stdout.String() + stderr.String()
}

type jsonRule struct {
	Methods        []string          `json:"methods"`
	Path           *string           `json:"path"`
	Prefix         *string           `json:"prefix"`
	EncodedSlashes *bool             `json:"encodedSlashes"`
	Operation      map[string]string `json:"operation"`
}

func (f *fixture) apis(name string) []jsonRule {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "app", "apis", name+".json"))
	if err != nil {
		f.t.Fatal(err)
	}
	var rules []jsonRule
	if err := json.Unmarshal(b, &rules); err != nil {
		f.t.Fatal(err)
	}
	return rules
}

// rule is the check's rule(): every rule of api whose first method is m and
// whose path, or prefix, is p.
func (f *fixture) rule(api, m, p string) []jsonRule {
	var out []jsonRule
	for _, r := range f.apis(api) {
		tpl := r.Path
		if tpl == nil {
			tpl = r.Prefix
		}
		if len(r.Methods) > 0 && r.Methods[0] == m && tpl != nil && *tpl == p {
			out = append(out, r)
		}
	}
	return out
}

// field is `rule ... | jq -r .operation.FIELD`, one line a rule.
func (f *fixture) field(api, m, p, field string) string {
	var out []string
	for _, r := range f.rule(api, m, p) {
		out = append(out, r.Operation[field])
	}
	return strings.Join(out, "\n")
}

func (f *fixture) class(api, m, p string) string { return f.field(api, m, p, "class") }

func slashes(r jsonRule) string {
	if r.EncodedSlashes == nil {
		return "null"
	}
	if *r.EncodedSlashes {
		return "true"
	}
	return "false"
}

func TestGeneratesTheFixture(t *testing.T) {
	f := newFixture(t)
	if code, said := f.generate(); code != 0 {
		t.Fatalf("exit %d: %s", code, said)
	}
	for _, c := range []struct {
		api, method, path, want, why string
	}{
		{"demo", "GET", "/v1/projects/*/secrets/*/versions/*:access", "guarded", "an exception did not decide"},
		{"demo", "GET", "/v1/projects/*/secrets/*/versions/*", "read", "*:verb was not its own template"},
		{"demo", "POST", "/v1/projects/*/secrets/*:getIamPolicy", "read", "a pattern did not decide"},
		{"demo", "POST", "/v1/projects/*/secrets/*:setIamPolicy", "guarded", "setIamPolicy is not guarded"},
		{"demo", "DELETE", "/v1/projects/*/secrets/*", "guarded", "a DELETE is not guarded"},
		{"demo", "POST", "/batch", "guarded", "the batch path is not guarded"},
		{"demo", "POST", "/demo.v1.Secrets/AccessSecretVersion", "guarded", "gRPC was not classed as the REST it maps to"},
		{"demo", "POST", "/demo.v1.Secrets/DeleteThing", "guarded", "an RPC with no HTTP rule was not classed by its name"},
		{"demo", "POST", "/upload/v1/b/*/o", "write", "an upload's first request is not its method's class"},
		{"demo", "POST", "/resumable/upload/v1/b/*/o", "write", "an upload's first request is not its method's class"},
		{"demo", "PUT", "/resumable/upload/v1/b/*/o/*", "write", "a PUT method's own upload was taken for a continuation"},
		{"demo", "GET", "/download/v1/b/*/o/*", "read", "a download has no rule"},
		{"demo", "GET", "/v2/projects/*/secrets/*", "read", "a stable version that is not preferred was left out"},
		{"demo", "POST", "/v1/operations/*/*/*:cancel", "write", "a name of any depth before a verb is not every depth"},
		{"demo", "POST", "/v1/operations/*/*/*/*/*/*/*/*/*/*/*/*:cancel", "write", "a name of any depth before a verb is not every depth"},
		{"demo", "POST", "/v1/*:setIamPolicy", "guarded", "a name with nothing literal before a verb was taken for every path ending so"},
	} {
		if got := f.class(c.api, c.method, c.path); got != c.want {
			t.Errorf("%s: %s %s is %q, not %q", c.why, c.method, c.path, got, c.want)
		}
	}
	for _, c := range []struct {
		api, method, path, field, want, why string
	}{
		{"demo", "POST", "/demo.v1.Secrets/GetSecret", "summary", "Gets a Secret.", "a proto's own words were not used"},
		{"demo", "POST", "/google.longrunning.Operations/GetOperation", "category", "google.longrunning.Operations", "a mixin is not its own"},
		{"demo", "GET", "/v1/projects/*/locations/*/secrets/*", "id", "demo.v1.Secrets.GetSecret", "an HTTP rule Discovery lacks has no REST rule"},
		{"other", "GET", "/v1/things", "id", "other.v1.Things.ReadThing", "a proto-only API's ** is not a prefix"},
	} {
		if got := f.field(c.api, c.method, c.path, c.field); got != c.want {
			t.Errorf("%s: %s %s's %s is %q, not %q", c.why, c.method, c.path, c.field, got, c.want)
		}
	}
	one := func(api, m, p string) jsonRule {
		rs := f.rule(api, m, p)
		if len(rs) != 1 {
			t.Fatalf("%s %s: %d rules", m, p, len(rs))
		}
		return rs[0]
	}
	if got := slashes(one("demo", "GET", "/v1/b/*/o/*")); got != "true" {
		t.Errorf("an object's name cannot hold a slash: %s", got)
	}
	if got := slashes(one("demo", "GET", "/v1/projects/*/secrets/*")); got != "null" {
		t.Errorf("encodedSlashes where nothing said so: %s", got)
	}
	if r := one("demo", "PUT", "/upload/v1/b/*/o"); r.Operation["id"]+" "+r.Operation["class"] != "demo.objects.insert.continue read" {
		t.Errorf("a resumable upload's continuing PUT is not a read of its own: %v", r.Operation)
	}
	if r := one("demo", "PUT", "/upload/v1/b/*/o/*"); r.Operation["id"]+" "+r.Operation["class"] != "demo.objects.update write" {
		t.Errorf("a PUT method's own upload was taken for a continuation: %v", r.Operation)
	}
	if r := one("demo", "GET", "/v1/projects/*/files"); r.Prefix == nil || *r.Prefix+" "+slashes(r) != "/v1/projects/*/files true" {
		t.Errorf("a name of any depth at the end is not a prefix, or its flatPath's encodedSlashes were missed: %+v", r)
	}
	if rs := f.rule("demo", "POST", "/v1/*/*:setIamPolicy"); len(rs) != 0 {
		t.Errorf("a name with nothing literal before a verb was taken for every path ending so: %+v", rs)
	}
	whole := f.apis("whole")
	if len(whole) != 3 {
		t.Errorf("an API guarded whole has %d rules, not 3", len(whole))
	}
	for _, r := range whole {
		if r.Operation["class"] != "guarded" {
			t.Errorf("an API guarded whole has a rule that is not guarded: %+v", r)
		}
	}
	for _, api := range []string{"demo", "other"} {
		b, _ := os.ReadFile(filepath.Join(f.dir, "app", "apis", api+".json"))
		if bytes.Contains(b, []byte("v1beta1")) {
			t.Errorf("%s: a beta that is not preferred, or a proto-only API's older version, was generated", api)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "app", "apis", "gone.json")); err == nil {
		t.Error("an API with no document was generated")
	}
	var index map[string]struct {
		Hosts     []string `json:"hosts"`
		Streaming []string `json:"streaming"`
	}
	b, err := os.ReadFile(filepath.Join(f.dir, "app", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &index); err != nil {
		t.Fatal(err)
	}
	if d := index["demo"]; strings.Join(d.Streaming, ",") != "demo.v1.Secrets.StreamSecrets" ||
		strings.Join(d.Hosts, ",") != "demo.europe-west1.rep.googleapis.com,demo.googleapis.com" {
		t.Errorf("the index is wrong: %s", b)
	}
	files, _ := filepath.Glob(filepath.Join(f.dir, "app", "apis", "*.json"))
	for _, file := range files {
		frisketsShape(t, file)
	}
}

// frisketsShape fails for a rule with a key frisket's rule does not have, or
// an operation with a key frisket's operation does not have.
func frisketsShape(t *testing.T, file string) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(b, &rules); err != nil {
		t.Fatal(err)
	}
	ruleKeys := map[string]bool{"methods": true, "path": true, "prefix": true, "encodedSlashes": true, "operation": true}
	opKeys := map[string]bool{"id": true, "summary": true, "description": true, "class": true, "category": true}
	for _, r := range rules {
		for k := range r {
			if !ruleKeys[k] {
				t.Errorf("%s: a rule is not frisket's shape: %s", file, k)
			}
		}
		var op map[string]json.RawMessage
		json.Unmarshal(r["operation"], &op)
		for k := range op {
			if !opKeys[k] {
				t.Errorf("%s: an operation is not frisket's shape: %s", file, k)
			}
		}
	}
}

// edit is a jq edit of one of the fixture's JSON files: a path to set, or
// to delete where value is del.
type edit struct {
	path  []string
	value any
}

var del = &struct{}{}

func (f *fixture) edit(file string, e edit) {
	f.t.Helper()
	v, err := loadJSON(file)
	if err != nil {
		f.t.Fatal(err)
	}
	o := v.(*object)
	for _, k := range e.path[:len(e.path)-1] {
		next, ok := o.vals[k].(*object)
		if !ok {
			next = newObject()
			o.set(k, next)
		}
		o = next
	}
	last := e.path[len(e.path)-1]
	if e.value == del {
		delete(o.vals, last)
		for i, k := range o.keys {
			if k == last {
				o.keys = append(o.keys[:i], o.keys[i+1:]...)
				break
			}
		}
	} else {
		o.set(last, e.value)
	}
	if err := os.WriteFile(file, []byte(jqPretty(v)), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func TestRefusesEveryWayTheClassificationCanBeWrong(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		what   string
		file   string // under the fixture; app/exceptions.json when empty
		edit   edit
		needle string
	}{
		{"two classes on one template, across APIs", "", edit{[]string{"write", "demo.projects.secrets.get"}, "x"}, "one method and template, two classes"},
		{"another API's literal deciding a stricter operation", "", edit{[]string{"guarded", "demo.projects.secrets.get"}, "x"}, "is more specific than a stricter one"},
		{"an exception naming nothing", "", edit{[]string{"read", "demo.nothing"}, "x"}, "exceptions that name no operation"},
		{"an exception that changes nothing", "", edit{[]string{"guarded", "demo.projects.secrets.delete"}, "x"}, "the class it has anyway"},
		{"an exception without a reason", "", edit{[]string{"guarded", "demo.objects.insert"}, ""}, "needs a reason"},
		{"one name in two classes", "", edit{[]string{"read", "demo.projects.secrets.versions.access"}, "x"}, "in more than one class"},
		{"a pattern matching nothing", "", edit{[]string{"patterns", "nothing"}, func() any {
			o := newObject()
			o.set("class", "read")
			o.set("reason", "x")
			return o
		}()}, "patterns that match no operation"},
		{"encodedSlashes naming nothing", "", edit{[]string{"encodedSlashes", "demo", "nothing"}, "x"}, "encodedSlashes that name no parameter"},
		{"an API guarded whole that is not generated", "", edit{[]string{"apis", "nothing"}, "x"}, "APIs guarded whole that are not generated"},
		{"an API guarded whole without a reason", "", edit{[]string{"apis", "whole"}, ""}, "needs a reason"},
		{"batch without a reason", "", edit{[]string{"batch"}, del}, "batch has no reason"},
		{"resumable without a reason", "", edit{[]string{"resumable"}, del}, "resumable has no reason"},
		{"one operation, two classes", "discoveries/demo.v2.json", edit{[]string{"resources", "projects", "resources", "secrets", "methods", "get", "httpMethod"}, "DELETE"}, "one operation, two classes"},
		{"a path frisket could not match", "discoveries/demo.v2.json", edit{[]string{"resources", "projects", "resources", "secrets", "methods", "get", "flatPath"}, "v2/pro%20jects/{p}"}, "a path frisket could not match"},
		{"a version Discovery does not have", "app/source.json", edit{[]string{"discovery", "versions", "demo:v9"}, "x"}, "versions not in Discovery's index"},
		{"a version with no document", "app/source.json", edit{[]string{"discovery", "versions", "gone:v1"}, "x"}, "versions without a document"},
	} {
		t.Run(c.what, func(t *testing.T) {
			file := c.file
			if file == "" {
				file = "app/exceptions.json"
			}
			path := filepath.Join(f.dir, file)
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer os.WriteFile(path, saved, 0o644)
			f.edit(path, c.edit)
			code, said := f.generate()
			if code == 0 {
				t.Fatalf("%s was not refused", c.what)
			}
			if code != 1 || !strings.HasPrefix(said, "gcloud: ") {
				t.Errorf("%s: exit %d, not gcloud.py's 1: %s", c.what, code, said)
			}
			if !strings.Contains(said, c.needle) {
				t.Errorf("%s: expected %q in: %s", c.what, c.needle, said)
			}
		})
	}
}

// What returns or mints a credential is guarded, in the table as committed.
func TestTheCommittedTable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "apps", "gcloud", "apis")
	load := func(names ...string) []jsonRule {
		var out []jsonRule
		for _, n := range names {
			b, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				t.Fatal(err)
			}
			var rules []jsonRule
			if err := json.Unmarshal(b, &rules); err != nil {
				t.Fatalf("%s: %v", n, err)
			}
			out = append(out, rules...)
		}
		return out
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	all := load(names...)
	allOf := func(ids []string, class, why string) {
		t.Helper()
		want := map[string]bool{}
		for _, id := range ids {
			want[id] = true
		}
		found := map[string]bool{}
		for _, r := range all {
			if want[r.Operation["id"]] {
				found[r.Operation["id"]] = true
				if r.Operation["class"] != class {
					t.Errorf("%s: %s is %s", why, r.Operation["id"], r.Operation["class"])
				}
			}
		}
		if len(found) != len(want) {
			t.Errorf("%s: only %d of %d are in the table", why, len(found), len(want))
		}
	}
	allOf([]string{"apikeys.projects.locations.keys.create", "google.api.apikeys.v2.ApiKeys.CreateKey",
		"androidenterprise.enterprises.getServiceAccount", "androidenterprise.serviceaccountkeys.insert",
		"notebooks.projects.locations.runtimes.refreshRuntimeTokenInternal", "agentidentitycredentials.projects.locations.authProviders.credentials.retrieve",
		"redis.projects.locations.clusters.tokenAuthUsers.authTokens.get", "redis.projects.locations.clusters.tokenAuthUsers.authTokens.list",
		"google.cloud.alloydb.v1.AlloyDBAdmin.GenerateClientCertificate", "iap.setIamPolicy", "compute.instances.update"},
		"guarded", "the committed table does not guard what returns a credential")
	for _, r := range load("iamcredentials.json", "sts.json") {
		if r.Operation["class"] != "guarded" {
			t.Errorf("the committed table does not guard iamcredentials and sts whole: %s", r.Operation["id"])
		}
	}
	// The check's jq printed each matching rule's class, a line each, and
	// compared the whole with "guarded": exactly one rule, guarded.
	if certs := select_(load("alloydb.json"), func(r jsonRule) bool {
		return r.Path != nil && *r.Path == "/v1/projects/*/locations/*/clusters/*:generateClientCertificate"
	}); len(certs) != 1 || certs[0].Operation["class"] != "guarded" {
		t.Errorf("AlloyDB's REST GenerateClientCertificate is not one guarded rule: %d rules", len(certs))
	}

	// An upload's continuing PUT reads; its first request is decided as its
	// method.
	continuing := select_(all, func(r jsonRule) bool { return strings.HasSuffix(r.Operation["id"], ".continue") })
	if len(continuing) == 0 {
		t.Error("no upload has a continuing PUT")
	}
	for _, r := range continuing {
		if strings.Join(r.Methods, ",") != "PUT" || r.Operation["class"] != "read" {
			t.Errorf("an upload's continuing PUT is not a read: %+v", r)
		}
	}
	var storage []string
	for _, r := range select_(load("storage.json"), func(r jsonRule) bool { return r.Path != nil && *r.Path == "/upload/storage/v1/b/*/o" }) {
		storage = append(storage, r.Methods[0]+" "+r.Operation["id"]+" "+r.Operation["class"])
	}
	if got := strings.Join(storage, ", "); got != "POST storage.objects.insert write, PUT storage.objects.insert.continue read" {
		t.Errorf("storage's upload is not a write and its continuation a read: %s", got)
	}
	var youtube []string
	for _, r := range select_(load("youtube.json"), func(r jsonRule) bool {
		return r.Path != nil && *r.Path == "/upload/youtube/v3/captions" && strings.Join(r.Methods, ",") == "PUT"
	}) {
		youtube = append(youtube, r.Operation["id"]+" "+r.Operation["class"])
	}
	if got := strings.Join(youtube, "\n"); got != "youtube.captions.update write" {
		t.Errorf("a method's own PUT was taken for another's continuation: %s", got)
	}
	// A bucket's patch and update ask: they can set its ACLs, and a person
	// is asked.
	allOf([]string{"storage.buckets.patch", "storage.buckets.update", "google.storage.v2.Storage.UpdateBucket"},
		"write", "a bucket's patch or update is not a write")
}

func select_(rules []jsonRule, keep func(jsonRule) bool) []jsonRule {
	var out []jsonRule
	for _, r := range rules {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}
