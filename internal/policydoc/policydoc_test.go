package policydoc

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/frisket/policy"
)

// The tier the lists are applied in: GitHub's REST, git, and GitHub's
// GraphQL, with a guarded operation in each.
const tierDoc = `{"routes": [
  {"name": "github", "paths": [
    {"methods": ["POST"], "path": "/repos/*/*/pulls", "ask": true, "operation": {"id": "pulls/create", "summary": "s", "class": "write", "category": "pulls"}},
    {"methods": ["PUT"], "path": "/repos/*/*/pulls/*/merge", "ask": true, "operation": {"id": "pulls/merge", "summary": "s", "class": "write", "category": "pulls"}},
    {"methods": ["DELETE"], "path": "/repos/*/*/git/refs/*", "refuse": true, "operation": {"id": "git/delete-ref", "summary": "s", "class": "guarded", "category": "git"}}]},
  {"name": "git", "git": {"repos": ["*"], "push": "ask"}, "paths": []},
  {"name": "gh", "paths": [], "graphql": [{"path": "/graphql", "unmatched": "ask",
    "query": {"operation": {"id": "graphql-query", "summary": "s", "class": "read", "category": "graphql"}},
    "mutations": [
      {"field": "mergePullRequest", "ask": true, "operation": {"id": "mergePullRequest", "summary": "s", "class": "write", "category": "pulls"}},
      {"field": "closePullRequest", "ask": true, "operation": {"id": "closePullRequest", "summary": "s", "class": "write", "category": "pulls"}},
      {"field": "deleteIssue", "refuse": true, "operation": {"id": "deleteIssue", "summary": "s", "class": "guarded", "category": "issues"}}],
    "subscriptions": []}]}]}`

func tier(t fataler) *policy.Document {
	t.Helper()
	var doc policy.Document
	if err := policy.Decode([]byte(tierDoc), &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

func lists(t testing.TB, s string) Lists {
	t.Helper()
	var l Lists
	if err := json.Unmarshal([]byte(s), &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func apply(t testing.TB, app, l string) (*policy.Document, error) {
	t.Helper()
	doc := tier(t)
	err := Apply(doc, app, lists(t, l))
	return doc, err
}

func verdict(ask, refuse bool) string {
	switch {
	case refuse:
		return "refuse"
	case ask:
		return "ask"
	}
	return "allow"
}

// answerOf is what the rule for the operation id says, in whichever route has
// it.
func answerOf(doc *policy.Document, id string) string {
	for _, r := range doc.Routes {
		for _, p := range r.Paths {
			if p.Operation != nil && p.Operation.ID == id {
				return verdict(p.Ask, p.Refuse)
			}
		}
	}
	return ""
}

func field(doc *policy.Document, name string) string {
	for _, m := range doc.Routes[2].GraphQL[0].Mutations {
		if m.Field == name {
			return verdict(m.Ask, m.Refuse)
		}
	}
	return ""
}

// A PROJECT'S LISTS (PLAN.md, decision 18), as launch applies them to a
// policy document: a name before a category, a category before the tier,
// git's push by its operation, and a name the route does not have an error
// rather than a rule that decides nothing.
func TestANameDecidesBeforeItsCategoryAndACategoryBeforeTheTier(t *testing.T) {
	got, err := apply(t, "github", `{"allow": ["category:pulls"], "ask": ["git/delete-ref"], "refuse": ["pulls/merge"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if answerOf(got, "pulls/create") != "allow" {
		t.Error("a category did not decide")
	}
	if answerOf(got, "pulls/merge") != "refuse" {
		t.Error("a name did not decide before its category")
	}
	if answerOf(got, "git/delete-ref") != "ask" {
		t.Error("a guarded operation named could not be asked about")
	}
	got, err = apply(t, "github", `{"allow": ["category:git"]}`)
	if err != nil || answerOf(got, "git/delete-ref") != "allow" {
		t.Errorf("a category did not decide its guarded operation: %v", err)
	}
}

func TestAnEndpointTheDescriptionDoesNotNameIsAdded(t *testing.T) {
	got, err := apply(t, "github", `{"allow": [{"methods": ["POST"], "path": "/markdown/x"}], "ask": [], "refuse": []}`)
	if err != nil {
		t.Fatal(err)
	}
	paths := got.Routes[0].Paths
	if last := paths[len(paths)-1]; !reflect.DeepEqual(last, policy.PathRule{Methods: []string{"POST"}, Path: "/markdown/x"}) {
		t.Errorf("an endpoint the description does not name was not added: %+v", last)
	}
	// Asked and refused ones are added answered so, after the route's own,
	// in the order allow, ask, refuse.
	got, err = apply(t, "github", `{"refuse": [{"methods": ["GET"], "path": "/b"}], "ask": [{"methods": ["GET", "HEAD"], "path": "/a"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if tail := got.Routes[0].Paths[3:]; !reflect.DeepEqual(tail, []policy.PathRule{
		{Methods: []string{"GET", "HEAD"}, Path: "/a", Ask: true},
		{Methods: []string{"GET"}, Path: "/b", Refuse: true},
	}) {
		t.Errorf("%+v", tail)
	}
}

// A GraphQL mutation is named, and its category decided, as any operation
// is; and GraphQL's path is not a project's to name.
func TestAGraphQLOperationIsNamedAsAnyOperationIs(t *testing.T) {
	got, err := apply(t, "gh", `{"allow": ["category:pulls", "deleteIssue"], "ask": [], "refuse": ["mergePullRequest"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if field(got, "closePullRequest") != "allow" {
		t.Error("a GraphQL category did not decide")
	}
	if field(got, "mergePullRequest") != "refuse" {
		t.Error("a GraphQL mutation's name did not decide before its category")
	}
	if field(got, "deleteIssue") != "allow" {
		t.Error("a guarded GraphQL mutation named could not be allowed")
	}
	got, err = apply(t, "gh", `{"allow": [], "ask": [], "refuse": ["graphql-query"]}`)
	if err != nil || !got.Routes[2].GraphQL[0].Query.Refuse {
		t.Errorf("GraphQL's query was not decided by its name: %v", err)
	}
	if _, err := apply(t, "gh", `{"allow": [{"methods": ["POST"], "path": "/graphql"}]}`); err == nil || err.Error() != "gh describes these, so name them: POST /graphql is GraphQL's, by operation" {
		t.Errorf("GraphQL's path was allowed as an endpoint: %v", err)
	}
}

func TestGitsPushIsDecidedByItsOperation(t *testing.T) {
	got, err := apply(t, "git", `{"allow": ["git-receive-pack"], "ask": [], "refuse": []}`)
	if err != nil || got.Routes[1].Git.Push != "allow" {
		t.Errorf("git's push was not decided by its operation: %v", err)
	}
}

// A name, a category or an app that is not there is an error, never a rule
// that decides nothing; and a path an operation describes is that operation,
// and is named: a literal would otherwise outrank the guarded rule unnamed.
// Each error says what jq said.
func TestWhatIsNotThereOrIsDescribedIsAnError(t *testing.T) {
	for _, v := range []struct{ app, lists, err string }{
		{"github", `{"allow": ["pulls/nope"]}`, "github has no pulls/nope"},
		{"github", `{"allow": ["category:nope"]}`, "github has no category:nope"},
		{"github", `{"allow": ["category:nope", "zz", "pulls/nope"], "ask": ["category:aa"]}`, "github has no pulls/nope, zz, category:aa, category:nope"},
		{"cloudflare", `{"allow": ["x"]}`, "cloudflare is not in this tier"},
		{"github", `{"allow": [{"methods": ["DELETE"], "path": "/repos/me/app/git/refs/main"}]}`,
			"github describes these, so name them: DELETE /repos/me/app/git/refs/main is git/delete-ref"},
		{"github", `{"allow": [{"methods": ["DELETE"], "path": "/repos/me/app/git/refs/main"}, {"methods": ["GET","PUT"], "path": "/repos/a/b/pulls/1/merge"}], "refuse": [{"methods": ["DELETE"], "path": "/repos/me/app/git/refs/main"}]}`,
			"github describes these, so name them: DELETE /repos/me/app/git/refs/main is git/delete-ref; GET,PUT /repos/a/b/pulls/1/merge is pulls/merge"},
		// git has no operation of its own but its push.
		{"git", `{"allow": ["git/delete-ref"]}`, "git has no git/delete-ref"},
	} {
		doc := tier(t)
		err := Apply(doc, v.app, lists(t, v.lists))
		if err == nil || err.Error() != v.err {
			t.Errorf("%s %s: %v, want %q", v.app, v.lists, err, v.err)
		}
		if !reflect.DeepEqual(doc, tier(t)) {
			t.Errorf("%s %s: the document was changed", v.app, v.lists)
		}
	}
	// A path no operation's methods reach is not described.
	if _, err := apply(t, "github", `{"allow": [{"methods": ["GET"], "path": "/repos/me/app/git/refs/main"}]}`); err != nil {
		t.Errorf("a path of other methods was refused: %v", err)
	}
}

func TestOverlaps(t *testing.T) {
	for _, v := range []struct {
		path, rulePath, rulePrefix string
		want                       bool
	}{
		{"/a/b", "/a/b", "", true},
		{"/a/b", "/a/*", "", true},
		{"/a/*", "/a/b", "", true},
		{"/a/b", "/a", "", false},
		{"/a/b", "", "/a", true},
		{"/a/b", "", "/a/", true},
		{"/a", "", "/a/b", false},
		{"/x/b", "", "/a", false},
		{"/a/b", "", "/", true},
		{"/a//b", "/a/b", "", false},
	} {
		if got := overlaps(v.path, v.rulePath, v.rulePrefix); got != v.want {
			t.Errorf("%+v: %v", v, got)
		}
	}
}

func TestAnEntryIsANameOrAnEndpointAndNothingElse(t *testing.T) {
	l := lists(t, `{"allow": ["x", {"methods": ["GET"], "path": "/p"}]}`)
	if !reflect.DeepEqual(l.Allow, []Entry{{Name: "x"}, {Endpoint: &Endpoint{Methods: []string{"GET"}, Path: "/p"}}}) {
		t.Errorf("%+v", l)
	}
	if b, _ := json.Marshal(l.Allow); string(b) != `["x",{"methods":["GET"],"path":"/p"}]` {
		t.Errorf("%s", b)
	}
	for _, bad := range []string{`{"allow": [1]}`, `{"allow": [{"methods": ["GET"], "path": "/p", "x": 1}]}`, `{"allow": [null]}`} {
		var l Lists
		if err := json.Unmarshal([]byte(bad), &l); err == nil {
			t.Errorf("%s was read as %+v", bad, l)
		}
	}
}

// An app's routes replace any of the same names the tier had, after the
// tier's own, and the names it needs are added to the tier's, sorted and
// each once -- unless the tier allows every name. The shape of Google
// Cloud's patch, merged as gcloud-launch merged it.
func TestAnAppsRoutesAndNamesAreMerged(t *testing.T) {
	doc := &policy.Document{Name: "trusted", Policy: policy.Policy{Allow: []string{"github.com"}, Routes: []policy.Route{{Name: "gcloud", Host: "x"}}}}
	Merge(doc, apps.Patch{
		Routes: []policy.Route{{Name: "gcloud", Host: "*.googleapis.com"}, {Name: "gcloud-mtls", Host: "*.mtls.googleapis.com"}},
		Allow:  []string{"*.googleapis.com"},
		Env:    map[string]string{"X": "y"},
	})
	var names []string
	for _, r := range doc.Routes {
		names = append(names, r.Name)
	}
	if !slices.Equal(doc.Allow, []string{"*.googleapis.com", "github.com"}) || !slices.Equal(names, []string{"gcloud", "gcloud-mtls"}) || doc.Routes[0].Host != "*.googleapis.com" {
		t.Errorf("the routes were not merged: %+v", doc)
	}

	doc = &policy.Document{Name: "t", Policy: policy.Policy{Allow: []string{"b", "*", "a"}, Routes: []policy.Route{{Name: "one"}, {Name: "two"}, {Name: "three"}}}}
	Merge(doc, apps.Patch{Routes: []policy.Route{{Name: "two", Host: "new"}}, Allow: []string{"c"}})
	if !slices.Equal(doc.Allow, []string{"b", "*", "a"}) {
		t.Errorf("a tier that allows every name was added to: %q", doc.Allow)
	}
	if b, _ := json.Marshal(doc.Routes); string(b) != `[{"name":"one","host":"","upstream":""},{"name":"three","host":"","upstream":""},{"name":"two","host":"new","upstream":""}]` {
		t.Errorf("%s", b)
	}

	// A tier with nothing allowed, and an app that needs no name, has an
	// allowlist of none, not null.
	doc = &policy.Document{Name: "closed"}
	Merge(doc, apps.Patch{})
	if b, _ := json.Marshal(doc); string(b) != `{"name":"closed","allow":[]}` {
		t.Errorf("%s", b)
	}
	doc = &policy.Document{Name: "t", Policy: policy.Policy{Allow: []string{"b", "a", "b"}}}
	Merge(doc, apps.Patch{Allow: []string{"a", "c"}})
	if !slices.Equal(doc.Allow, []string{"a", "b", "c"}) {
		t.Errorf("%q", doc.Allow)
	}
}

func normal(t *testing.T, s string) string {
	t.Helper()
	b, err := Normal([]byte(s))
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return string(b)
}

// sorted is s as jq -cS writes it, which the check compared by.
func sorted(t *testing.T, s string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// An envelope approved before its apps' empty fields were left out reads
// as the same envelope now.
func TestAnEnvelopeApprovedBeforeReadsAsTheSame(t *testing.T) {
	old := `{"secrets": "s.yaml", "seccomp": {"allow": [], "deny": []}, "bindings": {"github": {"allow": ["x"], "ask": [], "refuse": []}, "cloudflare": {"allow": [], "credential": {"secret": null}, "accountId": null}}}`
	now := `{"secrets": "s.yaml", "bindings": {"github": {"allow": ["x"]}}}`
	if a, b := sorted(t, normal(t, old)), sorted(t, normal(t, now)); a != b {
		t.Errorf("an envelope approved before reads as another: %s", a)
	}
	if got := normal(t, `{"secrets": "s.yaml"}`); got != `{"secrets":"s.yaml"}` {
		t.Errorf("an envelope without bindings was changed: %s", got)
	}
	// Docker's binding is new: an envelope that names no image and no port
	// reads as one approved before there was a binding to name.
	old = `{"secrets": "s.yaml", "bindings": {"github": {"allow": ["x"]}}}`
	now = `{"secrets": "s.yaml", "bindings": {"github": {"allow": ["x"]}, "docker": {"images": [], "ports": []}}}`
	if a, b := sorted(t, normal(t, old)), sorted(t, normal(t, now)); a != b {
		t.Errorf("an envelope without Docker reads as another: %s", b)
	}
	if got := normal(t, `{"bindings": {"docker": {"images": ["postgres:18"], "ports": []}}}`); got != `{"bindings":{"docker":{"images":["postgres:18"]}}}` {
		t.Errorf("an envelope's Docker images were not kept: %s", got)
	}
	if got := normal(t, `{"bindings": {"docker": {"images": [], "ports": [5432]}}}`); got != `{"bindings":{"docker":{"ports":[5432]}}}` {
		t.Errorf("an envelope's Docker ports were not kept: %s", got)
	}
}

// What jq wrote, byte for byte, for what it was given: keys where they
// were, numbers as decNumber writes them, strings as jq escapes them, and
// what is not null, [] or {} kept, false, 0 and "" too.
func TestAnEnvelopeIsWrittenAsJqWroteIt(t *testing.T) {
	for in, want := range map[string]string{
		`null`: `null`,
		`{"bindings":{"x":{"a":[{}],"b":false,"c":0,"d":"","e":{"f":[]}}},"seccomp":{"deny":[],"allow":[]}}`: `{"bindings":{"x":{"a":[{}],"b":false,"c":0,"d":""}}}`,
		`{"bindings":false}`:                       `{"bindings":false}`,
		`{"bindings":[{}]}`:                        `{"bindings":[{}]}`,
		`{"bindings":"x"}`:                         `{"bindings":"x"}`,
		`{"bindings":null}`:                        `{"bindings":null}`,
		`{"seccomp":{"allow":[],"deny":[],"x":1}}`: `{"seccomp":{"allow":[],"deny":[],"x":1}}`,
		`{"seccomp":{"allow":[],"deny":["a"]}}`:    `{"seccomp":{"allow":[],"deny":["a"]}}`,
		`{"a":1,"a":2}`:                            `{"a":2}`,
		`{"z":1,"a":{"y":2,"b":3}}`:                `{"z":1,"a":{"y":2,"b":3}}`,
		`{"bindings":{"x":{"p":[1e2,0.10],"q":1.50e1,"r":{"s":null,"t":0.0000001,"u":-0.0,"v":0e5,"w":123e-2}}},"seccomp":{"allow":["a"],"deny":[]},"z":0.000001}`:                              `{"bindings":{"x":{"p":[1E+2,0.10],"q":15.0,"r":{"t":1E-7,"u":-0.0,"v":0E+5,"w":1.23}}},"seccomp":{"allow":["a"],"deny":[]},"z":0.000001}`,
		`{"a":[1.0,1e2,-0,1.50,1E+2,0.1,100000000000000000000001,1.7976931348623157e309,-1e-400,12345678901234567890,1.25e-7,"\u001b\u007f\u0080/<>&é\u2028\ud83d\ude00\t\"\\\b\f\r\n\u0001"]}`: "{\"a\":[1.0,1E+2,-0,1.50,1E+2,0.1,100000000000000000000001,1.7976931348623157E+309,-1E-400,12345678901234567890,1.25E-7,\"\\u001b\\u007f\u0080/<>&é\u2028😀\\t\\\"\\\\\\b\\f\\r\\n\\u0001\"]}",
	} {
		if got := normal(t, in); got != want {
			t.Errorf("%s:\n got %s\nwant %s", in, got, want)
		}
	}
	for in, want := range map[string]string{
		`[]`:  `Cannot index array with string ("seccomp")`,
		`"s"`: `Cannot index string with string ("seccomp")`,
		`1`:   `Cannot index number with string ("seccomp")`,
	} {
		if _, err := Normal([]byte(in)); err == nil || err.Error() != want {
			t.Errorf("%s: %v", in, err)
		}
	}
	for _, bad := range []string{``, `{`, `{} {}`} {
		if got, err := Normal([]byte(bad)); err == nil {
			t.Errorf("%q was read as %s", bad, got)
		}
	}
}

// fataler is a *testing.T or a *rapid.T.
type fataler interface {
	Helper()
	Fatal(args ...any)
}
