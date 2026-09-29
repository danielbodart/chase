package generate

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// What each piece of the jq program and of PyYAML did, held here by the
// answers jq 1.8 and PyYAML gave for the same input.

func TestSentence(t *testing.T) {
	for _, c := range []struct {
		in   string
		want any
	}{
		{"Hello. World", "Hello."},
		{"Hello.\u00a0World", "Hello."}, // Oniguruma's \s is Unicode's
		{"Hello.\vWorld", "Hello."},
		{"Hello.\u2028World", "Hello."},
		{"Hi\nThere. x", "Hi"},
		{"x.y. z", "x.y."},
		{"Hello.\nx", "Hello."},
		{"Hello.", "Hello."},
		{"What? Yes", "What?"},
		{"No end", "No end"},
		{"", nil}, // "" | split("\n") is [], and [][0] is null
	} {
		if got := sentence(c.in); got != c.want {
			t.Errorf("sentence(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestPathShapes(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/a/{b}", "/a"},
		{"/a/{b}\n", "/a\n"}, // jq's $ is before a final newline too
		{"/a/{b}/c", "/a/{b}/c"},
		{"/{}", ""},
		{"/a/x{b}", "/a/x{b}"},
	} {
		if got := withoutLastParam(c.in); got != c.want {
			t.Errorf("withoutLastParam(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"a\nwildcard path parameter", false},
		{"wildcard path parameter\n", true},
		{"wildcard path parameter\nx", false},
		{"WILDCARD path parameter", true},
	} {
		if got := wildcard(c.in); got != c.want {
			t.Errorf("wildcard(%q) = %v", c.in, got)
		}
	}
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"/a/\n", true}, {"/a/", true}, {"/", false}, {"//", true}, {"/a\n/", false},
		{"/a*", true}, {"a", true}, {"/a/b", false},
	} {
		if got := oddPath(c.in); got != c.want {
			t.Errorf("oddPath(%q) = %v", c.in, got)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"/v1/{a}/x", "/v1/*/x"}, {"/{scan_id}.png", "/*"}, {"", ""}, {"/", "/"},
	} {
		if got := template(c.in); got != c.want {
			t.Errorf("template(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := idFrom("GET", "/a/{b}/\u00e9 c//"); got != "get-a-b-c" {
		t.Errorf("idFrom = %q", got)
	}
	for _, c := range []struct {
		a      string
		aexact bool
		b      string
		bexact bool
		want   bool
	}{
		{"/api/v3/items", true, "/api/v3", false, true},
		{"/api/v3/items/*", true, "/api/v3/items", true, false},
		{"/api/models/*/revision/*", true, "/api/models/*/*/*", true, true},
		{"/a/b", true, "/a/b/c", false, false},
		{"/a/*", false, "/a/b/c", true, true},
		{"/a/x", false, "/a/y", false, false},
	} {
		if got := overlaps(c.a, c.aexact, c.b, c.bexact); got != c.want {
			t.Errorf("overlaps(%q, %v, %q, %v) = %v", c.a, c.aexact, c.b, c.bexact, got)
		}
	}
}

func TestCanonicalNumber(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"1", "1"}, {"1.0", "1.0"}, {"1e2", "1E+2"}, {"1.50", "1.50"}, {"-0", "-0"},
		{"100000000000000000000001", "100000000000000000000001"}, {"0.1e-5", "0.000001"},
		{"1E400", "1E+400"}, {"1.000000000000000000001", "1.000000000000000000001"},
		{"0.0", "0.0"}, {"12.5e3", "1.25E+4"}, {"0.0000001", "1E-7"}, {"-2.5E-3", "-0.0025"},
	} {
		if got := canonicalNumber(c.in); got != c.want {
			t.Errorf("canonicalNumber(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestToJSON(t *testing.T) {
	o := obj("b", Number("1"), "a", "\u007f\u2028<>&\u0001\u001f \u00e9\"\\\t", "c", []any{nil, true, Double(math.MaxFloat64), Double(math.NaN())})
	want := `{"b":1,"a":"\u007f` + "\u2028" + `<>&\u0001\u001f ` + "\u00e9" + `\"\\\t","c":[null,true,1.7976931348623157e+308,null]}`
	if got := toJSON(o); got != want {
		t.Fatalf("toJSON = %s\nwant    %s", got, want)
	}
}

func TestDuplicateKeys(t *testing.T) {
	for _, c := range []struct {
		in  string
		dup bool
	}{
		{`{"a": 1, "b": 2}`, false},
		{`{"a": 1, "a": 2}`, true},
		{`{"a": 1, "\u0061": 2}`, true}, // the same key, as jq reads it
		{`{"x": {"a": 1, "b": {"c": [{"d": 1, "d": 2}]}}}`, true},
		{`[{"a": 1}, {"a": 2}]`, false},
		{`{"a": {"a": 1}}`, false},
		{`{} {"a": 1, "a": 1}`, true},
		{``, false},
	} {
		_, dup, err := parseJSON([]byte(c.in))
		if err != nil || dup != c.dup {
			t.Errorf("parseJSON(%s): dup %v, %v", c.in, dup, err)
		}
	}
	// The last value, in the first place.
	values, _, _ := parseJSON([]byte(`{"a": 1, "b": 2, "a": 3}`))
	if got := toJSON(values[0]); got != `{"a":3,"b":2}` {
		t.Errorf("a key given twice is %s", got)
	}
	if _, _, err := parseJSON([]byte(`{"a": `)); err == nil {
		t.Error("a truncated object was read")
	}
}

// Whatever keys an object is written with, twice or not, the token reader
// says it gave one twice exactly where a map of what was read has fewer
// keys than were written.
func TestDuplicateKeysProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		keys := rapid.SliceOf(rapid.SampledFrom([]string{"a", "b", "c", "\u00e9"})).Draw(t, "keys")
		var b strings.Builder
		b.WriteString("{")
		seen := map[string]bool{}
		dup := false
		for i, k := range keys {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(toJSON(k) + ":" + toJSON(Number("1")))
			dup = dup || seen[k]
			seen[k] = true
		}
		b.WriteString("}")
		values, got, err := parseJSON([]byte(b.String()))
		if err != nil {
			t.Fatal(err)
		}
		if got != dup || values[0].(*Object).Len() != len(seen) {
			t.Fatalf("%s: dup %v, want %v", b.String(), got, dup)
		}
	})
}

func TestCompare(t *testing.T) {
	values, _, _ := parseJSON([]byte(`[3, "x", null, 1.5, {"b": 1}, false, true, [1], {"a": 2}, "X", 1e0]`))
	got := toJSON(sortBy(values[0].([]any), func(v any) any { return v }))
	if want := `[null,false,true,1,1.5,3,"X","x",[1],{"a":2},{"b":1}]`; got != want {
		t.Fatalf("sorted %s, want %s", got, want)
	}
	if got := toJSON(unique([]any{Number("1"), Number("1.0"), "a", "a"})); got != `[1,"a"]` {
		t.Errorf("unique %s", got)
	}
}

func TestPyRepr(t *testing.T) {
	for _, c := range []struct {
		in   float64
		want string
	}{
		{1e16, "1e+16"}, {1e15, "1000000000000000.0"}, {1e-5, "1e-05"}, {0.0001, "0.0001"},
		{100, "100.0"}, {1.5e20, "1.5e+20"}, {0, "0.0"}, {math.Copysign(0, -1), "-0.0"},
		{123456789012345678, "1.2345678901234568e+17"}, {1234.5, "1234.5"}, {-2.5, "-2.5"},
	} {
		if got := pyRepr(c.in); got != c.want {
			t.Errorf("pyRepr(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPyResolve(t *testing.T) {
	for in, want := range map[string]string{
		"yes": "bool", "on": "bool", "OFF": "bool", "y": "str", "1e5": "str", "1.0e5": "str",
		"1.0e+5": "float", "012": "int", "09": "str", "0x1F": "int", "1:30": "int", "~": "null",
		"": "null", "null": "null", "2001-12-14": "timestamp", "<<": "merge", "=": "value",
		".5": "float", "-.inf": "float", ".NaN": "float", "1_000": "int", "0b101": "int",
		"190:20:30.15": "float", "1.": "float", "+1": "int", "text": "str",
	} {
		if got := pyResolve(in); got != want {
			t.Errorf("pyResolve(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestReadYAML(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"{on: 1, 12: 2, 1.5: x, ~: 4, true: 6, 0x10: 7, 010: 8}", `{"true":6,"12":2,"1.5":"x","null":4,"16":7,"8":8}`},
		{"a: &a {x: 1, y: 1}\nb: {<<: *a, y: 2}", `{"a":{"x":1,"y":1},"b":{"x":1,"y":2}}`},
		{"p: &p {b: 1}\nq: &q {b: 2, c: 2}\nr:\n  <<: [*p, *q]\n  d: 3", `{"p":{"b":1},"q":{"b":2,"c":2},"r":{"b":1,"c":2,"d":3}}`},
		{"[yes, 'yes', 0o7, 012, 1_000, 1:30, 190:20:30.15, 1.0, 1e5, .inf, -.inf, !!str 5, !!int '12']",
			`[true,"yes","0o7",10,1000,90,685230.15,1.0,"1e5",1.7976931348623157e+308,-1.7976931348623157e+308,"5",12]`},
		{"", "null"},
		{"x: |\n  a\n  b\n", `{"x":"a\nb\n"}`},
	} {
		v, err := readYAML([]byte(c.in))
		if err != nil {
			t.Errorf("readYAML(%q): %v", c.in, err)
			continue
		}
		got := toJSON(v)
		if got != c.want {
			t.Errorf("readYAML(%q) = %s\nwant %s", c.in, got, c.want)
		}
	}
	for _, in := range []string{"t: 2001-12-14", "a: 1\n---\nb: 2", "? [a]\n: 1", "x: !!binary aGk=", "x: !custom 1", "a: &a [*a]"} {
		if _, err := readYAML([]byte(in)); err == nil {
			t.Errorf("readYAML(%q) read what JSON cannot hold", in)
		}
	}
}

func TestSchemaFields(t *testing.T) {
	sdl := `
schema { query: Query mutation: M }
type Query { "q" a: Int }
type M {
  """
    Create a thing.
    It is made.
  """
  createThing: Int @docsCategory(name: "things")
  # a comment between
  "Delete"
  deleteThing: Int @deprecated(reason: "Use removeThing.")
  ""
  empty: Int @deprecated(reason: "")
  none: Int @deprecated
}
extend type M { "Later" later: Int }
type Subscription { "Sub" sub: Int }
`
	fields, err := schemaFields(sdl)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fields {
		got = append(got, toJSON([]any{f.kind, f.name, f.description, f.category, f.deprecated}))
	}
	want := []string{
		`["mutation","createThing","Create a thing.\nIt is made.","things",null]`,
		`["mutation","deleteThing","Delete",null,"Use removeThing."]`,
		`["mutation","empty","",null,"Deprecated."]`,
		`["mutation","none",null,null,"Deprecated."]`,
		`["mutation","later","Later",null,null]`,
		`["subscription","sub","Sub",null,null]`,
		`["query","a","q",null,null]`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("fields:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, err := schemaFields("type M {"); err == nil {
		t.Fatal("a schema that is not GraphQL was read")
	}
}

func TestFetchRetries(t *testing.T) {
	old := firstDelay
	firstDelay = time.Millisecond
	t.Cleanup(func() { firstDelay = old })
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/flaky":
			if n.Add(1) < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte("spec"))
		case "/moved":
			http.Redirect(w, r, "/flaky", http.StatusFound)
		default:
			n.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "spec")
	if err := fetch(context.Background(), srv.Client(), srv.URL+"/moved", path); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "spec" || n.Load() != 3 {
		t.Fatalf("fetched %q after %d tries", data, n.Load())
	}
	n.Store(0)
	if err := fetch(context.Background(), srv.Client(), srv.URL+"/gone", path); err == nil || n.Load() != 1 {
		t.Fatalf("a 404 was retried or taken: %v after %d tries", err, n.Load())
	}
}

// A spec neither given nor vendored is fetched from the pinned URL, and
// read only once it hashes as pinned.
func TestOperationsFetchesThePin(t *testing.T) {
	spec := read(t, filepath.Join(repo, "tests", "operations", "legacy", "openapi.json"))
	served := spec
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(served)) }))
	defer srv.Close()
	f := fresh(t)
	f.app = "legacy"
	if err := os.Remove(f.path("openapi.json")); err != nil {
		t.Fatal(err)
	}
	f.edit("source.json", func(o *Object) { o.Set("url", srv.URL+"/openapi.json") })
	var stderr bytes.Buffer
	o := OperationsOptions{Apps: f.apps, Name: "legacy", Client: srv.Client(), Stderr: &stderr}
	if err := Operations(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(f.rules()) != 3 {
		t.Fatal("the fetched spec did not generate")
	}
	served = spec + " "
	err := Operations(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "is not the pinned spec") {
		t.Fatalf("a fetched spec that is not the pin was read: %v", err)
	}
}

func TestRunOperationsUsage(t *testing.T) {
	var stderr bytes.Buffer
	for _, args := range [][]string{nil, {"a", "b", "c"}} {
		var ee *ExitError
		if err := RunOperations(context.Background(), args, &stderr); !errors.As(err, &ee) || ee.Code != 2 || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("%q: %v", args, err)
		}
	}
	// Without -apps, the checkout's apps: this one's.
	var ee *ExitError
	err := RunOperations(context.Background(), []string{"no-such-app"}, &stderr)
	abs, _ := filepath.Abs(filepath.Join(repo, "apps", "no-such-app", "source.json"))
	if !errors.As(err, &ee) || ee.Code != 2 || err.Error() != "operations: "+abs+" does not exist" {
		t.Fatalf("%v", err)
	}
}

// What chase's own binary is built from reads neither YAML nor GraphQL:
// those are this dev-only command's alone.
func TestChaseDoesNotImportTheGenerator(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go binary to list chase's imports with")
	}
	out, err := exec.Command(gobin, "list", "-deps", "../../cmd/chase").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.Contains(dep, "yaml") || strings.Contains(dep, "gqlparser") || strings.HasSuffix(dep, "/internal/generate") {
			t.Errorf("cmd/chase imports %s", dep)
		}
	}
}
