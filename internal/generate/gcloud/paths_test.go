package gcloud

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Each case's want is what gcloud.py's own function returned for it: the
// port reads a description, a path and a version as Python did.

func TestSentence(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Gets a secret.\n\nMetadata only.", "Gets a secret."},
		{"  Ends here.\u001cNext\nline", "Ends here."},
		{"No end", "No end"},
		{"e.g. this. That", "e.g."},
		{"What? Yes", "What?"},
		{"a.b.c d", "a.b.c d"},
		{"", ""},
		{"   ", ""},
		{"x.\u00a0y", "x."},
		{"x.\u000by", "x."},
		{"Done!", "Done!"},
	} {
		if got := sentence(c.in); got != c.want {
			t.Errorf("sentence(%q) = %q, not %q", c.in, got, c.want)
		}
	}
}

func TestWords(t *testing.T) {
	for _, c := range []struct{ id, text, summary, description string }{
		{"id", "", "id", ""},
		{"id", "Gets a Secret.", "Gets a Secret.", ""},
		{"id", "Gets.\nMore", "Gets.", "Gets.\nMore"},
		{"id", "  x  ", "x", ""},
	} {
		s, d := words(c.id, c.text)
		if s != c.summary || d != c.description {
			t.Errorf("words(%q, %q) = %q, %q", c.id, c.text, s, d)
		}
	}
}

func TestTemplate(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"v1/{+name}", "/v1/*"},
		{"/v1/projects/{projectsId}/secrets/{secretsId}:access", "/v1/projects/*/secrets/*:access"},
		{"v1/{a}{b}", "/v1/*"},
		{"v1/{a}:9x", "/v1/*"},
		{"v1/x{a}", "/v1/*"},
		{"//v1//x/", "/v1//x"},
		{"v1/{a}:getIamPolicy", "/v1/*:getIamPolicy"},
	} {
		if got := template(c.in); got != c.want {
			t.Errorf("template(%q) = %q, not %q", c.in, got, c.want)
		}
	}
}

func TestProtoTemplate(t *testing.T) {
	for _, c := range []struct {
		in, want   string
		prefix, ok bool
	}{
		{"/v1/{name=projects/*/secrets/*}", "/v1/projects/*/secrets/*", false, true},
		{"/v1/{name=things/**}", "/v1/things", true, true},
		{"/v1/{name=things/**}:x", "", false, false},
		{"/v1/**/x", "", false, false},
		{"/v1/{a}", "/v1/*", false, true},
		{"/v1/a*b", "", false, false},
		{"/v1/{name=projects/*}:cancel", "/v1/projects/*:cancel", false, true},
		{"/**", "/", true, true},
		{"/v1/{x=**}", "/v1", true, true},
		{"/v1/{parent=projects/*}/things", "/v1/projects/*/things", false, true},
		{"/v1/a:b:c", "/v1/a:b:c", false, true},
	} {
		got, prefix, ok := protoTemplate(c.in)
		if got != c.want || prefix != c.prefix || ok != c.ok {
			t.Errorf("protoTemplate(%q) = %q %v %v", c.in, got, prefix, ok)
		}
	}
}

func TestVersionRank(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string // stability,major,minor as Python's tuple, or "" for None
	}{
		{"v1", "2,1,0"}, {"v1beta1", "1,1,1"}, {"v2alpha", "0,2,0"}, {"v1p1beta1", "1,1,1"},
		{"v10", "2,10,0"}, {"v0", "2,0,0"}, {"v1p", ""}, {"v1x", ""}, {"V1", ""}, {"v", ""},
		{"v1beta", "1,1,0"}, {"v007", "2,7,0"}, {"v1alpha2", "0,1,2"}, {"v\u0661", "2,1,0"},
		{"v99999999999999999999999", "2,99999999999999999999999,0"}, {"v1p2", "2,1,0"}, {"v1beta1x", ""},
	} {
		r := versionRank(c.in)
		got := ""
		if r.ok {
			n := func(s string) string {
				if s == "" {
					return "0"
				}
				return s
			}
			got = fmt.Sprintf("%d,%s,%s", r.stability, n(r.major), n(r.minor))
		}
		if got != c.want {
			t.Errorf("versionRank(%q) = %q, not %q", c.in, got, c.want)
		}
	}
	order := []string{"", "v1alpha", "v2alpha1", "v1beta", "v1beta2", "v1", "v1p5", "v2", "v10", "v99999999999999999999999"}
	for i := range order {
		for j := range order {
			a, b := versionRank(order[i]), versionRank(order[j])
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			// v1 and v1p5 are one rank: the p part is not compared.
			if (order[i] == "v1" && order[j] == "v1p5") || (order[i] == "v1p5" && order[j] == "v1") {
				want = 0
			}
			if got := a.compare(b); got != want {
				t.Errorf("%q against %q: %d, not %d", order[i], order[j], got, want)
			}
		}
	}
}

func TestHostOf(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://demo.googleapis.com/", "demo.googleapis.com"},
		{"https://x.com", "x.com"},
		{"http://x.com/a", "http:"},
		{"/abs", ""},
		{"https://a/b\nc/d", "a/b\nc"},
		{"https://a/b\n", "a\n"},
		{"https://a/b\nc", "a/b\nc"},
		{"x/y/z", "x"},
	} {
		if got := hostOf(c.in); got != c.want {
			t.Errorf("hostOf(%q) = %q, not %q", c.in, got, c.want)
		}
	}
}

func TestPyRepr(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"a", "'a'"},
		{"it's", "\"it's\""},
		{"a\"b'c", "'a\"b\\'c'"},
		{"tab\there", "'tab\\there'"},
		{"\u00e9\u0085\u00a0x", "'\u00e9\\x85\\xa0x'"},
		{"\u007f\u0001", "'\\x7f\\x01'"},
		{"\u2028", "'\\u2028'"},
		{"\U0001F680", "'\U0001F680'"},
		{"\U000E0001", "'\\U000e0001'"},
		{"back\\slash", "'back\\\\slash'"},
	} {
		if got := pyRepr(c.in); got != c.want {
			t.Errorf("pyRepr(%q) = %s, not %s", c.in, got, c.want)
		}
	}
}

func TestSpans(t *testing.T) {
	depths := func(before, after string) string {
		var out []string
		for n := 1; n <= depth; n++ {
			out = append(out, fmt.Sprintf(`["path", "%s%s%s"]`, before, strings.TrimSuffix(strings.Repeat("*/", n), "/"), after))
		}
		return "[" + strings.Join(out, ", ") + "]"
	}
	for _, c := range []struct{ path, pattern, want string }{
		{"v1/{+name}", "^projects/[^/]+/files/.*$", `[["prefix", "/v1/projects/*/files"]]`},
		{"v1/{+name}:cancel", "^operations/.*$", depths("/v1/operations/", ":cancel")},
		{"v1/{+resource}:setIamPolicy", "^.*$", "null"},
		{"v1/{+name}", "^v1/.*$", `[["prefix", "/v1/v1"]]`},
		{"v1/{+name}", "^projects/[^/]+$", "null"},
		{"v1/{+name}", "^a b/.*$", "null"},
		{"v1/{+name}/x", "^.*$", "null"},
	} {
		params, _ := decodeJSON([]byte(fmt.Sprintf(`{"name": {"pattern": %q}, "resource": {"pattern": %q}}`, c.pattern, c.pattern)))
		var got []string
		for _, s := range spans(c.path, params.(*object)) {
			got = append(got, fmt.Sprintf(`["%s", "%s"]`, s.kind, s.path))
		}
		g := "null"
		if got != nil {
			g = "[" + strings.Join(got, ", ") + "]"
		}
		if g != c.want {
			t.Errorf("spans(%q, %q) = %s, not %s", c.path, c.pattern, g, c.want)
		}
	}
}

func TestServiceConfig(t *testing.T) {
	for _, c := range []struct {
		name, text string
		service    bool
		apis       string
	}{
		{"the fixture's", "type: google.api.Service\nconfig_version: 3\nname: demo.googleapis.com\napis:\n- name: demo.v1.Secrets\n- name: google.longrunning.Operations\n", true, "demo.v1.Secrets,google.longrunning.Operations"},
		{"indented, with other keys", "type: google.api.Service\napis:\n  - name: a.B\n    mixins:\n    - name: not.This\n  - version: x\n    name: 'c.D'\ntypes:\n- name: not.That\n", true, "a.B,c.D"},
		{"a codegen config", "type: com.google.api.codegen.ConfigProto\napis:\n- name: a.B\n", false, ""},
		{"quoted, commented", "# a comment\ntype: \"google.api.Service\"  \napis: # the apis\n- name: a.B # this one\n", true, "a.B"},
		{"no apis", "type: google.api.Service\nname: x\n", true, ""},
		{"a block scalar", "type: google.api.Service\ndocumentation:\n  summary: |-\n    apis:\n    - name: not.This\napis:\n- name: a.B\n", true, "a.B"},
		{"an item's name given as a later key", "type: google.api.Service\napis:\n-\n  name: a.B\n", true, "a.B"},
		{"apis empty as a flow sequence", "type: google.api.Service\napis: []\n", true, ""},
		{"apis null", "type: google.api.Service\napis: ~\n", true, ""},
		{"a flow mapping in a codegen config", "type: other\napis:\n- {name: a.B}\n", false, ""},
		{"a second key after the name", "type: google.api.Service\napis:\n- name: a.B\n  version: v1\n- name: c.D\n", true, "a.B,c.D"},
	} {
		service, apis, err := serviceConfig(c.text)
		if err != nil || service != c.service || strings.Join(apis, ",") != c.apis {
			t.Errorf("%s: %v %q %v", c.name, service, apis, err)
		}
	}
}

// What the reader cannot read as PyYAML would, it refuses, rather than
// read no names and lose a mixin with nothing said.
func TestServiceConfigRefuses(t *testing.T) {
	for _, c := range []struct{ name, text string }{
		{"an item as a flow mapping", "type: google.api.Service\napis:\n- {name: google.iam.v1.IAMPolicy}\n"},
		{"apis as a flow sequence", "type: google.api.Service\napis: [{name: google.iam.v1.IAMPolicy}]\n"},
		{"an item that is not a mapping", "type: google.api.Service\napis:\n- google.iam.v1.IAMPolicy\n"},
		{"an empty item", "type: google.api.Service\napis:\n-\n- name: a.B\n"},
		{"an empty last item", "type: google.api.Service\napis:\n- name: a.B\n-\n"},
		{"apis as a mapping", "type: google.api.Service\napis:\n  name: a.B\n"},
		{"an alias", "type: google.api.Service\napis:\n- *x\n"},
		{"a name as an alias", "type: google.api.Service\napis:\n- name: *x\n"},
		{"a tagged item", "type: google.api.Service\napis:\n- !!map {name: a.B}\n"},
		{"a second document", "type: google.api.Service\napis:\n- name: a.B\n---\ntype: x\n"},
		{"a second document in anything", "type: other\n---\ntype: x\n"},
	} {
		if _, apis, err := serviceConfig(c.text); err == nil {
			t.Errorf("%s: read as %q", c.name, apis)
		}
	}
}

// Every YAML file in a googleapis checkout reads here as PyYAML reads it:
// whether it is a service config and, if so, the names in its apis, or a
// refusal where gcloud.py failed or read what this does not. Given a
// checkout, as TestRegeneratesTheCommittedTable is, and a python3 with
// PyYAML (nix develop has one).
func TestServiceConfigsAsPyYAML(t *testing.T) {
	googleapis := os.Getenv("CHASE_GCLOUD_GOOGLEAPIS")
	if googleapis == "" {
		t.Skip("set CHASE_GCLOUD_GOOGLEAPIS to a googleapis checkout")
	}
	if err := exec.Command("python3", "-c", "import yaml").Run(); err != nil {
		t.Skip("no python3 with PyYAML")
	}
	var paths []string
	err := filepath.WalkDir(googleapis, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() && e.Name() == ".git" {
			return filepath.SkipDir
		}
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".yaml") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no YAML in the checkout")
	}
	// For each file a line: "error", "other", or "service" and its apis'
	// names -- gcloud.py's reading, where an item that is not a mapping
	// failed it.
	const script = `
import json, sys, yaml
for path in sys.stdin.read().split("\0"):
    if not path:
        continue
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
        if isinstance(doc, dict) and doc.get("type") == "google.api.Service":
            names = []
            for a in doc.get("apis") or []:
                if not isinstance(a, dict):
                    raise ValueError(a)
                if "name" in a:
                    names.append(str(a["name"]))
            print(json.dumps(["service", names]))
        else:
            print(json.dumps(["other", []]))
    except Exception:
        print(json.dumps(["error", []]))
`
	cmd := exec.Command("python3", "-c", script)
	cmd.Stdin = strings.NewReader(strings.Join(paths, "\x00"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	read := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(read) != len(paths) {
		t.Fatalf("PyYAML read %d files of %d", len(read), len(paths))
	}
	services := 0
	for i, path := range paths {
		var py []any
		if err := json.Unmarshal([]byte(read[i]), &py); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		service, apis, rerr := serviceConfig(string(b))
		var names []string
		for _, n := range py[1].([]any) {
			names = append(names, n.(string))
		}
		switch py[0] {
		case "error":
			if rerr == nil {
				t.Errorf("%s: PyYAML failed, read here as %v %q", path, service, apis)
			}
		case "other":
			if rerr != nil || service {
				t.Errorf("%s: not a service config, read here as %v %q %v", path, service, apis, rerr)
			}
		case "service":
			services++
			if rerr != nil || !service || strings.Join(apis, "\n") != strings.Join(names, "\n") {
				t.Errorf("%s: a service config with apis %q, read here as %v %q %v", path, names, service, apis, rerr)
			}
		}
	}
	t.Logf("%d YAML files, %d service configs", len(paths), services)
}

// A rule's JSON and index.json's are what Python's json.dumps writes, which
// Go's encoder would not: it escapes <, > and &, and U+2028 and U+2029.
func TestPyString(t *testing.T) {
	for _, c := range []struct {
		in         string
		ascii, raw string
	}{
		{"<a & b>", `"<a & b>"`, `"<a & b>"`},
		{"\u2028\u2029", `"\u2028\u2029"`, "\"\u2028\u2029\""},
		{"é🚀\x7f", `"\u00e9\ud83d\ude80\u007f"`, "\"é🚀\x7f\""},
		{"\"\\\n\r\t\b\f\x01\x1f", `"\"\\\n\r\t\b\f\u0001\u001f"`, `"\"\\\n\r\t\b\f\u0001\u001f"`},
	} {
		var a, r strings.Builder
		pyString(&a, c.in, true)
		pyString(&r, c.in, false)
		if a.String() != c.ascii || r.String() != c.raw {
			t.Errorf("%q: %s and %s, not %s and %s", c.in, a.String(), r.String(), c.ascii, c.raw)
		}
	}
}

// Whatever a string holds, what pyString writes reads back as it: the
// rules are JSON that frisket parses.
func TestPyStringReadsBack(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.String().Draw(t, "s")
		for _, ascii := range []bool{true, false} {
			var b strings.Builder
			pyString(&b, s, ascii)
			var back string
			if err := json.Unmarshal([]byte(b.String()), &back); err != nil {
				t.Fatalf("%q as %s: %v", s, b.String(), err)
			}
			if back != s {
				t.Fatalf("%q read back as %q", s, back)
			}
		}
	})
}

func TestJqPretty(t *testing.T) {
	v, err := decodeJSON([]byte(`{"b": {"x": [], "y": {}}, "a": ["1", "\u007f\u00e9"], "n": null, "t": true}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"b\": {\n    \"x\": [],\n    \"y\": {}\n  },\n  \"a\": [\n    \"1\",\n    \"\\u007fé\"\n  ],\n  \"n\": null,\n  \"t\": true\n}\n"
	if got := jqPretty(v); got != want {
		t.Errorf("jqPretty:\n%s\nnot:\n%s", got, want)
	}
}

// A key written twice keeps its first place and its last value, as
// Python's json.load keeps it.
func TestOrderedJSON(t *testing.T) {
	v, err := decodeJSON([]byte(`{"b": 1, "a": 2, "b": 3}`))
	if err != nil {
		t.Fatal(err)
	}
	o := v.(*object)
	if strings.Join(o.keys, ",") != "b,a" || o.vals["b"].(json.Number) != "3" {
		t.Errorf("%v %v", o.keys, o.vals)
	}
}
