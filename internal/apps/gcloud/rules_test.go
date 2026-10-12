package gcloud

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"testing"

	"github.com/danielbodart/frisket/policy"
	"pgregory.net/rapid"

	"github.com/danielbodart/chase/internal/apps"
)

func sha16(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

func op(id, class, category string) *policy.Operation {
	return &policy.Operation{ID: id, Summary: id, Class: class, Category: category}
}

// One rule per template: a carried API's over the floor's, and one that
// takes an encoded slash over one that does not; otherwise the later.
// In jq's order: by methods, then path, with a prefix-only rule, whose path
// is null, first.
func TestOneRulePerTemplateAsJqChoseIt(t *testing.T) {
	carried := []policy.PathRule{
		{Methods: []string{"POST"}, Path: "/v1/*:signBlob", Operation: op("a.sign", "guarded", "a")},
		{Methods: []string{"GET"}, Path: "/o/*", Operation: op("a.first", "read", "a")},
		{Methods: []string{"GET"}, Path: "/o/*", EncodedSlashes: true, Operation: op("a.slashes", "read", "a")},
		{Methods: []string{"GET"}, Path: "/o/*", Operation: op("a.last", "read", "a")},
		{Methods: []string{"GET", "HEAD"}, Path: "/b", Operation: op("a.b", "write", "a")},
		{Methods: []string{"GET"}, Prefix: "/p", Operation: op("a.p", "read", "a")},
	}
	floor := []policy.PathRule{
		{Methods: []string{"POST"}, Path: "/v1/*:signBlob", Operation: op("b.sign", "guarded", "")},
		{Methods: []string{"DELETE"}, Path: "/x", Operation: op("b.x", "guarded", "")},
		{Methods: []string{"DELETE"}, Path: "/x", Operation: op("c.x", "guarded", "")},
	}
	got, encoded := paths(carried, floor)
	ids := map[string]string{}
	for k, e := range got {
		ids[k] = e.Operation.ID
	}
	want := map[string]string{"DELETE /x": "c.x", "GET /p/**": "a.p", "GET /o/*": "a.slashes", "GET,HEAD /b": "a.b", "POST /v1/*:signBlob": "a.sign"}
	if !maps.Equal(ids, want) {
		t.Errorf("chose %q, want %q", ids, want)
	}
	if !maps.Equal(encoded, map[string]bool{"GET /o/*": true}) {
		t.Errorf("encoded slashes %v", encoded)
	}
}

// Whatever the rules, the route has each template once, a carried API's
// wherever it has one, and every template of either.
func TestEveryTemplateOnceAndTheCarriedFirst(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		gen := func(label string) []policy.PathRule {
			return rapid.SliceOfN(rapid.Custom(func(t *rapid.T) policy.PathRule {
				r := policy.PathRule{
					Methods:   rapid.SliceOfN(rapid.SampledFrom(every), 1, 2).Draw(t, "methods"),
					Operation: op(label, rapid.SampledFrom([]string{"read", "write", "guarded"}).Draw(t, "class"), ""),
				}
				p := rapid.SampledFrom([]string{"/a", "/b", "/a/*", "/"}).Draw(t, "p")
				if rapid.Bool().Draw(t, "prefix") {
					r.Prefix = p
				} else {
					r.Path = p
				}
				return r
			}), 0, 12).Draw(t, label)
		}
		carried, floor := gen("carried"), gen("floor")
		got, _ := paths(carried, floor)
		for _, r := range slices.Concat(carried, floor) {
			g, ok := got[apps.Endpoint(r.Methods, r.Path, r.Prefix)]
			if !ok {
				t.Fatalf("%+v is missing", r)
			}
			if r.Operation.ID == "carried" && g.Operation.ID != "carried" {
				t.Fatalf("the floor decided a carried template: %+v", g)
			}
		}
	})
}

func TestTheAPIsResolveAsJqResolvedThem(t *testing.T) {
	known := map[string]bool{"bigquery": true, "storage": true, "pubsub": true}
	for _, c := range []struct {
		tier    []string
		binding string
		want    []string
		err     string
	}{
		{[]string{"storage", "bigquery"}, `{}`, []string{"bigquery", "storage"}, ""},
		{[]string{"storage", "bigquery"}, `{"apis": null}`, []string{"bigquery", "storage"}, ""},
		{[]string{"bigquery", "storage"}, `{"apis": {"add": ["pubsub", "bigquery"], "remove": ["storage"]}}`, []string{"bigquery", "pubsub"}, ""},
		{[]string{"bigquery"}, `{"apis": {"add": false, "remove": null}}`, []string{"bigquery"}, ""},
		{[]string{"bigquery"}, `{"apis": {"remove": ["bigquery"], "add": ["bigquery"]}}`, nil, ""},
		{nil, `{"apis": {"add": ["nope", "pubsub", "nope"], "remove": ["nah"]}}`, nil, "no Google API named nope, nope, nah"},
		{nil, `{"apis": "pubsub"}`, nil, "apis is not an object"},
		{nil, `{"apis": {"add": "pubsub"}}`, nil, "apis.add is not a list of names"},
		{nil, `{"apis": {"remove": [1]}}`, nil, "apis.remove is not a list of names"},
	} {
		var b map[string]json.RawMessage
		json.Unmarshal([]byte(c.binding), &b)
		ch, err := changes(b)
		var got []string
		if err == nil {
			got, err = resolve(c.tier, ch, known)
		}
		if (err == nil) != (c.err == "") || err != nil && err.Error() != c.err || !slices.Equal(got, c.want) {
			t.Errorf("%q %s: %q, %v; want %q, %q", c.tier, c.binding, got, err, c.want, c.err)
		}
	}
}

// A value as jq -r printed it into a command substitution.
func TestJqRaw(t *testing.T) {
	for in, want := range map[string]string{
		``:            "",
		`null`:        "",
		`false`:       "",
		`true`:        "true",
		`"a@b"`:       "a@b",
		`"a@b\n\n"`:   "a@b",
		`5`:           "5",
		`1.50`:        "1.50",
		`[1,2]`:       "[\n  1,\n  2\n]",
		`{}`:          "{}",
		`{"a":"b"}`:   "{\n  \"a\": \"b\"\n}",
		`"tab\there"`: "tab\there",
	} {
		if got := jqRaw(json.RawMessage(in)); got != want {
			t.Errorf("jqRaw(%s) = %q, want %q", in, got, want)
		}
	}
}

// The floor is every guarded rule of the committed catalogue, with no
// category or description, and nothing else.
func TestTheFloorOfTheCommittedCatalogue(t *testing.T) {
	floor, err := Floor(catalogue(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(floor) < 1000 {
		t.Errorf("a floor of %d rules", len(floor))
	}
	for _, r := range floor {
		if r.Operation == nil || r.Operation.Class != "guarded" || r.Operation.Category != "" || r.Operation.Description != "" {
			t.Fatalf("%+v is in the floor", r)
		}
	}
}
