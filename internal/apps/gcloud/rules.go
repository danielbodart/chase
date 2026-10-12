package gcloud

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/apps"
)

// Which APIs a session carries is a tier's default and a project's override
// (docs/gcloud.md, decision 9): the tier's, with what the project adds and
// without what it removes.

// apiChanges is a binding's `apis`: what it adds to the tier's, and removes.
type apiChanges struct {
	Add, Remove []string
}

// changes reads a binding's apis. Absent, null or false is no change, as
// jq's `//` had it; anything but an object, or lists of names, is refused.
func changes(binding map[string]json.RawMessage) (apiChanges, error) {
	var c apiChanges
	raw := binding["apis"]
	if absent(raw) {
		return c, nil
	}
	var o map[string]json.RawMessage
	if json.Unmarshal(raw, &o) != nil || o == nil {
		return c, errors.New("apis is not an object")
	}
	for _, f := range []struct {
		name string
		to   *[]string
	}{{"add", &c.Add}, {"remove", &c.Remove}} {
		if v := o[f.name]; !absent(v) && json.Unmarshal(v, f.to) != nil {
			return c, fmt.Errorf("apis.%s is not a list of names", f.name)
		}
	}
	return c, nil
}

// absent is what jq's `// default` takes the default for: nothing, null or
// false.
func absent(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "false"
}

// resolve is the APIs a session carries, sorted and each once. A name the
// project adds or removes that is no API is refused, every one of them
// named: a removal of nothing is as likely a typo as an addition.
func resolve(tier []string, c apiChanges, known map[string]bool) ([]string, error) {
	var unknown []string
	for _, a := range slices.Concat(c.Add, c.Remove) {
		if !known[a] {
			unknown = append(unknown, a)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("no Google API named %s", strings.Join(unknown, ", "))
	}
	var out []string
	for _, a := range slices.Concat(tier, c.Add) {
		if !slices.Contains(c.Remove, a) {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// known is every API the catalogue names, from its index.
func known(catalogue string) (map[string]bool, error) {
	b, err := os.ReadFile(filepath.Join(catalogue, "index.json"))
	if err != nil {
		return nil, err
	}
	var index map[string]json.RawMessage
	if err := json.Unmarshal(b, &index); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(catalogue, "index.json"), err)
	}
	k := make(map[string]bool, len(index))
	for name := range index {
		k[name] = true
	}
	return k, nil
}

// rulesOf is an API's generated rules, as its file has them. A field frisket
// does not know is refused here, as frisket would refuse it.
func rulesOf(file string) ([]policy.PathRule, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var rules []policy.PathRule
	if err := policy.Decode(b, &rules); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return rules, nil
}

// Floor is every API's guarded operations, whichever a session carries: a
// request to an API it does not carry is unmatched, but never one of these,
// and a carried API's "*" never decides another's "*:verb" among them.
// Named, not categorised: a category is an API the session carries, so each
// has no category, and no description to carry about for it either.
//
// In the order the module's jq read them: the files by name, bytewise, as
// a glob in the build's C locale sorts them, and each file's rules in its
// order. Where two APIs guard one template, the last is the one kept.
func Floor(catalogue string) ([]policy.PathRule, error) {
	files, err := filepath.Glob(filepath.Join(catalogue, "apis", "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var floor []policy.PathRule
	for _, f := range files {
		rules, err := rulesOf(f)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			if r.Operation == nil || r.Operation.Class != "guarded" {
				continue
			}
			op := *r.Operation
			op.Description, op.Category = "", ""
			r.Operation = &op
			floor = append(floor, r)
		}
	}
	return floor, nil
}

// candidate is a rule, and whether it came from the floor.
type candidate struct {
	rule  policy.PathRule
	floor bool
}

// paths is what the route's requests are, a version 2 route's paths: the
// carried APIs' and the floor's operations, one per method and template,
// and the templates whose "*" takes a segment holding an encoded slash.
// How each is answered is its class's, the route's writes, guarded and
// unmatched, which are the tier's.
//
// A carried API's own rule wins where both have a template, and among
// rules of one template, the one that lets a "*" take an encoded slash: a
// Cloud Storage object's name is one segment. Where they are otherwise
// alike, the later is kept, as jq's max_by keeps it.
func paths(carried, floor []policy.PathRule) (map[string]policy.EndpointV2, map[string]bool) {
	all := make([]candidate, 0, len(carried)+len(floor))
	for _, r := range carried {
		all = append(all, candidate{r, false})
	}
	for _, r := range floor {
		all = append(all, candidate{r, true})
	}
	// jq's group_by: sorted by [methods, path, prefix] as jq orders values,
	// stably, so a group keeps the order its rules were read in.
	sort.SliceStable(all, func(i, j int) bool { return compareTemplate(all[i].rule, all[j].rule) < 0 })
	out := map[string]policy.EndpointV2{}
	encoded := map[string]bool{}
	for i := 0; i < len(all); {
		j := i + 1
		for j < len(all) && compareTemplate(all[i].rule, all[j].rule) == 0 {
			j++
		}
		best := all[i]
		for _, c := range all[i+1 : j] {
			if preference(c) >= preference(best) {
				best = c
			}
		}
		r := best.rule
		key := apps.Endpoint(r.Methods, r.Path, r.Prefix)
		out[key] = policy.EndpointV2{Operation: r.Operation}
		if r.EncodedSlashes {
			encoded[key] = true
		}
		i = j
	}
	if len(encoded) == 0 {
		encoded = nil
	}
	return out, encoded
}

// preference orders a template's rules as [not floor, encodedSlashes] does
// in jq, where false is less than true.
func preference(c candidate) int {
	p := 0
	if !c.floor {
		p += 2
	}
	if c.rule.EncodedSlashes {
		p++
	}
	return p
}

// compareTemplate orders rules by [methods, path, prefix] as jq orders
// those values: arrays element by element, the shorter first where one is
// the other's start; strings bytewise; an absent path or prefix, null,
// before any string.
func compareTemplate(a, b policy.PathRule) int {
	if c := slices.Compare(a.Methods, b.Methods); c != 0 {
		return c
	}
	if c := compareOptional(a.Path, b.Path); c != 0 {
		return c
	}
	return compareOptional(a.Prefix, b.Prefix)
}

func compareOptional(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return -1
	case b == "":
		return 1
	default:
		return strings.Compare(a, b)
	}
}
