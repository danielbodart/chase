// Package policydoc is what a launch does to a session's policy document,
// and to the grant it is made from: an app's routes merged into the
// tier's, a project's lists applied to an app's route, and a grant put in
// the form it is approved in.
//
// The policy document is frisket's own types, so a field frisket does not
// know is a compile error here rather than a document frisket refuses on
// someone's machine. The grant is not frisket's, and is JSON as jq held
// it.
package policydoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/danielbodart/frisket/policy"
)

// Lists are a project's lists for one app, as its grant binds them
// (PLAN.md, decision 18): `allow`, `ask` and `refuse`, each naming
// operations by id, whole categories as "category:<name>", or methods and an
// exact path for an endpoint the description does not name.
type Lists struct {
	Allow  []Entry `json:"allow"`
	Ask    []Entry `json:"ask"`
	Refuse []Entry `json:"refuse"`
}

// Entry is one thing a list names: an operation's id or "category:<name>"
// as Name, or an endpoint.
type Entry struct {
	Name     string
	Endpoint *Endpoint
}

// Endpoint is methods and an exact path template, for an endpoint the
// description does not name.
type Endpoint struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
}

// UnmarshalJSON reads a name or an endpoint, and refuses anything else, and
// any field of an endpoint but its methods and path: the grant's options
// admit nothing else, and an entry read as something else would be one that
// silently decides nothing.
func (e *Entry) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case bytes.HasPrefix(b, []byte(`"`)):
		var name string
		if err := json.Unmarshal(b, &name); err == nil {
			*e = Entry{Name: name}
			return nil
		}
	case bytes.HasPrefix(b, []byte(`{`)):
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var ep Endpoint
		if err := dec.Decode(&ep); err == nil {
			*e = Entry{Endpoint: &ep}
			return nil
		}
	}
	return fmt.Errorf("a list names an operation, a category or an endpoint: %s", b)
}

// MarshalJSON writes the entry as it was read.
func (e Entry) MarshalJSON() ([]byte, error) {
	if e.Endpoint != nil {
		return json.Marshal(e.Endpoint)
	}
	return json.Marshal(e.Name)
}

const (
	allow  = "allow"
	ask    = "ask"
	refuse = "refuse"
)

// answer makes a rule's ask and refuse say verb.
func answer(verb string, asks, refuses *bool) {
	switch verb {
	case allow:
		*asks, *refuses = false, false
	case ask:
		*asks, *refuses = true, false
	default:
		*asks, *refuses = false, true
	}
}

// decide answers a rule by its operation's name, or else by its category.
func decide(op *policy.Operation, byID, byCategory map[string]string, asks, refuses *bool) {
	if op == nil {
		return
	}
	if v, ok := byID[op.ID]; ok {
		answer(v, asks, refuses)
	} else if v, ok := byCategory[op.Category]; ok && op.Category != "" {
		answer(v, asks, refuses)
	}
}

// overlaps is whether an exact path and a rule can match one request:
// segment by segment a literal meets itself or a "*", and a prefix matches
// that many segments or more.
func overlaps(path, rulePath, rulePrefix string) bool {
	x := strings.Split(path, "/")[1:]
	pattern := rulePath
	if pattern == "" {
		pattern = rulePrefix
	}
	var y []string
	for _, s := range strings.Split(pattern, "/")[1:] {
		if s != "" {
			y = append(y, s)
		}
	}
	if rulePath != "" && len(x) != len(y) || rulePath == "" && len(x) < len(y) {
		return false
	}
	for i := range y {
		if x[i] != "*" && y[i] != "*" && x[i] != y[i] {
			return false
		}
	}
	return true
}

// Apply applies a project's lists for app to app's route in doc: an
// operation the lists name, or whose category they name, is answered as
// that list says, and an endpoint they name is added, answered so.
//
// A name decides before a category, and a category before what the tier
// and the app said. A name or category the route does not have is an error:
// a typo would otherwise be a rule that silently decides nothing. So is a
// path that one of the route's operations already describes: a literal
// beats a "*", so {DELETE, /repos/me/app} would decide repos/delete without
// naming it. An operation the description has is loosened by its name,
// which is what the person approving it reads. And so is an entry in two
// lists, which the grant refuses before approval: were one to get here,
// nothing here would refuse it, and the later of allow, ask and refuse would
// decide, as it always has.
//
// git's push is the operation `git-receive-pack`, in frisket's git rule; a
// GraphQL query and each mutation are operations of their own, in its
// graphql rules, and an endpoint's path is theirs.
//
// doc is changed only when nil is returned.
func Apply(doc *policy.Document, app string, lists Lists) error {
	byID, byCategory := map[string]string{}, map[string]string{}
	type endpoint struct {
		verb string
		*Endpoint
	}
	var endpoints []endpoint
	for _, l := range []struct {
		verb    string
		entries []Entry
	}{{allow, lists.Allow}, {ask, lists.Ask}, {refuse, lists.Refuse}} {
		for _, e := range l.entries {
			switch {
			case e.Endpoint != nil:
				endpoints = append(endpoints, endpoint{l.verb, e.Endpoint})
			case strings.HasPrefix(e.Name, "category:"):
				byCategory[strings.TrimPrefix(e.Name, "category:")] = l.verb
			default:
				byID[e.Name] = l.verb
			}
		}
	}
	i := slices.IndexFunc(doc.Routes, func(r policy.Route) bool { return r.Name == app })
	if i < 0 {
		return fmt.Errorf("%s is not in this tier", app)
	}
	route := doc.Routes[i]

	var fields []*policy.GraphQLField
	for gi := range route.GraphQL {
		g := &route.GraphQL[gi]
		if g.Query != nil {
			fields = append(fields, g.Query)
		}
		for j := range g.Mutations {
			fields = append(fields, &g.Mutations[j])
		}
		for j := range g.Subscriptions {
			fields = append(fields, &g.Subscriptions[j])
		}
	}
	ids, categories := map[string]bool{}, map[string]bool{}
	know := func(op *policy.Operation) {
		if op != nil {
			ids[op.ID] = true
			if op.Category != "" {
				categories[op.Category] = true
			}
		}
	}
	for _, p := range route.Paths {
		know(p.Operation)
	}
	for _, f := range fields {
		know(f.Operation)
	}
	if route.Git != nil {
		ids["git-receive-pack"] = true
	}
	var unknown []string
	for _, id := range sortedKeys(byID) {
		if !ids[id] {
			unknown = append(unknown, id)
		}
	}
	for _, c := range sortedKeys(byCategory) {
		if !categories[c] {
			unknown = append(unknown, "category:"+c)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%s has no %s", app, strings.Join(unknown, ", "))
	}

	described := map[string]bool{}
	for _, e := range endpoints {
		said := strings.Join(e.Methods, ",") + " " + e.Path
		for _, p := range route.Paths {
			if p.Operation != nil && slices.ContainsFunc(p.Methods, func(m string) bool { return slices.Contains(e.Methods, m) }) && overlaps(e.Path, p.Path, p.Prefix) {
				described[said+" is "+p.Operation.ID] = true
			}
		}
		for _, g := range route.GraphQL {
			if overlaps(e.Path, g.Path, "") {
				described[said+" is GraphQL's, by operation"] = true
			}
		}
	}
	if len(described) > 0 {
		return fmt.Errorf("%s describes these, so name them: %s", app, strings.Join(sortedKeys(described), "; "))
	}

	paths := make([]policy.PathRule, 0, len(route.Paths)+len(endpoints))
	for _, p := range route.Paths {
		decide(p.Operation, byID, byCategory, &p.Ask, &p.Refuse)
		paths = append(paths, p)
	}
	for _, e := range endpoints {
		p := policy.PathRule{Methods: slices.Clone(e.Methods), Path: e.Path}
		answer(e.verb, &p.Ask, &p.Refuse)
		paths = append(paths, p)
	}
	route.Paths = paths
	if route.GraphQL != nil {
		graphql := make([]policy.GraphQLRule, len(route.GraphQL))
		for gi, g := range route.GraphQL {
			if g.Query != nil {
				q := *g.Query
				decide(q.Operation, byID, byCategory, &q.Ask, &q.Refuse)
				g.Query = &q
			}
			g.Mutations = decided(g.Mutations, byID, byCategory)
			g.Subscriptions = decided(g.Subscriptions, byID, byCategory)
			graphql[gi] = g
		}
		route.GraphQL = graphql
	}
	if v, ok := byID["git-receive-pack"]; route.Git != nil && ok {
		git := *route.Git
		git.Push = v
		route.Git = &git
	}
	routes := slices.Clone(doc.Routes)
	routes[i] = route
	doc.Routes = routes
	return nil
}

// decided is fields, each answered by name or else by category.
func decided(fields []policy.GraphQLField, byID, byCategory map[string]string) []policy.GraphQLField {
	if fields == nil {
		return nil
	}
	out := make([]policy.GraphQLField, len(fields))
	for i, f := range fields {
		decide(f.Operation, byID, byCategory, &f.Ask, &f.Refuse)
		out[i] = f
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
