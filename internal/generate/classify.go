package generate

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The classification: what was the jq program in scripts/operations.sh, step
// for step and failure for failure, in the same order, so that the same
// wrong input is refused with the same words. Every failure is a halt, not
// a warning: a classification that is quietly wrong is worse than none,
// because the gate would trust it.

var classes = []string{"read", "write", "guarded"}

// methodKeys are the only keys of a path item that are operations;
// "parameters" and "x-*" sit beside them.
var methodKeys = map[string]bool{"get": true, "put": true, "post": true, "patch": true, "delete": true, "head": true, "options": true, "trace": true}

// natural is the class a method has unless an exception says otherwise.
func natural(method string) string {
	switch method {
	case "GET", "HEAD":
		return "read"
	case "DELETE":
		return "guarded"
	}
	return "write"
}

// fieldNatural is the class a GraphQL field has unless an exception says
// otherwise: as a DELETE is guarded, so is a mutation that says it deletes.
func fieldNatural(name string) string {
	if strings.HasPrefix(name, "delete") {
		return "guarded"
	}
	return "write"
}

// sentence is an operation's summary: the first sentence of its
// description -- up to the first '.', '!' or '?' before a line ends that is
// followed by white space or the end -- or else its first line. An empty
// description has no first line, as jq splits "" into no lines at all, and
// so no summary: null.
func sentence(d string) any {
	if d == "" {
		return nil
	}
	for i := 0; i < len(d); {
		r, size := utf8.DecodeRuneInString(d[i:])
		if r == '\n' {
			break
		}
		if r == '.' || r == '!' || r == '?' {
			end := i + size
			if end == len(d) {
				return d[:end]
			}
			if next, _ := utf8.DecodeRuneInString(d[end:]); unicode.IsSpace(next) {
				return d[:end]
			}
		}
		i += size
	}
	first, _, _ := strings.Cut(d, "\n")
	return first
}

// template is what a rule matches on: a whole segment "*" for any segment
// holding a parameter.
func template(spec string) string {
	parts := split(spec, "/")
	for i, p := range parts {
		if strings.ContainsAny(p, "{}") {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, "/")
}

// withoutLastParam is the template's path without the parameter that ends
// it: jq's sub("/[{][^/]*[}]$"; "").
func withoutLastParam(s string) string {
	for p := 0; p+1 < len(s); p++ {
		if s[p] != '/' || s[p+1] != '{' {
			continue
		}
		for _, e := range ends(s) {
			if e-1 >= p+2 && s[e-1] == '}' && !strings.Contains(s[p+2:e-1], "/") {
				return s[:p] + s[e:]
			}
		}
	}
	return s
}

// wildcard is whether a parameter's description is Hugging Face's
// "Wildcard path parameter", in any case.
func wildcard(s string) bool {
	for _, e := range ends(s) {
		if strings.EqualFold(s[:e], "wildcard path parameter") {
			return true
		}
	}
	return false
}

// oddPath is a path frisket could not match as written: a literal "*"
// would be indistinguishable from a template, and an empty segment or a
// trailing slash is a path no client sends.
func oddPath(s string) bool {
	if strings.Contains(s, "*") || !strings.HasPrefix(s, "/") || strings.Contains(s, "//") {
		return true
	}
	for _, e := range ends(s) {
		if e >= 2 && s[e-1] == '/' && s[e-2] != '\n' {
			return true
		}
	}
	return false
}

var schemeAndHost = regexp.MustCompile(`^[a-z]+://[^/]+`)

var notIDChars = regexp.MustCompile(`[^A-Za-z0-9_.:]+`)

// idFrom is the operation id a spec with none gets, from the method and
// the path, in the characters an envelope may name one by: what a person
// writes in exceptions.json, and in a project allow-list.
func idFrom(method, spec string) string {
	id := strings.ToLower(method) + spec
	id = strings.NewReplacer("{", "", "}", "").Replace(id)
	id = notIDChars.ReplaceAllString(id, "-")
	return strings.TrimSuffix(id, "-")
}

// overlaps is whether two templates can match one path: segment by
// segment, where both have one, a literal meets itself or a "*"; an exact
// template is that many segments, a prefix that many or more.
func overlaps(a string, aexact bool, b string, bexact bool) bool {
	x, y := tail(split(a, "/")), tail(split(b, "/"))
	var lengths bool
	switch {
	case aexact && bexact:
		lengths = len(x) == len(y)
	case aexact:
		lengths = len(x) >= len(y)
	case bexact:
		lengths = len(y) >= len(x)
	default:
		lengths = true
	}
	if !lengths {
		return false
	}
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != "*" && y[i] != "*" && x[i] != y[i] {
			return false
		}
	}
	return true
}

func tail(xs []string) []string {
	if len(xs) == 0 {
		return xs
	}
	return xs[1:]
}

// field is one field of a GraphQL root type, as scripts/schema.py gave it.
type field struct {
	kind        string
	name        string
	description any // a string, or nil where the schema gives none
	category    any
	deprecated  any
}

type classifyInput struct {
	name        string
	root        any // the spec
	exceptions  any // exceptions.json, or {} where there is none
	admit       any // admit.json, or nil where there is none
	fields      []field
	graphqlPath string
	flavor      string
	server      string
	basePath    string
	version     string
}

// Failure is the classification refusing what it was given, with why.
type Failure struct {
	Name    string
	Message string
}

func (f *Failure) Error() string { return fmt.Sprintf("operations: %s: %s", f.Name, f.Message) }

// operation is one method of one path of the spec.
type operation struct {
	method      string
	spec        string
	rest        []any
	id          any
	summary     any
	description any
	category    any
	path        string // where exact
	prefix      string // where the rest of the path
	isPrefix    bool
}

func (o *operation) where() string {
	if o.isPrefix {
		return o.prefix
	}
	return o.path
}

// classify is operations.json's text, or the reason there is none.
func classify(in classifyInput) (string, error) {
	q := &eval{}
	fail := func(format string, args ...any) error {
		return &Failure{Name: in.name, Message: fmt.Sprintf(format, args...)}
	}
	jqErr := func() error { return &Failure{Name: in.name, Message: "jq: error: " + q.err.Error()} }
	root := in.root
	admit := in.admit
	// What exceptions.json holds is taken as jq bound it: looked up now,
	// iterated where it is first used, so that it fails where jq did.
	rulesV := alt(q.get(in.exceptions, "rules"), []any{})
	reclassedV := map[string]any{}
	for _, c := range classes {
		reclassedV[c] = alt(q.get(in.exceptions, c), NewObject())
	}
	if q.err != nil {
		return "", jqErr()
	}

	// A parameter may be written once under components and referred to.
	resolve := func(v any) any {
		if !q.has(v, "$ref") {
			return v
		}
		r := q.get(v, "$ref")
		if s, ok := r.(string); ok {
			r = strings.TrimPrefix(s, "#/")
		}
		cur := root
		for _, p := range split(q.str(r), "/") {
			cur = q.get(cur, p)
		}
		return cur
	}

	// A path parameter that holds slashes: what Hugging Face calls a
	// "Wildcard path parameter", and GitHub marks x-multi-segment -- a file
	// in a repository, a ref, a branch.
	multisegment := func(p any) bool {
		if equal(q.get(p, "x-multi-segment"), true) {
			return true
		}
		return wildcard(q.str(alt(q.get(q.get(p, "schema"), "description"), "")))
	}

	// The servers url is what the templates are prefixed with. A spec that
	// moved it would produce rules for paths nobody sends. A Swagger spec's
	// templates are what follows its basePath, which is the API's version:
	// frisket strips a version it admits before it matches.
	var prefix string
	if in.flavor == "swagger2" {
		if v := q.get(root, "swagger"); q.err == nil && !equal(v, "2.0") {
			return "", fail("swagger is %s, not 2.0", interp(v))
		}
		if v := q.get(root, "basePath"); q.err == nil && !equal(v, in.basePath) {
			return "", fail("basePath is %s, not %s", interp(v), in.basePath)
		}
		if v := q.get(q.get(root, "info"), "version"); q.err == nil && !equal(v, in.version) {
			return "", fail("info.version is %s, not %s, the top of apiVersions: bump the range with the pin", interp(v), in.version)
		}
	} else {
		urls := []any{}
		for _, s := range q.iter(q.get(root, "servers")) {
			urls = append(urls, q.get(s, "url"))
		}
		if q.err == nil && !equal(urls, []any{in.server}) {
			return "", fail("servers is %s, not %s", toJSON(urls), in.server)
		}
		prefix = in.server
		if loc := schemeAndHost.FindStringIndex(in.server); loc != nil {
			prefix = in.server[loc[1]:]
		}
	}
	if q.err != nil {
		return "", jqErr()
	}

	// Only method keys are operations; "parameters" and "x-*" sit beside
	// them. A parameter that holds slashes, as the last segment, is the
	// rest of the path, which is a prefix to frisket; anywhere else it is
	// one segment, and a value with a slash matches nothing and is left to
	// `unmatched`. A Swagger body is a parameter too, and is never one of
	// these.
	var ops []*operation
	for _, pe := range q.entries(q.get(root, "paths")) {
		shared := alt(q.get(pe.value, "parameters"), []any{})
		for _, me := range q.entries(pe.value) {
			if !methodKeys[me.key] {
				continue
			}
			params := append(append([]any{}, q.iter(shared)...), q.iter(alt(q.get(me.value, "parameters"), []any{}))...)
			var slashed []any
			for _, p := range params {
				p = resolve(p)
				if !equal(q.get(p, "in"), "path") || !multisegment(p) {
					continue
				}
				slashed = append(slashed, q.get(p, "name"))
			}
			rest := []any{}
			for _, s := range slashed {
				if strings.HasSuffix(pe.key, "/{"+interp(s)+"}") {
					rest = append(rest, s)
				}
			}
			category := alt(q.get(q.get(me.value, "x-github"), "category"), nil)
			if !truthy(category) {
				t := &eval{}
				tags := t.get(me.value, "tags")
				var first any
				if a, ok := tags.([]any); ok {
					if len(a) > 0 {
						first = a[0]
					}
				} else if tags != nil {
					t.errorf("Cannot index %s with number", typeName(tags))
				}
				if t.err == nil {
					category = alt(first, nil)
				}
			}
			ops = append(ops, &operation{
				method: strings.ToUpper(me.key), spec: pe.key, rest: rest,
				id: q.get(me.value, "operationId"), summary: q.get(me.value, "summary"),
				description: q.get(me.value, "description"), category: category,
			})
			if q.err != nil {
				return "", jqErr()
			}
		}
	}
	if q.err != nil {
		return "", jqErr()
	}

	var odd []any
	for _, o := range ops {
		if o.summary == nil {
			odd = append(odd, o.method+" "+o.spec)
		}
	}
	if len(odd) > 0 {
		return "", fail("an operation has no summary: %s", toJSON(odd))
	}

	// A literal "*" would be indistinguishable from a template, and an
	// empty segment or a trailing slash is a path no client sends.
	odd = nil
	for _, o := range ops {
		if oddPath(o.spec) {
			odd = append(odd, o.spec)
		}
	}
	if odd = unique(odd); len(odd) > 0 {
		return "", fail("a path frisket could not match as written: %s", toJSON(odd))
	}

	// Only one rest of the path.
	odd = []any{}
	for _, o := range ops {
		if len(o.rest) > 1 {
			odd = append(odd, o.method+" "+o.spec)
		}
	}
	if len(odd) > 0 {
		return "", fail("two parameters that are both the rest of the path: %s", toJSON(odd))
	}

	// A spec with no operation ids gets them from the method and the path,
	// in the characters an envelope may name one by: what a person writes
	// in exceptions.json, and in a project allow-list.
	for _, o := range ops {
		if !truthy(o.id) {
			o.id = idFrom(o.method, o.spec)
		}
	}

	// GraphQL endpoints, and the fields of the one whose schema is pinned.
	endpoints := q.iter(alt(q.get(in.exceptions, "graphql"), []any{}))
	if q.err != nil {
		return "", jqErr()
	}
	odd = []any{}
	for _, e := range endpoints {
		reason := q.get(e, "reason")
		bad := !isString(reason) || equal(reason, "")
		if !bad {
			bad = !strings.HasPrefix(q.str(alt(q.get(e, "path"), "")), "/")
		}
		bad = bad || !isString(q.get(q.get(e, "operation"), "id")) || !isString(q.get(q.get(e, "operation"), "summary"))
		if q.err != nil {
			return "", jqErr()
		}
		if bad {
			odd = append(odd, alt(q.get(e, "path"), "?"))
		}
	}
	if len(odd) > 0 {
		return "", fail("a GraphQL endpoint needs a path, a reason, and its query's operation id and summary: %s", toJSON(odd))
	}
	var endpointPaths []any
	for _, e := range endpoints {
		endpointPaths = append(endpointPaths, q.get(e, "path"))
	}
	if in.graphqlPath != "" && !contains(endpointPaths, in.graphqlPath) {
		return "", fail("source.json pins a GraphQL schema for %s, which exceptions.json does not declare", in.graphqlPath)
	}
	odd = []any{}
	for _, f := range in.fields {
		if f.description == nil {
			odd = append(odd, f.name)
		}
	}
	if len(odd) > 0 {
		return "", fail("a GraphQL field has no description: %s", toJSON(odd))
	}

	// An endpoint replacing an operation may keep its id: it is that
	// operation, seen into.
	rules := q.iter(rulesV)
	var replaced []any
	for _, e := range endpoints {
		replaced = append(replaced, tryIter(q.get(e, "replaces"))...)
	}
	var ids []any
	for _, o := range ops {
		if !contains(replaced, o.id) {
			ids = append(ids, o.id)
		}
	}
	for _, r := range rules {
		ids = append(ids, q.get(q.get(r, "operation"), "id"))
	}
	for _, e := range endpoints {
		ids = append(ids, q.get(q.get(e, "operation"), "id"))
	}
	for _, f := range in.fields {
		ids = append(ids, f.name)
	}
	if q.err != nil {
		return "", jqErr()
	}
	if twice := dups(ids); len(twice) > 0 {
		return "", fail("the same operation id twice: %s", toJSON(twice))
	}

	// An exception naming an operation the spec no longer has is how a pin
	// bump that removed one gets noticed. One giving an operation the class
	// it has anyway would do nothing, so it is a mistake too.
	naturals := map[string]string{}
	for _, o := range ops {
		s, ok := o.id.(string)
		if !ok {
			return "", &Failure{Name: in.name, Message: fmt.Sprintf("jq: error: Cannot use %s as object key", describe(o.id))}
		}
		naturals[s] = natural(o.method)
	}
	for _, f := range in.fields {
		naturals[f.name] = fieldNatural(f.name)
	}
	reclassed := map[string]*Object{}
	for _, c := range classes {
		reclassed[c] = q.object(reclassedV[c])
	}
	if q.err != nil {
		return "", jqErr()
	}
	var all []any
	for _, c := range classes {
		all = append(all, strs(reclassed[c].SortedKeys())...)
	}
	if both := dups(all); len(both) > 0 {
		return "", fail("in more than one class: %s", toJSON(both))
	}
	unreasoned := []any{}
	for _, c := range classes {
		for _, e := range q.entries(reclassed[c]) {
			if s, ok := e.value.(string); !ok || s == "" {
				unreasoned = append(unreasoned, e.key)
			}
		}
	}
	if len(unreasoned) > 0 {
		return "", fail("an exception needs a reason: %s", toJSON(unreasoned))
	}
	missing := []any{}
	for _, c := range classes {
		for _, k := range reclassed[c].SortedKeys() {
			if _, ok := naturals[k]; !ok {
				missing = append(missing, k)
			}
		}
	}
	if len(missing) > 0 {
		return "", fail("not in the pinned spec: %s", toJSON(missing))
	}
	same := []any{}
	for _, c := range classes {
		for _, k := range reclassed[c].SortedKeys() {
			if naturals[k] == c {
				same = append(same, k)
			}
		}
	}
	if len(same) > 0 {
		return "", fail("an exception gives an operation the class it has anyway: %s", toJSON(same))
	}
	exception := map[string]string{}
	for _, c := range classes {
		for _, k := range reclassed[c].SortedKeys() {
			exception[k] = c
		}
	}

	// What admit.json names is an operation, admitted by its methods and a
	// docker block, and nothing else.
	if admit != nil {
		var opIDs []any
		for _, o := range ops {
			opIDs = append(opIDs, o.id)
		}
		missing := []any{}
		for _, k := range q.keys(admit) {
			if !contains(opIDs, k) {
				missing = append(missing, k)
			}
		}
		if q.err != nil {
			return "", jqErr()
		}
		if len(missing) > 0 {
			return "", fail("admit.json names what is not in the pinned spec: %s", toJSON(missing))
		}
		odd := []any{}
		for _, e := range q.entries(admit) {
			v, ok := e.value.(*Object)
			bad := !ok
			if !bad {
				k := v.SortedKeys()
				bad = len(k) != 2 || k[0] != "docker" || k[1] != "methods"
			}
			if !bad {
				_, isObj := q.get(v, "docker").(*Object)
				methods, isArr := q.get(v, "methods").([]any)
				bad = !isObj || !isArr || len(methods) == 0
			}
			if bad {
				odd = append(odd, e.key)
			}
		}
		if len(odd) > 0 {
			return "", fail("an admitted operation needs its methods and a docker block, and nothing else: %s", toJSON(odd))
		}
		// Nothing else admits: a hand-written rule, a GraphQL endpoint or a
		// reclassification would be a rule with no docker block, which
		// frisket would pass unfiltered.
		if q.length(rulesV) > 0 || len(endpoints) > 0 || in.graphqlPath != "" || len(exception) > 0 {
			if q.err != nil {
				return "", jqErr()
			}
			return "", fail("an admitted app takes no hand-written rules, GraphQL or classes: admit.json is all it admits")
		}
		if q.err != nil {
			return "", jqErr()
		}
	}

	// A hand-written rule says why it exists, what it is, what class, and
	// exactly one of the two ways a rule matches.
	odd = []any{}
	for _, r := range rules {
		reason := q.get(r, "reason")
		op := q.get(r, "operation")
		bad := !isString(reason) || equal(reason, "") ||
			!isString(q.get(op, "id")) || !isString(q.get(op, "summary")) ||
			!contains(strs(classes), q.get(r, "class")) ||
			(q.get(r, "path") != nil) == (q.get(r, "prefix") != nil)
		if !bad {
			bad = q.length(q.get(r, "methods")) == 0
		}
		if q.err != nil {
			return "", jqErr()
		}
		if bad {
			odd = append(odd, alt(q.get(op, "id"), "?"))
		}
	}
	if q.err != nil {
		return "", jqErr()
	}
	if len(odd) > 0 {
		return "", fail("a hand-written rule needs a reason, an operation id and summary, a class, methods, and one of path or prefix: %s", toJSON(odd))
	}

	// A parameter becomes "*" as a whole segment, even where it shares one
	// with literal text ({scan_id}.png, {event_t}.{event_n}): frisket
	// matches segments, and "*" matching a little more than the spec says
	// is the direction that stays inside one operation.
	for _, o := range ops {
		if len(o.rest) == 0 {
			o.path = prefix + template(o.spec)
		} else {
			o.isPrefix = true
			o.prefix = prefix + template(withoutLastParam(o.spec))
		}
	}

	// A GET answers HEAD too, unless the spec says what a HEAD there is:
	// Docker's /_ping has one of each. Where an app is admitted, its
	// admit.json says which of them are.
	type where struct {
		prefix bool
		s      string
	}
	heads := map[where]bool{}
	for _, o := range ops {
		if o.method == "HEAD" {
			heads[where{o.isPrefix, o.where()}] = true
		}
	}
	var generated []*Object
	for _, o := range ops {
		methods := []any{o.method}
		if o.method == "GET" && !heads[where{o.isPrefix, o.where()}] {
			methods = []any{"GET", "HEAD"}
		}
		var admitted any
		if admit != nil {
			admitted = q.at(admit, o.id)
		}
		if q.err != nil {
			return "", jqErr()
		}
		if admitted != nil {
			extra := minus(q.array(q.get(admitted, "methods")), methods)
			if q.err != nil {
				return "", jqErr()
			}
			if len(extra) > 0 {
				return "", fail("admit.json gives %s %s, and the spec has it for %s", interp(o.id), toJSON(q.get(admitted, "methods")), toJSON(methods))
			}
		}
		rule := NewObject()
		rule.Set("methods", alt(q.get(admitted, "methods"), methods))
		if o.isPrefix {
			rule.Set("prefix", o.prefix)
		} else {
			rule.Set("path", o.path)
		}
		if admit != nil && admitted == nil {
			rule.Set("refuse", true)
		}
		operation := NewObject()
		operation.Set("id", o.id)
		operation.Set("summary", o.summary)
		if !equal(alt(o.description, ""), "") {
			operation.Set("description", o.description)
		}
		class := natural(o.method)
		if c, ok := exception[o.id.(string)]; ok {
			class = c
		}
		operation.Set("class", class)
		if o.category != nil {
			operation.Set("category", o.category)
		}
		rule.Set("operation", operation)
		if admitted != nil {
			rule.Set("docker", q.get(admitted, "docker"))
		}
		generated = append(generated, rule)
	}
	if q.err != nil {
		return "", jqErr()
	}

	// A HAND-WRITTEN RULE MAY NOT DECIDE WHAT THE SPEC ALREADY DOES. frisket
	// takes the most specific rule, segment by segment, so a hand rule with
	// a literal where an operation has a parameter wins wherever the two
	// both match -- /api/models/*/revision/* would admit the jwt of a
	// repository named "revision", which asks. So a rule that can match any
	// path an operation with the same method matches must be of the same
	// class.
	clash := []any{}
	for _, r := range rules {
		for _, g := range generated {
			if equal(q.get(q.get(g, "operation"), "class"), q.get(r, "class")) {
				continue
			}
			gm := q.array(q.get(g, "methods"))
			rm := q.array(q.get(r, "methods"))
			if q.err != nil {
				return "", jqErr()
			}
			if equal(minus(gm, rm), gm) {
				continue
			}
			gw := alt(q.get(g, "path"), q.get(g, "prefix"))
			rw := alt(q.get(r, "path"), q.get(r, "prefix"))
			if !overlaps(q.str(gw), q.get(g, "path") != nil, q.str(rw), q.get(r, "path") != nil) {
				continue
			}
			if q.err != nil {
				return "", jqErr()
			}
			clash = append(clash, interp(q.get(q.get(r, "operation"), "id"))+" and "+interp(q.get(q.get(g, "operation"), "id")))
		}
	}
	if q.err != nil {
		return "", jqErr()
	}
	if len(clash) > 0 {
		return "", fail("a hand-written rule overlaps an operation of another class: %s", toJSON(clash))
	}
	all2 := append([]*Object{}, generated...)
	for _, r := range rules {
		rule := q.object(r).Clone()
		var op *Object
		switch o := q.get(rule, "operation").(type) {
		case nil:
			op = NewObject()
		case *Object:
			op = o.Clone()
		default:
			q.errorf("Cannot index %s with \"class\"", typeName(o))
			op = NewObject()
		}
		class, _ := rule.Get("class")
		op.Set("class", class)
		rule.Set("operation", op)
		rule.Delete("reason")
		rule.Delete("class")
		all2 = append(all2, rule)
	}
	if q.err != nil {
		return "", jqErr()
	}

	// Two operations on one method and template would make the match, and
	// so the words in the dialog, a coin toss -- unless they are the same
	// words and the same class, when they are one operation the spec wrote
	// twice ({slug} and {slug}-{id}, say), and the first id speaks for both.
	get := func(o *Object, k string) any { v, _ := o.Get(k); return v }
	opOf := func(o *Object) any { return get(o, "operation") }
	var merged []*Object
	for _, g := range groupBy(all2, func(o *Object) any {
		return []any{get(o, "methods"), get(o, "path"), get(o, "prefix")}
	}) {
		if len(g) == 1 {
			merged = append(merged, g[0])
			continue
		}
		var sigs []any
		for _, o := range g {
			sigs = append(sigs, []any{q.get(opOf(o), "class"), q.get(opOf(o), "summary"), get(o, "refuse"), get(o, "docker")})
		}
		if q.err != nil {
			return "", jqErr()
		}
		if len(unique(sigs)) == 1 {
			merged = append(merged, sortBy(g, func(o *Object) any { return q.get(opOf(o), "id") })[0])
			continue
		}
		var gids []any
		for _, o := range g {
			gids = append(gids, q.get(opOf(o), "id"))
		}
		joined, err := join(gids, ", ")
		if err != nil {
			return "", &Failure{Name: in.name, Message: "jq: error: " + err.Error()}
		}
		return "", fail("the same method and template twice: %s %s (%s)", toJSON(get(g[0], "methods")), interp(alt(get(g[0], "path"), get(g[0], "prefix"))), joined)
	}

	// A GraphQL endpoint decides every request at its path, so what the
	// spec has there is replaced -- and named, so that it is not replaced
	// unseen.
	odd = []any{}
	for _, e := range endpoints {
		p := q.get(e, "path")
		said := sortBy(q.array(alt(q.get(e, "replaces"), []any{})), func(x any) any { return x })
		there := []any{}
		for _, r := range merged {
			if equal(get(r, "path"), p) {
				there = append(there, q.get(opOf(r), "id"))
			}
		}
		there = sortBy(there, func(x any) any { return x })
		if q.err != nil {
			return "", jqErr()
		}
		if !equal(said, there) {
			odd = append(odd, fmt.Sprintf("%s has %s, and replaces %s", interp(p), toJSON(there), toJSON(said)))
		}
	}
	if len(odd) > 0 {
		return "", fail("a GraphQL endpoint names what the spec has at its path, in `replaces`: %s", toJSON(odd))
	}
	var kept []*Object
	for _, r := range merged {
		if !contains(endpointPaths, get(r, "path")) {
			kept = append(kept, r)
		}
	}

	kept = sortBy(kept, func(o *Object) any {
		var first any
		switch m := get(o, "methods").(type) {
		case []any:
			if len(m) > 0 {
				first = m[0]
			}
		case nil:
		default:
			q.errorf("Cannot index %s with number", typeName(m))
		}
		return []any{alt(get(o, "path"), get(o, "prefix")), first}
	})
	if q.err != nil {
		return "", jqErr()
	}
	if admit != nil {
		neither := []any{}
		for _, r := range kept {
			if equal(get(r, "refuse"), true) == (get(r, "docker") != nil) {
				neither = append(neither, q.get(opOf(r), "id"))
			}
		}
		if len(neither) > 0 {
			return "", fail("a rule of an admitted app is neither refused nor admitted by admit.json: %s", toJSON(neither))
		}
	}
	for _, e := range endpoints {
		rule := NewObject()
		rule.Set("graphql", q.get(e, "path"))
		rule.Set("query", true)
		op := q.object(q.get(e, "operation")).Clone()
		op.Set("class", "read")
		rule.Set("operation", op)
		kept = append(kept, rule)
	}
	for _, f := range sortBy(in.fields, func(f field) any { return []any{f.kind, f.name} }) {
		d := f.description.(string)
		summary := sentence(d)
		description := d
		if truthy(f.deprecated) {
			description += "\n\nDeprecated: " + interp(f.deprecated)
		}
		rule := NewObject()
		rule.Set("graphql", in.graphqlPath)
		rule.Set(f.kind, f.name)
		op := NewObject()
		op.Set("id", f.name)
		op.Set("summary", summary)
		if !equal(description, summary) {
			op.Set("description", description)
		}
		class := fieldNatural(f.name)
		if c, ok := exception[f.name]; ok {
			class = c
		}
		op.Set("class", class)
		if f.category != nil {
			op.Set("category", f.category)
		}
		rule.Set("operation", op)
		kept = append(kept, rule)
	}
	if q.err != nil {
		return "", jqErr()
	}
	lines := make([]string, len(kept))
	for i, r := range kept {
		lines[i] = toJSON(r)
	}
	return "[\n" + strings.Join(lines, ",\n") + "\n]\n", nil
}

func isString(v any) bool {
	_, ok := v.(string)
	return ok
}
