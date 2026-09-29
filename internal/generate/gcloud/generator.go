package gcloud

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Failed is the generator's refusal: every way the classification it would
// write is wrong, one a line. Nothing is written when it is returned.
type Failed struct {
	Problems []string
}

func (f *Failed) Error() string { return strings.Join(f.Problems, "\n") }

// operation is what a rule's operation says: frisket's shape.
type operation struct {
	id, summary, description, class, category string
}

// rule is one of frisket's path rules: methods and a template, a path or a
// prefix, and the operation it is.
type rule struct {
	methods        []string
	kind           string // "path" or "prefix"
	path           string
	encodedSlashes bool
	op             *operation
	grpc           bool // one of the gRPC rules at POST /package.Service/Method
}

type api struct {
	title      any
	versions   []string
	hosts      map[string]bool
	mtls       map[string]bool
	rules      []*rule
	continuing []*rule
	grpc       map[string]bool
	streaming  map[string]bool
}

type restKey struct {
	api, verb, kind, path string
}

type restHit struct {
	api, id, class string
}

type slashKey struct{ api, param string }

// generator is one run of the classification: what it read, and what it
// has used of the exceptions, so that one naming nothing is refused.
type generator struct {
	app, discoveries, googleapis string
	source, exceptions           *object
	protos                       *protos

	whole    *object            // exceptions.apis: the APIs guarded whole
	patterns map[string]*object // exceptions.patterns: a method name's class
	slashed  *object            // exceptions.encodedSlashes
	explicit map[string]string  // an operation's own exception's class

	usedIDs      map[string]bool
	usedAPIs     map[string]bool
	usedPatterns map[string]bool
	usedSlashes  map[slashKey]bool
	usedBatch    bool
	usedResume   bool

	natural   map[string]map[string]bool // what each operation would be without its own exception
	continued map[string]bool

	docs     map[string][]*object
	docNames []string
	apis     map[string]*api
	apiNames []string // in the order they were made
	problems []string
	counts   map[string]int
	shared   int
	used     map[string]bool // the entries of the chosen services, which pins names

	err error // the first thing read that was not what the generator reads
}

// Generate is `gcloud.py generate`: the classification from Discovery
// documents in discoveries, the googleapis checkout's BUILD.bazel and
// service configs in googleapis, and protoc's descriptor set of the entries,
// written to app/apis/<api>.json and app/index.json. What it did is said on
// stderr. A *Failed is every way the result would be wrong; nothing is
// written then.
func Generate(app, discoveries, googleapis, descriptors, entries string, stderr io.Writer) error {
	g, err := newGenerator(app, discoveries, googleapis, descriptors, entries)
	if err != nil {
		return err
	}
	if err := g.generate(); err != nil {
		return err
	}
	if err := g.write(); err != nil {
		return err
	}
	return g.report(stderr)
}

// Pins is `gcloud.py pins`: after the same classification, the files it
// read, as {"discovery": [...], "googleapis": [...], "entries": [...]}.
func Pins(app, discoveries, googleapis, descriptors, entries string) (*PinList, error) {
	g, err := newGenerator(app, discoveries, googleapis, descriptors, entries)
	if err != nil {
		return nil, err
	}
	if err := g.generate(); err != nil {
		return nil, err
	}
	return g.pins()
}

func newGenerator(app, discoveries, googleapis, descriptors, entries string) (*generator, error) {
	g := &generator{app: app, discoveries: discoveries, googleapis: googleapis}
	var err error
	if g.source, err = loadObject(filepath.Join(app, "source.json")); err != nil {
		return nil, err
	}
	if g.exceptions, err = loadObject(filepath.Join(app, "exceptions.json")); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(entries)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, e := range pyFields(string(b)) {
		names[e] = true
	}
	if g.protos, err = loadProtos(descriptors, names); err != nil {
		return nil, err
	}
	g.counts = map[string]int{}
	return g, nil
}

func loadObject(path string) (*object, error) {
	v, err := loadJSON(path)
	if err != nil {
		return nil, err
	}
	o, ok := v.(*object)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object", path)
	}
	return o, nil
}

// fail records a problem, as gcloud.py wrote one: the first forty items as
// a Python list, and how many there are.
func (g *generator) fail(what string, items []string) {
	if len(items) == 0 {
		return
	}
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	more := ""
	if len(sorted) > 40 {
		sorted, more = sorted[:40], " ..."
	}
	g.problems = append(g.problems, fmt.Sprintf("%s: %s%s (%d)", what, pyList(sorted), more, len(items)))
}

func (g *generator) failSet(what string, set map[string]bool) { g.fail(what, sortedKeys(set)) }

// bad records the first thing read that is not what the generator reads:
// where gcloud.py stopped with a traceback, the port stops with it.
func (g *generator) bad(format string, args ...any) {
	if g.err == nil {
		g.err = fmt.Errorf(format, args...)
	}
}

// member is o[key] as an object, or an empty one where it is missing: what
// `o.get(key, {})` is where the value is then iterated.
func (g *generator) member(o *object, key, where string) *object {
	v, ok := o.get(key)
	if !ok {
		return newObject()
	}
	m, ok := v.(*object)
	if !ok {
		g.bad("%s.%s is not an object", where, key)
		return newObject()
	}
	return m
}

// str is o[key] as a string: required.
func (g *generator) str(o *object, key, where string) string {
	v, ok := o.get(key)
	s, isString := v.(string)
	if !ok || !isString {
		g.bad("%s has no string %s", where, key)
	}
	return s
}

// optional is o.get(key, def) as a string.
func (g *generator) optional(o *object, key, def, where string) string {
	v, ok := o.get(key)
	if !ok {
		return def
	}
	s, isString := v.(string)
	if !isString {
		g.bad("%s: %s is not a string", where, key)
	}
	return s
}

// orString is `o.get(key) or def` as a string.
func (g *generator) orString(o *object, key, def, where string) string {
	v, _ := o.get(key)
	if !truthy(v) {
		return def
	}
	s, isString := v.(string)
	if !isString {
		g.bad("%s: %s is not a string", where, key)
	}
	return s
}

func asObject(v any) *object {
	if o, ok := v.(*object); ok {
		return o
	}
	return newObject()
}

var unstable = regexp.MustCompile(`alpha|beta|preview`)

// documents is the Discovery documents generated from: each API's
// preferred version and every stable one, and any source.json names.
func (g *generator) documents() error {
	v, err := loadJSON(filepath.Join(g.discoveries, "index.json"))
	if err != nil {
		return err
	}
	itemsV, _ := asObject(v).get("items")
	items, ok := itemsV.([]any)
	if !ok {
		return errors.New("Discovery's index has no items")
	}
	extra := g.member(g.member(g.source, "discovery", "source.json"), "versions", "source.json discovery")
	type entry struct{ id, name, version string }
	var index []entry
	ids := map[string]bool{}
	chosen := map[string]bool{}
	for _, it := range items {
		o := asObject(it)
		e := entry{g.str(o, "id", "an index item"), g.str(o, "name", "an index item"), g.str(o, "version", "an index item")}
		index = append(index, e)
		ids[e.id] = true
		preferred, _ := o.get("preferred")
		if truthy(preferred) || !unstable.MatchString(e.version) {
			chosen[e.id] = true
		}
	}
	missing := map[string]bool{}
	for _, k := range extra.keys {
		chosen[k] = true
		if !ids[k] {
			missing[k] = true
		}
	}
	g.failSet("versions not in Discovery's index", missing)
	sort.SliceStable(index, func(i, j int) bool { return index[i].id < index[j].id })
	g.docs = map[string][]*object{}
	for _, e := range index {
		path := filepath.Join(g.discoveries, e.name+"."+e.version+".json")
		if !chosen[e.id] {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		d, err := loadObject(path)
		if err != nil {
			return err
		}
		if _, ok := g.docs[e.name]; !ok {
			g.docNames = append(g.docNames, e.name)
		}
		g.docs[e.name] = append(g.docs[e.name], d)
	}
	without := map[string]bool{}
	for _, k := range extra.keys {
		found := false
		for _, name := range g.docNames {
			for _, d := range g.docs[name] {
				if id, _ := d.get("id"); id == k {
					found = true
				}
			}
		}
		if !found {
			without[k] = true
		}
	}
	g.failSet("versions without a document at the pinned commit", without)
	return g.err
}

// classify is an operation's class: its API's, where the whole API is
// guarded; else its own exception's; else what its name or method says.
func (g *generator) classify(id, base string, apiName *string) string {
	if g.natural[id] == nil {
		g.natural[id] = map[string]bool{}
	}
	g.natural[id][base] = true
	if apiName != nil {
		if _, ok := g.whole.get(*apiName); ok {
			g.usedAPIs[*apiName] = true
			return "guarded"
		}
	}
	if c, ok := g.explicit[id]; ok {
		g.usedIDs[id] = true
		return c
	}
	return base
}

// base is what a method's name says, where a pattern names it, else what
// its HTTP method says.
func (g *generator) base(leaf, verb string) string {
	if p := g.patterns[leaf]; p != nil && len(p.keys) > 0 {
		g.usedPatterns[leaf] = true
		c, _ := p.vals["class"].(string)
		return c
	}
	return natural(verb)
}

func (g *generator) generate() error {
	ex := g.exceptions
	g.whole = g.member(ex, "apis", "exceptions.json")
	patterns := g.member(ex, "patterns", "exceptions.json")
	g.patterns = map[string]*object{}
	for _, k := range patterns.keys {
		p, ok := patterns.vals[k].(*object)
		if !ok {
			g.bad("exceptions.json: patterns.%s is not an object", k)
			p = newObject()
		}
		g.patterns[k] = p
	}
	g.slashed = g.member(ex, "encodedSlashes", "exceptions.json")
	g.explicit = map[string]string{}
	byClass := map[string]*object{}
	for _, c := range classes {
		byClass[c] = g.member(ex, c, "exceptions.json")
		for _, id := range byClass[c].keys {
			if _, ok := g.explicit[id]; ok {
				g.fail("in more than one class", []string{id})
			}
			g.explicit[id] = c
		}
	}
	var reasonless []string
	for _, c := range classes {
		for _, k := range byClass[c].keys {
			if r, ok := byClass[c].vals[k].(string); !ok || r == "" {
				reasonless = append(reasonless, k)
			}
		}
	}
	for _, k := range g.whole.keys {
		if r, ok := g.whole.vals[k].(string); !ok || r == "" {
			reasonless = append(reasonless, k)
		}
	}
	for _, a := range g.slashed.keys {
		ps := g.member(g.slashed, a, "exceptions.json encodedSlashes")
		for _, k := range ps.keys {
			if r, ok := ps.vals[k].(string); !ok || r == "" {
				reasonless = append(reasonless, a+"."+k)
			}
		}
	}
	for _, k := range patterns.keys {
		p := g.patterns[k]
		reason, _ := p.get("reason")
		class, _ := p.get("class")
		c, _ := class.(string)
		if !truthy(reason) || classIndex(c) < 0 {
			reasonless = append(reasonless, k)
		}
	}
	g.fail("an exception needs a reason", reasonless)
	g.usedIDs, g.usedAPIs, g.usedPatterns = map[string]bool{}, map[string]bool{}, map[string]bool{}
	g.usedSlashes = map[slashKey]bool{}
	g.natural = map[string]map[string]bool{}
	g.continued = map[string]bool{}

	if err := g.documents(); err != nil {
		return err
	}
	g.apis = map[string]*api{}
	rest := map[restKey]restHit{}
	for _, name := range g.docNames {
		g.rest(name, rest)
	}
	if g.err != nil {
		return g.err
	}

	if err := g.grpc(rest); err != nil {
		return err
	}
	g.uncontinued()

	unused := map[string]bool{}
	for id := range g.explicit {
		if !g.usedIDs[id] {
			unused[id] = true
		}
	}
	g.failSet("exceptions that name no operation", unused)
	unused = map[string]bool{}
	for _, a := range g.whole.keys {
		if !g.usedAPIs[a] {
			unused[a] = true
		}
	}
	g.failSet("APIs guarded whole that are not generated", unused)
	unused = map[string]bool{}
	for _, p := range patterns.keys {
		if !g.usedPatterns[p] {
			unused[p] = true
		}
	}
	g.failSet("patterns that match no operation", unused)
	unused = map[string]bool{}
	for _, a := range g.slashed.keys {
		for _, p := range asObject(g.slashed.vals[a]).keys {
			if !g.usedSlashes[slashKey{a, p}] {
				unused[a+"."+p] = true
			}
		}
	}
	g.failSet("encodedSlashes that name no parameter", unused)
	if batch, _ := ex.get("batch"); g.usedBatch && !truthy(batch) {
		g.fail("batch has no reason, and APIs have batch paths", []string{"batch"})
	}
	if resumable, _ := ex.get("resumable"); g.usedResume && !truthy(resumable) {
		g.fail("resumable has no reason, and APIs have resumable uploads", []string{"resumable"})
	}
	clash := map[string]bool{}
	for id := range g.continued {
		if _, ok := g.natural[id]; ok {
			clash[id] = true
		}
	}
	g.failSet("an upload's continuation has an operation's own id", clash)
	for _, c := range classes {
		var anyway []string
		for id, cls := range g.explicit {
			if n := g.natural[id]; cls == c && len(n) == 1 && n[c] {
				anyway = append(anyway, id)
			}
		}
		g.fail(fmt.Sprintf("an exception gives the class it has anyway (%s)", c), anyway)
	}
	g.invariants()
	if g.err != nil {
		return g.err
	}
	if len(g.problems) > 0 {
		return &Failed{Problems: g.problems}
	}
	return nil
}

// rest is one API's Discovery documents as rules: every method at its
// template, its uploads' and download's, and the batch path; and each
// method at its HTTP method and template in rest, for gRPC to find.
func (g *generator) rest(name string, rest map[restKey]restHit) {
	a := &api{hosts: map[string]bool{}, mtls: map[string]bool{}, grpc: map[string]bool{}, streaming: map[string]bool{}}
	ds := g.docs[name]
	slashed := g.member(g.slashed, name, "exceptions.json encodedSlashes")
	_, wholeAPI := g.whole.get(name)
	for _, d := range ds {
		where := "Discovery document " + name
		a.versions = append(a.versions, g.str(d, "version", where))
		a.hosts[hostOf(g.str(d, "rootUrl", where))] = true
		if eps, ok := d.get("endpoints"); ok {
			list, _ := eps.([]any)
			for _, e := range list {
				a.hosts[hostOf(g.str(asObject(e), "endpointUrl", where))] = true
			}
		}
		if v, _ := d.get("mtlsRootUrl"); truthy(v) {
			a.mtls[hostOf(g.orString(d, "mtlsRootUrl", "", where))] = true
		}
		sp := g.optional(d, "servicePath", "", where)

		var walk func(node *object)
		walk = func(node *object) {
			methods, _ := node.get("methods")
			ms := asObject(methods)
			for _, k := range ms.keys {
				g.method(name, a, asObject(ms.vals[k]), sp, slashed, wholeAPI, rest)
			}
			resources, _ := node.get("resources")
			rs := asObject(resources)
			for _, k := range rs.keys {
				walk(asObject(rs.vals[k]))
			}
		}
		walk(d)

		if v, _ := d.get("batchPath"); truthy(v) {
			g.usedBatch = true
			title := name
			if t, ok := d.get("title"); ok {
				title = pyFormat(t)
			}
			a.rules = append(a.rules, &rule{methods: []string{"POST"}, kind: "path", path: "/" + g.orString(d, "batchPath", "", where), op: &operation{
				id: name + ".batch", summary: "A batch of " + title + " requests in one, each a whole request frisket cannot see.",
				class: "guarded", category: name}})
		}
	}
	if t, ok := ds[0].get("title"); ok {
		a.title = t
	} else {
		a.title = name
	}
	g.apis[name] = a
	g.apiNames = append(g.apiNames, name)
}

// pyFormat is a JSON value as an f-string writes it, for a title that is
// not a string.
func pyFormat(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case nil:
		return "None"
	case bool:
		if v {
			return "True"
		}
		return "False"
	}
	var b strings.Builder
	pyValue(&b, v, false)
	return b.String()
}

func (g *generator) method(name string, a *api, m *object, sp string, slashed *object, wholeAPI bool, rest map[restKey]restHit) {
	where := "a method of " + name
	id := g.str(m, "id", where)
	verb := g.str(m, "httpMethod", where)
	path := g.str(m, "path", where)
	rel := g.orString(m, "flatPath", path, where)
	leaf := id[strings.LastIndexByte(id, '.')+1:]
	apiName := name
	cls := g.classify(id, g.base(leaf, verb), &apiName)
	descV, _ := m.get("description")
	desc := ""
	if truthy(descV) {
		s, ok := descV.(string)
		if !ok {
			g.bad("%s: %s's description is not a string", where, id)
		}
		desc = s
	}
	summary, description := words(id, desc)
	op := &operation{id: id, summary: summary, description: description, class: cls, category: name}
	flat := g.optional(m, "flatPath", "", where)
	enc := false
	for _, p := range slashed.keys {
		if strings.Contains(path+flat, "{"+p+"}") {
			enc = true
			g.usedSlashes[slashKey{name, p}] = true
		}
	}
	methods := []string{verb}
	if verb == "GET" {
		methods = []string{"GET", "HEAD"}
	}
	paramsV, _ := m.get("parameters")
	params := newObject()
	if truthy(paramsV) {
		params = asObject(paramsV)
	}
	shapes := func(p, flat string) []shape {
		if flat == "" {
			flat = p
		}
		out := []shape{{"path", template(flat)}}
		seen := map[shape]bool{out[0]: true}
		for _, s := range spans(p, params) {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		return out
	}
	own := shapes(sp+path, sp+rel)
	for _, s := range own {
		rest[restKey{name, verb, s.kind, pyLower(s.path)}] = restHit{name, id, cls}
	}
	type pathRule struct {
		methods []string
		shape
	}
	var paths []pathRule
	for _, s := range own {
		paths = append(paths, pathRule{methods, s})
	}
	upload, _ := m.get("mediaUpload")
	protocolsV, _ := asObject(upload).get("protocols")
	protocols := newObject()
	if truthy(protocolsV) {
		protocols = asObject(protocolsV)
	}
	for _, k := range protocols.keys {
		for _, s := range shapes(g.str(asObject(protocols.vals[k]), "path", where), "") {
			paths = append(paths, pathRule{[]string{verb}, s})
		}
	}
	_, resumable := protocols.get("resumable")
	simple, hasSimple := protocols.get("simple")
	if resumable && hasSimple && verb != "PUT" {
		g.usedResume = true
		class := "read"
		if wholeAPI {
			class = "guarded"
		}
		more := &operation{id: id + ".continue", summary: "Continues an upload that " + id + " began: the next chunk of a request already decided.",
			class: class, category: name}
		g.continued[more.id] = true
		for _, s := range shapes(g.str(asObject(simple), "path", where), "") {
			a.continuing = append(a.continuing, &rule{methods: []string{"PUT"}, kind: s.kind, path: s.path, encodedSlashes: enc, op: more})
		}
	}
	if v, _ := m.get("useMediaDownloadService"); truthy(v) {
		for _, s := range shapes("/download/"+sp+path, "/download/"+sp+rel) {
			paths = append(paths, pathRule{methods, s})
		}
	}
	for _, p := range paths {
		a.rules = append(a.rules, &rule{methods: p.methods, kind: p.kind, path: p.path, encodedSlashes: enc, op: op})
	}
}

// grpc makes each gRPC method a rule at POST /package.Service/Method: the
// Discovery operation its google.api.http rule names, or one of its own.
func (g *generator) grpc(rest map[restKey]restHit) error {
	byHost := map[string][]rpc{}
	var hosts []string
	for _, r := range g.protos.rpcs {
		if r.host != "" && !mixins[r.service] {
			if _, ok := byHost[r.host]; !ok {
				hosts = append(hosts, r.host)
			}
			byHost[r.host] = append(byHost[r.host], r)
		}
	}
	yamls, err := g.serviceYAMLs()
	if err != nil {
		return err
	}
	apiOfHost := map[string]string{}
	for _, name := range g.docNames {
		for _, d := range g.docs[name] {
			root, _ := d.get("rootUrl")
			s, _ := root.(string)
			apiOfHost[hostOf(s)] = name
		}
	}
	chosen := map[string]map[string]bool{}
	for _, host := range hosts {
		rpcs := byHost[host]
		name := apiOfHost[host]
		if name == "" {
			name, _, _ = strings.Cut(host, ".")
		}
		services := map[string]bool{}
		if _, ok := g.apis[name]; ok {
			for _, r := range rpcs {
				for _, b := range r.http {
					if _, hit := g.lookup(rest, name, b.verb, b.path); hit {
						services[r.service] = true
					}
				}
			}
			withHTTP := map[string]bool{}
			for _, r := range rpcs {
				if len(r.http) > 0 {
					withHTTP[r.service] = true
				}
			}
			var bare []rpc
			for _, r := range rpcs {
				if !withHTTP[r.service] {
					bare = append(bare, r)
				}
			}
			if len(bare) > 0 {
				best := rankOf(bare[0])
				for _, r := range bare[1:] {
					if rk := rankOf(r); rk.compare(best) > 0 {
						best = rk
					}
				}
				for _, r := range bare {
					if rankOf(r).compare(best) == 0 {
						services[r.service] = true
					}
				}
			}
		} else {
			best := rankOf(rpcs[0])
			for _, r := range rpcs[1:] {
				if rk := rankOf(r); rk.compare(best) > 0 {
					best = rk
				}
			}
			versions := map[string]bool{}
			for _, r := range rpcs {
				if rankOf(r).compare(best) == 0 {
					services[r.service] = true
				}
			}
			for _, r := range rpcs {
				if services[r.service] {
					versions[packageVersion(r.pkg)] = true
				}
			}
			a := &api{title: host, versions: sortedKeys(versions), hosts: map[string]bool{host: true}, mtls: map[string]bool{},
				grpc: map[string]bool{}, streaming: map[string]bool{}}
			if strings.HasSuffix(host, ".googleapis.com") {
				a.mtls[strings.ReplaceAll(host, ".googleapis.com", ".mtls.googleapis.com")] = true
			}
			g.apis[name] = a
			g.apiNames = append(g.apiNames, name)
		}
		if chosen[name] == nil {
			chosen[name] = map[string]bool{}
		}
		for s := range services {
			chosen[name][s] = true
		}
		if len(services) > 0 {
			g.apis[name].hosts[host] = true
		}
	}

	rpcsOf := map[string][]rpc{}
	var mixinRPCs []rpc
	for _, r := range g.protos.rpcs {
		rpcsOf[r.service] = append(rpcsOf[r.service], r)
		if mixins[r.service] {
			mixinRPCs = append(mixinRPCs, r)
		}
	}
	g.used = map[string]bool{}
	restOps := map[string]*operation{}
	for _, name := range g.apiNames {
		for _, r := range g.apis[name].rules {
			restOps[r.op.id] = r.op
		}
	}
	for _, name := range sortedKeys(setOf(chosen)) {
		a := g.apis[name]
		grpc := map[string]bool{}
		for s := range chosen[name] {
			file := rpcsOf[s][0].file
			g.used[file] = true
			only, err := g.restOnly(file)
			if err != nil {
				return err
			}
			if !only {
				grpc[s] = true
			}
		}
		served := map[string]bool{}
		for s := range grpc {
			for m := range yamls[dir(rpcsOf[s][0].file)] {
				served[m] = true
			}
		}
		var all []rpc
		for s := range chosen[name] {
			all = append(all, rpcsOf[s]...)
		}
		sort.SliceStable(all, func(i, j int) bool { return all[i].path < all[j].path })
		for _, r := range mixinRPCs {
			if served[r.service] {
				g.used[r.file] = true
				all = append(all, r)
			}
		}
		for _, r := range all {
			mixin := mixins[r.service]
			mapped := map[string]bool{}
			if !mixin {
				for _, b := range r.http {
					if hit, ok := g.lookup(rest, name, b.verb, b.path); ok {
						mapped[hit.id] = true
					}
				}
			}
			leaf := strings.ToLower(r.method[:1]) + r.method[1:]
			verb := aipVerb(r.method)
			if len(r.http) > 0 {
				verb = r.http[0].verb
			}
			var base string
			if len(mapped) > 0 {
				best := -1
				for _, id := range sortedKeys(mapped) {
					if c := restOps[id].class; classIndex(c) > best {
						best, base = classIndex(c), c
					}
				}
			} else {
				base = g.base(leaf, verb)
			}
			if len(r.http) == 0 && !mixin {
				g.counts["classed by name"]++
			}
			var apiName *string
			category := r.service
			if !mixin {
				n := name
				apiName, category = &n, name
			}
			summary, description := words(r.name, r.comment)
			op := &operation{id: r.name, summary: summary, description: description, class: g.classify(r.name, base, apiName), category: category}
			if grpc[r.service] || mixin {
				a.rules = append(a.rules, &rule{methods: []string{"POST"}, kind: "path", path: r.path, op: op, grpc: true})
				a.grpc[r.service] = true
				if r.streaming {
					a.streaming[op.id] = true
				}
			}
			if !mixin {
				for _, b := range r.http {
					if _, hit := g.lookup(rest, name, b.verb, b.path); hit {
						continue
					}
					tpl, prefix, ok := protoTemplate(b.path)
					if !ok {
						g.counts["HTTP rules no template can say"]++
						continue
					}
					methods := []string{b.verb}
					if b.verb == "GET" {
						methods = []string{"GET", "HEAD"}
					}
					kind := "path"
					if prefix {
						kind = "prefix"
					}
					a.rules = append(a.rules, &rule{methods: methods, kind: kind, path: tpl, op: op})
				}
			}
		}
	}
	return nil
}

func setOf[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func rankOf(r rpc) rank { return versionRank(packageVersion(r.pkg)) }

// uncontinued adds each upload's continuing PUT, but where some method's
// own PUT has that template: that is the method's first request, and keeps
// its class.
func (g *generator) uncontinued() {
	type key struct {
		prefix bool
		path   string
	}
	own := map[key]bool{}
	for _, name := range g.apiNames {
		for _, r := range g.apis[name].rules {
			for _, m := range r.methods {
				if m == "PUT" {
					own[key{r.kind == "prefix", pyLower(r.path)}] = true
				}
			}
		}
	}
	for _, name := range g.apiNames {
		a := g.apis[name]
		continuing := a.continuing
		a.continuing = nil
		var kept []*rule
		for _, r := range continuing {
			if !own[key{r.kind == "prefix", pyLower(r.path)}] {
				kept = append(kept, r)
			}
		}
		g.counts["continuations a method's own PUT decides"] += len(continuing) - len(kept)
		a.rules = append(a.rules, kept...)
	}
}

func (g *generator) lookup(rest map[restKey]restHit, apiName, verb, path string) (restHit, bool) {
	tpl, prefix, ok := protoTemplate(path)
	if !ok {
		return restHit{}, false
	}
	kind := "path"
	if prefix {
		kind = "prefix"
	}
	hit, ok := rest[restKey{apiName, verb, kind, pyLower(tpl)}]
	return hit, ok
}

// restOnly is whether a proto's directory builds its clients for REST
// alone: its services are then served by the REST rules, not at a gRPC
// path.
func (g *generator) restOnly(file string) (bool, error) {
	path := filepath.Join(g.googleapis, dir(file), "BUILD.bazel")
	if _, err := os.Stat(path); err != nil {
		return false, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	text := string(b)
	return strings.Contains(text, `transport = "rest"`) && !strings.Contains(text, `transport = "grpc`), nil
}

// serviceYAMLs is, for each directory of a proto with services, the
// mixins its service configs name.
func (g *generator) serviceYAMLs() (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	dirs := map[string]bool{}
	for _, r := range g.protos.rpcs {
		dirs[dir(r.file)] = true
	}
	for _, d := range sortedKeys(dirs) {
		full := filepath.Join(g.googleapis, d)
		if info, err := os.Stat(full); err != nil || !info.IsDir() {
			continue
		}
		entries, err := os.ReadDir(full)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(full, e.Name()))
			if err != nil {
				return nil, err
			}
			service, apis, err := serviceConfig(string(b))
			if err != nil {
				// gcloud.py failed here, on what PyYAML refused or
				// what it could not take a name from; this refuses
				// what it cannot read, rather than lose a mixin.
				return nil, fmt.Errorf("%s: %w", filepath.ToSlash(filepath.Join(d, e.Name())), err)
			}
			if !service {
				continue
			}
			if out[d] == nil {
				out[d] = map[string]bool{}
			}
			for _, n := range apis {
				if mixins[n] {
					out[d][n] = true
				}
			}
		}
	}
	return out, nil
}

type tableKey struct {
	method string
	prefix bool
	path   string
}

type classed struct{ class, id string }

// invariants: one path table for every host, so two operations at one
// method and template are one class, whichever APIs they are in.
func (g *generator) invariants() {
	table := map[tableKey]map[classed]bool{}
	var order []tableKey
	ids := map[string]map[string]bool{}
	for _, name := range g.apiNames {
		for _, r := range g.apis[name].rules {
			for _, m := range r.methods {
				k := tableKey{m, r.kind == "prefix", pyLower(r.path)}
				if table[k] == nil {
					table[k] = map[classed]bool{}
					order = append(order, k)
				}
				table[k][classed{r.op.class, r.op.id}] = true
			}
			if ids[r.op.id] == nil {
				ids[r.op.id] = map[string]bool{}
			}
			ids[r.op.id][r.op.class] = true
		}
	}
	var two []string
	for _, k := range order {
		v := table[k]
		cs := map[string]bool{}
		var said []string
		for c := range v {
			cs[c.class] = true
			said = append(said, c.id+" "+c.class)
		}
		if len(cs) > 1 {
			sort.Strings(said)
			two = append(two, fmt.Sprintf("%s %s (%s)", k.method, k.path, strings.Join(said, ", ")))
		}
	}
	g.fail("one method and template, two classes", two)
	var twice []string
	for id, cs := range ids {
		if len(cs) > 1 {
			twice = append(twice, id)
		}
	}
	g.fail("one operation, two classes", twice)
	unmatchable := map[string]bool{}
	for _, name := range g.apiNames {
		for _, r := range g.apis[name].rules {
			if !matchable(r.path) {
				unmatchable[r.path] = true
			}
		}
	}
	g.failSet("a path frisket could not match as written", unmatchable)
	g.shared = 0
	for _, v := range table {
		idsHere := map[string]bool{}
		for c := range v {
			idsHere[c.id] = true
		}
		if len(idsHere) > 1 {
			g.shared++
		}
	}
	g.failSet("a less strict operation of another API is more specific than a stricter one", g.outranked())
}

// outranked: frisket takes the most specific rule, so on one path table a
// literal of one API where another has "*" decides that API's requests. A
// "*:verb" is Google's own custom method wherever it is, and is not
// counted.
func (g *generator) outranked() map[string]bool {
	type entry struct {
		api  string
		cls  int
		segs []string
		id   string
	}
	type bucket struct {
		method string
		n      int
	}
	by := map[bucket][]entry{}
	for _, name := range g.apiNames {
		for _, r := range g.apis[name].rules {
			if r.kind != "path" {
				continue
			}
			segs := strings.Split(pyLower(r.path), "/")[1:]
			for _, m := range r.methods {
				k := bucket{m, len(segs)}
				by[k] = append(by[k], entry{name, classIndex(r.op.class), segs, r.op.id})
			}
		}
	}
	out := map[string]bool{}
	for _, rules := range by {
		for _, x := range rules {
			for _, y := range rules {
				if y.api == x.api || y.cls >= x.cls {
					continue
				}
				all := true
				for i := range x.segs {
					if !meet(x.segs[i], y.segs[i]) {
						all = false
						break
					}
				}
				if !all {
					continue
				}
				for i := range x.segs {
					a, b := x.segs[i], y.segs[i]
					if a == b {
						continue
					}
					if a == "*" && !strings.HasPrefix(b, "*") {
						out[y.id+" over "+x.id] = true
					}
					break
				}
			}
		}
	}
	return out
}
