package gcloud

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ruleJSON is a rule as one line of apis/<api>.json: frisket's shape, keys
// in this order, no spaces, and every character but the quote, the
// backslash and C0 as itself (json.dumps(separators=(",", ":"),
// ensure_ascii=False)).
func ruleJSON(r *rule) string {
	var b strings.Builder
	b.WriteString(`{"methods":[`)
	for i, m := range r.methods {
		if i > 0 {
			b.WriteByte(',')
		}
		pyString(&b, m, false)
	}
	b.WriteString(`],`)
	pyString(&b, r.kind, false)
	b.WriteByte(':')
	pyString(&b, r.path, false)
	if r.encodedSlashes {
		b.WriteString(`,"encodedSlashes":true`)
	}
	b.WriteString(`,"operation":{"id":`)
	pyString(&b, r.op.id, false)
	b.WriteString(`,"summary":`)
	pyString(&b, r.op.summary, false)
	if r.op.description != "" {
		b.WriteString(`,"description":`)
		pyString(&b, r.op.description, false)
	}
	b.WriteString(`,"class":`)
	pyString(&b, r.op.class, false)
	b.WriteString(`,"category":`)
	pyString(&b, r.op.category, false)
	b.WriteString(`}}`)
	return b.String()
}

func stringList(b *strings.Builder, items []string) {
	b.WriteByte('[')
	for i, s := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		pyString(b, s, true)
	}
	b.WriteByte(']')
}

func lessStrings(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// write replaces app/apis with one file an API, its rules sorted by
// template, methods and operation and each (methods, template) once, and
// app/index.json with what each API is. Each file is truncated and
// rewritten where it is, as gcloud.py wrote it; an API no longer generated
// has its file removed.
func (g *generator) write() error {
	out := filepath.Join(g.app, "apis")
	if err := os.MkdirAll(out, 0o777); err != nil {
		return err
	}
	existing, err := os.ReadDir(out)
	if err != nil {
		return err
	}
	for _, e := range existing {
		if stem, ok := strings.CutSuffix(e.Name(), ".json"); ok {
			if _, keep := g.apis[stem]; !keep {
				if err := os.Remove(filepath.Join(out, e.Name())); err != nil {
					return err
				}
			}
		}
	}
	var index strings.Builder
	index.WriteString("{\n")
	for i, name := range sortedKeys(setOf(g.apis)) {
		a := g.apis[name]
		sort.SliceStable(a.rules, func(i, j int) bool {
			x, y := a.rules[i], a.rules[j]
			if x.path != y.path {
				return x.path < y.path
			}
			if !slicesEqual(x.methods, y.methods) {
				return lessStrings(x.methods, y.methods)
			}
			return x.op.id < y.op.id
		})
		type seenKey struct{ methods, kind, path string }
		seen := map[seenKey]bool{}
		var rules []*rule
		for _, r := range a.rules {
			k := seenKey{strings.Join(r.methods, "\x00"), r.kind, r.path}
			if seen[k] {
				g.counts["rules one API has twice"]++
				continue
			}
			seen[k] = true
			rules = append(rules, r)
		}
		a.rules = rules
		lines := make([]string, len(rules))
		for i, r := range rules {
			lines[i] = ruleJSON(r)
		}
		if err := os.WriteFile(filepath.Join(out, name+".json"), []byte("[\n"+strings.Join(lines, ",\n")+"\n]\n"), 0o666); err != nil {
			return err
		}

		if i > 0 {
			index.WriteString(",\n")
		}
		pyString(&index, name, true)
		index.WriteString(`:{"title":`)
		pyValue(&index, a.title, true)
		index.WriteString(`,"versions":`)
		stringList(&index, a.versions)
		index.WriteString(`,"hosts":`)
		stringList(&index, sortedKeys(a.hosts))
		index.WriteString(`,"mtls":`)
		stringList(&index, sortedKeys(a.mtls))
		index.WriteString(`,"grpc":`)
		stringList(&index, sortedKeys(a.grpc))
		index.WriteString(`,"streaming":`)
		stringList(&index, sortedKeys(a.streaming))
		index.WriteString(`,"classes":{`)
		first := true
		for _, c := range classes {
			n := 0
			for _, r := range rules {
				if r.op.class == c {
					n++
				}
			}
			if n == 0 {
				continue
			}
			if !first {
				index.WriteByte(',')
			}
			first = false
			fmt.Fprintf(&index, `"%s":%d`, c, n)
		}
		index.WriteString("}}")
	}
	index.WriteString("\n}\n")
	return os.WriteFile(filepath.Join(g.app, "index.json"), []byte(index.String()), 0o666)
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// report says on stderr what was generated, four lines as gcloud.py said
// them.
func (g *generator) report(stderr io.Writer) error {
	var rules, grpc []*rule
	streaming := 0
	for _, name := range g.apiNames {
		a := g.apis[name]
		rules = append(rules, a.rules...)
		streaming += len(a.streaming)
		for _, r := range a.rules {
			if r.grpc {
				grpc = append(grpc, r)
			}
		}
	}
	count := func(rs []*rule) string {
		parts := make([]string, len(classes))
		for i, c := range classes {
			n := 0
			for _, r := range rs {
				if r.op.class == c {
					n++
				}
			}
			parts[i] = fmt.Sprintf("%d %s", n, c)
		}
		return strings.Join(parts, ", ")
	}
	size := int64(0)
	for name := range g.apis {
		info, err := os.Stat(filepath.Join(g.app, "apis", name+".json"))
		if err != nil {
			return err
		}
		size += info.Size()
	}
	ops := map[string]bool{}
	for _, r := range rules {
		ops[r.op.id] = true
	}
	var counted []string
	for _, what := range sortedKeys(setOf(g.counts)) {
		counted = append(counted, fmt.Sprintf("%d %s", g.counts[what], what))
	}
	fmt.Fprintf(stderr, "gcloud: %d APIs, %d rules: %s.\n", len(g.apis), len(rules), count(rules))
	fmt.Fprintf(stderr, "gcloud: of which gRPC %d: %s; streaming %d.\n", len(grpc), count(grpc), streaming)
	fmt.Fprintf(stderr, "gcloud: %d operations; %d templates shared by more than one; %d bytes.\n", len(ops), g.shared, size)
	fmt.Fprintf(stderr, "gcloud: %s.\n", strings.Join(counted, "; "))
	return nil
}

// PinList is what a bump pins: the Discovery documents generated from and
// Discovery's index; every proto the chosen services need, with each of
// their directories' BUILD.bazel and YAML files; and the entries, the
// protos of the chosen services and their mixins, which protoc compiles.
type PinList struct {
	Discovery  []string `json:"discovery"`
	Googleapis []string `json:"googleapis"`
	Entries    []string `json:"entries"`
}

// JSON is the list as gcloud.py's pins printed it: json.dump's default
// separators, no newline at the end.
func (p *PinList) JSON() string {
	var b strings.Builder
	list := func(items []string) {
		b.WriteByte('[')
		for i, s := range items {
			if i > 0 {
				b.WriteString(", ")
			}
			pyString(&b, s, true)
		}
		b.WriteByte(']')
	}
	b.WriteString(`{"discovery": `)
	list(p.Discovery)
	b.WriteString(`, "googleapis": `)
	list(p.Googleapis)
	b.WriteString(`, "entries": `)
	list(p.Entries)
	b.WriteByte('}')
	return b.String()
}

func (g *generator) pins() (*PinList, error) {
	disco := map[string]bool{"discoveries/index.json": true}
	for _, name := range g.docNames {
		for _, d := range g.docs[name] {
			v, _ := d.get("version")
			disco[fmt.Sprintf("discoveries/%s.%s.json", name, pyFormat(v))] = true
		}
	}
	files := g.protos.closure(g.used)
	dirs := map[string]bool{}
	for f := range g.used {
		dirs[dir(f)] = true
	}
	for _, d := range sortedKeys(dirs) {
		entries, err := os.ReadDir(filepath.Join(g.googleapis, d))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Name() == "BUILD.bazel" || strings.HasSuffix(e.Name(), ".yaml") {
				files[pathJoin(d, e.Name())] = true
			}
		}
	}
	return &PinList{Discovery: sortedKeys(disco), Googleapis: sortedKeys(files), Entries: sortedKeys(g.used)}, nil
}

// pathJoin is os.path.join of a directory and a name: the name alone where
// the directory is empty.
func pathJoin(d, name string) string {
	if d == "" {
		return name
	}
	if strings.HasSuffix(d, "/") {
		return d + name
	}
	return d + "/" + name
}
