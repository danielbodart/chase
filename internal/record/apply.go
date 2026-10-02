package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/danielbodart/chase/internal/grant"
)

// MERGING A PROPOSAL into the checkout's chase.jsonc is an edit of the
// file a person keeps, not a rewrite of it: it is parsed as HuJSON and each
// entry patched in where it goes, so the file's own comments stay, as do
// the comments beside each entry the proposal holds -- a person may have
// edited the proposal, and what they wrote there comes too. The result is
// formatted as HuJSON formats, and must be a grant chase reads, or nothing
// is written.
//
// An entry already in its list is left. One in another of the same lists
// -- an operation the grant asks about, now allowed -- is moved: a name in
// two lists is a grant approve refuses.

// Change is what a merge did with one entry: added it, moved it from
// another list (From), or found it there already (Kept).
type Change struct {
	Path  []string
	Value string
	From  string
	Kept  bool
}

// lists are the lists each place in a grant has, and so the shape a
// proposal may have: under apps, each app with lists, and ssh's hosts;
// network's allow; seccomp's allow and deny.
var (
	appLists     = []string{"allow", "ask", "refuse"}
	seccompLists = []string{"allow", "deny"}
)

// item is one entry of a proposal: the list it goes in, the lists it may
// be in instead, and its value, with the comments before it.
type item struct {
	path     []string
	siblings []string
	value    hujson.Value
}

// items is every entry of proposal, or why proposal is not one: anything
// but the lists a grant has is refused, so an apply never writes to a
// grant what a proposal could not have held.
func items(proposal []byte) ([]item, error) {
	v, err := hujson.Parse(proposal)
	if err != nil {
		return nil, err
	}
	root, ok := v.Value.(*hujson.Object)
	if !ok {
		return nil, errors.New("a proposal is an object")
	}
	var out []item
	var walkLists func(at []string, o *hujson.Object, lists []string) error
	walkLists = func(at []string, o *hujson.Object, lists []string) error {
		for _, m := range o.Members {
			name := m.Name.Value.(hujson.Literal).String()
			if !slices.Contains(lists, name) {
				return fmt.Errorf("%s: a proposal holds only %s", strings.Join(append(at, name), "."), strings.Join(lists, ", "))
			}
			a, ok := m.Value.Value.(*hujson.Array)
			if !ok {
				return fmt.Errorf("%s is not a list", strings.Join(append(at, name), "."))
			}
			for _, e := range a.Elements {
				out = append(out, item{path: append(slices.Clone(at), name), siblings: lists, value: e})
			}
		}
		return nil
	}
	object := func(at []string, v hujson.Value) (*hujson.Object, error) {
		o, ok := v.Value.(*hujson.Object)
		if !ok {
			return nil, fmt.Errorf("%s is not an object", strings.Join(at, "."))
		}
		return o, nil
	}
	for _, m := range root.Members {
		name := m.Name.Value.(hujson.Literal).String()
		o, err := object([]string{name}, m.Value)
		if err != nil {
			return nil, err
		}
		switch name {
		case "network":
			err = walkLists([]string{name}, o, []string{"allow"})
		case "seccomp":
			err = walkLists([]string{name}, o, seccompLists)
		case "apps":
			for _, am := range o.Members {
				app := am.Name.Value.(hujson.Literal).String()
				ao, err := object([]string{name, app}, am.Value)
				if err != nil {
					return nil, err
				}
				switch {
				case slices.Contains(grantApps, app):
					err = walkLists([]string{name, app}, ao, appLists)
				case app == "ssh":
					for _, hm := range ao.Members {
						if hm.Name.Value.(hujson.Literal).String() != "hosts" {
							return nil, errors.New("apps.ssh: a proposal holds only hosts")
						}
						hosts, err := object([]string{name, app, "hosts"}, hm.Value)
						if err != nil {
							return nil, err
						}
						for _, h := range hosts.Members {
							host := h.Name.Value.(hujson.Literal).String()
							ho, err := object([]string{name, app, "hosts", host}, h.Value)
							if err != nil {
								return nil, err
							}
							if err := walkLists([]string{name, app, "hosts", host}, ho, appLists); err != nil {
								return nil, err
							}
						}
					}
				default:
					err = fmt.Errorf("apps.%s: a proposal holds only %s and ssh", app, strings.Join(grantApps, ", "))
				}
				if err != nil {
					return nil, err
				}
			}
		default:
			err = fmt.Errorf("%s: a proposal holds only apps, network and seccomp", name)
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// pointer is path as a JSON pointer.
func pointer(path []string) string {
	var b strings.Builder
	for _, k := range path {
		b.WriteString("/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(k))
	}
	return b.String()
}

// standard is v as compact JSON, its comments gone: what two entries are
// compared by.
func standard(v hujson.Value) string {
	// Standardize on a copy of the bytes: a Value's comments are slices of
	// the text it was parsed from, which Standardize blanks in place.
	s, err := hujson.Standardize(hujson.Value{Value: v.Value}.Pack())
	if err != nil {
		return ""
	}
	var b bytes.Buffer
	json.Compact(&b, s)
	return b.String()
}

// remove takes the entry at i out of the list at path, by an RFC 6902
// remove, which keeps the comments around it with its neighbours.
func remove(g *hujson.Value, path []string, i int) error {
	return g.Patch([]byte(fmt.Sprintf(`[{"op": "remove", "path": %s}]`, marshal(fmt.Sprintf("%s/%d", pointer(path), i)))))
}

// layout is how a composite is written: on many lines, its contents at
// indent, its closing bracket at outer; or on one.
type layout struct {
	multi         bool
	indent, outer string
}

// editor adds members and entries to a grant as the file already lays
// itself out: on many lines, at its own indentation, where the object or
// list is; on one line where it is.
type editor struct {
	// unit is the file's indentation, a level's.
	unit string
}

// indentOf is what follows the last line break in e, or false for an e
// with none: the indentation of what comes after it.
func indentOf(e hujson.Extra) (string, bool) {
	i := bytes.LastIndexByte(e, '\n')
	if i < 0 {
		return "", false
	}
	return string(e[i+1:]), true
}

// layoutOf is how the composite v, whose own line is at outer and whose
// parent is laid out as parent, is laid out: as its contents are, or, with
// none, as its parent.
func (ed editor) layoutOf(v hujson.ValueTrimmed, outer string, parent bool) layout {
	var first hujson.Extra
	var after hujson.Extra
	n := 0
	switch c := v.(type) {
	case *hujson.Object:
		if n = len(c.Members); n > 0 {
			first = c.Members[0].Name.BeforeExtra
		}
		after = c.AfterExtra
	case *hujson.Array:
		if n = len(c.Elements); n > 0 {
			first = c.Elements[0].BeforeExtra
		}
		after = c.AfterExtra
	}
	if in, ok := indentOf(first); ok {
		return layout{multi: true, indent: in, outer: outer}
	}
	if n > 0 {
		_, multi := indentOf(after)
		return layout{multi: multi, indent: outer + ed.unit, outer: outer}
	}
	return layout{multi: parent, indent: outer + ed.unit, outer: outer}
}

// lead is what goes before a new member or entry of a composite laid out
// as l, with n before it, and its comments, each its own // line where
// the composite is on many lines and /* */ where it is on one.
func lead(l layout, n int, notes []string) hujson.Extra {
	var b bytes.Buffer
	if l.multi {
		for _, c := range notes {
			b.WriteString("\n" + l.indent + "// " + c)
		}
		b.WriteString("\n" + l.indent)
		return b.Bytes()
	}
	if n > 0 {
		b.WriteString(" ")
	}
	for _, c := range notes {
		b.WriteString("/* " + strings.ReplaceAll(c, "*/", "* /") + " */ ")
	}
	return b.Bytes()
}

// appended adds v to the composite c, laid out as l, after its last: with
// a trailing comma where the last had one, or, in a composite it opens on
// many lines, as a grant written by hand has one.
func appended(c hujson.ValueTrimmed, l layout, v *hujson.Value) {
	switch c := c.(type) {
	case *hujson.Object:
		trailing := l.multi
		if n := len(c.Members); n > 0 {
			trailing = c.Members[n-1].Value.AfterExtra != nil
		} else if l.multi {
			c.AfterExtra = hujson.Extra("\n" + l.outer)
		}
		if trailing {
			v.AfterExtra = hujson.Extra{}
		}
	case *hujson.Array:
		trailing := l.multi
		if n := len(c.Elements); n > 0 {
			trailing = c.Elements[n-1].AfterExtra != nil
		} else if l.multi {
			c.AfterExtra = hujson.Extra("\n" + l.outer)
		}
		if trailing {
			v.AfterExtra = hujson.Extra{}
		}
		c.Elements = append(c.Elements, *v)
	}
}

// member is the member name of the object at v, laid out as l, made an
// empty list (last) or object when it is not there; and how it is laid
// out.
func (ed editor) member(v *hujson.Value, l layout, name string, last bool) (*hujson.Value, layout, error) {
	o, ok := v.Value.(*hujson.Object)
	if !ok {
		return nil, layout{}, fmt.Errorf("%s is not an object", name)
	}
	for i := range o.Members {
		m := &o.Members[i]
		if m.Name.Value.(hujson.Literal).String() == name {
			outer, ok := indentOf(m.Name.BeforeExtra)
			if !ok {
				outer = l.outer
			}
			return &m.Value, ed.layoutOf(m.Value.Value, outer, l.multi), nil
		}
	}
	var empty hujson.ValueTrimmed = &hujson.Object{}
	if last {
		empty = &hujson.Array{}
	}
	m := hujson.ObjectMember{
		Name:  hujson.Value{BeforeExtra: lead(l, len(o.Members), nil), Value: hujson.String(name)},
		Value: hujson.Value{BeforeExtra: hujson.Extra(" "), Value: empty},
	}
	// appended's trailing comma goes after the member's value.
	trailing := hujson.Value{}
	appended(o, l, &trailing)
	m.Value.AfterExtra = trailing.AfterExtra
	o.Members = append(o.Members, m)
	at := &o.Members[len(o.Members)-1]
	return &at.Value, layout{multi: l.multi, indent: l.indent + ed.unit, outer: l.indent}, nil
}

// notes are the comments in e, each without its // or /* */.
func notes(e hujson.Extra) []string {
	var out []string
	for len(e) > 0 {
		e = e[len(e)-len(bytes.TrimLeft(e, " \t\r\n")):]
		switch {
		case bytes.HasPrefix(e, []byte("//")):
			line, rest, _ := bytes.Cut(e[2:], []byte("\n"))
			out = append(out, strings.TrimSpace(string(line)))
			e = rest
		case bytes.HasPrefix(e, []byte("/*")):
			body, rest, _ := bytes.Cut(e[2:], []byte("*/"))
			out = append(out, strings.TrimSpace(string(body)))
			e = rest
		default:
			return out
		}
	}
	return out
}

// unitOf is the file's indentation: its first member's, or two spaces.
func unitOf(g hujson.Value) string {
	if o, ok := g.Value.(*hujson.Object); ok && len(o.Members) > 0 {
		if in, ok := indentOf(o.Members[0].Name.BeforeExtra); ok && in != "" {
			return in
		}
	}
	return "  "
}

// Merge is current -- a checkout's chase.jsonc, or nil for none -- with
// each entry of proposal in it, and what was done with each. What it
// returns is a grant ParseFile reads, or an error and nothing.
func Merge(current, proposal []byte) ([]byte, []Change, error) {
	its, err := items(proposal)
	if err != nil {
		return nil, nil, fmt.Errorf("the proposal: %w", err)
	}
	if len(bytes.TrimSpace(current)) == 0 {
		current = []byte("{}\n")
	}
	g, err := hujson.Parse(slices.Clone(current))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", grant.FileName, err)
	}
	if _, ok := g.Value.(*hujson.Object); !ok {
		return nil, nil, fmt.Errorf("%s is not an object", grant.FileName)
	}
	ed := editor{unit: unitOf(g)}
	var changes []Change
	for _, it := range its {
		want := standard(it.value)
		parent := it.path[:len(it.path)-1]
		list := it.path[len(it.path)-1]
		c := Change{Path: it.path, Value: want}
		for _, l := range append([]string{list}, it.siblings...) {
			at := g.Find(pointer(append(slices.Clone(parent), l)))
			if at == nil {
				continue
			}
			a, ok := at.Value.(*hujson.Array)
			if !ok {
				return nil, nil, fmt.Errorf("%s is not a list", strings.Join(append(slices.Clone(parent), l), "."))
			}
			i := slices.IndexFunc(a.Elements, func(e hujson.Value) bool { return standard(e) == want })
			switch {
			case i < 0:
			case l == list:
				c.Kept = true
			case c.From == "":
				if err := remove(&g, append(slices.Clone(parent), l), i); err != nil {
					return nil, nil, err
				}
				c.From = l
			}
			if c.Kept {
				break
			}
		}
		changes = append(changes, c)
		if c.Kept {
			continue
		}
		at, l := &g, ed.layoutOf(g.Value, "", true)
		for i, k := range it.path {
			if at, l, err = ed.member(at, l, k, i == len(it.path)-1); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", strings.Join(it.path[:i], "."), err)
			}
		}
		a := at.Value.(*hujson.Array)
		v := hujson.Value{BeforeExtra: lead(l, len(a.Elements), notes(it.value.BeforeExtra)), Value: it.value.Value}
		appended(a, l, &v)
	}
	out := g.Pack()
	// ParseFile standardizes what it is given in place.
	if _, err := grant.ParseFile(slices.Clone(out)); err != nil {
		return nil, nil, fmt.Errorf("with the proposal, %s would not be a grant: %w", grant.FileName, err)
	}
	return out, changes, nil
}
