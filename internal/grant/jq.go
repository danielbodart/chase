package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/danielbodart/chase/internal/policydoc"
)

// WHAT JQ DID TO A GRANT. The grant was read, compared, shown and
// stored by jq, and some of what jq did is what a person reads -- the
// approval's diff is `jq -S .` of each side -- and some is what is compared
// -- `jq -cS .` of the approved and the proposed. So a grant is held
// here as jq held it: an object's keys in the order they came, a number as
// the literal it was written as and written back as jq writes it
// (policydoc.Number), a string escaped as jq escapes one (policydoc.Quote),
// and values ordered as jq orders them. Nothing here is a general jq: each
// function is one filter the script ran, named where it is used.

// value is one JSON value. kind is '{', '[', '"', '0' (a number), 't', 'f'
// or 'n'.
type value struct {
	kind    byte
	keys    []string
	members map[string]*value
	items   []*value
	text    string
}

var jnull = &value{kind: 'n'}

func jstr(s string) *value { return &value{kind: '"', text: s} }

func jobject() *value { return &value{kind: '{', members: map[string]*value{}} }

// parseJSON reads one JSON value, and nothing after it.
func parseJSON(b []byte) (*value, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("more than one JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (*value, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			v := jobject()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				m, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				// A key given twice is the last one's, where the first was.
				v.set(kt.(string), m)
			}
			_, err := dec.Token()
			return v, err
		case '[':
			v := &value{kind: '['}
			for dec.More() {
				m, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				v.items = append(v.items, m)
			}
			_, err := dec.Token()
			return v, err
		}
	case string:
		return jstr(t), nil
	case json.Number:
		return &value{kind: '0', text: string(t)}, nil
	case bool:
		if t {
			return &value{kind: 't'}, nil
		}
		return &value{kind: 'f'}, nil
	case nil:
		return jnull, nil
	}
	return nil, fmt.Errorf("unexpected %v", tok)
}

// set is `. + {(k): m}`: in its place if k is there, last if it is not.
func (v *value) set(k string, m *value) {
	if _, ok := v.members[k]; !ok {
		v.keys = append(v.keys, k)
	}
	v.members[k] = m
}

// del is `del(.k)`.
func (v *value) del(k string) {
	if _, ok := v.members[k]; !ok {
		return
	}
	delete(v.members, k)
	v.keys = slices.DeleteFunc(v.keys, func(x string) bool { return x == k })
}

// truthy is what jq's `//` keeps: anything but null and false.
func (v *value) truthy() bool { return v != nil && v.kind != 'n' && v.kind != 'f' }

// or is `. // alt`.
func (v *value) or(alt *value) *value {
	if v.truthy() {
		return v
	}
	return alt
}

// typeName is what jq calls v's kind in an error.
func (v *value) typeName() string {
	return map[byte]string{'{': "object", '[': "array", '"': "string", '0': "number", 't': "boolean", 'f': "boolean", 'n': "null"}[v.kind]
}

// index is `.k`: a member, null for one that is not there or of null, and
// jq's error for anything that is not an object.
func (v *value) index(k string) (*value, error) {
	switch v.kind {
	case 'n':
		return jnull, nil
	case '{':
		if m, ok := v.members[k]; ok {
			return m, nil
		}
		return jnull, nil
	}
	return nil, fmt.Errorf("Cannot index %s with %s", v.typeName(), policydoc.Quote(k))
}

// path is .k1.k2...: index, one after another.
func (v *value) path(keys ...string) (*value, error) {
	var err error
	for _, k := range keys {
		if v, err = v.index(k); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// iterate is `.[]`: an array's items, or an object's values in its order.
func (v *value) iterate() ([]*value, error) {
	switch v.kind {
	case '[':
		return v.items, nil
	case '{':
		out := make([]*value, len(v.keys))
		for i, k := range v.keys {
			out[i] = v.members[k]
		}
		return out, nil
	}
	return nil, fmt.Errorf("Cannot iterate over %s", v.describe())
}

// describe is v as jq names it in an error: its kind, and itself.
func (v *value) describe() string {
	s := v.compact()
	if len(s) > 11 {
		s = s[:10] + "..."
	}
	return fmt.Sprintf("%s (%s)", v.typeName(), s)
}

// entries is `to_entries[]` as a key and a value each: an object's in its
// order, an array's by index.
func (v *value) entries() ([]string, []*value, error) {
	switch v.kind {
	case '{':
		vals := make([]*value, len(v.keys))
		for i, k := range v.keys {
			vals[i] = v.members[k]
		}
		return v.keys, vals, nil
	case '[':
		keys := make([]string, len(v.items))
		for i := range v.items {
			keys[i] = strconv.Itoa(i)
		}
		return keys, v.items, nil
	}
	return nil, nil, fmt.Errorf("%s has no keys", v.describe())
}

// length is jq's `length`.
func (v *value) length() (float64, error) {
	switch v.kind {
	case 'n':
		return 0, nil
	case '[':
		return float64(len(v.items)), nil
	case '{':
		return float64(len(v.keys)), nil
	case '"':
		return float64(len([]rune(v.text))), nil
	case '0':
		f := v.number()
		if f < 0 {
			f = -f
		}
		return f, nil
	}
	return 0, fmt.Errorf("%s has no length", v.describe())
}

func (v *value) number() float64 {
	f, _ := strconv.ParseFloat(v.text, 64)
	return f
}

// compact is `jq -c .`; sorted is `jq -cS .`.
func (v *value) compact() string { return v.format(false, false) }
func (v *value) sorted() string  { return v.format(true, false) }

// pretty is `jq .`; prettySorted is `jq -S .`. Neither has the newline jq
// ends its output with.
func (v *value) pretty() string       { return v.format(false, true) }
func (v *value) prettySorted() string { return v.format(true, true) }

func (v *value) format(sortKeys, pretty bool) string {
	var b strings.Builder
	v.write(&b, sortKeys, pretty, 0)
	return b.String()
}

func (v *value) write(b *strings.Builder, sortKeys, pretty bool, depth int) {
	newline := func(d int) {
		if pretty {
			b.WriteByte('\n')
			b.WriteString(strings.Repeat("  ", d))
		}
	}
	switch v.kind {
	case '{':
		if len(v.keys) == 0 {
			b.WriteString("{}")
			return
		}
		keys := v.keys
		if sortKeys {
			keys = slices.Clone(keys)
			slices.Sort(keys)
		}
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			newline(depth + 1)
			b.WriteString(policydoc.Quote(k))
			b.WriteByte(':')
			if pretty {
				b.WriteByte(' ')
			}
			v.members[k].write(b, sortKeys, pretty, depth+1)
		}
		newline(depth)
		b.WriteByte('}')
	case '[':
		if len(v.items) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, m := range v.items {
			if i > 0 {
				b.WriteByte(',')
			}
			newline(depth + 1)
			m.write(b, sortKeys, pretty, depth+1)
		}
		newline(depth)
		b.WriteByte(']')
	case '"':
		b.WriteString(policydoc.Quote(v.text))
	case '0':
		b.WriteString(policydoc.Number(v.text))
	case 't':
		b.WriteString("true")
	case 'f':
		b.WriteString("false")
	case 'n':
		b.WriteString("null")
	}
}

// raw is what `jq -r` prints of v, without its newline: a string as itself,
// anything else as JSON.
func (v *value) raw() string {
	if v.kind == '"' {
		return v.text
	}
	return v.pretty()
}

// tostring is jq's `tostring`, which is also what "\(v)" makes of v.
func (v *value) tostring() string {
	if v.kind == '"' {
		return v.text
	}
	return v.compact()
}

// optional is `.k // empty | -r`, as a command substitution held it: the
// member's raw text if it is truthy, and nothing if it is not.
func (v *value) optional(k string) (string, error) {
	m, err := v.index(k)
	if err != nil {
		return "", err
	}
	if !m.truthy() {
		return "", nil
	}
	return strings.TrimRight(m.raw(), "\n"), nil
}

// rank is where each kind sorts, as jq sorts them.
func (v *value) rank() int {
	return strings.IndexByte("nft0\"[{", v.kind)
}

// compare is jq's order of values: null, false, true, numbers, strings,
// arrays, objects; numbers by value, strings by their bytes, arrays item by
// item, and objects by their sorted keys and then their values in that
// order.
func compare(a, b *value) int {
	if r := a.rank() - b.rank(); r != 0 {
		return r
	}
	switch a.kind {
	case '0':
		x, y := a.number(), b.number()
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	case '"':
		return strings.Compare(a.text, b.text)
	case '[':
		for i := 0; i < len(a.items) && i < len(b.items); i++ {
			if c := compare(a.items[i], b.items[i]); c != 0 {
				return c
			}
		}
		return len(a.items) - len(b.items)
	case '{':
		ka, kb := slices.Sorted(slices.Values(a.keys)), slices.Sorted(slices.Values(b.keys))
		if c := slices.Compare(ka, kb); c != 0 {
			return c
		}
		for _, k := range ka {
			if c := compare(a.members[k], b.members[k]); c != 0 {
				return c
			}
		}
	}
	return 0
}

// join is jq's `join($sep)`: null as nothing, a string as itself, a
// number or a boolean as JSON, and anything else refused.
func join(items []*value, sep string) (string, error) {
	parts := make([]string, len(items))
	for i, x := range items {
		switch x.kind {
		case 'n':
		case '"':
			parts[i] = x.text
		case '0', 't', 'f':
			parts[i] = x.compact()
		default:
			return "", fmt.Errorf("Cannot join with %s", x.typeName())
		}
	}
	return strings.Join(parts, sep), nil
}

// sortValues is jq's `sort`: stable, in jq's order.
func sortValues(items []*value) { slices.SortStableFunc(items, compare) }
