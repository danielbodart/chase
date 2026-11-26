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
)

// WHAT JQ DID TO A GRANT. The grant was read, compared, shown and
// stored by jq, and some of what jq did is what a person reads -- the
// approval's diff is `jq -S .` of each side -- and some is what is compared
// -- `jq -cS .` of the approved and the proposed. So a grant is held
// here as jq held it: an object's keys in the order they came, a number as
// the literal it was written as and written back as jq writes it
// (number), a string escaped as jq escapes one (jqQuote),
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

// truthy is what jq's `//` keeps: anything but null and false.
func (v *value) truthy() bool { return v != nil && v.kind != 'n' && v.kind != 'f' }

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
	return nil, fmt.Errorf("Cannot index %s with %s", v.typeName(), jqQuote(k))
}

func (v *value) number() float64 {
	f, _ := strconv.ParseFloat(v.text, 64)
	return f
}

// compact is `jq -c .`; sorted is `jq -cS .`.
func (v *value) compact() string { return v.format(false, false) }

// pretty is `jq .`; prettySorted is `jq -S .`. Neither has the newline jq
// ends its output with.
func (v *value) pretty() string { return v.format(false, true) }

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
			b.WriteString(jqQuote(k))
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
		b.WriteString(jqQuote(v.text))
	case '0':
		b.WriteString(number(v.text))
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
