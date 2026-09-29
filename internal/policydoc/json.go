package policydoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// value is JSON as jq holds it: an object's keys in the order they came, and
// a number as the literal it was written as. An envelope is read and written
// back through here, rather than through a map, so that what is stored and
// compared is the bytes jq wrote for the same envelope.
type value struct {
	// kind is '{', '[', '"', '0' (a number), 't', 'f' or 'n'.
	kind    byte
	keys    []string
	members map[string]*value
	items   []*value
	text    string
}

func (v *value) empty() bool {
	switch v.kind {
	case 'n':
		return true
	case '{':
		return len(v.keys) == 0
	case '[':
		return len(v.items) == 0
	}
	return false
}

func (v *value) get(k string) *value {
	if v.kind != '{' {
		return nil
	}
	return v.members[k]
}

func (v *value) del(k string) {
	if _, ok := v.members[k]; !ok {
		return
	}
	delete(v.members, k)
	for i, x := range v.keys {
		if x == k {
			v.keys = append(v.keys[:i:i], v.keys[i+1:]...)
			return
		}
	}
}

// typeName is what jq calls v's type in an error.
func (v *value) typeName() string {
	return map[byte]string{'{': "object", '[': "array", '"': "string", '0': "number", 't': "boolean", 'f': "boolean", 'n': "null"}[v.kind]
}

// parse reads one JSON value, and nothing after it.
func parse(b []byte) (*value, error) {
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
			v := &value{kind: '{', members: map[string]*value{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				m, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				// A key given twice is the last one's, where the first was.
				if _, ok := v.members[k]; !ok {
					v.keys = append(v.keys, k)
				}
				v.members[k] = m
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
		return &value{kind: '"', text: t}, nil
	case json.Number:
		return &value{kind: '0', text: string(t)}, nil
	case bool:
		if t {
			return &value{kind: 't'}, nil
		}
		return &value{kind: 'f'}, nil
	case nil:
		return &value{kind: 'n'}, nil
	}
	return nil, fmt.Errorf("unexpected %v", tok)
}

// compact is v as jq -c writes it.
func (v *value) compact(b *strings.Builder) {
	switch v.kind {
	case '{':
		b.WriteByte('{')
		for i, k := range v.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			quote(b, k)
			b.WriteByte(':')
			v.members[k].compact(b)
		}
		b.WriteByte('}')
	case '[':
		b.WriteByte('[')
		for i, m := range v.items {
			if i > 0 {
				b.WriteByte(',')
			}
			m.compact(b)
		}
		b.WriteByte(']')
	case '"':
		quote(b, v.text)
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

// quote is s as jq writes a string: '"' and '\' escaped, the five controls
// with short escapes by them, every other C0 and DEL as \u00xx, and all else
// -- '/', HTML's characters, U+2028 -- as itself.
func quote(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// number is a JSON number's literal as jq writes one it did not compute:
// decNumber's scientific string of it, so 1e2 is 1E+2 and 1.50e1 is 15.0,
// and the digits written are all kept.
func number(lit string) string {
	sign := ""
	if strings.HasPrefix(lit, "-") {
		sign, lit = "-", lit[1:]
	}
	mant, exp := lit, 0
	if i := strings.IndexAny(lit, "eE"); i >= 0 {
		mant = lit[:i]
		e, err := strconv.Atoi(strings.TrimPrefix(lit[i+1:], "+"))
		if err != nil {
			return sign + lit
		}
		exp = e
	}
	digits := mant
	if i := strings.IndexByte(mant, '.'); i >= 0 {
		digits = mant[:i] + mant[i+1:]
		exp -= len(mant) - i - 1
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		digits = "0"
	}
	n := len(digits)
	adjusted := exp + n - 1
	if exp <= 0 && adjusted >= -6 {
		switch {
		case exp == 0:
			return sign + digits
		case n > -exp:
			return sign + digits[:n+exp] + "." + digits[n+exp:]
		default:
			return sign + "0." + strings.Repeat("0", -exp-n) + digits
		}
	}
	s := digits[:1]
	if n > 1 {
		s += "." + digits[1:]
	}
	if adjusted >= 0 {
		return sign + s + "E+" + strconv.Itoa(adjusted)
	}
	return sign + s + "E-" + strconv.Itoa(-adjusted)
}
