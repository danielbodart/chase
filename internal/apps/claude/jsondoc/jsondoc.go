// Package jsondoc edits a JSON document the way the jq filters it replaces
// did: keys stay in the order the file had them, a number keeps the literal it
// was written as, and what comes out is laid out as jq lays it out -- two
// spaces, one member a line. The files it edits are other programs' own
// (~/.claude.json, ~/.codex/auth.json), so what it does not mean to change it
// leaves as it found it rather than re-encoding it through a Go map.
//
// Field access and assignment follow jq's rules, errors included, since which
// document the scripts refused was part of what they did: `.k` of an object
// is its member or null, of null is null, and of anything else an error; `.k
// = v` makes an object of null and is an error on anything but an object.
package jsondoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Kind is which of JSON's six a Value is.
type Kind int

const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

func (k Kind) String() string {
	return [...]string{"null", "boolean", "number", "string", "array", "object"}[k]
}

// Value is one JSON value. Num is a number's literal as written; Obj keeps
// its members in order.
type Value struct {
	Kind Kind
	Bool bool
	Num  string
	Str  string
	Arr  []Value
	Obj  []Member
}

// Member is one key of an object and its value.
type Member struct {
	Key   string
	Value Value
}

// Str is s as a JSON string.
func Str(s string) Value { return Value{Kind: String, Str: s} }

// True is JSON true.
var True = Value{Kind: Bool, Bool: true}

// Obj is an object of the given members, in order.
func Obj(members ...Member) Value { return Value{Kind: Object, Obj: members} }

// Parse reads exactly one JSON value, as `jq . FILE` or `--argjson` would
// accept it: whitespace around it is fine, a second value or anything else
// after it is not. A key given twice keeps its first place and its last
// value, as jq does.
func Parse(data []byte) (Value, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return Value{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			err = errors.New("more than one JSON value")
		}
		return Value{}, err
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (Value, error) {
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return Value{}, io.ErrUnexpectedEOF
		}
		return Value{}, err
	}
	switch t := tok.(type) {
	case nil:
		return Value{Kind: Null}, nil
	case bool:
		return Value{Kind: Bool, Bool: t}, nil
	case json.Number:
		return Value{Kind: Number, Num: string(t)}, nil
	case string:
		return Str(t), nil
	case json.Delim:
		switch t {
		case '[':
			v := Value{Kind: Array, Arr: []Value{}}
			for dec.More() {
				e, err := parseValue(dec)
				if err != nil {
					return Value{}, err
				}
				v.Arr = append(v.Arr, e)
			}
			if _, err := dec.Token(); err != nil {
				return Value{}, err
			}
			return v, nil
		case '{':
			v := Value{Kind: Object, Obj: []Member{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return Value{}, err
				}
				k, ok := kt.(string)
				if !ok {
					return Value{}, fmt.Errorf("object key %v is not a string", kt)
				}
				e, err := parseValue(dec)
				if err != nil {
					return Value{}, err
				}
				v = v.set(k, e)
			}
			if _, err := dec.Token(); err != nil {
				return Value{}, err
			}
			return v, nil
		}
	}
	return Value{}, fmt.Errorf("unexpected JSON token %v", tok)
}

// Truthy is jq's truth: everything but null and false.
func (v Value) Truthy() bool {
	return !(v.Kind == Null || (v.Kind == Bool && !v.Bool))
}

// Or is jq's `v // alt`: v unless it is null or false.
func (v Value) Or(alt Value) Value {
	if v.Truthy() {
		return v
	}
	return alt
}

// Field is jq's `.key`.
func (v Value) Field(key string) (Value, error) {
	switch v.Kind {
	case Null:
		return Value{Kind: Null}, nil
	case Object:
		for _, m := range v.Obj {
			if m.Key == key {
				return m.Value, nil
			}
		}
		return Value{Kind: Null}, nil
	}
	return Value{}, fmt.Errorf("cannot index %s with %q", v.Kind, key)
}

// SetField is jq's `.key = x`: the member replaced where it stands, or added
// last.
func (v Value) SetField(key string, x Value) (Value, error) {
	switch v.Kind {
	case Null:
		return Obj(Member{key, x}), nil
	case Object:
		return v.set(key, x), nil
	}
	return Value{}, fmt.Errorf("cannot index %s with %q", v.Kind, key)
}

// set is SetField on an object, never sharing the members it was given.
func (v Value) set(key string, x Value) Value {
	obj := make([]Member, len(v.Obj), len(v.Obj)+1)
	copy(obj, v.Obj)
	for i := range obj {
		if obj[i].Key == key {
			obj[i].Value = x
			return Value{Kind: Object, Obj: obj}
		}
	}
	return Value{Kind: Object, Obj: append(obj, Member{key, x})}
}

// Split is jq's `split(sep)` on a string: nothing at all from the empty
// string, where strings.Split would give one empty piece.
func Split(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, sep)
}

// Marshal is v as jq prints it, without the newline jq ends with.
func (v Value) Marshal() []byte {
	var b bytes.Buffer
	v.write(&b, 0)
	return b.Bytes()
}

// Raw is v as `jq -r` prints it, without its newline: a string's own text,
// anything else as Marshal.
func (v Value) Raw() string {
	if v.Kind == String {
		return v.Str
	}
	return string(v.Marshal())
}

func (v Value) write(b *bytes.Buffer, depth int) {
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		if v.Bool {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case Number:
		b.WriteString(v.Num)
	case String:
		writeString(b, v.Str)
	case Array:
		if len(v.Arr) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[")
		for i, e := range v.Arr {
			if i > 0 {
				b.WriteString(",")
			}
			newline(b, depth+1)
			e.write(b, depth+1)
		}
		newline(b, depth)
		b.WriteString("]")
	case Object:
		if len(v.Obj) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{")
		for i, m := range v.Obj {
			if i > 0 {
				b.WriteString(",")
			}
			newline(b, depth+1)
			writeString(b, m.Key)
			b.WriteString(": ")
			m.Value.write(b, depth+1)
		}
		newline(b, depth)
		b.WriteString("}")
	}
}

func newline(b *bytes.Buffer, depth int) {
	b.WriteByte('\n')
	for range depth {
		b.WriteString("  ")
	}
}

// writeString escapes as jq does: the quote, the backslash, the five short
// escapes, and every other C0 byte and DEL as \u00xx; everything else,
// non-ASCII included, as itself.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(b, `\u%04x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}
