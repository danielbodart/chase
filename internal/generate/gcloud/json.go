package gcloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// What the generator reads is JSON whose key ORDER matters: a Discovery
// document's methods and resources are walked in the order they are written,
// and where two of them share a template the later one is what gRPC maps to
// (Python's dicts keep insertion order, and the port must walk the same
// way). So JSON is read into an object that keeps its keys in order, as
// Python's json.load does: a key written twice keeps its first place and its
// last value.
type object struct {
	keys []string
	vals map[string]any
}

func (o *object) get(key string) (any, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.vals[key]
	return v, ok
}

func (o *object) set(key string, v any) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

func newObject() *object { return &object{vals: map[string]any{}} }

// loadJSON reads a file as ordered JSON: strings, json.Number, bools, nil,
// []any and *object.
func loadJSON(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := decodeJSON(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

func decodeJSON(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := decodeValue(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("more than one JSON value")
	}
	return v, nil
}

func decodeValue(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t := t.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := newObject()
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				v, err := decodeValue(d)
				if err != nil {
					return nil, err
				}
				o.set(k.(string), v)
			}
			if _, err := d.Token(); err != nil {
				return nil, err
			}
			return o, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := decodeValue(d)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := d.Token(); err != nil {
				return nil, err
			}
			return a, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return t, nil
	}
}

// truthy is Python's truth of a JSON value: what `x or default` and `if x:`
// take for present.
func truthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case json.Number:
		f, err := v.Float64()
		return err != nil || f != 0
	case []any:
		return len(v) > 0
	case *object:
		return len(v.keys) > 0
	}
	return true
}

// pyString is a string as Python's json.dumps writes it: with ensureASCII,
// as its default does (index.json), every character outside printable ASCII
// escaped, astral ones as a surrogate pair; without, as the rules are
// written (ensure_ascii=False), only the quote, the backslash and C0.
func pyString(b *strings.Builder, s string, ensureASCII bool) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(b, `\u%04x`, r)
			case ensureASCII && r > 0x7e && r < 0x10000:
				fmt.Fprintf(b, `\u%04x`, r)
			case ensureASCII && r >= 0x10000:
				r -= 0x10000
				fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800|(r>>10)&0x3ff, 0xdc00|r&0x3ff)
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// pyValue is any decoded JSON value as json.dumps writes it with separators
// (",", ":"). Only an API's title can be something other than what the
// generator builds, so this is where a title that is not a string goes.
func pyValue(b *strings.Builder, v any, ensureASCII bool) {
	switch v := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case string:
		pyString(b, v, ensureASCII)
	case json.Number:
		b.WriteString(pyNumber(v))
	case []any:
		b.WriteByte('[')
		for i, x := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			pyValue(b, x, ensureASCII)
		}
		b.WriteByte(']')
	case *object:
		b.WriteByte('{')
		for i, k := range v.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			pyString(b, k, ensureASCII)
			b.WriteByte(':')
			pyValue(b, v.vals[k], ensureASCII)
		}
		b.WriteByte('}')
	}
}

// pyNumber is a JSON number as Python re-writes it: an integer as itself,
// a float as its repr (the shortest digits that read back the same, in
// exponent form below 1e-4 and from 1e16).
func pyNumber(n json.Number) string {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		if i, ok := new(big.Int).SetString(s, 10); ok {
			return i.String()
		}
		return s
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		if math.IsInf(f, 1) {
			return "Infinity"
		} else if math.IsInf(f, -1) {
			return "-Infinity"
		}
		return s
	}
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	x, _ := strconv.Atoi(exp)
	if x < -4 || x >= 16 {
		sign := "+"
		if x < 0 {
			sign, x = "-", -x
		}
		return fmt.Sprintf("%se%s%02d", mant, sign, x)
	}
	out := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(out, ".") {
		out += ".0"
	}
	return out
}

// jqString is a string as jq writes it: the quote, the backslash and the
// short escapes, every other character below a space and DEL as \u00xx,
// everything else as itself.
func jqString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		s = s[n:]
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// jqPretty is a value as jq writes it by default: two spaces an indent, one
// key or element a line, an empty object or array on one line, and a
// newline at the end. source.json is rewritten by jq, and is read in review,
// so a bump must write it byte for byte as jq did.
func jqPretty(v any) string {
	var b strings.Builder
	jqIndent(&b, v, 0)
	b.WriteByte('\n')
	return b.String()
}

func jqIndent(b *strings.Builder, v any, depth int) {
	pad := func(d int) { b.WriteString(strings.Repeat("  ", d)) }
	switch v := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case string:
		jqString(b, v)
	case json.Number:
		b.WriteString(v.String())
	case []any:
		if len(v) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, x := range v {
			if i > 0 {
				b.WriteString(",\n")
			}
			pad(depth + 1)
			jqIndent(b, x, depth+1)
		}
		b.WriteByte('\n')
		pad(depth)
		b.WriteByte(']')
	case *object:
		if len(v.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range v.keys {
			if i > 0 {
				b.WriteString(",\n")
			}
			pad(depth + 1)
			jqString(b, k)
			b.WriteString(": ")
			jqIndent(b, v.vals[k], depth+1)
		}
		b.WriteByte('\n')
		pad(depth)
		b.WriteByte('}')
	}
}
