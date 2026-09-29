package generate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// What the generator reads, it reads as jq did, because what it writes is
// compared byte for byte with what jq wrote, and a reviewer reads the diff:
// an object keeps its keys in the order they were first given, a key given
// twice keeps its first place and its last value, and a number is the
// literal it was written as, printed as jq 1.8 prints one. encoding/json's
// maps would sort the keys and its float64s would round the numbers, so a
// value here is one of nil, bool, Number (or Double), string, []any or
// *Object.

// Object is a JSON object in the order its keys were first given.
type Object struct {
	keys []string
	vals map[string]any
}

// NewObject is an empty object.
func NewObject() *Object { return &Object{vals: map[string]any{}} }

// Get is the value at k, and whether there is one.
func (o *Object) Get(k string) (any, bool) {
	v, ok := o.vals[k]
	return v, ok
}

// Set puts v at k: in k's place where it is already given, else last.
func (o *Object) Set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

// Delete removes k.
func (o *Object) Delete(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, key := range o.keys {
		if key == k {
			o.keys = append(o.keys[:i:i], o.keys[i+1:]...)
			return
		}
	}
}

// Keys are the keys in the order they were first given: jq's keys_unsorted.
func (o *Object) Keys() []string { return append([]string(nil), o.keys...) }

// SortedKeys are the keys as jq's keys gives them, by their bytes.
func (o *Object) SortedKeys() []string {
	k := o.Keys()
	sort.Strings(k)
	return k
}

// Len is how many keys.
func (o *Object) Len() int { return len(o.keys) }

// Clone is a shallow copy: jq's values are immutable, so where the program
// changes one, it changes a copy.
func (o *Object) Clone() *Object {
	c := &Object{keys: append([]string(nil), o.keys...), vals: make(map[string]any, len(o.vals))}
	for k, v := range o.vals {
		c.vals[k] = v
	}
	return c
}

// Number is a JSON number, as the literal it was written as.
type Number string

// Double is a number jq holds as a double rather than as a literal: what it
// made of Python's Infinity (the largest double) and NaN (printed as null).
type Double float64

// parseJSON reads every JSON value in data, as jq reads a file: none at all
// is no values, and several are several. dup says whether any object in the
// text gives a key twice -- which jq, like every JSON reader here, would
// quietly resolve to the last.
func parseJSON(data []byte) (values []any, dup bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		v, d, err := readValue(dec)
		if errors.Is(err, io.EOF) {
			return values, dup, nil
		}
		if err != nil {
			return nil, false, err
		}
		dup = dup || d
		values = append(values, v)
	}
}

// readValue reads one value from dec's tokens.
func readValue(dec *json.Decoder) (any, bool, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, false, err
	}
	return fromToken(dec, t)
}

func fromToken(dec *json.Decoder, t json.Token) (any, bool, error) {
	switch t := t.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := NewObject()
			dup := false
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, false, unexpectedEOF(err)
				}
				k, ok := kt.(string)
				if !ok {
					return nil, false, fmt.Errorf("an object key that is not a string: %v", kt)
				}
				if _, seen := o.Get(k); seen {
					dup = true
				}
				v, d, err := readValue(dec)
				if err != nil {
					return nil, false, unexpectedEOF(err)
				}
				dup = dup || d
				o.Set(k, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, false, unexpectedEOF(err)
			}
			return o, dup, nil
		case '[':
			a := []any{}
			dup := false
			for dec.More() {
				v, d, err := readValue(dec)
				if err != nil {
					return nil, false, unexpectedEOF(err)
				}
				dup = dup || d
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, false, unexpectedEOF(err)
			}
			return a, dup, nil
		}
		return nil, false, fmt.Errorf("unexpected %v", t)
	case json.Number:
		return Number(t), false, nil
	case string, bool, nil:
		return t, false, nil
	}
	return nil, false, fmt.Errorf("unexpected token %v", t)
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// toJSON is jq's tojson: compact, keys in their order, a number as jq 1.8
// prints its literal, and a string escaped as jq escapes one -- control
// characters and DEL as \u00xx, everything else, '<' and U+2028 included, as
// it is.
func toJSON(v any) string {
	var b strings.Builder
	writeJSON(&b, v)
	return b.String()
}

func writeJSON(b *strings.Builder, v any) {
	switch v := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case Number:
		b.WriteString(canonicalNumber(string(v)))
	case Double:
		if math.IsNaN(float64(v)) {
			b.WriteString("null")
		} else {
			b.WriteString(strconv.FormatFloat(float64(v), 'g', 17, 64))
		}
	case string:
		writeString(b, v)
	case []any:
		b.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, e)
		}
		b.WriteByte(']')
	case *Object:
		b.WriteByte('{')
		for i, k := range v.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			writeJSON(b, v.vals[k])
		}
		b.WriteByte('}')
	default:
		panic(fmt.Sprintf("generate: not a JSON value: %T", v))
	}
}

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
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
		case r == utf8.RuneError && size == 1:
			// jq holds only UTF-8, and reads a byte that is not as U+FFFD.
			b.WriteString("\uFFFD")
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}

// canonicalNumber is how jq 1.8 prints a number literal it read and did not
// compute with: decNumber's scientific string, which keeps the literal's
// digits and trailing zeros (1.50 stays 1.50) but not its spelling (1e2 is
// 1E+2, 0.1e-5 is 0.000001).
func canonicalNumber(lit string) string {
	s := lit
	neg := false
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	exp := 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return lit
		}
		exp, s = e, s[:i]
	}
	intPart, frac, _ := strings.Cut(s, ".")
	coef := strings.TrimLeft(intPart+frac, "0")
	if coef == "" {
		coef = "0"
	}
	exp -= len(frac)
	adjusted := exp + len(coef) - 1
	var out string
	switch {
	case exp <= 0 && adjusted >= -6:
		if exp == 0 {
			out = coef
		} else if point := len(coef) + exp; point > 0 {
			out = coef[:point] + "." + coef[point:]
		} else {
			out = "0." + strings.Repeat("0", -point) + coef
		}
	default:
		out = coef[:1]
		if len(coef) > 1 {
			out += "." + coef[1:]
		}
		sign := "+"
		if adjusted < 0 {
			sign = "-"
		}
		out += "E" + sign + strconv.Itoa(abs(adjusted))
	}
	if neg {
		out = "-" + out
	}
	return out
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// interp is a value as jq's string interpolation writes it: a string as it
// is, anything else as its JSON.
func interp(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return toJSON(v)
}

// truthy is jq's truth: all but null and false.
func truthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	}
	return true
}

// alt is jq's `a // b` for an a that is one value.
func alt(a, b any) any {
	if truthy(a) {
		return a
	}
	return b
}

func kindOrder(v any) int {
	switch v := v.(type) {
	case nil:
		return 0
	case bool:
		if v {
			return 2
		}
		return 1
	case Number, Double:
		return 3
	case string:
		return 4
	case []any:
		return 5
	case *Object:
		return 6
	}
	panic(fmt.Sprintf("generate: not a JSON value: %T", v))
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case Number, Double:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case *Object:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// compare is jq's order, which sort, group_by and unique use: null, false,
// true, numbers, strings by their bytes, arrays element by element, then
// objects by their sorted keys and then their values in that order.
func compare(a, b any) int {
	ka, kb := kindOrder(a), kindOrder(b)
	if ka != kb {
		return ka - kb
	}
	switch a.(type) {
	case Number, Double:
		x, y := numberValue(a), numberValue(b)
		switch {
		case x == nil:
			return -1
		case y == nil:
			return 1
		}
		return x.Cmp(y)
	}
	switch a := a.(type) {
	case string:
		return strings.Compare(a, b.(string))
	case []any:
		b := b.([]any)
		for i := 0; i < len(a) && i < len(b); i++ {
			if c := compare(a[i], b[i]); c != 0 {
				return c
			}
		}
		return len(a) - len(b)
	case *Object:
		b := b.(*Object)
		ak, bk := a.SortedKeys(), b.SortedKeys()
		for i := 0; i < len(ak) && i < len(bk); i++ {
			if c := strings.Compare(ak[i], bk[i]); c != 0 {
				return c
			}
		}
		if len(ak) != len(bk) {
			return len(ak) - len(bk)
		}
		for _, k := range ak {
			if c := compare(a.vals[k], b.vals[k]); c != 0 {
				return c
			}
		}
	}
	return 0
}

// numberValue is a number's exact value; nil for NaN, which jq orders
// before every number.
func numberValue(n any) *big.Rat {
	switch n := n.(type) {
	case Number:
		r, ok := new(big.Rat).SetString(string(n))
		if !ok {
			return new(big.Rat)
		}
		return r
	case Double:
		if math.IsNaN(float64(n)) {
			return nil
		}
		return new(big.Rat).SetFloat64(float64(n))
	}
	return nil
}

func equal(a, b any) bool { return compare(a, b) == 0 }

// sortBy is jq's sort_by: stable, by key.
func sortBy[T any](xs []T, key func(T) any) []T {
	keys := make([]any, len(xs))
	for i, x := range xs {
		keys[i] = key(x)
	}
	idx := make([]int, len(xs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(i, j int) bool { return compare(keys[idx[i]], keys[idx[j]]) < 0 })
	out := make([]T, len(xs))
	for i, j := range idx {
		out[i] = xs[j]
	}
	return out
}

// groupBy is jq's group_by: sorted by key, and each run of equal keys one
// group, in the order it had.
func groupBy[T any](xs []T, key func(T) any) [][]T {
	sorted := sortBy(xs, key)
	var groups [][]T
	for i, x := range sorted {
		if i > 0 && equal(key(sorted[i-1]), key(x)) {
			groups[len(groups)-1] = append(groups[len(groups)-1], x)
			continue
		}
		groups = append(groups, []T{x})
	}
	return groups
}

// unique is jq's unique: sorted, each value once.
func unique(xs []any) []any {
	out := []any{}
	for _, g := range groupBy(xs, func(x any) any { return x }) {
		out = append(out, g[0])
	}
	return out
}

// dups is jq's `group_by(.) | map(select(length > 1)[0])`.
func dups(xs []any) []any {
	out := []any{}
	for _, g := range groupBy(xs, func(x any) any { return x }) {
		if len(g) > 1 {
			out = append(out, g[0])
		}
	}
	return out
}

// contains is jq's `index($x)` on an array, as a membership test.
func contains(xs []any, x any) bool {
	for _, e := range xs {
		if equal(e, x) {
			return true
		}
	}
	return false
}

// minus is jq's array subtraction: a without every element b has.
func minus(a, b []any) []any {
	out := []any{}
	for _, e := range a {
		if !contains(b, e) {
			out = append(out, e)
		}
	}
	return out
}

func strs(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// join is jq 1.8's join: null as nothing, a string as it is, a number or a
// boolean as its JSON. An array or object in it is an error.
func join(xs []any, sep string) (string, error) {
	var b strings.Builder
	for i, x := range xs {
		if i > 0 {
			b.WriteString(sep)
		}
		switch x := x.(type) {
		case nil:
		case string:
			b.WriteString(x)
		case []any, *Object:
			return "", fmt.Errorf("cannot join with %s", typeName(x))
		default:
			b.WriteString(toJSON(x))
		}
	}
	return b.String(), nil
}

// keyString is a from_entries key: a string as it is, anything else its
// JSON.
func keyString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return toJSON(v)
}
