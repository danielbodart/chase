package generate

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// eval holds the first error of a run of jq-shaped steps -- indexing
// something that cannot be indexed, iterating over what is not a collection
// -- where jq would have stopped with an error of its own rather than with
// one of the program's failures. Each step after the first error does
// nothing, and the caller checks err before it trusts anything computed, as
// bufio.Scanner is used.
type eval struct{ err error }

func (q *eval) errorf(format string, args ...any) {
	if q.err == nil {
		q.err = fmt.Errorf(format, args...)
	}
}

func describe(v any) string {
	s := toJSON(v)
	if len(s) > 11 {
		s = s[:10] + "..."
	}
	return fmt.Sprintf("%s (%s)", typeName(v), s)
}

// get is `.k`: null has nothing at any key, and only an object has keys.
func (q *eval) get(v any, k string) any {
	switch o := v.(type) {
	case nil:
		return nil
	case *Object:
		x, _ := o.Get(k)
		return x
	}
	q.errorf("Cannot index %s with %q", typeName(v), k)
	return nil
}

// at is `.[$k]` where $k may be any value: a string indexes an object, a
// number an array.
func (q *eval) at(v any, k any) any {
	if s, ok := k.(string); ok {
		return q.get(v, s)
	}
	if v == nil {
		return nil
	}
	q.errorf("Cannot index %s with %s", typeName(v), typeName(k))
	return nil
}

// has is `has($k)` on an object, and false on null.
func (q *eval) has(v any, k string) bool {
	switch o := v.(type) {
	case nil:
		return false
	case *Object:
		_, ok := o.Get(k)
		return ok
	}
	q.errorf("Cannot check whether %s has a string key", typeName(v))
	return false
}

// iter is `.[]`: an array's elements, an object's values.
func (q *eval) iter(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case *Object:
		out := make([]any, 0, x.Len())
		for _, k := range x.keys {
			out = append(out, x.vals[k])
		}
		return out
	}
	q.errorf("Cannot iterate over %s", describe(v))
	return nil
}

// tryIter is `.[]?`: what .[] gives, or nothing where it would fail.
func tryIter(v any) []any {
	q := &eval{}
	out := q.iter(v)
	if q.err != nil {
		return nil
	}
	return out
}

// entry is one of to_entries: an object's key is a string, an array's its
// index, a number.
type entry struct {
	key   any
	value any
}

// entries is to_entries: an object's in its order, and an array's by index,
// as jq's keys_unsorted gives both.
func (q *eval) entries(v any) []entry {
	switch x := v.(type) {
	case *Object:
		out := make([]entry, 0, x.Len())
		for _, k := range x.keys {
			out = append(out, entry{k, x.vals[k]})
		}
		return out
	case []any:
		out := make([]entry, 0, len(x))
		for i, e := range x {
			out = append(out, entry{index(i), e})
		}
		return out
	}
	q.errorf("%s has no keys", describe(v))
	return nil
}

// keys is jq's keys: an object's sorted, and an array's indices, numbers.
// An exceptions.json class, or an admit.json, written as an array is taken
// as jq took it: an empty one names nothing, and the indices of another
// fail where jq failed on them.
func (q *eval) keys(v any) []any {
	switch x := v.(type) {
	case *Object:
		return strs(x.SortedKeys())
	case []any:
		out := make([]any, 0, len(x))
		for i := range x {
			out = append(out, index(i))
		}
		return out
	}
	q.errorf("%s has no keys", describe(v))
	return nil
}

// index is an array index as jq holds it.
func index(i int) Number { return Number(strconv.Itoa(i)) }

// object is v where it must be an object to go on.
func (q *eval) object(v any) *Object {
	o, ok := v.(*Object)
	if !ok {
		q.errorf("%s is not an object", describe(v))
		return NewObject()
	}
	return o
}

// array is v where it must be an array to go on.
func (q *eval) array(v any) []any {
	a, ok := v.([]any)
	if !ok {
		q.errorf("%s is not an array", describe(v))
		return nil
	}
	return a
}

// str is v where it must be a string to go on: what split, test and the
// like take.
func (q *eval) str(v any) string {
	s, ok := v.(string)
	if !ok {
		q.errorf("%s cannot be matched, as it is not a string", describe(v))
		return ""
	}
	return s
}

// length is jq's length: of an array or object its size, of a string its
// codepoints, of null 0, of a number its absolute value.
func (q *eval) length(v any) float64 {
	switch x := v.(type) {
	case nil:
		return 0
	case []any:
		return float64(len(x))
	case *Object:
		return float64(x.Len())
	case string:
		return float64(len([]rune(x)))
	case Number, Double:
		r := numberValue(x)
		if r == nil {
			return math.NaN()
		}
		f, _ := r.Float64()
		if f < 0 {
			f = -f
		}
		return f
	}
	q.errorf("%s has no length", describe(v))
	return 0
}

// split is jq's split on a string: the empty string is no parts at all.
func split(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, sep)
}

// ends are where jq's `$` matches in s: its end, and before a final newline.
// (jq's regular expressions are Oniguruma's Perl syntax, in which `$` is \Z,
// not \z.)
func ends(s string) []int {
	if strings.HasSuffix(s, "\n") {
		return []int{len(s), len(s) - 1}
	}
	return []int{len(s)}
}
