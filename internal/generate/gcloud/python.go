package gcloud

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// The classification was written in Python, and what it writes is committed
// and reviewed as a diff: a port that splits a description at another
// space, or lower-cases a path another way, would rewrite lines nothing
// changed. So where Python's string semantics differ from Go's, these are
// Python's.

// pySpace is Python's str.isspace, which str.split(), str.strip() and a
// regular expression's \s all use: Go's unicode.IsSpace and the ASCII
// separators U+001C to U+001F, which Python counts and Go does not.
func pySpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// pyStrip is str.strip() with no argument.
func pyStrip(s string) string { return strings.TrimFunc(s, pySpace) }

// pyFields is str.split() with no argument.
func pyFields(s string) []string { return strings.FieldsFunc(s, pySpace) }

// pyLower is str.lower(): Go's per-rune lower case, but for the one
// character whose lower case is two, U+0130, which Python lowers to i and a
// combining dot above.
func pyLower(s string) string {
	if !strings.ContainsRune(s, 0x130) {
		return strings.ToLower(s)
	}
	var b strings.Builder
	for _, r := range s {
		if r == 0x130 {
			b.WriteString("i̇")
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// pyRepr is repr() of a string: in single quotes unless it holds one and no
// double quote, with the backslash, the quote, \t \n \r and every character
// Python does not print escaped.
func pyRepr(s string) string {
	q := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == rune(q) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f || unicode.IsPrint(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(q)
	return b.String()
}

// pyList is repr() of a list of strings.
func pyList(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = pyRepr(s)
	}
	return "[" + strings.Join(out, ", ") + "]"
}

// sortedKeys is sorted(set): code point order, which for UTF-8 is byte
// order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
