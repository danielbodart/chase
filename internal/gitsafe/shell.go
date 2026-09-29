package gitsafe

import (
	"strings"
)

// WHAT THE SHELL DID TO WHAT IT READ. The selector was bash, and bash reads
// what a command prints through a command substitution, a here-string or a
// `read`, each of which changes it a little: trailing newlines go, NUL bytes
// go, fields split on IFS. Those changes decided what the selector saw of a
// path or a URL a session wrote -- which line of a multi-line value is the
// first, which field of a line with a tab in it is the root -- so they are
// kept, here, by name, where each call site says which it is.

// TrimNL is `$(...)`'s end: every trailing newline gone.
func TrimNL(s string) string { return strings.TrimRight(s, "\n") }

// StripNUL is what the shell does to a NUL byte it reads: drops it.
func StripNUL(s string) string { return strings.ReplaceAll(s, "\x00", "") }

// Output is what `$(CMD)` holds of what CMD printed: no NUL bytes, no
// trailing newlines.
func Output(b []byte) string { return TrimNL(StripNUL(string(b))) }

// HereLines is each line `while read ...; done <<< "$S"` reads: S and the
// newline the here-string adds, so every line of S, the last included.
func HereLines(s string) []string { return strings.Split(s, "\n") }

// ReadLines is each line `while read ...; done < FILE` reads: only those a
// newline ends, since read fails on the last one when it does not.
func ReadLines(s string) []string {
	lines := strings.Split(s, "\n")
	return lines[:len(lines)-1]
}

// FirstOf is `${S%%$'\n'*}`: S up to its first newline.
func FirstOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// LastOf is `${S##*$'\n'}`: S after its last newline.
func LastOf(s string) string {
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// Fields is `IFS=IFS read -r V1 ... Vn <<< LINE` of a line with no newline,
// for an IFS of whitespace only (tab, or space tab and newline): leading and
// trailing IFS characters dropped, each run of them one separator, and the
// last variable the rest of the line.
func Fields(line, ifs string, n int) []string {
	out := make([]string, n)
	s := strings.TrimLeft(line, ifs)
	for i := 0; i < n-1; i++ {
		j := strings.IndexAny(s, ifs)
		if j < 0 {
			out[i], s = s, ""
			continue
		}
		out[i] = s[:j]
		s = strings.TrimLeft(s[j:], ifs)
	}
	out[n-1] = strings.TrimRight(s, ifs)
	return out
}

// Read is `IFS=IFS read -r V1 ... Vn <<< "$S"`: the fields of S's first line.
func Read(s, ifs string, n int) []string { return Fields(FirstOf(s), ifs, n) }

// Tab and Blank are the two IFS the selector read with: a tab alone, and the
// default of space, tab and newline.
const (
	Tab   = "\t"
	Blank = " \t\n"
)

// Quote is bash's `printf %q` of s under LC_ALL=C: two single quotes for
// nothing, $'...' for anything with a byte that is not printable ASCII, and
// otherwise s with a backslash before each character the shell would read as
// syntax.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e {
			return ansiC(s)
		}
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case strings.IndexByte(" \t\n!\"$&'()*,;<>?[\\]^`{|}", c) >= 0:
			b.WriteByte('\\')
		case c == '#' && i == 0:
			b.WriteByte('\\')
		case c == '~' && (i == 0 || s[i-1] == ':' || s[i-1] == '='):
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func ansiC(s string) string {
	var b strings.Builder
	b.WriteString("$'")
	for i := 0; i < len(s); i++ {
		c := s[i]
		var e byte
		switch c {
		case 0x1b:
			e = 'E'
		case '\a':
			e = 'a'
		case '\v':
			e = 'v'
		case '\b':
			e = 'b'
		case '\f':
			e = 'f'
		case '\n':
			e = 'n'
		case '\r':
			e = 'r'
		case '\t':
			e = 't'
		case '\\', '\'':
			e = c
		default:
			if c >= 0x20 && c <= 0x7e {
				b.WriteByte(c)
			} else {
				b.WriteByte('\\')
				b.WriteByte('0' + c>>6)
				b.WriteByte('0' + (c>>3)&7)
				b.WriteByte('0' + c&7)
			}
			continue
		}
		b.WriteByte('\\')
		b.WriteByte(e)
	}
	b.WriteByte('\'')
	return b.String()
}
