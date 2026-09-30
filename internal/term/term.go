// Package term is how chase says anything to a person's terminal.
//
// What chase says can carry what a session wrote -- a path in its checkout, a
// remote's URL, a diff of its flake -- so no control character but a newline
// reaches the terminal: an escape sequence there could retitle it, redraw
// what the person is reading, or write their clipboard. That is C0, DEL and
// C1. Nor does a bidirectional control, which a terminal does not act on but
// which reorders how the text around it is shown, so a path or a diff put in
// front of the person approving it could read as something it is not.
//
// It is read as UTF-8, as the terminals chase writes to read it: a letter of
// any script is itself, and a byte that is not part of valid UTF-8 is a '?'.
// A terminal that is not reading UTF-8 would take some bytes of valid
// characters -- continuations from 0x80 to 0x9f -- for C1 controls; chase
// does not write for one.
package term

import (
	"fmt"
	"io"
	"unicode/utf8"
)

// Clean is s with every control character but a newline, every
// bidirectional control and every byte of invalid UTF-8 made one '?' each.
func Clean(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			out = append(out, '?')
		case r == '\n':
			out = append(out, '\n')
		case r < 0x20, r >= 0x7f && r <= 0x9f, bidi(r):
			out = append(out, '?')
		default:
			out = append(out, s[i:i+n]...)
		}
		i += n
	}
	return string(out)
}

// bidi is whether r is one of Unicode's bidirectional formatting controls:
// the marks, the embeddings and overrides, and the isolates.
func bidi(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		0x202a <= r && r <= 0x202e || 0x2066 <= r && r <= 0x2069
}

// Say writes one line, "chase: " and the message, cleaned, to w.
func Say(w io.Writer, format string, args ...any) {
	fmt.Fprint(w, Clean("chase: "+fmt.Sprintf(format, args...))+"\n")
}
