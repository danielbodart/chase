// Package term is how chase says anything to a person's terminal.
//
// What chase says can carry what a session wrote -- a path in its checkout, a
// remote's URL, a diff of its flake -- so no control byte but a newline
// reaches the terminal: an escape sequence there could retitle it, redraw
// what the person is reading, or write their clipboard. That is C0 and DEL,
// and C1 too, both as UTF-8 (\xc2\x80 to \xc2\x9f) and as the raw bytes
// (\x80 to \x9f) a terminal not reading UTF-8 acts on. The raw bytes are also
// continuations of other UTF-8 characters, which come out mangled: a refusal
// read wrong is better than one that writes.
package term

import (
	"fmt"
	"io"
)

// Clean is s with every control byte but a newline made a '?': a UTF-8 C1
// character is one '?', and every other byte in C0, DEL or the C1 range is
// one '?' each.
func Clean(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0xc2 && i+1 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x9f:
			out = append(out, '?')
			i++
		case c == '\n':
			out = append(out, c)
		case c < 0x20, c >= 0x7f && c <= 0x9f:
			out = append(out, '?')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// Say writes one line, "chase: " and the message, cleaned, to w.
func Say(w io.Writer, format string, args ...any) {
	fmt.Fprint(w, Clean("chase: "+fmt.Sprintf(format, args...))+"\n")
}
