package term

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"
)

func TestEveryControlByteButANewlineIsMadeSafe(t *testing.T) {
	for in, want := range map[string]string{
		"plain /home/alice/x":            "plain /home/alice/x",
		"two\nlines":                     "two\nlines",
		"\x1b]0;PWNED\x07":               "?]0;PWNED?",
		"tab\there\rcr":                  "tab?here?cr",
		"del\x7f":                        "del?",
		"utf-8 c1 \xc2\x9b31m":           "utf-8 c1 ?31m",
		"raw c1 \x9b31m":                 "raw c1 ?31m",
		"é stays":                        "é stays",
		"\xc2\xa0 is no-break, and kept": "\xc2\xa0 is no-break, and kept",
		// A letter whose UTF-8 has a continuation byte in the C1 range is
		// still itself.
		"ā, ě and Łódź":                      "ā, ě and Łódź",
		"invalid \xff\xc4 bytes":             "invalid ?? bytes",
		"a \u202eright-to-left\u202c trick":  "a ?right-to-left? trick",
		"\u2066isolate\u2069 and \u200emark": "?isolate? and ?mark",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSayPrefixesAndEndsTheLine(t *testing.T) {
	var b bytes.Buffer
	Say(&b, "%s: refused", "/w/\x1b[8m")
	if got := b.String(); got != "chase: /w/?[8m: refused\n" {
		t.Errorf("said %q", got)
	}
}

// Whatever goes in, what comes out is valid UTF-8 with no control
// character but a newline and no bidirectional control.
func TestNothingCleanHoldsAControlCharacter(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		out := Clean(string(rapid.SliceOf(rapid.Byte()).Draw(t, "in")))
		if !utf8.ValidString(out) {
			t.Fatalf("not UTF-8: %q", out)
		}
		if strings.ContainsFunc(out, func(r rune) bool { return r != '\n' && (r < 0x20 || r >= 0x7f && r <= 0x9f || bidi(r)) }) {
			t.Fatalf("%q", out)
		}
	})
}
