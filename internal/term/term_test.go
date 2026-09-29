package term

import (
	"bytes"
	"strings"
	"testing"

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
		// A continuation byte in the C1 range, of a character that is not
		// C1, is mangled rather than passed.
		"ā": "\xc4?",
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

// Whatever goes in, nothing a terminal acts on comes out but a newline.
func TestNothingCleanHoldsAControlByte(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		out := Clean(string(rapid.SliceOf(rapid.Byte()).Draw(t, "in")))
		if strings.ContainsFunc(out, func(r rune) bool { return r != '\n' && (r < 0x20 || r >= 0x7f && r <= 0x9f) }) {
			t.Fatalf("%q", out)
		}
		for i := 0; i < len(out); i++ {
			if c := out[i]; c != '\n' && (c < 0x20 || c >= 0x7f && c <= 0x9f) {
				t.Fatalf("byte %#x in %q", c, out)
			}
		}
	})
}
