package gitsafe_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/danielbodart/chase/internal/gitsafe"
)

// bash is the shell the selector was, to hold what is kept of it to.
func bash(t *testing.T) string {
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	return p
}

func TestQuoteIsBashsPrintfQ(t *testing.T) {
	b := bash(t)
	check := func(t interface{ Fatalf(string, ...any) }, s string) {
		cmd := exec.Command(b, "-c", `printf %q "$1"`, "-", s)
		cmd.Env = []string{"LC_ALL=C"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("bash: %v", err)
		}
		if got := gitsafe.Quote(s); got != string(out) {
			t.Fatalf("Quote(%q) = %q, bash gives %q", s, got, out)
		}
	}
	for _, s := range []string{"", "refs/heads/a..b", "a b", "é", "~x", "#a", "a#b", "a=~b", "a:~b", "x~", "a,b", "it's", "\x1b[31m", "\t\n", "\\", "\x7f\x80\xff", "a\x00b"[:1]} {
		check(t, s)
	}
	rapid.Check(t, func(r *rapid.T) {
		s := rapid.StringOfN(rapid.SampledFrom([]rune("aZ/.~#=:, \t\n'\"\\$`!*?[]{}()<>|&;^%@-+\x01\x1b\x7f\u00e9")), 0, 12, -1).Draw(r, "s")
		check(r, s)
	})
}

func TestFieldsIsBashsRead(t *testing.T) {
	b := bash(t)
	check := func(t interface{ Fatalf(string, ...any) }, s, ifs string, n int) {
		vars := []string{"a", "b", "c", "d", "e"}[:n]
		script := `IFS="$1" read -r ` + strings.Join(vars, " ") + ` <<< "$2"; printf '%s\0' ` + "\"$" + strings.Join(vars, "\" \"$") + "\""
		cmd := exec.Command(b, "-c", script, "-", ifs, s)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("bash: %v", err)
		}
		want := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
		got := gitsafe.Read(s, ifs, n)
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("Read(%q, %q, %d) = %q, bash gives %q", s, ifs, n, got, want)
		}
	}
	check(t, "\t\tx\t\ty\t z\t\t", gitsafe.Tab, 3)
	check(t, "  x   y  z  ", gitsafe.Blank, 2)
	rapid.Check(t, func(r *rapid.T) {
		s := rapid.StringOfN(rapid.SampledFrom([]rune("ab \t\n/")), 0, 16, -1).Draw(r, "s")
		ifs := rapid.SampledFrom([]string{gitsafe.Tab, gitsafe.Blank}).Draw(r, "ifs")
		n := rapid.IntRange(1, 5).Draw(r, "n")
		check(r, s, ifs, n)
	})
}

func TestOutputIsWhatACommandSubstitutionHolds(t *testing.T) {
	b := bash(t)
	for _, s := range []string{"", "a", "a\n", "a\n\n\n", "\na", "a\x00b\n", "\n"} {
		cmd := exec.Command(b, "-c", `x=$(printf '%s' "$1" | tr '#' '\000'); printf '%s' "$x"`, "-", strings.ReplaceAll(s, "\x00", "#"))
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if got := gitsafe.Output([]byte(s)); got != string(out) {
			t.Errorf("Output(%q) = %q, bash gives %q", s, got, out)
		}
	}
	if got := gitsafe.ReadLines("a\nb\nc"); !bytes.Equal([]byte(strings.Join(got, "|")), []byte("a|b")) {
		t.Errorf("ReadLines read a line no newline ended: %q", got)
	}
}
