package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// `chase run`'s options end at the program or a `--`; every word after
// the program is the program's, an option of chase's spelling included.
func TestParseRun(t *testing.T) {
	pwd := t.TempDir()
	other := filepath.Join(pwd, "other")
	os.Mkdir(other, 0o755)
	if o, p, rest, err := parseRun([]string{"--tier", "ops", "claude", "--tier", "host", "--resume"}, pwd); err != nil || o.tier != "ops" || p != "claude" || !slices.Equal(rest, []string{"--tier", "host", "--resume"}) {
		t.Errorf("an agent's own words: %+v %q %q %v", o, p, rest, err)
	}
	if o, p, rest, err := parseRun([]string{"--tier=ops", "--with", "other", "--with=" + other + ":ro", "--", "docker", "ps"}, pwd); err != nil || o.tier != "ops" || p != "docker" || !slices.Equal(rest, []string{"ps"}) || !slices.Equal(o.with, []string{other + ":rw", other + ":ro"}) {
		t.Errorf("--with and --: %+v %q %q %v", o, p, rest, err)
	}
	if _, p, rest, err := parseRun([]string{"--", "--tier"}, pwd); err != nil || p != "--tier" || len(rest) != 0 {
		t.Errorf("a program after --: %q %q %v", p, rest, err)
	}
	for args, want := range map[string]string{
		"":                             "no program",
		"--tier":                       "--tier needs a value",
		"--tier ops":                   "no program",
		"--tier a --tier b":            "given twice",
		"-x claude":                    "unknown option '-x'",
		"--with nope shell":            "--with:",
		"--with " + pwd + "/a:b shell": "--with:",
	} {
		if _, _, _, err := parseRun(strings.Fields(args), pwd); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", args, err, want)
		}
	}
}
