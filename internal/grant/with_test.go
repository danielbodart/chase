package grant

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// chase.with is read from the stage approve wrote, never the checkout's
// file: each directory relative to the checkout, under the home or
// absolute, resolved, with its mode; one that is not there is said and
// not mounted; a launch nothing approved is refused.
func TestWithIsTheStagedFilesDirectories(t *testing.T) {
	root := t.TempDir()
	home, ws := filepath.Join(root, "home"), filepath.Join(root, "home", "p", "shop")
	for _, d := range []string{ws, filepath.Join(home, "p", "lib"), filepath.Join(home, "notes"), filepath.Join(root, "abs")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.Symlink(filepath.Join(home, "p", "lib"), filepath.Join(home, "p", "link"))
	c := Config{Home: home, Runtime: filepath.Join(root, "run")}
	os.MkdirAll(c.Runtime+"/chase/.grant", 0o700)
	var said bytes.Buffer
	if _, err := With(c, ws, "m1", &said); err == nil || !strings.Contains(err.Error(), "nothing was approved") {
		t.Errorf("an unapproved launch: %v", err)
	}
	stage := `{"file":{"chase":{"with":{"../link":"rw","~/notes":"ro","` + root + `/abs":"rw","../gone":"rw"}},"version":2},"secrets":null}`
	os.WriteFile(staged(c, "m1"), []byte(stage), 0o600)
	// The checkout's own file says otherwise, and is not read.
	os.WriteFile(ws+"/chase.json", []byte(`{"chase":{"with":{"/":"rw"}},"version":2}`), 0o644)
	got, err := With(c, ws, "m1", &said)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(home, "p", "lib") + ":rw", root + "/abs:rw", filepath.Join(home, "notes") + ":ro"}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if !strings.Contains(said.String(), "gone, which is not there: not mounted") {
		t.Errorf("a missing directory was not said: %q", said.String())
	}
	os.WriteFile(staged(c, "m2"), []byte("null\n"), 0o600)
	if got, err := With(c, ws, "m2", &said); err != nil || len(got) != 0 {
		t.Errorf("the tier as it is: %q %v", got, err)
	}
}

// What chase.with may say: a directory, and rw or ro.
func TestChaseWithIsChecked(t *testing.T) {
	for file, want := range map[string]string{
		`{"chase":{"with":{"../lib":"rw","~/n":"ro"}},"version":2}`: "",
		`{"chase":{"with":{"":"rw"}},"version":2}`:                  "names no directory",
		`{"chase":{"with":{"~":"rw"}},"version":2}`:                 "names no directory",
		`{"chase":{"with":{"a:b":"rw"}},"version":2}`:               "has a ':'",
		`{"chase":{"with":{"../lib":"rx"}},"version":2}`:            "is not rw or ro",
	} {
		_, _, err := ParseDoc([]byte(file))
		if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: %v, want %q", file, err, want)
		}
	}
}

// A project's seccomp.debug and seccomp.log are flong's, said as the
// lines seccompPolicy prints: ptrace allowed, and @known logged.
func TestFlongDebugAndLogAreLines(t *testing.T) {
	d, _, err := ParseDoc([]byte(`{"flong":{"seccomp":{"debug":true,"log":true,"syscalls":{"keyctl":"deny"}}},"version":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Flong.Lines().Lines(); got != "allow ptrace\ndeny keyctl\nlog @known\n" {
		t.Errorf("printed %q", got)
	}
}
