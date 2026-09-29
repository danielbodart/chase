package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// goldenFile is what jq wrote for each call below, kept so that the
// comparison is made where there is no jq -- a gated build, whose check
// inputs have none -- rather than skipped there, as it was. Where jq is on
// PATH it is run as well, and must still write what was kept: a jq that
// writes something else is a difference to look at, not a file to refresh.
// CHASE_UPDATE_JQ=1, with jq on PATH, writes the file from it.
const goldenFile = "testdata/jq.json"

type golden struct {
	// What is the call, for a person reading the file.
	What   string `json:"what"`
	Output string `json:"output"`
}

// goldenKey is one call, its arguments and its input, as a file name is:
// both may hold bytes that are not UTF-8, which JSON cannot keep.
func goldenKey(input string, args []string) string {
	h := sha256.New()
	for _, a := range args {
		h.Write([]byte(a))
		h.Write([]byte{0})
	}
	h.Write([]byte{0})
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

func readGolden(t *testing.T) map[string]golden {
	t.Helper()
	g := map[string]golden{}
	b, err := os.ReadFile(goldenFile)
	if errors.Is(err, os.ErrNotExist) {
		return g
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("%s: %v", goldenFile, err)
	}
	return g
}

// jq is what jq, which the script ran, writes of input with args: as it
// was kept, and, where jq is on PATH, as it writes it now.
func jq(t *testing.T, input string, args ...string) string {
	t.Helper()
	k := goldenKey(input, args)
	kept, have := readGolden(t)[k]
	p, err := exec.LookPath("jq")
	if err != nil {
		if !have {
			t.Fatalf("jq %q of %q was never kept in %s, and jq is not on PATH to run it", args, input, goldenFile)
		}
		return kept.Output
	}
	cmd := exec.Command(p, args...)
	cmd.Stdin = strings.NewReader(input)
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("jq %q: %v", args, err)
	}
	out := string(b)
	if os.Getenv("CHASE_UPDATE_JQ") != "" {
		if !utf8.ValidString(out) {
			t.Fatalf("jq %q of %q wrote bytes that are not UTF-8, which %s cannot keep", args, input, goldenFile)
		}
		g := readGolden(t)
		g[k] = golden{What: fmt.Sprintf("jq %q of %q", args, input), Output: out}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(g); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(goldenFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenFile, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return out
	}
	switch {
	case !have:
		t.Errorf("jq %q of %q is not kept in %s: run the tests with CHASE_UPDATE_JQ=1", args, input, goldenFile)
	case kept.Output != out:
		t.Errorf("jq %q of %q writes %q, and %s kept %q", args, input, out, goldenFile, kept.Output)
	}
	return out
}

var envelopes = []string{
	`null`,
	`{}`,
	`{"bindings": {}}`,
	`{"z": 1, "a": [], "m": {"y": [1, 2.50, 1e2, -0.0, 1E-7], "b": "\u0001\u007f\u001f\"\\/<>& é"}}`,
	`{"bindings": {"docker": {"images": ["postgres:18"], "ports": [64320, 64321]}}, "dockerProject": "example/shop", "seccomp": {"allow": ["a"], "deny": []}}`,
	`{"a": {"b": {"c": [[], {}, [{}], [[1]]]}}, "B": true, "_": false, "": null}`,
}

// What an envelope is written, compared and shown as is what jq wrote.
func TestAnEnvelopeIsPrintedAsJqPrintedIt(t *testing.T) {
	for _, e := range envelopes {
		v, err := parseJSON([]byte(e))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			got  string
			args []string
		}{
			{v.compact() + "\n", []string{"-c", "."}},
			{v.sorted() + "\n", []string{"-cS", "."}},
			{v.pretty() + "\n", []string{"."}},
			{v.prettySorted() + "\n", []string{"-S", "."}},
		} {
			if want := jq(t, e, c.args...); c.got != want {
				t.Errorf("jq %q of %s: %q, not %q", c.args, e, c.got, want)
			}
		}
	}
}

// The approver's stdin is what `jq -n --arg ...` made of the three strings,
// whatever is in them: a path a session named, a diff of its flake.
func TestTheApproversDocumentIsJqs(t *testing.T) {
	for _, s := range []string{"plain", "x\x1b]0;TITLE\x07y", "tab\tnewline\n\"quote\" \\ back", "é   <&>", "bad \xff\xfe utf-8", "nul\x01"} {
		doc := jobject()
		doc.set("kind", jstr("flake"))
		doc.set("workspace", jstr(s))
		doc.set("diff", jstr(s+"\n"))
		want := jq(t, "", "-n", "--arg", "kind", "flake", "--arg", "workspace", s, "--arg", "diff", s+"\n",
			"{kind: $kind, workspace: $workspace, diff: $diff}")
		if got := doc.pretty() + "\n"; got != want {
			t.Errorf("%q: %q, not %q", s, got, want)
		}
	}
}

// @sh is jq's.
func TestShIsJqs(t *testing.T) {
	for _, e := range []string{`"it's"`, `""`, `"a'b'c"`, `5`, `1.50`, `true`, `null`, `["a", 1, "b'c"]`, `[]`} {
		v, _ := parseJSON([]byte(e))
		got, err := sh(v)
		if err != nil {
			t.Fatal(err)
		}
		if want := jq(t, e, "-r", "@sh"); got+"\n" != want {
			t.Errorf("@sh of %s: %q, not %q", e, got, want)
		}
	}
	for _, e := range []string{`{"a": 1}`, `[[1]]`} {
		v, _ := parseJSON([]byte(e))
		if _, err := sh(v); err == nil {
			t.Errorf("@sh of %s was escaped", e)
		}
	}
}

// Values are ordered as jq orders them: what `sort` gives is what
// namedTwice's groups are in.
func TestValuesAreOrderedAsJqOrdersThem(t *testing.T) {
	in := `[{"b": 1}, {"a": 2}, {"a": 1, "b": 1}, [2], [1, 2], "b", "a", "ab", 10, 9.5, true, false, null, {"a": 1}]`
	v, _ := parseJSON([]byte(in))
	items := append([]*value(nil), v.items...)
	sortValues(items)
	out := &value{kind: '[', items: items}
	if want := jq(t, in, "-c", "sort"); out.compact()+"\n" != want {
		t.Errorf("sorted: %s, not %s", out.compact(), want)
	}
}
