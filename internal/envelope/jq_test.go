package envelope

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// jqBin is jq, which the script ran, for comparing what is shown with what
// it showed: skipped without one, unless CHASE_REQUIRE_JQ is set.
func jqBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("jq")
	if err != nil {
		if os.Getenv("CHASE_REQUIRE_JQ") != "" {
			t.Fatalf("jq is not on PATH, and CHASE_REQUIRE_JQ is set: %v", err)
		}
		t.Skip("jq is not on PATH, so what it wrote is not compared")
	}
	return p
}

func jq(t *testing.T, input string, args ...string) string {
	t.Helper()
	cmd := exec.Command(jqBin(t), args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("jq %q: %v", args, err)
	}
	return string(out)
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
