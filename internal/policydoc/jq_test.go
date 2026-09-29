package policydoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/frisket/policy"
	"pgregory.net/rapid"
)

// What this package replaces is jq, in ../../project, for as long as it is
// there: while it is, and jq is on the PATH, whatever each is given, each
// does the same -- the same error, word for word, or the same document, and
// for an envelope the same bytes.
func jqProgram(t *testing.T, name string) (string, string) {
	t.Helper()
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("no jq to compare with")
	}
	prog, _ := filepath.Abs(filepath.Join("..", "..", "project", name))
	if _, err := os.Stat(prog); err != nil {
		t.Skipf("no %s to compare with", name)
	}
	return jq, prog
}

// runJq is jq's output, or its error's message without jq's own prefix.
func runJq(t *rapid.T, jq string, stdin []byte, args ...string) ([]byte, string) {
	cmd := exec.Command(jq, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSuffix(stderr.String(), "\n")
		if i := strings.Index(msg, "): "); strings.HasPrefix(msg, "jq: error (at ") && i >= 0 {
			msg = msg[i+3:]
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, msg
	}
	return stdout.Bytes(), ""
}

// same is whether jq's document is ours, as frisket would read both.
func same(t *rapid.T, fromJq []byte, ours *policy.Document) {
	var theirs policy.Document
	if err := policy.Decode(fromJq, &theirs); err != nil {
		t.Fatalf("jq wrote what frisket cannot read: %v\n%s", err, fromJq)
	}
	a, _ := json.Marshal(theirs)
	b, _ := json.Marshal(ours)
	if !bytes.Equal(a, b) {
		t.Fatalf("jq:\n%s\nours:\n%s", a, b)
	}
}

var (
	names      = []string{"pulls/create", "pulls/merge", "git/delete-ref", "graphql-query", "mergePullRequest", "closePullRequest", "deleteIssue", "git-receive-pack", "nope", "zz"}
	categories = []string{"pulls", "git", "graphql", "issues", "nope"}
	endpoints  = []string{"/markdown/x", "/graphql", "/graphql/x", "/repos/me/app/git/refs/main", "/repos/a/b/pulls", "/repos/*/x/pulls", "/repos/a/b/pulls/1/merge", "/x/y", "/"}
	methods    = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
)

func entries(t *rapid.T, label string) []Entry {
	return rapid.SliceOfN(rapid.Custom(func(t *rapid.T) Entry {
		switch rapid.IntRange(0, 2).Draw(t, "kind") {
		case 0:
			return Entry{Name: rapid.SampledFrom(names).Draw(t, "name")}
		case 1:
			return Entry{Name: "category:" + rapid.SampledFrom(categories).Draw(t, "category")}
		}
		return Entry{Endpoint: &Endpoint{
			Methods: rapid.SliceOfNDistinct(rapid.SampledFrom(methods), 1, 3, rapid.ID[string]).Draw(t, "methods"),
			Path:    rapid.SampledFrom(endpoints).Draw(t, "path"),
		}}
	}), 0, 3).Draw(t, label)
}

func TestListsDoWhatListsJqDid(t *testing.T) {
	jq, prog := jqProgram(t, "lists.jq")
	rapid.Check(t, func(t *rapid.T) {
		app := rapid.SampledFrom([]string{"github", "git", "gh", "cloudflare"}).Draw(t, "app")
		l := Lists{Allow: entries(t, "allow"), Ask: entries(t, "ask"), Refuse: entries(t, "refuse")}
		arg, _ := json.Marshal(l)
		out, msg := runJq(t, jq, []byte(tierDoc), "-c", "--arg", "app", app, "--argjson", "lists", string(arg), "-f", prog)
		doc := tier(t)
		err := Apply(doc, app, l)
		switch {
		case msg != "" && (err == nil || err.Error() != msg):
			t.Fatalf("%s %s: jq said %q, and we %v", app, arg, msg, err)
		case msg == "" && err != nil:
			t.Fatalf("%s %s: jq applied it, and we said %v", app, arg, err)
		case msg == "":
			same(t, out, doc)
		}
	})
}

func TestMergeDoesWhatMergeJqDid(t *testing.T) {
	jq, prog := jqProgram(t, "merge.jq")
	hosts := []string{"a.example", "b.example", "*", "c.example"}
	rapid.Check(t, func(t *rapid.T) {
		doc := tier(t)
		doc.Name = "t"
		doc.Allow = rapid.SliceOfN(rapid.SampledFrom(hosts), 0, 4).Draw(t, "allow")
		var patch apps.Patch
		for _, n := range rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"github", "git", "gh", "new", "other"}), 0, 3, rapid.ID[string]).Draw(t, "routes") {
			patch.Routes = append(patch.Routes, policy.Route{Name: n, Host: n + ".example", Upstream: "https://" + n + ".example", CredentialFile: "/run/" + n})
		}
		patch.Allow = rapid.SliceOfN(rapid.SampledFrom(hosts), 0, 3).Draw(t, "patch allow")
		in, _ := json.Marshal(doc)
		p, _ := json.Marshal(patch)
		f := filepath.Join(os.TempDir(), fmt.Sprintf("policydoc-patch-%d.json", os.Getpid()))
		if err := os.WriteFile(f, p, 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f)
		out, msg := runJq(t, jq, in, "-c", "--slurpfile", "patch", f, "-f", prog)
		if msg != "" {
			t.Fatalf("jq: %s", msg)
		}
		Merge(doc, patch)
		same(t, out, doc)
	})
}

// envelope is a JSON text shaped like an envelope, with what normal.jq
// prunes and keeps anywhere in it, and numbers and strings written as a
// person or Nix might.
func envelope(t *rapid.T, depth int, label string) string {
	scalars := []string{`null`, `[]`, `{}`, `false`, `true`, `0`, `""`, `"s.yaml"`, `1e2`, `0.10`, `-0`, `1.50e1`, `5432`, `0.0000001`, `12345678901234567890`, `"x\u001b\u007fé\u2028/<&>\"\\\t"`, `[{}]`, `[null]`, `{"allow": [], "deny": []}`}
	if depth == 0 || rapid.IntRange(0, 2).Draw(t, label+" leaf") == 0 {
		return rapid.SampledFrom(scalars).Draw(t, label)
	}
	keys := rapid.SliceOfN(rapid.SampledFrom([]string{"secrets", "seccomp", "bindings", "github", "docker", "allow", "deny", "images", "credential", "secret"}), 0, 4).Draw(t, label+" keys")
	if rapid.Bool().Draw(t, label+" array") {
		var items []string
		for i := range keys {
			items = append(items, envelope(t, depth-1, fmt.Sprintf("%s[%d]", label, i)))
		}
		return "[" + strings.Join(items, ",") + "]"
	}
	var members []string
	for _, k := range keys {
		members = append(members, fmt.Sprintf("%q: %s", k, envelope(t, depth-1, label+"."+k)))
	}
	return "{" + strings.Join(members, ", ") + "}"
}

func TestNormalWritesWhatNormalJqWrote(t *testing.T) {
	jq, prog := jqProgram(t, "normal.jq")
	rapid.Check(t, func(t *rapid.T) {
		in := envelope(t, 4, "envelope")
		out, msg := runJq(t, jq, []byte(in), "-c", "-f", prog)
		got, err := Normal([]byte(in))
		switch {
		case msg != "" && (err == nil || err.Error() != msg):
			t.Fatalf("%s: jq said %q, and we %v", in, msg, err)
		case msg == "" && err != nil:
			t.Fatalf("%s: jq wrote %s, and we said %v", in, out, err)
		case msg == "" && string(got)+"\n" != string(out):
			t.Fatalf("%s:\n  jq %s\nours %s", in, out, got)
		}
	})
}
