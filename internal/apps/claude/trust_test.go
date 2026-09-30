package claude

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// original is the activation script as the module had it, for comparing
// against where the host has bash, jq and cmp.
const original = `
f="$HOME/.claude.json"
if [ -f "$f" ]; then
  t=$(mktemp) || exit 0
  if jq \
       --argjson paths "$PATHS" \
       'reduce $paths[] as $p (.; .projects[$p].hasTrustDialogAccepted = true)' \
       "$f" > "$t" 2>/dev/null && [ -s "$t" ]; then
    if ! cmp -s "$t" "$f"; then
      chmod 0600 "$t" && mv "$t" "$f"
      echo "claude: pre-trusted $N workspaces"
    else
      rm -f "$t"
    fi
  else
    rm -f "$t"
  fi
fi
`

func trustIn(t *testing.T, content string, paths ...string) (string, string, os.FileInfo) {
	t.Helper()
	f := filepath.Join(t.TempDir(), ".claude.json")
	if content != "" {
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := TrustWorkspaces(Config{ClaudeJSON: f, TrustPaths: paths}, &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	fi, _ := os.Stat(f)
	return string(b), out.String(), fi
}

func TestTrustsEachPathKeepingEverythingElse(t *testing.T) {
	in := `{"numStartups":3,"projects":{"/h/p":{"allowedTools":[],"hasTrustDialogAccepted":false},"/other":{"x":1}},"userID":"u"}`
	got, said, fi := trustIn(t, in, "/h", "/h/p", "/h")
	want := `{
  "numStartups": 3,
  "projects": {
    "/h/p": {
      "allowedTools": [],
      "hasTrustDialogAccepted": true
    },
    "/other": {
      "x": 1
    },
    "/h": {
      "hasTrustDialogAccepted": true
    }
  },
  "userID": "u"
}
`
	if got != want {
		t.Errorf("wrote\n%s", got)
	}
	// Counted as given once each.
	if said != "claude: pre-trusted 2 workspaces\n" {
		t.Errorf("said %q", said)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
}

func TestMakesWhatIsMissing(t *testing.T) {
	for in, want := range map[string]string{
		`{}`:                "{\n  \"projects\": {\n    \"/h\": {\n      \"hasTrustDialogAccepted\": true\n    }\n  }\n}\n",
		`null`:              "{\n  \"projects\": {\n    \"/h\": {\n      \"hasTrustDialogAccepted\": true\n    }\n  }\n}\n",
		`{"projects":null}`: "{\n  \"projects\": {\n    \"/h\": {\n      \"hasTrustDialogAccepted\": true\n    }\n  }\n}\n",
		// Anything but true is not trusted.
		`{"projects":{"/h":{"hasTrustDialogAccepted":"true"}}}`: "{\n  \"projects\": {\n    \"/h\": {\n      \"hasTrustDialogAccepted\": true\n    }\n  }\n}\n",
	} {
		got, said, _ := trustIn(t, in, "/h")
		if got != want || said != "claude: pre-trusted 1 workspaces\n" {
			t.Errorf("%s: wrote %q, said %q", in, got, said)
		}
	}
}

// Claude Code's own file, in a shape this does not expect, is left alone,
// and an activation is never stopped over it.
func TestLeavesAloneWhatItCannotEdit(t *testing.T) {
	for _, in := range []string{
		`{`, `[]`, `"s"`, `1`, `true`, `{} {}`, ` `,
		`{"projects":[]}`, `{"projects":"x"}`,
		`{"projects":{"/h":"x"}}`, `{"projects":{"/h":[]}}`,
	} {
		f := filepath.Join(t.TempDir(), ".claude.json")
		os.WriteFile(f, []byte(in), 0o644)
		var out bytes.Buffer
		if err := TrustWorkspaces(Config{ClaudeJSON: f, TrustPaths: []string{"/other", "/h"}}, &out); err != nil {
			t.Errorf("%s: %v", in, err)
		}
		b, _ := os.ReadFile(f)
		fi, _ := os.Stat(f)
		if string(b) != in || out.Len() != 0 || fi.Mode().Perm() != 0o644 {
			t.Errorf("%s: became %q at %v, said %q", in, b, fi.Mode(), out.String())
		}
	}
}

func TestNoFileIsNothingToDo(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := TrustWorkspaces(Config{ClaudeJSON: filepath.Join(dir, ".claude.json"), TrustPaths: []string{"/h"}}, &out); err != nil || out.Len() != 0 {
		t.Errorf("%v, said %q", err, out.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("made %v", entries)
	}
	// Nor is a directory there.
	os.Mkdir(filepath.Join(dir, ".claude.json"), 0o700)
	if err := TrustWorkspaces(Config{ClaudeJSON: filepath.Join(dir, ".claude.json"), TrustPaths: []string{"/h"}}, &out); err != nil || out.Len() != 0 {
		t.Errorf("%v, said %q", err, out.String())
	}
}

func TestAlreadyTrustedIsNotRewritten(t *testing.T) {
	f := filepath.Join(t.TempDir(), ".claude.json")
	in := `{"projects":{"/h":{"hasTrustDialogAccepted":true},"/h/p":{"hasTrustDialogAccepted":true}}}`
	os.WriteFile(f, []byte(in), 0o644)
	before, _ := os.Stat(f)
	var out bytes.Buffer
	if err := TrustWorkspaces(Config{ClaudeJSON: f, TrustPaths: []string{"/h/p", "/h"}}, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(f)
	b, _ := os.ReadFile(f)
	if string(b) != in || out.Len() != 0 || !os.SameFile(before, after) || after.Mode().Perm() != 0o644 {
		t.Errorf("rewrote it: %q, said %q", b, out.String())
	}
}

// Replaced whole, never half-written: Claude Code may read it at any moment.
func TestTheFileIsReplacedNotRewritten(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".claude.json")
	os.WriteFile(f, []byte(`{}`), 0o644)
	before, _ := os.Stat(f)
	if err := TrustWorkspaces(Config{ClaudeJSON: f, TrustPaths: []string{"/h"}}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(f)
	if os.SameFile(before, after) {
		t.Error("rewritten in place")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left beside it: %v", entries)
	}
}

// As mv did: a link at the path is replaced by the file, and what it pointed
// to is left as it was.
func TestALinkIsReplacedAndItsTargetKept(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	os.WriteFile(target, []byte(`{}`), 0o644)
	f := filepath.Join(dir, ".claude.json")
	os.Symlink(target, f)
	if err := TrustWorkspaces(Config{ClaudeJSON: f, TrustPaths: []string{"/h"}}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(f); !fi.Mode().IsRegular() {
		t.Errorf("still %v", fi.Mode())
	}
	if b, _ := os.ReadFile(target); string(b) != `{}` {
		t.Errorf("target became %q", b)
	}
}

func TestDefaultsToHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{}`), 0o600)
	var out bytes.Buffer
	if err := TrustWorkspaces(Config{TrustPaths: []string{home}}, &out); err != nil || out.String() != "claude: pre-trusted 1 workspaces\n" {
		t.Errorf("%v, said %q", err, out.String())
	}
}

func TestAWriteThatFailsIsAnError(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".claude.json")
	os.WriteFile(f, []byte(`{}`), 0o644)
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	if os.Geteuid() == 0 {
		t.Skip("root writes anyway")
	}
	if err := TrustWorkspaces(Config{ClaudeJSON: f, TrustPaths: []string{"/h"}}, &bytes.Buffer{}); err == nil {
		t.Error("no error")
	}
}

// What the original wrote from a file jq itself had laid out, this writes
// byte for byte, and says the same.
