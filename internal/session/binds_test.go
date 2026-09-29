package session

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func binds(t *testing.T, c Config, tier, ws string) []string {
	t.Helper()
	var out bytes.Buffer
	if err := Binds(c, tier, ws, &out); err != nil {
		t.Fatal(err)
	}
	return strings.FieldsFunc(out.String(), func(r rune) bool { return r == '\n' })
}

// A group's other members, read-write, sorted and once each; a member that
// is not there is not bound, and a workspace in no group binds none.
func TestAGroupsOtherMembersAreBoundReadWrite(t *testing.T) {
	root := t.TempDir()
	api, web, docs, gone := filepath.Join(root, "api"), filepath.Join(root, "web"), filepath.Join(root, "docs"), filepath.Join(root, "gone")
	for _, d := range []string{api, web, docs} {
		os.Mkdir(d, 0o755)
	}
	c := Config{Home: root, WorkspaceGroups: [][]string{{web, api, gone}, {api, docs, web}}, Tiers: map[string]Tier{"strict": {}}}
	got := binds(t, c, "strict", api)
	want := []string{docs + ":rw", web + ":rw"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := binds(t, c, "strict", docs); strings.Join(got, "|") != api+":rw|"+web+":rw" {
		t.Errorf("not transitive: %q", got)
	}
	if got := binds(t, c, "strict", filepath.Join(root, "alone")); len(got) != 0 {
		t.Errorf("a workspace in no group bound %q", got)
	}
}

// An isolated Claude Code binds this workspace's transcripts, where Claude
// Code keeps them, made if missing.
func TestAnIsolatedClaudeBindsItsTranscripts(t *testing.T) {
	home := t.TempDir()
	c := Config{Home: home, Tiers: map[string]Tier{"strict": {Claude: "isolated"}}}
	got := binds(t, c, "strict", "/home/alice/Projects/shop.v2")
	want := filepath.Join(home, ".claude", "projects", "-home-alice-Projects-shop-v2")
	if len(got) != 1 || got[0] != want+":rw" {
		t.Fatalf("got %q", got)
	}
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Errorf("not made: %v", err)
	}
}

// A shared Claude Code's bound sources are made: flong refuses a session
// whose bind source is missing. Nothing extra is bound: the container's own
// mounts do that.
func TestASharedClaudeHasItsSourcesMade(t *testing.T) {
	home := t.TempDir()
	run := t.TempDir()
	c := Config{Home: home, Runtime: run, Tiers: map[string]Tier{"trusted": {Claude: "shared"}}}
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	os.WriteFile(filepath.Join(home, ".claude", "history.jsonl"), []byte("kept\n"), 0o600)
	if got := binds(t, c, "trusted", "/w"); len(got) != 0 {
		t.Errorf("bound %q", got)
	}
	if fi, err := os.Stat(filepath.Join(run, "cc-socks")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("cc-socks: %v %v", fi, err)
	}
	// Again, with everything there already.
	if got := binds(t, c, "trusted", "/w"); len(got) != 0 {
		t.Errorf("bound %q", got)
	}
	for _, d := range []string{"projects", "plugins", "file-history", "plans", "paste-cache", "sessions"} {
		if fi, err := os.Stat(filepath.Join(home, ".claude", d)); err != nil || !fi.IsDir() {
			t.Errorf("%s not made", d)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".claude", "history.jsonl")); string(b) != "kept\n" {
		t.Errorf("history.jsonl became %q", b)
	}
}

// An isolated codex binds a home of the workspace's own, given the
// placeholder afresh, replacing a link a session left rather than writing
// through it.
func TestAnIsolatedCodexHomeGetsThePlaceholderAfresh(t *testing.T) {
	root := t.TempDir()
	placeholder := filepath.Join(root, "auth-placeholder.json")
	os.WriteFile(placeholder, []byte(`{"placeholder":true}`), 0o600)
	state := filepath.Join(root, "codex")
	c := Config{Home: root, Tiers: map[string]Tier{"strict": {Codex: &Codex{State: "isolated", StateDir: state, Placeholder: placeholder}}}}
	home := filepath.Join(state, "-w-shop")
	os.MkdirAll(home, 0o700)
	target := filepath.Join(root, "planted")
	os.WriteFile(target, []byte("theirs"), 0o644)
	if err := os.Symlink(target, filepath.Join(home, "auth.json")); err != nil {
		t.Fatal(err)
	}
	got := binds(t, c, "strict", "/w/shop")
	if len(got) != 1 || got[0] != home+":rw" {
		t.Fatalf("got %q", got)
	}
	fi, err := os.Lstat(filepath.Join(home, "auth.json"))
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("auth.json is %v, %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(home, "auth.json")); string(b) != `{"placeholder":true}` {
		t.Errorf("auth.json is %q", b)
	}
	if b, _ := os.ReadFile(target); string(b) != "theirs" {
		t.Errorf("wrote through the link: %q", b)
	}
	// A shared codex binds nothing here: its container mounts do.
	c.Tiers["trusted"] = Tier{Codex: &Codex{State: "shared"}}
	if got := binds(t, c, "trusted", "/w/shop"); len(got) != 0 {
		t.Errorf("shared bound %q", got)
	}
}

// A tier's Cloudflare account id is copied into its directory, bound
// read-only.
func TestCloudflaresAccountIDIsCopiedAndBoundReadOnly(t *testing.T) {
	root := t.TempDir()
	id := filepath.Join(root, "id")
	os.WriteFile(id, []byte("0123abc\n"), 0o644)
	dir := filepath.Join(root, "cloudflare", "trusted")
	c := Config{Home: root, Tiers: map[string]Tier{"trusted": {Cloudflare: &Cloudflare{Dir: dir, AccountIDFile: id}}}}
	if got := binds(t, c, "trusted", "/w"); len(got) != 1 || got[0] != dir {
		t.Fatalf("got %q", got)
	}
	fi, _ := os.Stat(filepath.Join(dir, "account-id"))
	if b, _ := os.ReadFile(filepath.Join(dir, "account-id")); string(b) != "0123abc\n" || fi.Mode().Perm() != 0o600 {
		t.Errorf("account-id %q at %v", b, fi.Mode())
	}
}

func TestMungeIsClaudeCodes(t *testing.T) {
	for in, want := range map[string]string{
		"/home/alice/Projects/shop": "-home-alice-Projects-shop",
		"/w/a.b_c d":                "-w-a-b-c-d",
		"/w/Łódź":                   "-w---d-",
		"/w/😀":                      "-w---",
	} {
		if got := Munge(in); got != want {
			t.Errorf("Munge(%q) = %q, want %q", in, got, want)
		}
	}
}
