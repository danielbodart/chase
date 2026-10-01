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

// A Claude Code of the workspace's scope binds this workspace's
// transcripts, where Claude Code keeps them, made if missing; one of the
// session's binds nothing.
func TestAWorkspacesClaudeBindsItsTranscripts(t *testing.T) {
	home := t.TempDir()
	c := Config{Home: home, Tiers: map[string]Tier{"strict": {Claude: &Claude{Scope: "workspace"}}, "plain": {Claude: &Claude{Scope: "session"}}}}
	got := binds(t, c, "strict", "/home/alice/Projects/shop.v2")
	want := filepath.Join(home, ".claude", "projects", "-home-alice-Projects-shop-v2")
	if len(got) != 1 || got[0] != want+":rw" {
		t.Fatalf("got %q", got)
	}
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Errorf("not made: %v", err)
	}
	if got := binds(t, c, "plain", "/home/alice/Projects/shop.v2"); len(got) != 0 {
		t.Errorf("the session's bound %q", got)
	}
}

// The host's Claude Code has its bound sources made: flong refuses a
// session whose bind source is missing. Nothing extra is bound: the
// container's own mounts do that.
func TestTheHostsClaudeHasItsSourcesMade(t *testing.T) {
	home := t.TempDir()
	run := t.TempDir()
	c := Config{Home: home, Runtime: run, Tiers: map[string]Tier{"trusted": {Claude: &Claude{Scope: "host"}}}}
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

// The host's Claude Code, in a tier that trusts its checkouts, has the
// workspace trusted in the host's ~/.claude.json, which the session shares;
// in one that does not, the file is left as it was.
func TestTheHostsClaudeTrustsTheWorkspaceWhereTheTierSays(t *testing.T) {
	home := t.TempDir()
	c := Config{Home: home, Runtime: t.TempDir(), Tiers: map[string]Tier{
		"trusted": {Claude: &Claude{Scope: "host", Trust: true}},
		"wary":    {Claude: &Claude{Scope: "host"}},
	}}
	file := filepath.Join(home, ".claude.json")
	os.WriteFile(file, []byte(`{"projects":{}}`), 0o600)
	binds(t, c, "wary", "/w/shop")
	if b, _ := os.ReadFile(file); string(b) != `{"projects":{}}` {
		t.Errorf("a tier that does not trust wrote %s", b)
	}
	binds(t, c, "trusted", "/w/shop")
	if b, _ := os.ReadFile(file); !strings.Contains(string(b), `"/w/shop": {`) || !strings.Contains(string(b), `"hasTrustDialogAccepted": true`) {
		t.Errorf("the workspace was not trusted: %s", b)
	}
}

// A store is a directory for each workspace, or one for the tier, the
// user's alone, made if missing and kept if not, with its files installed
// afresh each launch: replacing a link a session left rather than writing
// through it.
func TestAStoreIsMadeAndItsFilesInstalledAfresh(t *testing.T) {
	root := t.TempDir()
	placeholder := filepath.Join(root, "auth-placeholder.json")
	os.WriteFile(placeholder, []byte(`{"placeholder":true}`), 0o600)
	state := filepath.Join(root, "codex")
	codex := Store{Scope: "workspace", Root: state, Files: map[string]string{"auth.json": placeholder}}
	c := Config{Home: root, Tiers: map[string]Tier{"strict": {Stores: map[string]Store{"codex": codex}}}}
	home := filepath.Join(state, "strict", "-w-shop")
	os.MkdirAll(home, 0o700)
	os.WriteFile(filepath.Join(home, "kept"), nil, 0o600)
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
	if _, err := os.Stat(filepath.Join(home, "kept")); err != nil {
		t.Errorf("what the last session left went: %v", err)
	}

	// The tier's: one directory, whatever the workspace, made the user's
	// alone.
	caches := filepath.Join(root, "caches")
	c.Tiers["trusted"] = Tier{Stores: map[string]Store{"caches": {Scope: "tier", Root: caches}}}
	all := filepath.Join(caches, "trusted", "all")
	for _, ws := range []string{"/w/shop", "/w/other"} {
		if got := binds(t, c, "trusted", ws); len(got) != 1 || got[0] != all+":rw" {
			t.Errorf("%s: got %q", ws, got)
		}
	}
	if fi, err := os.Stat(all); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("not made the user's alone: %v %v", fi, err)
	}
	// Several, by name.
	c.Tiers["both"] = Tier{Stores: map[string]Store{"z": {Scope: "tier", Root: root + "/z"}, "a": {Scope: "tier", Root: root + "/a"}}}
	if got := binds(t, c, "both", "/w"); strings.Join(got, "|") != root+"/a/both/all:rw|"+root+"/z/both/all:rw" {
		t.Errorf("got %q", got)
	}
}

// A tier's Cloudflare account binds nothing: its id is read on the host
// and given to the session as a variable (Payload).
func TestCloudflaresAccountBindsNothing(t *testing.T) {
	root := t.TempDir()
	id := filepath.Join(root, "id")
	os.WriteFile(id, []byte("0123abc\n"), 0o600)
	c := Config{Home: root, Tiers: map[string]Tier{"trusted": {Cloudflare: &Cloudflare{AccountIDFile: id}}}}
	if got := binds(t, c, "trusted", "/w"); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
	if left, _ := os.ReadDir(root); len(left) != 1 {
		t.Errorf("binds made %v", left)
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
