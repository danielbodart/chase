package codex

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// moved is a Config whose state an earlier chase kept under agents/, with
// a tier's home there holding what codex kept.
func moved(t *testing.T) (Config, string) {
	t.Helper()
	c := config(t)
	home := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(c.StateDir))))
	c.FormerStateDir = filepath.Join(home, ".local", "state", "agents", "codex")
	if err := os.MkdirAll(filepath.Join(c.FormerStateDir, "strict", "-w"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.FormerStateDir, "strict", "-w", "history.jsonl"), []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c, home
}

// What an earlier chase kept is moved whole to where chase keeps it now,
// before the placeholder is written there, and ~/.local/state/agents, empty
// then, goes; a second run has nothing to move and says nothing.
func TestTheFormerStateIsMovedOnceBeforeThePlaceholderIsWritten(t *testing.T) {
	c, home := moved(t)
	var said bytes.Buffer
	MoveState(c, &said)
	if err := WritePlaceholder(c); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(c.StateDir, "strict", "-w", "history.jsonl")); err != nil || string(b) != "kept" {
		t.Errorf("a tier's home was not moved: %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(home, ".local", "state", "agents")); !os.IsNotExist(err) {
		t.Errorf("the empty agents directory is still there: %v", err)
	}
	if !strings.Contains(said.String(), "codex: "+c.FormerStateDir+" is "+c.StateDir+" now") {
		t.Errorf("the move was not said: %q", said.String())
	}
	said.Reset()
	MoveState(c, &said)
	if said.Len() != 0 {
		t.Errorf("a second run said something: %q", said.String())
	}
}

// Both there, both are left as they were, and that is said: neither is
// merged into the other, nor removed. Nor is an agents directory that holds
// anything else.
func TestBothStatesAreLeftWhereBothExist(t *testing.T) {
	c, home := moved(t)
	if err := WritePlaceholder(c); err != nil {
		t.Fatal(err)
	}
	var said bytes.Buffer
	MoveState(c, &said)
	if b, err := os.ReadFile(filepath.Join(c.FormerStateDir, "strict", "-w", "history.jsonl")); err != nil || string(b) != "kept" {
		t.Errorf("the former state was changed: %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(c.StateDir, "strict")); !os.IsNotExist(err) {
		t.Errorf("the former state was merged into the new: %v", err)
	}
	if !strings.Contains(said.String(), "is left as it was, beside "+c.StateDir) {
		t.Errorf("it was not said: %q", said.String())
	}

	c, home = moved(t)
	other := filepath.Join(home, ".local", "state", "agents", "cloudflare")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	MoveState(c, &said)
	if _, err := os.Stat(other); err != nil {
		t.Errorf("another directory under agents went: %v", err)
	}
}

func TestNoFormerStateMovesNothing(t *testing.T) {
	c := config(t)
	var said bytes.Buffer
	MoveState(c, &said)
	if _, err := os.Lstat(c.StateDir); !os.IsNotExist(err) || said.Len() != 0 {
		t.Errorf("something was done: %v %q", err, said.String())
	}
}

// sqlite3 is the sqlite3 on PATH, which the flake's checks and dev shell
// give: an index is codex's own sqlite, so nothing less shows it repointed.
func sqlite3(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Fatalf("sqlite3 is not on PATH, as the flake's checks and dev shell have it: %v", err)
	}
	return bin
}

// sql runs statements against db, and is what they printed.
func sql(t *testing.T, bin, db, statements string) string {
	t.Helper()
	out, err := exec.Command(bin, "-init", os.DevNull, "-batch", "-bail", db, statements).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v: %s", statements, err, out)
	}
	return strings.TrimSpace(string(out))
}

// paths is each thread's rollout_path in db, by id.
func paths(t *testing.T, bin, db string) string {
	t.Helper()
	return sql(t, bin, db, "SELECT id || ' ' || rollout_path FROM threads ORDER BY id;")
}

// codex opens a thread by the absolute path its index holds, so a home
// moved whole would list its threads and resume none. Each index's paths
// under the former directory are repointed to the same paths where the
// home is now -- in a tier's home and a workspace's, under a home whose
// path needs quoting and is not ASCII -- and nothing else: a path elsewhere,
// a sibling the former's name begins, and the thread's own history. A
// session started before the move goes on writing the former path, which
// the next run repoints too.
func TestEachMovedHomesThreadsArePointedAtWhereTheHomeIsNow(t *testing.T) {
	bin := sqlite3(t)
	home := filepath.Join(t.TempDir(), "d'an é")
	c := Config{
		StateDir:       filepath.Join(home, ".local", "state", "chase", "codex"),
		FormerStateDir: filepath.Join(home, ".local", "state", "agents", "codex"),
		SQLite:         bin,
	}
	c.Placeholder = filepath.Join(c.StateDir, "auth-placeholder.json")
	from, to := c.FormerStateDir, c.StateDir
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	var dbs []string
	for _, h := range []string{"strict", filepath.Join("strict", "-w")} {
		dir := filepath.Join(from, h)
		if err := os.MkdirAll(filepath.Join(dir, "sessions", "2026", "09", "20"), 0o700); err != nil {
			t.Fatal(err)
		}
		db := filepath.Join(dir, "state_5.sqlite")
		rollout := filepath.Join(dir, "sessions", "2026", "09", "20", "rollout-a.jsonl")
		sql(t, bin, db, "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL, title TEXT NOT NULL);"+
			"INSERT INTO threads VALUES ('a', "+q(rollout)+", "+q("read "+rollout)+"),"+
			" ('b', '/elsewhere/rollout-b.jsonl', 'b'),"+
			" ('c', "+q(from+"x/rollout-c.jsonl")+", 'c');")
		dbs = append(dbs, h)
	}
	// One no deeper than a home's sessions/, which is no home.
	deep := filepath.Join(from, "strict", "-w", "sessions", "state_5.sqlite")
	sql(t, bin, deep, "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL);"+
		"INSERT INTO threads VALUES ('a', "+q(from+"/x")+");")

	var said bytes.Buffer
	MoveState(c, &said)
	for _, h := range dbs {
		db := filepath.Join(to, h, "state_5.sqlite")
		rollout := filepath.Join(h, "sessions", "2026", "09", "20", "rollout-a.jsonl")
		want := "a " + filepath.Join(to, rollout) + "\nb /elsewhere/rollout-b.jsonl\nc " + from + "x/rollout-c.jsonl"
		if got := paths(t, bin, db); got != want {
			t.Errorf("%s holds\n%s\nnot\n%s", db, got, want)
		}
		if got := sql(t, bin, db, "SELECT title FROM threads WHERE id = 'a';"); got != "read "+filepath.Join(from, rollout) {
			t.Errorf("a thread's own history was rewritten: %q", got)
		}
		if !strings.Contains(said.String(), "codex: the threads "+db+" indexes under "+from+" are under "+to+" now (1 of them)") {
			t.Errorf("the repointing of %s was not said: %q", db, said.String())
		}
	}
	if got := sql(t, bin, filepath.Join(to, "strict", "-w", "sessions", "state_5.sqlite"), "SELECT rollout_path FROM threads;"); got != from+"/x" {
		t.Errorf("an index below a home was repointed: %q", got)
	}

	db := filepath.Join(to, "strict", "state_5.sqlite")
	sql(t, bin, db, "INSERT INTO threads VALUES ('d', "+q(filepath.Join(from, "strict", "rollout-d.jsonl"))+", 'd');")
	said.Reset()
	MoveState(c, &said)
	if got := sql(t, bin, db, "SELECT rollout_path FROM threads WHERE id = 'd';"); got != filepath.Join(to, "strict", "rollout-d.jsonl") {
		t.Errorf("a row written at the former path after the move was not repointed: %q", got)
	}
	said.Reset()
	MoveState(c, &said)
	if said.Len() != 0 {
		t.Errorf("a run with nothing to repoint said something: %q", said.String())
	}
}

// An index that cannot be repointed is said, and does not stop the rest.
func TestAnIndexThatCannotBeRepointedIsSaid(t *testing.T) {
	bin := sqlite3(t)
	c, _ := moved(t)
	c.SQLite = bin
	broken := filepath.Join(c.FormerStateDir, "strict", "state_5.sqlite")
	if err := os.WriteFile(broken, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(c.FormerStateDir, "strict", "-w", "state_5.sqlite")
	sql(t, bin, good, "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL);"+
		"INSERT INTO threads VALUES ('a', '"+c.FormerStateDir+"/strict/-w/r.jsonl');")
	var said bytes.Buffer
	MoveState(c, &said)
	if !strings.Contains(said.String(), "codex: the threads "+filepath.Join(c.StateDir, "strict", "state_5.sqlite")+" indexes still name "+c.FormerStateDir) {
		t.Errorf("the index left as it was is not said: %q", said.String())
	}
	if got := sql(t, bin, filepath.Join(c.StateDir, "strict", "-w", "state_5.sqlite"), "SELECT rollout_path FROM threads;"); got != c.StateDir+"/strict/-w/r.jsonl" {
		t.Errorf("the other index was not repointed: %q", got)
	}
}
