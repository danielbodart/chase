package files

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicReplacesTheFileAndLeavesNothingBeside(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)
	if err := WriteAtomic(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(p)
	if b, _ := os.ReadFile(p); string(b) != "new" || after.Mode().Perm() != 0o600 {
		t.Errorf("got %q at %v", b, after.Mode())
	}
	if os.SameFile(before, after) {
		t.Error("the file was rewritten in place, not replaced")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left beside it: %v", entries)
	}
}

// What a session has bind-mounted keeps its inode, so the mount still shows it.
func TestWriteInPlaceKeepsTheInode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(p, []byte("a much longer old value"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)
	if err := WriteInPlace(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(p)
	if b, _ := os.ReadFile(p); string(b) != "new" || !os.SameFile(before, after) {
		t.Errorf("got %q, same inode %v", b, os.SameFile(before, after))
	}
}

func TestWriteInPlaceFollowsNoLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("keep"), 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteInPlace(link, []byte("x"), 0o600); err == nil {
		t.Error("wrote through a link")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("the link's target became %q", b)
	}
}

func TestLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		u, err := Lock(dir)
		if err == nil {
			u()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("a second lock was taken while the first was held")
	default:
	}
	unlock()
	<-got
}

// A directory chase keeps elsewhere now is moved there once, whole, and
// asking again finds nothing to move.
func TestMoveDirMovesTheDirectoryOnce(t *testing.T) {
	home := t.TempDir()
	from, to := filepath.Join(home, "agents", "codex"), filepath.Join(home, "chase", "codex")
	if err := os.MkdirAll(filepath.Join(from, "strict"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(from, "strict", "auth.json"), []byte("login"), 0o600); err != nil {
		t.Fatal(err)
	}
	if moved, err := MoveDir(from, to); !moved || err != nil {
		t.Fatalf("not moved: %v %v", moved, err)
	}
	if b, err := os.ReadFile(filepath.Join(to, "strict", "auth.json")); err != nil || string(b) != "login" {
		t.Errorf("what was kept is not at the new place: %q %v", b, err)
	}
	if _, err := os.Lstat(from); !os.IsNotExist(err) {
		t.Errorf("the old place is still there: %v", err)
	}
	if moved, err := MoveDir(from, to); moved || err != nil {
		t.Errorf("a second move did something: %v %v", moved, err)
	}
}

// Something at both places is left as it is, both of them: neither is
// merged into the other, and neither is removed -- not even an empty one.
func TestMoveDirLeavesBothWhereBothExist(t *testing.T) {
	home := t.TempDir()
	from, to := filepath.Join(home, "agents", "codex"), filepath.Join(home, "chase", "codex")
	for _, d := range []string{from, to} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(from, "kept"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved, err := MoveDir(from, to)
	if moved || !errors.Is(err, ErrBothExist) {
		t.Fatalf("both were not left: %v %v", moved, err)
	}
	if b, _ := os.ReadFile(filepath.Join(from, "kept")); string(b) != "old" {
		t.Errorf("the old place was changed: %q", b)
	}
	if entries, _ := os.ReadDir(to); len(entries) != 0 {
		t.Errorf("something was merged into the new place: %v", entries)
	}
}

func TestMoveDirMovesNothingThatIsNotADirectory(t *testing.T) {
	home := t.TempDir()
	from, to := filepath.Join(home, "codex"), filepath.Join(home, "chase", "codex")
	if err := os.Symlink(home, from); err != nil {
		t.Fatal(err)
	}
	if moved, err := MoveDir(from, to); moved || err == nil {
		t.Errorf("a link was moved: %v %v", moved, err)
	}
	if moved, err := MoveDir(filepath.Join(home, "absent"), to); moved || err != nil {
		t.Errorf("nothing was something: %v %v", moved, err)
	}
	if _, err := os.Lstat(to); !os.IsNotExist(err) {
		t.Errorf("the new place was made: %v", err)
	}
}
