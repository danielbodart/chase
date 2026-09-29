package files

import (
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
