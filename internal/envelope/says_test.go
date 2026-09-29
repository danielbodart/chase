package envelope

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/sys/unix"
)

// A needle is found wherever it falls: in one read, across two, at either
// end, and in reads of a byte at a time.
func TestContainsFindsANeedleAcrossReads(t *testing.T) {
	needle := []byte("chaseModules")
	for _, at := range []int{0, 1, 64<<10 - 6, 64 << 10, 64<<10 - 12, 3 * 64 << 10} {
		text := bytes.Repeat([]byte("x"), at+200000)
		copy(text[at:], needle)
		if !contains(bytes.NewReader(text), needle) {
			t.Errorf("at %d: not found", at)
		}
		if !contains(iotest.OneByteReader(bytes.NewReader(text[:at+len(needle)+3])), needle) {
			t.Errorf("at %d, a byte at a time: not found", at)
		}
		text[at+5] = 'X'
		if contains(bytes.NewReader(text), needle) {
			t.Errorf("at %d: found when broken", at)
		}
	}
	if contains(strings.NewReader("chaseModule"), needle) {
		t.Error("found in less than itself")
	}
}

// Only a plain file is read, through a link as grep read it, and a pipe is
// not waited on.
func TestOnlyAPlainFileSaysChaseModules(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "flake.nix")
	if err := os.WriteFile(f, []byte("{ outputs = _: { chaseModules.default = {}; }; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !saysChaseModules(f) {
		t.Error("a flake that says chaseModules does not")
	}
	link := filepath.Join(dir, "link.nix")
	if err := os.Symlink(f, link); err != nil {
		t.Fatal(err)
	}
	if !saysChaseModules(link) {
		t.Error("a link to a flake that says chaseModules was not read through")
	}
	if saysChaseModules(dir) || saysChaseModules(filepath.Join(dir, "absent")) {
		t.Error("a directory or nothing says chaseModules")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	go func() { done <- saysChaseModules(fifo) }()
	select {
	case said := <-done:
		if said {
			t.Error("a pipe says chaseModules")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a pipe was waited on")
	}
}
