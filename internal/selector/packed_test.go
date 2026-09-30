package selector_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
	"github.com/danielbodart/chase/internal/selector"
)

const (
	commitA = "1111111111111111111111111111111111111111"
	commitB = "2222222222222222222222222222222222222222"
)

// packed-refs is read as `grep -F " REF"` and `read -r o name` read it.
func TestPackedRefsIsReadAsGrepAndReadDid(t *testing.T) {
	d := gitsafetest.Dir(t)
	p := filepath.Join(d, "packed-refs")
	for _, c := range []struct{ name, file, want string }{
		{"found", "# pack-refs with: peeled fully-peeled sorted \n" + commitA + " refs/heads/main\n", commitA},
		{"the first match", commitA + " refs/heads/main\n" + commitB + " refs/heads/main\n", commitA},
		{"a longer name is not it", commitA + " refs/heads/main2\n" + commitB + " refs/heads/main\n", commitB},
		{"the last line unended", commitB + " refs/heads/x\n" + commitA + " refs/heads/main", commitA},
		{"blanks around", "  " + commitA + "\t refs/heads/main  \n", commitA},
		{"a NUL after the match", commitA + " refs/heads/main\n\x00\n", ""},
		{"not there", commitA + " refs/heads/other\n", ""},
		{"empty", "", ""},
	} {
		if err := os.WriteFile(p, []byte(c.file), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := selector.PackedRef(p, "refs/heads/main"); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// Swapped after it was looked at, packed-refs is not followed as a link,
// not waited on as a pipe, and not read past its size.
func TestPackedRefsSwappedAfterItsLookIsNotRead(t *testing.T) {
	d := gitsafetest.Dir(t)
	real := filepath.Join(d, "real")
	os.WriteFile(real, []byte(commitA+" refs/heads/main\n"), 0o600)

	link := filepath.Join(d, "link")
	os.Symlink(real, link)
	if got := selector.PackedRef(link, "refs/heads/main"); got != "" {
		t.Errorf("a link was followed: %q", got)
	}

	fifo := filepath.Join(d, "fifo")
	if err := mkfifo(fifo); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() { done <- selector.PackedRef(fifo, "refs/heads/main") }()
	select {
	case got := <-done:
		if got != "" {
			t.Errorf("a pipe was read: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a pipe was waited on")
	}

	// A sparse file of a hundred gigabytes is not read to its end.
	sparse := filepath.Join(d, "sparse")
	os.WriteFile(sparse, []byte(commitA+" refs/heads/main\n"), 0o600)
	if err := truncate(sparse, 100<<30); err != nil {
		t.Fatal(err)
	}
	if got := selector.PackedRef(sparse, "refs/heads/main"); got != "" {
		t.Errorf("a sparse file was read: %q", got)
	}
	// Its match first and blank lines after: only its size is what fails
	// a file one byte over. Each is 64 MiB read a line at a time, which the
	// race detector takes most of a minute over, so checks.test holds the
	// size and checks.race does not.
	if race {
		return
	}
	line := commitA + " refs/heads/main\n"
	over := filepath.Join(d, "over")
	os.WriteFile(over, []byte(line+strings.Repeat("\n", gitsafe.PackedRefsSize+1-len(line))), 0o600)
	if got := selector.PackedRef(over, "refs/heads/main"); got != "" {
		t.Errorf("a file grown past its size was read: %q", got)
	}
	exact := filepath.Join(d, "exact")
	os.WriteFile(exact, []byte(line+strings.Repeat("\n", gitsafe.PackedRefsSize-len(line))), 0o600)
	if got := selector.PackedRef(exact, "refs/heads/main"); got != commitA {
		t.Errorf("a file of just the size was not read: %q", got)
	}
}
