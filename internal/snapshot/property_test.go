package snapshot

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// The names every tree here is made of, in the checkout and the host's
// directory alike, so a link followed anywhere finds something by the name
// the list gave.
var names = []string{"a", "b", "c"}

const hostByte = "HOSTSECRET"

// hostTree is a host directory beside the checkout: a and b directories,
// and c a file, at every level, and all three files at the bottom, every
// file holding a host byte.
func hostTree(t *rapid.T, dir string, depth int) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		p := filepath.Join(dir, n)
		if n == "c" || depth == 0 {
			if err := os.WriteFile(p, []byte(hostByte+" "+p), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		hostTree(t, p, depth-1)
	}
}

func relPath(t *rapid.T, label string, max int) string {
	return strings.Join(rapid.SliceOfN(rapid.SampledFrom(names), 1, max).Draw(t, label), "/")
}

// Whatever tree of files, directories and links a session leaves in its
// checkout -- links to the host's directory and its files, by absolute path
// and by climbing out, and links within -- and whatever the index lists,
// nothing outside the checkout is ever copied: every file in the copy is the
// checkout's file at that path, reached through no link; every link in the
// copy is the checkout's link at that path, as it was; and a copy that
// succeeds has everything listed.
func TestNothingOutsideTheCheckoutIsEverCopied(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		root, err := os.MkdirTemp("", "snapshot-property")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(root)
		ws, host, out := filepath.Join(root, "ws"), filepath.Join(root, "host"), filepath.Join(root, "out")
		hostTree(t, host, 3)
		for _, d := range []string{ws, out} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}

		entries := rapid.IntRange(0, 12).Draw(t, "entries")
		for i := 0; i < entries; i++ {
			rel := relPath(t, "entry", 3)
			p := filepath.Join(ws, rel)
			depth := strings.Count(rel, "/")
			// What cannot be made where an earlier entry is -- under a file
			// or a link -- is not made: the tree is whatever came of it.
			os.MkdirAll(filepath.Dir(p), 0o755)
			switch rapid.IntRange(0, 6).Draw(t, "kind") {
			case 0:
				os.Mkdir(p, 0o755)
			case 1:
				os.WriteFile(p, []byte("ws "+rel), 0o644)
			case 2:
				os.WriteFile(p, []byte("ws "+rel), 0o755)
			case 3:
				os.Symlink(filepath.Join(host, relPath(t, "target", 2)), p)
			case 4:
				os.Symlink(host, p)
			case 5:
				os.Symlink(strings.Repeat("../", depth+1)+"host/"+relPath(t, "target", 2), p)
			case 6:
				os.Symlink(relPath(t, "target", 2), p)
			}
		}

		listed := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) string { return relPath(t, "listed", 4) }), 0, 8).Draw(t, "list")
		err = CopyTracked(ws, out, listed)
		var refused *Refused
		if err != nil && !errors.As(err, &refused) {
			t.Fatalf("a fault of the host's: %v", err)
		}

		filepath.WalkDir(out, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || p == out {
				return walkErr
			}
			rel, _ := filepath.Rel(out, p)
			switch {
			case d.Type().IsRegular():
				b, _ := os.ReadFile(p)
				if bytes.Contains(b, []byte(hostByte)) {
					t.Fatalf("%s holds the host's %q", rel, b)
				}
				if !linkless(ws, rel) {
					t.Fatalf("%s was copied through a link", rel)
				}
				if w, _ := os.ReadFile(filepath.Join(ws, rel)); !bytes.Equal(b, w) {
					t.Fatalf("%s is %q, and the checkout's %q", rel, b, w)
				}
			case d.Type()&fs.ModeSymlink != 0:
				got, _ := os.Readlink(p)
				want, err := os.Readlink(filepath.Join(ws, rel))
				if err != nil || got != want || !linkless(ws, filepath.Dir(rel)) {
					t.Fatalf("%s is a link to %q, and the checkout's %q %v", rel, got, want, err)
				}
			case d.IsDir():
				if !linkless(ws, rel) {
					t.Fatalf("%s was made for a link", rel)
				}
			}
			return nil
		})
		if err == nil {
			for _, p := range listed {
				if _, err := os.Lstat(filepath.Join(out, p)); err != nil {
					t.Fatalf("%s was listed and not copied: %v", p, err)
				}
			}
		}
	})
}

// linkless is whether rel is reached from ws through no link: every
// component above it a directory, and itself not a link. "." is.
func linkless(ws, rel string) bool {
	if rel == "." {
		return true
	}
	p := ws
	for _, c := range strings.Split(rel, "/") {
		p = filepath.Join(p, c)
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&fs.ModeSymlink != 0 {
			return false
		}
	}
	return true
}
