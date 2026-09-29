package checkout_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
)

// chase-checkout, chase-origin and chase-ls-files each leave nothing of
// their own git behind, though what calls them then exits.
func TestEntryPointsLeaveNoEmptyRepositoryBehind(t *testing.T) {
	fx := gitsafetest.NewFixture(t)
	r := gitsafetest.Dir(t)
	fx.Repo(r+"/c", "git@github.com:example/shop.git", "a@example.com")
	os.WriteFile(r+"/c/f", nil, 0o644)
	fx.Run("-C", r+"/c", "add", "f")
	runtime := gitsafetest.Dir(t)
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	g, err := gitsafe.New(gitsafe.Config{Git: gitsafetest.GitPath(t)})
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func(context.Context, *gitsafe.Git, []string, *bytes.Buffer, *bytes.Buffer) int{
		"chase-checkout": checkoutCmd, "chase-origin": originCmd, "chase-ls-files": lsFilesCmd,
	} {
		if out, rc := call(t, g, run, r+"/c"); rc != 0 {
			t.Errorf("%s: %q %d", name, out, rc)
		}
		if es, _ := os.ReadDir(runtime); len(es) != 0 {
			t.Errorf("%s left %v in $XDG_RUNTIME_DIR", name, es)
		}
	}
}

// A copy of the index cut short by its timeout writes nothing after it:
// removed then, the copy is not made again.
func TestAnIndexCopyCutShortLeavesNothing(t *testing.T) {
	d := gitsafetest.Dir(t)
	index := filepath.Join(d, "index")
	f, _ := os.Create(index)
	f.Truncate(200 << 20)
	f.Close()
	tmp := filepath.Join(d, "tmp")
	os.Mkdir(tmp, 0o700)
	if _, err := checkout.CopyIndexWithin(index, filepath.Join(tmp, "index"), time.Nanosecond); err == nil {
		t.Skip("the copy finished within a nanosecond, so it was not cut short")
	}
	os.RemoveAll(tmp)
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
		t.Errorf("the copy was made again after it was removed: %v", err)
	}

	// Whole, it is made where it is asked for, and not over anything there.
	os.Mkdir(tmp, 0o700)
	os.WriteFile(index, []byte("DIRC"), 0o600)
	if n, err := checkout.CopyIndexWithin(index, filepath.Join(tmp, "index"), time.Minute); err != nil || n != 4 {
		t.Errorf("a whole copy: %d %v", n, err)
	}
	if _, err := checkout.CopyIndexWithin(index, filepath.Join(tmp, "index"), time.Minute); err == nil {
		t.Error("a copy was made over a file already there")
	}
}
