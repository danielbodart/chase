package grant

import (
	"encoding/json"
	"io"
	"os"
	"slices"

	"golang.org/x/sys/unix"
)

// maxFile is the largest chase.jsonc read before its approval.
const maxFile = 1 << 20

// AsksForNixStore is whether the checkout's chase.jsonc, as it is now, asks
// for a store of the session's own (apps.nix): what binds, which runs
// before the grant is approved, makes one for. What it says decides only
// whether an empty store is made, which nothing uses unless the grant
// approved after it asks for it too: exec gives the session its store, and
// its devShell, from the approved grant alone. A tier that takes no
// checkout's grant, and a file that is missing, no plain file, or not a
// grant, ask for nothing.
func AsksForNixStore(c Config, ws, tier string) bool {
	if slices.Contains(c.Ungranted, tier) {
		return false
	}
	f, err := os.OpenFile(ws+"/"+FileName, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil || len(b) > maxFile {
		return false
	}
	out, err := ParseFile(b)
	if err != nil {
		return false
	}
	var g File
	if json.Unmarshal(out, &g) != nil {
		return false
	}
	return g.Apps.Nix.asks()
}
