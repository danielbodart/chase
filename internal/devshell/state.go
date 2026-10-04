package devshell

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// lockDir holds dir/lock until the returned function is called, so one
// launch of a checkout checks, realises, records and prunes at a time, and
// the next finds what it left. wait false is a try, ErrHeld when another
// holds it.
func lockDir(dir string, wait bool) (func(), error) {
	f, err := os.OpenFile(dir+"/lock", os.O_RDONLY|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	how := unix.LOCK_EX
	if !wait {
		how |= unix.LOCK_NB
	}
	if err := unix.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errHeld
		}
		return nil, fmt.Errorf("lock %s: %w", dir, err)
	}
	return func() { f.Close() }, nil
}

var errHeld = errors.New("held")

// sweep lets go of every devShell whose checkout is gone: its devshell
// directory, its GC root among it, removed, unless a launch holds it. One
// small read for each checkout chase keeps anything of, at each launch
// that wants a devShell.
func sweep(state string) {
	found, _ := filepath.Glob(state + "/checkouts/*/devshell/state.json")
	for _, p := range found {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var s struct {
			Workspace string `json:"workspace"`
		}
		if json.Unmarshal(b, &s) != nil || s.Workspace == "" {
			continue
		}
		if fi, err := os.Lstat(s.Workspace); err == nil && fi.IsDir() {
			continue
		}
		dir := filepath.Dir(p)
		unlock, err := lockDir(dir, false)
		if err != nil {
			continue
		}
		os.RemoveAll(dir)
		unlock()
	}
}

var generation = regexp.MustCompile(`^profile-[0-9]+-link$`)

// prune removes every generation of the profile but the one it points to:
// nix keeps each, and each is a GC root.
func prune(dir string) {
	current, _ := os.Readlink(dir + "/profile")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if generation.MatchString(e.Name()) && e.Name() != current && !strings.HasSuffix(current, "/"+e.Name()) {
			os.Remove(dir + "/" + e.Name())
		}
	}
}

// staleSnapshots removes every snapshot in dir but mine older than age: one
// a launch killed before it removed its own, never one a launch is still
// realising from, which is no older than its timeout.
func staleSnapshots(dir, mine string, age time.Duration) {
	found, _ := filepath.Glob(dir + "/devshell-snapshot.*")
	for _, p := range found {
		if fi, err := os.Lstat(p); err == nil && p != mine && fi.IsDir() && time.Since(fi.ModTime()) > age {
			os.RemoveAll(p)
		}
	}
}
