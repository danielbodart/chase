// Package nixstore is a session's own Nix store, kept on the host for one
// launch (flong's PLAN §3): an overlay of the host's /nix/store, its upper
// a directory of the caller's, over which the session runs nix itself,
// single-user, against a local-overlay store whose lower is the host's,
// read-only. What a session of other people's code evaluates and fetches
// is then the session's own, under its own filters and through its own
// network -- frisket, for a tier whose egress is frisket's -- and nothing
// of it is ever evaluated on the host.
//
// Its directory is <root>/<machine>, ~/.cache/chase/nix/sessions/<machine>:
//
//	layers/{upper,work}  the overlay's, which flong shapes and mounts; never
//	                     bound in
//	state/               the store's own database, profiles, roots and log,
//	                     bound read-write
//	lower/               the read-only lower's state: the directories it
//	                     needs, empty, and db, a link to the host's
//	                     database, which flong binds read-only; bound
//	                     read-only
//	roots                the host's GC root for what the store looks at of
//	                     the host's (Refresh)
//	promote.list         the names promoted after it (Promote)
//
// Made at binds (Binds), watched from postStart (Watch), and gone at
// postStop (PostStop), keyed by the machine flong names the session by
// before binds, so every hook finds the same one. A directory no
// container holds, left by a launcher that was killed, is swept by the
// next launch's binds and by an hourly timer (Sweep).
package nixstore

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// The host's store and database, as the session sees them too: flong binds
// both at their own paths, the store under the overlay.
const (
	Store  = "/nix/store"
	hostDB = "/nix/var/nix/db"
)

// machineName is a machine flong names a session by: what may be a
// directory's name and nothing more.
var machineName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Dir is the directory of machine's store, refused for a machine that is
// no plain name.
func Dir(s *session.NixSession, machine string) (string, error) {
	if !machineName.MatchString(machine) {
		return "", fmt.Errorf("the session's machine %q is no name a directory may have", term.Clean(machine))
	}
	return filepath.Join(s.Root, machine), nil
}

// lowerDirs are what a read-only local store wants in its state directory,
// empty: it neither makes them nor writes in them.
var lowerDirs = []string{"gcroots/per-user", "profiles/per-user", "temproots", "active-builds"}

// Binds makes machine's store and prints what flong's binds is to print
// of it: the overlay of the host's store, its layers in the directory;
// the store's state, read-write; and the lower's, read-only. What a
// killed launch left is swept first.
func Binds(s *session.NixSession, machine string, out io.Writer, stderr io.Writer) error {
	Sweep(s, stderr)
	dir, err := Dir(s, machine)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return err
	}
	// A directory of this machine's is a launch's that died before its
	// postStop: nothing of it is this one's.
	if _, err := os.Lstat(dir); err == nil {
		if err := remove(dir); err != nil {
			return fmt.Errorf("%s is left from an earlier session, and could not be removed: %v", dir, err)
		}
	}
	for _, d := range []string{"layers", "state"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return err
		}
	}
	for _, d := range lowerDirs {
		if err := os.MkdirAll(filepath.Join(dir, "lower", d), 0o755); err != nil {
			return err
		}
	}
	if err := os.Symlink(hostDB, filepath.Join(dir, "lower", "db")); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s:overlay:%s\n%s:rw\n%s\n", Store, filepath.Join(dir, "layers"), filepath.Join(dir, "state"), filepath.Join(dir, "lower"))
	return err
}

// Made is whether binds, as $binds shows it, put a store of the session's
// own over the host's: flong shows the overlay without its layers.
func Made(binds string) bool {
	for _, l := range strings.Split(binds, "\n") {
		if l == Store+":overlay" {
			return true
		}
	}
	return false
}

// Env is what the session's nix is told of its store: the local-overlay
// store over the host's, its upper named but never bound in, and its
// mount not checked, since flong passes the layers by descriptor; its log
// in the store's state; and nix's configuration the container's alone.
func Env(s *session.NixSession, machine string) ([]session.Var, error) {
	dir, err := Dir(s, machine)
	if err != nil {
		return nil, err
	}
	lower := "local?" + query([][2]string{{"real", Store}, {"state", filepath.Join(dir, "lower")}, {"read-only", "true"}})
	store := "local-overlay://?" + query([][2]string{
		{"real", Store}, {"state", filepath.Join(dir, "state")}, {"lower-store", lower},
		{"upper-layer", filepath.Join(dir, "layers", "upper")}, {"check-mount", "false"},
	})
	return []session.Var{
		{Name: "NIX_REMOTE", Value: store},
		{Name: "NIX_LOG_DIR", Value: filepath.Join(dir, "state", "log")},
		{Name: "NIX_USER_CONF_FILES", Value: ""},
		{Name: "NIX_CONF_DIR", Value: s.ConfDir},
	}, nil
}

// query is a URL's query of each pair, in order, each escaped but its
// slashes, which a query may hold as they are and nix reads as such.
func query(pairs [][2]string) string {
	var q []string
	for _, p := range pairs {
		q = append(q, escape(p[0])+"="+escape(p[1]))
	}
	return strings.Join(q, "&")
}

func escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "%2F", "/")
}

// orphanAfter is how old a directory no container holds must be before it
// is swept: a launch's binds makes it a moment before flong locks it.
const orphanAfter = 10 * time.Minute

// Sweep removes every session's store that no container holds and that
// is older than orphanAfter, with its root: what a launcher killed before
// its postStop left. flong holds a store's layers locked until its
// container's cgroup is empty, so one it does not hold is no session's.
func Sweep(s *session.NixSession, stderr io.Writer) {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !machineName.MatchString(e.Name()) {
			continue
		}
		dir := filepath.Join(s.Root, e.Name())
		fi, err := os.Lstat(dir)
		if err != nil || time.Since(fi.ModTime()) < orphanAfter || held(dir) {
			continue
		}
		if err := remove(dir); err != nil {
			term.Say(stderr, "%s is a session's nix store left behind, and could not be removed: %v", dir, err)
		}
	}
}

// held is whether a container holds dir's layers: flong's lock on them,
// tried.
func held(dir string) bool {
	fd, err := unix.Open(filepath.Join(dir, "layers"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	return errors.Is(unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB), unix.EWOULDBLOCK)
}

// remove removes dir, all of it, as `chmod -R u+w`, then `rm -rf`, would:
// a store's paths are read-only, and the upper's root is the container's
// root's, its sticky bit leaving the caller to remove its own entries
// and then the root, which is in a directory of the caller's. Its root
// for the host goes last, so what the session's store looks at is held
// until nothing of it is left.
func remove(dir string) error {
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			unix.Fchmodat(unix.AT_FDCWD, p, 0o700, 0)
		}
		return nil
	})
	roots := filepath.Join(dir, "roots")
	var err error
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if p := filepath.Join(dir, e.Name()); p != roots {
			if rerr := os.RemoveAll(p); rerr != nil && err == nil {
				err = rerr
			}
		}
	}
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}
