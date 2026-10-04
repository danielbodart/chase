package nixstore

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// every is how often a session's store is looked at.
const every = 2 * time.Second

// Watch is `chase nix-watch`, started by postStart in the session's
// cgroup, so it lives exactly as long as the session: every couple of
// seconds it measures the upper, and stops the session once it is past
// the tier's bytes or inodes, said on the session's terminal; and, when
// the store's database has changed since it last looked, it roots on the
// host what the store looks at of the host's (Refresh). leader is the
// session's pid 1, as postStart is told it: killed, it ends the session.
// It returns when ctx is done, or once it has stopped the session.
func Watch(ctx context.Context, n session.Nix, machine string, leader int, stderr io.Writer) error {
	dir, err := Dir(n.Session, machine)
	if err != nil {
		return err
	}
	var seen [2]stamp
	said := ""
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if bytes, inodes, err := Usage(filepath.Join(dir, "layers", "upper")); err == nil && over(n.Session, bytes, inodes) {
			term.Say(stderr, "%s: the session's nix store is over its limit (%d bytes, %d inodes, of %d and %d): the session is stopped", dir, bytes, inodes, n.Session.MaxBytes, n.Session.MaxInodes)
			os.WriteFile(filepath.Join(dir, "over"), nil, 0o600)
			if leader > 1 {
				syscall.Kill(leader, syscall.SIGKILL)
			}
			return nil
		}
		now := [2]stamp{stampOf(filepath.Join(dir, "state", "db", "db.sqlite")), stampOf(filepath.Join(dir, "state", "db", "db.sqlite-wal"))}
		if now != seen {
			// Tried again at the next look, said once until it is said
			// otherwise.
			if err := Refresh(ctx, n, dir, stderr); err != nil {
				if err.Error() != said {
					term.Say(stderr, "%s: what the session's nix store looks at of the host's could not be rooted: %v", dir, err)
					said = err.Error()
				}
			} else {
				seen, said = now, ""
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// over is whether an upper of bytes and inodes is past s's limits.
func over(s *session.NixSession, bytes, inodes int64) bool {
	return bytes > s.MaxBytes || inodes > s.MaxInodes
}

// stamp is what tells a file changed: its size and its modification.
type stamp struct {
	size int64
	mod  int64
}

func stampOf(p string) stamp {
	fi, err := os.Lstat(p)
	if err != nil {
		return stamp{}
	}
	return stamp{fi.Size(), fi.ModTime().UnixNano()}
}

// Usage is the bytes and inodes under upper, each inode counted once, as
// the disk holds them: its blocks, not its size, so a sparse file is what
// it costs.
func Usage(upper string) (bytes, inodes int64, err error) {
	seen := map[[2]uint64]bool{}
	err = filepath.WalkDir(upper, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil {
			return nil
		}
		id := [2]uint64{st.Dev, st.Ino}
		if seen[id] {
			return nil
		}
		seen[id] = true
		inodes++
		bytes += st.Blocks * 512
		return nil
	})
	return bytes, inodes, err
}
