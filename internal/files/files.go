// Package files is how chase writes what others read while it writes.
//
// Two ways, and which is not a matter of taste. A file a reader may open at
// any moment -- a staged approval, the address ledger, a token -- is written
// beside itself and renamed over, so a reader sees the old bytes or the new
// and never half of either. A file a session has bind-mounted -- Codex's
// auth.json -- is written in place: a rename would detach the bind and
// uncover the real file under it, so the same inode is truncated and
// rewritten instead.
package files

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// WriteAtomic replaces path with data, at mode, by renaming a file written
// beside it: a reader sees the old file or the new, whole. Nothing is left
// behind when it fails.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// WriteInPlace truncates path and writes data into the same inode, creating
// it at mode if it is not there. For a file bind-mounted into a session,
// which a rename would detach. It follows no link at path.
func WriteInPlace(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Lock holds an exclusive lock on dir/.lock until the returned function is
// called, so read-modify-writes of what the directory holds are one at a
// time across processes.
func Lock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDONLY|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s: %w", dir, err)
	}
	return func() { f.Close() }, nil
}
