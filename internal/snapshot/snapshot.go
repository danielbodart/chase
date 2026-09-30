// Package snapshot copies a checkout's tracked files into a directory of the
// user's own, following no link at any component on either side.
//
// What is copied is read and decrypted on the host, and the checkout is
// one a session writes. A copier that opens WS/dir/f by its path lets the
// kernel resolve dir, so a session that makes dir a link to a host directory
// -- another project's sops directory, say -- has that host's f copied in,
// and a check for links before and after the copy is raced by another live
// session of the same checkout. So WS is opened once, and every path is
// walked from it one component at a time, each directory opened beneath the
// one before it with O_NOFOLLOW: what is opened is always a directory below
// WS, whatever is swapped in while it runs.
//
// A tracked file is copied with its exec bit. A tracked link is made again
// as a link, never read through: where it points is decided by what reads
// the copy. A tracked directory -- a submodule's gitlink -- is made empty, as
// tar made it. Anything else, a link or a file above a tracked path, and a
// tracked path missing from the work tree all refuse: the list is the index,
// which the session writes, so a path that is absolute, or has an empty, '.'
// or '..' component, refuses too, since it would leave WS.
package snapshot

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/term"
)

const (
	dirFlags  = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	leafFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	newFlags  = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC
	// A tracked file is read and written this much at a time.
	chunk = 1 << 20
)

// Refused is why a checkout's tracked files were not copied, in words for the
// person: what the index listed, or what the work tree has, is not something
// a snapshot may take. Anything else CopyTracked returns is a fault of the
// host's -- the destination could not be written -- rather than of the
// checkout's.
type Refused struct {
	Reason string
}

func (r *Refused) Error() string { return r.Reason }

func uncopied(path, why string) *Refused {
	return &Refused{"its tracked files could not be copied: " + path + ": " + why}
}

// strerror is the C library's words for an errno, as the copier this replaces
// said them: Go's table is the same text with its first letter lowered, so it
// is raised again where the second is lower-case, as Go's own generator
// lowered it.
func strerror(err error) string {
	var e unix.Errno
	if !errors.As(err, &e) {
		return err.Error()
	}
	s := e.Error()
	if len(s) >= 2 && s[0] >= 'a' && s[0] <= 'z' && s[1] >= 'a' && s[1] <= 'z' {
		s = string(s[0]-'a'+'A') + s[1:]
	}
	return s
}

// retry is f again for as long as it is interrupted: Go's runtime signals
// its own threads, and a system call it interrupts is not restarted for us.
func retry(f func() error) error {
	for {
		if err := f(); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func openat(dir int, name string, flags int, mode uint32) (int, error) {
	var fd int
	err := retry(func() (err error) {
		fd, err = unix.Openat(dir, name, flags, mode)
		return err
	})
	return fd, err
}

// openDir is the directory name beneath fd, never a link: prefix names it.
func openDir(fd int, name, prefix string) (int, error) {
	d, err := openat(fd, name, dirFlags, 0)
	if err == nil {
		return d, nil
	}
	if !errors.Is(err, unix.ELOOP) && !errors.Is(err, unix.ENOTDIR) {
		return -1, uncopied(prefix, strerror(err))
	}
	var st unix.Stat_t
	mode := uint32(unix.S_IFLNK)
	if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
		mode = st.Mode
	}
	if mode&unix.S_IFMT == unix.S_IFLNK {
		return -1, &Refused{prefix + " is a link, so what is tracked under it would be copied from wherever it points"}
	}
	return -1, uncopied(prefix, "it is not a directory")
}

// makeDir is the directory name beneath fd, made if it is not there.
func makeDir(fd int, name, prefix string) (int, error) {
	err := retry(func() error { return unix.Mkdirat(fd, name, 0o755) })
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, fmt.Errorf("mkdir %s: %w", prefix, err)
	}
	return openDir(fd, name, prefix)
}

// copyLeaf copies name beneath ws to name beneath src: path names it.
func copyLeaf(ws, src int, name, path string) error {
	fd, err := openat(ws, name, leafFlags, 0)
	if err != nil {
		if !errors.Is(err, unix.ELOOP) {
			return uncopied(path, strerror(err))
		}
		target, err := readlinkat(ws, name)
		if err != nil {
			return uncopied(path, strerror(err))
		}
		if err := unix.Symlinkat(target, src, name); err != nil {
			return fmt.Errorf("symlink %s: %w", path, err)
		}
		return nil
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		d, err := makeDir(src, name, path)
		if err != nil {
			return err
		}
		return unix.Close(d)
	case unix.S_IFREG:
		if err := unix.SetNonblock(fd, false); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		mode := uint32(0o644)
		if st.Mode&unix.S_IXUSR != 0 {
			mode = 0o755
		}
		out, err := openat(src, name, newFlags, mode)
		if err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		if err := pour(out, fd); err != nil {
			unix.Close(out)
			return fmt.Errorf("copy %s: %w", path, err)
		}
		// Where the copy is written -- NFS, FUSE, a home with a quota -- a
		// write may fail only when it is closed, and a copy cut short is
		// what would be compared, read and decrypted: the copier this
		// replaces died of it, and so does this. Close is not retried on
		// EINTR: on Linux the descriptor is gone either way.
		if err := unix.Close(out); err != nil {
			return fmt.Errorf("close %s: %w", path, err)
		}
		return nil
	default:
		return uncopied(path, "it is not a file, a link or a directory")
	}
}

// readlinkat is where the link name beneath dir points, however long.
func readlinkat(dir int, name string) (string, error) {
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		var n int
		err := retry(func() (err error) {
			n, err = unix.Readlinkat(dir, name, buf)
			return err
		})
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
}

// pour writes everything read from in to out.
func pour(out, in int) error {
	buf := make([]byte, chunk)
	for {
		var n int
		if err := retry(func() (err error) {
			n, err = unix.Read(in, buf)
			return err
		}); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		for view := buf[:n]; len(view) > 0; {
			var w int
			if err := retry(func() (err error) {
				w, err = unix.Write(out, view)
				return err
			}); err != nil {
				return err
			}
			view = view[w:]
		}
	}
}

// held is a directory open on both sides: its name, beneath the one held
// before it, in the checkout and in the copy.
type held struct {
	name     string
	ws, dest int
}

// CopyTracked copies each of paths, relative to ws, from ws into dest,
// following no link at any component on either side. A *Refused says why
// the checkout could not be copied; any other error is the host's. What was
// copied before either is left where it is, for the caller to remove.
func CopyTracked(ws, dest string, paths []string) error {
	wsRoot, err := openat(unix.AT_FDCWD, ws, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", ws, err)
	}
	defer unix.Close(wsRoot)
	destRoot, err := openat(unix.AT_FDCWD, dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", dest, err)
	}
	defer unix.Close(destRoot)
	// The directories above the last path copied, open on both sides: the
	// next shares a prefix with it more often than not, and no more are held
	// than a path is deep.
	var dirs []held
	release := func(keep int) {
		for _, h := range dirs[keep:] {
			unix.Close(h.ws)
			unix.Close(h.dest)
		}
		dirs = dirs[:keep]
	}
	defer release(0)
	done := map[string]bool{}
	for _, path := range paths {
		parts := strings.Split(path, "/")
		if strings.HasPrefix(path, "/") || leaves(parts) {
			return &Refused{"its index lists " + path + ", which is not a path below it"}
		}
		if done[path] {
			// An unmerged path is listed once for each of its stages.
			continue
		}
		done[path] = true
		above := parts[:len(parts)-1]
		keep := 0
		for keep < min(len(dirs), len(above)) && dirs[keep].name == above[keep] {
			keep++
		}
		release(keep)
		for i := keep; i < len(above); i++ {
			w, s := wsRoot, destRoot
			if len(dirs) > 0 {
				w, s = dirs[len(dirs)-1].ws, dirs[len(dirs)-1].dest
			}
			prefix := strings.Join(above[:i+1], "/")
			wd, err := openDir(w, above[i], prefix)
			if err != nil {
				return err
			}
			sd, err := makeDir(s, above[i], prefix)
			if err != nil {
				unix.Close(wd)
				return err
			}
			dirs = append(dirs, held{above[i], wd, sd})
		}
		w, s := wsRoot, destRoot
		if len(dirs) > 0 {
			w, s = dirs[len(dirs)-1].ws, dirs[len(dirs)-1].dest
		}
		if err := copyLeaf(w, s, parts[len(parts)-1], path); err != nil {
			return err
		}
	}
	return nil
}

// leaves is whether any component would not be a name below the directory
// before it.
func leaves(parts []string) bool {
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return true
		}
	}
	return false
}

const usage = "usage: chase-copy-tracked WS SRC < PATHS\n"

// Run is chase-copy-tracked WS SRC: the paths to copy on stdin, each ended by
// a NUL. It succeeds silently, or prints why it refused, on stdout, and
// returns 1; a fault of the host's is said on stderr, and is 1 too, with
// nothing on stdout. Wrong arguments print the usage on stdout and return 2.
//
// What is refused names what the session wrote, and whoever reads stdout
// says it to a person, so it is cleaned here too: cleaning twice is cleaning
// once.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		io.WriteString(stdout, usage)
		return 2
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		term.Say(stderr, "copy-tracked: %v", err)
		return 1
	}
	listed := strings.Split(string(data), "\x00")
	if listed[len(listed)-1] == "" {
		listed = listed[:len(listed)-1]
	}
	err = CopyTracked(args[0], args[1], listed)
	var refused *Refused
	switch {
	case err == nil:
		return 0
	case errors.As(err, &refused):
		io.WriteString(stdout, term.Clean(refused.Reason)+"\n")
		return 1
	default:
		term.Say(stderr, "copy-tracked: %v", err)
		return 1
	}
}
