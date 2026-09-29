package gitsafe

import (
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Exists is `[ -e P ] || [ -L P ]`: anything at all is there, a dangling link
// included.
func Exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// ExistsFollowing is `[ -e P ]`: something is there once links are followed,
// so a dangling link is not.
func ExistsFollowing(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// IsDir is `[ -d P ]`, following links.
func IsDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// IsLink is `[ -L P ]`.
func IsLink(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

// Regular is a plain file: not a link, a pipe or a device, which git would
// follow or wait on.
func Regular(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Sizes a file read here may be, and no larger: a gitdir file, HEAD or a
// loose ref is a line; a config a few kilobytes; packed-refs a line a ref;
// an index some hundred bytes a tracked file, and 256 MiB is well over a
// million of them. git itself caps a gitdir file.
const (
	LineSize       = 4096
	ConfigSize     = 1 << 20
	PackedRefsSize = 64 << 20
	IndexSize      = 256 << 20
)

// Small is a plain file of at most max bytes.
func Small(p string, max int64) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Size() <= max
}

// FirstLine is the first line of a file as `$(head -n 1 -- P)` gave it: up
// to the first newline, without it and without the NUL bytes the shell
// dropped. The file is opened without following a link or waiting on a
// pipe, and at most LineSize bytes are read: every file read this way has
// been held to that size first.
func FirstLine(p string) (string, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, LineSize+1))
	if err != nil {
		return "", err
	}
	if i := strings.IndexByte(string(b), '\n'); i >= 0 {
		b = b[:i]
	}
	return StripNUL(string(b)), nil
}

// ReadLine is `IFS= read -r LINE < P`: the first line, and whether it ended
// in a newline -- read's own status. The file is opened as FirstLine opens it.
func ReadLine(p string) (line string, full bool, err error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", false, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, LineSize+1))
	if err != nil {
		return "", false, err
	}
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return StripNUL(s[:i]), true, nil
	}
	return StripNUL(s), false, nil
}

// maxLinks is how many links Realpath follows before it calls the path a
// loop, as the kernel's own limit for one lookup is 40.
const maxLinks = 40

// Realpath is `realpath -e -- P`: P, absolute, every link in it resolved and
// every component of it there. It is resolved one component at a time, as
// realpath resolves it, so a ".." after a link is the link target's parent
// and not the lexical one.
func Realpath(p string) (string, error) {
	if p == "" {
		return "", syscall.ENOENT
	}
	rest := p
	resolved := "/"
	if !strings.HasPrefix(p, "/") {
		wd, err := unix.Getwd()
		if err != nil {
			return "", err
		}
		resolved = wd
	}
	links := 0
	// A path ending in a slash names a directory, as the kernel reads it.
	for rest != "" {
		var comp string
		rest = strings.TrimLeft(rest, "/")
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			comp, rest = rest[:i], rest[i:]
		} else {
			comp, rest = rest, ""
		}
		switch comp {
		case "", ".":
			continue
		case "..":
			resolved = parent(resolved)
			continue
		}
		next := join(resolved, comp)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			links++
			if links > maxLinks {
				return "", syscall.ELOOP
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(target, "/") {
				resolved = "/"
			}
			rest = target + rest
			continue
		}
		if !fi.IsDir() && rest != "" {
			return "", syscall.ENOTDIR
		}
		resolved = next
	}
	return resolved, nil
}

func parent(p string) string {
	if p == "/" {
		return "/"
	}
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func join(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// Resolve is a path as `$(realpath -e -- P)` gave it: resolved, and without the
// newlines the command substitution stripped from its end. Resolution
// failing is ok false.
func Resolve(p string) (string, bool) {
	r, err := Realpath(p)
	if err != nil {
		return "", false
	}
	return TrimNL(r), true
}

// Searchable is whether cd could enter p: a directory the user may search.
func Searchable(p string) bool {
	return IsDir(p) && unix.Access(p, unix.X_OK) == nil
}
