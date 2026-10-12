package checkout

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/gitsafe"
)

// What HEAD names, and the repository's objects, read as the selector reads
// a checkout's first commit: never by a git that reads the checkout's own
// config.

var commitID = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// HeadCommit is the commit HEAD names, resolved here rather than by git,
// which would read the checkout's config to find it: HEAD in the checkout's
// own gitdir, a branch in refs/heads/ or packed-refs of the repository, each
// a plain file inside it. A branch is any name git would give one, as git
// itself checks it. It is the commit, or why HEAD was not read -- nothing
// when there is simply no commit -- and false.
func (c Checkout) HeadCommit(ctx context.Context, g *gitsafe.Git) (string, bool) {
	ref := "HEAD"
	for range 5 {
		var file string
		switch {
		case ref == "HEAD":
			file = c.GitDir + "/HEAD"
		case strings.HasPrefix(ref, "refs/heads/") && len(ref) > len("refs/heads/") &&
			g.Run(ctx, "check-ref-format", ref).OK():
			file = c.GitCommon + "/" + ref
		default:
			return "HEAD names " + gitsafe.Quote(ref) + ", which is not a branch that is read", false
		}
		line := ""
		if gitsafe.Exists(file) {
			if r, _ := gitsafe.Resolve(file); !gitsafe.Small(file, gitsafe.LineSize) || r != file {
				return file + " is not a plain file the size of a ref, so HEAD is not read", false
			}
			l, full, err := gitsafe.ReadLine(file)
			if err != nil || (!full && l == "") {
				return "", false
			}
			line = l
			if strings.HasPrefix(line, "ref: ") {
				ref = strings.TrimPrefix(line, "ref: ")
				continue
			}
		} else if packed := c.GitCommon + "/packed-refs"; ref != "HEAD" && gitsafe.ExistsFollowing(packed) {
			if !gitsafe.Small(packed, gitsafe.PackedRefsSize) {
				return packed + " is not a plain file of a size that is read", false
			}
			line = PackedRef(packed, ref)
		}
		if !commitID.MatchString(line) {
			return "", false
		}
		return line, true
	}
	return "HEAD names refs through more than five links, which are not followed", false
}

// PackedRef is the object packed-refs gives ref: of the lines that have " ref"
// in them, as `grep -F` finds them, the first whose second field is ref. A
// file with a NUL in it is one grep calls binary and prints no line of.
//
// It was looked at before -- a plain file of at most PackedRefsSize -- but a
// session can write its .git while this runs, and swap in a link, a pipe or
// a sparse file of a hundred gigabytes after that look. grep streamed the
// file; this process has no address-space limit of its own and no timeout
// here. So it is opened without following a link or waiting on a pipe, must
// still be a plain file, and is read a line at a time and no further than
// PackedRefsSize: a file that has grown past it since is one not read.
func PackedRef(packed, ref string) string {
	fd, err := unix.Open(packed, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	f := os.NewFile(uintptr(fd), packed)
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	limited := &io.LimitedReader{R: f, N: gitsafe.PackedRefsSize + 1}
	r := bufio.NewReader(limited)
	found, matched := "", false
	for {
		l, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return ""
		}
		if limited.N == 0 || strings.IndexByte(l, 0) >= 0 {
			return ""
		}
		// grep ends the last line with a newline if the file does not. The
		// first match is the answer, but the rest is still read: a NUL
		// anywhere makes the whole file one grep prints nothing of.
		l = strings.TrimSuffix(l, "\n")
		if !matched && strings.Contains(l, " "+ref) {
			if fields := gitsafe.Fields(l, gitsafe.Blank, 2); fields[1] == ref {
				found, matched = fields[0], true
			}
		}
		if err == io.EOF {
			return found
		}
	}
}

// NotPlain is whether anything under objects, which is not followed if it is
// a link, is neither a plain file nor a directory: `find -P OBJECTS ! -type f
// ! -type d -print -quit`. What cannot be read is passed over, as find
// passed over it.
func NotPlain(objects string) bool {
	found := false
	var walk func(dir string)
	walk = func(dir string) {
		f, err := os.Open(dir)
		if err != nil {
			return
		}
		entries, _ := f.ReadDir(-1)
		f.Close()
		for _, e := range entries {
			if found {
				return
			}
			p := dir + "/" + e.Name()
			fi, err := os.Lstat(p)
			if err != nil {
				continue
			}
			switch {
			case fi.IsDir():
				walk(p)
			case fi.Mode().IsRegular():
			default:
				found = true
				return
			}
		}
	}
	walk(objects)
	return found
}
