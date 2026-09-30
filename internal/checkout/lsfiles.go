package checkout

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/gitsafe"
)

// copyTimeout is how long copying an index is given, as `timeout 20 dd` gave
// it.
const copyTimeout = 20 * time.Second

// LsFiles is WHAT A CHECKOUT TRACKS, for what copies it: the grant's
// snapshot. `git ls-files` in the checkout would read its config, and with
// it core.fsmonitor, a command git runs on any read of the index -- on the
// host, as the user, before anything is approved. So the checkout is Find's,
// found from where the directory is, and its index is read by gitsafe's git
// in the empty repository of the checkout's object format, GIT_INDEX_FILE
// naming a copy of the index and nothing else of the checkout named at all:
// no config, no hooks, no work tree. A copy, taken once without following a
// link or waiting on a pipe, because git reads a split index's shared part
// from beside the index it is given, which a session could make anything.
// An index that needs more than itself -- that shared part, or a sparse
// index's trees, whose directories git would otherwise drop from the list
// without a word -- fails.
//
// It is the tracked paths at or below dir, relative to dir, each ended by a
// NUL. A checkout with no index yet tracks nothing.
func (f *Finder) LsFiles(ctx context.Context, dir string) ([]byte, error) {
	c, err := f.find(ctx, dir)
	if err != nil {
		return nil, err
	}
	abs, ok := gitsafe.Resolve(dir)
	if !ok {
		// The script stopped here, printing nothing of its own.
		return nil, fmt.Errorf("%s: no such directory", dir)
	}
	prefix := ""
	if abs != c.Root {
		prefix = strings.TrimPrefix(abs, strings.TrimSuffix(c.Root, "/")+"/") + "/"
	}
	index := c.GitDir + "/index"
	if !gitsafe.Exists(index) {
		return nil, nil
	}
	if !gitsafe.Small(index, gitsafe.IndexSize) {
		return nil, unsortable("%s is not a plain file of an index's size", index)
	}
	format, err := c.Repo().Config(ctx, f.Git, "extensions.objectFormat")
	if err != nil {
		return nil, unsortable("the config of %s cannot be read", c.Root)
	}
	format = gitsafe.Output([]byte(format))
	if format == "" {
		format = "sha1"
	}
	if format != "sha1" && format != "sha256" {
		return nil, unsortable("%s has an object format of %s", c.Root, format)
	}
	empty, err := f.Git.Empty(format)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "chase-ls-files-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	// Swapped since it was looked at, a link is not followed and a pipe not
	// waited on; grown since, it is cut short, and git refuses what is left.
	copied := filepath.Join(tmp, "index")
	if n, err := copyIndex(index, copied); err != nil || n > gitsafe.IndexSize {
		return nil, unsortable("%s cannot be copied", index)
	}
	// The empty repository never sets index.sparse, so git always expands a
	// sparse index to list it, from trees that repository does not have: it
	// says so on stderr, drops what is under them, and succeeds. Anything it
	// says is therefore the guard, and a failure.
	res := f.Git.Run(ctx, "GIT_DIR="+empty, "GIT_INDEX_FILE="+copied, "ls-files", "-z", "--cached")
	if !res.OK() {
		return nil, unsortable("the index of %s cannot be read on its own, as a split index cannot", c.Root)
	}
	if len(res.Stderr) > 0 {
		return nil, unsortable("the index of %s is sparse, or cannot be read on its own", c.Root)
	}
	var out bytes.Buffer
	entries := strings.Split(string(res.Stdout), "\x00")
	for _, p := range entries[:len(entries)-1] {
		if strings.HasPrefix(p, prefix) {
			out.WriteString(strings.TrimPrefix(p, prefix))
			out.WriteByte(0)
		}
	}
	return out.Bytes(), nil
}

// copyIndex is `dd if=FROM of=TO iflag=nofollow,nonblock bs=1M count=257`
// under `timeout 20`: at most 257 reads of a MiB each, the file opened
// without following a link or blocking on a pipe. It is the bytes copied.
//
// timeout killed dd, and nothing of it outlived the command. Go cannot kill
// a goroutine, nor interrupt a read(2) the kernel has blocked -- an index on
// FUSE or NFS that never answers -- and closing a file another goroutine is
// reading waits for that read. So what outlives a copy cut short is made
// harmless instead: TO is made here, before the copy starts, so nothing can
// make it again after the caller removes it; the copy writes only through
// its own descriptors, which it closes itself when its read returns; and
// once it is told to stop it writes nothing more, and reads no further.
// The file it was writing is then already unlinked, and gone with its
// descriptor. dd blocked in such a read was not killed by timeout either,
// until the read returned.
func copyIndex(from, to string) (int64, error) {
	return copyIndexWithin(from, to, copyTimeout)
}

func copyIndexWithin(from, to string, timeout time.Duration) (int64, error) {
	out, err := unix.Open(to, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return 0, err
	}
	type result struct {
		n   int64
		err error
	}
	var stop atomic.Bool
	done := make(chan result, 1)
	go func() {
		n, err := copyReads(from, out, &stop)
		done <- result{n, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.n, r.err
	case <-timer.C:
		stop.Store(true)
		return 0, errors.New("copying the index took too long")
	}
}

// copyReads copies from into out, and closes out: at most 257 reads of a
// MiB, none after stop is set.
func copyReads(from string, out int, stop *atomic.Bool) (int64, error) {
	defer unix.Close(out)
	in, err := unix.Open(from, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(in)
	buf := make([]byte, 1<<20)
	var n int64
	for i := 0; i < 257; i++ {
		if stop.Load() {
			return n, errors.New("stopped")
		}
		r, err := unix.Read(in, buf)
		if err != nil {
			return n, err
		}
		if r == 0 {
			break
		}
		if stop.Load() {
			return n, errors.New("stopped")
		}
		if err := writeAll(out, buf[:r]); err != nil {
			return n, err
		}
		n += int64(r)
	}
	return n, nil
}

func writeAll(fd int, b []byte) error {
	for len(b) > 0 {
		w, err := unix.Write(fd, b)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		b = b[w:]
	}
	return nil
}

// RunLsFiles is `chase-ls-files DIR`: the tracked paths at or below DIR,
// relative to DIR, each ended by a NUL, and 0; or why they cannot be read,
// as a line, and 1. A usage error is 2. It closes g before it returns.
func RunLsFiles(ctx context.Context, g *gitsafe.Git, args []string, stdout, stderr io.Writer) int {
	defer g.Close()
	if len(args) != 1 {
		fmt.Fprintln(stdout, "usage: chase-ls-files DIR")
		return 2
	}
	list, err := (&Finder{Git: g}).LsFiles(ctx, args[0])
	return reportFind(err, stdout, stderr, func() { stdout.Write(list) })
}
