# chase-copy-tracked WS SRC: copies the paths listed on stdin, each ended
# by a NUL and relative to WS, from WS into SRC, following no link at any
# component on either side.
#
# What is copied is evaluated and decrypted on the host, and WS is a
# checkout a session writes. A copier that opens WS/dir/f by its path lets
# the kernel resolve dir, so a session that makes dir a link to a host
# directory -- another project's sops directory, say -- has that host's f
# copied in, and a check for links before and after the copy is raced by
# another live session of the same checkout. So WS is opened once, and
# every path is walked from it one component at a time, each directory
# opened beneath the one before it with O_NOFOLLOW: what is opened is
# always a directory below WS, whatever is swapped in while it runs.
#
# A tracked file is copied with its exec bit. A tracked link is made again
# as a link, never read through: where it points is decided by what reads
# the copy. A tracked directory -- a submodule's gitlink -- is made empty,
# as tar made it. Anything else, a link or a file above a tracked path, and
# a tracked path missing from the work tree all refuse: the list is the
# index, which the session writes, so a path that is absolute, or has an
# empty, '.' or '..' component, refuses too, since it would leave WS.
#
# Succeeds silently, or prints why it refused, on stdout, and exits 1.

import errno
import os
import stat
import sys

DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
LEAF = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
NEW = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
# What no component of a path below WS is.
STEPS = (b"", b".", b"..")


class Refused(Exception):
    pass


def uncopied(path, why):
    return Refused(b"its tracked files could not be copied: "
                   + path + b": " + why)


def strerror(e):
    return os.strerror(e.errno).encode()


def open_dir(fd, name, prefix):
    """The directory NAME beneath FD, never a link: PREFIX names it."""
    try:
        return os.open(name, DIR, dir_fd=fd)
    except OSError as e:
        if e.errno not in (errno.ELOOP, errno.ENOTDIR):
            raise uncopied(prefix, strerror(e))
        try:
            mode = os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode
        except OSError:
            mode = stat.S_IFLNK
        if stat.S_ISLNK(mode):
            raise Refused(prefix + b" is a link, so what is tracked under it"
                          b" would be copied from wherever it points")
        raise uncopied(prefix, b"it is not a directory")


def make_dir(fd, name, prefix):
    try:
        os.mkdir(name, 0o755, dir_fd=fd)
    except FileExistsError:
        pass
    return open_dir(fd, name, prefix)


def copy_leaf(ws, src, name, path):
    try:
        fd = os.open(name, LEAF, dir_fd=ws)
    except OSError as e:
        if e.errno != errno.ELOOP:
            raise uncopied(path, strerror(e))
        try:
            target = os.readlink(name, dir_fd=ws)
        except OSError as e:
            raise uncopied(path, strerror(e))
        os.symlink(target, name, dir_fd=src)
        return
    try:
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            os.close(make_dir(src, name, path))
        elif stat.S_ISREG(st.st_mode):
            os.set_blocking(fd, True)
            mode = 0o755 if st.st_mode & stat.S_IXUSR else 0o644
            out = os.open(name, NEW, mode, dir_fd=src)
            try:
                while True:
                    chunk = os.read(fd, 1 << 20)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(out, view):]
            finally:
                os.close(out)
        else:
            raise uncopied(path, b"it is not a file, a link or a directory")
    finally:
        os.close(fd)


def copy(ws_path, src_path, listed):
    ws_root = os.open(ws_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    src_root = os.open(src_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    roots = (ws_root, src_root)
    # The directories above the last path copied, open on both sides:
    # the next shares a prefix with it more often than not, and no more are
    # held than a path is deep.
    held = []
    done = set()
    for path in listed:
        parts = path.split(b"/")
        if path.startswith(b"/") or any(p in STEPS for p in parts):
            raise Refused(b"its index lists " + path
                          + b", which is not a path below it")
        if path in done:
            # An unmerged path is listed once for each of its stages.
            continue
        done.add(path)
        dirs = parts[:-1]
        keep = 0
        while keep < min(len(held), len(dirs)) \
                and held[keep][0] == dirs[keep]:
            keep += 1
        for _, w, s in held[keep:]:
            os.close(w)
            os.close(s)
        del held[keep:]
        for i in range(keep, len(dirs)):
            ws, src = held[-1][1:] if held else roots
            prefix = b"/".join(dirs[:i + 1])
            w = open_dir(ws, dirs[i], prefix)
            try:
                s = make_dir(src, dirs[i], prefix)
            except BaseException:
                os.close(w)
                raise
            held.append((dirs[i], w, s))
        ws, src = held[-1][1:] if held else roots
        copy_leaf(ws, src, parts[-1], path)


def main():
    if len(sys.argv) != 3:
        sys.stdout.write("usage: chase-copy-tracked WS SRC < PATHS\n")
        sys.exit(2)
    data = sys.stdin.buffer.read()
    listed = data.split(b"\0")
    if listed and listed[-1] == b"":
        listed.pop()
    try:
        copy(os.fsencode(sys.argv[1]), os.fsencode(sys.argv[2]), listed)
    except Refused as e:
        sys.stdout.buffer.write(e.args[0] + b"\n")
        sys.exit(1)


main()
