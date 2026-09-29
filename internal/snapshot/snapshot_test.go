package snapshot

import (
	"bytes"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

const topsecret = "TOPSECRET"

// host is a directory of the host's, beside the checkouts, with the sops
// file another project would have.
func host(t *testing.T) string {
	t.Helper()
	h := filepath.Join(t.TempDir(), "hostsecret")
	must(t, os.MkdirAll(h, 0o755))
	must(t, os.WriteFile(filepath.Join(h, "secrets.yaml"), []byte(topsecret+"\n"), 0o644))
	return h
}

// checkout is a work tree with a flake, and each tracked a file of the
// project's own.
func checkout(t *testing.T, tracked ...string) string {
	t.Helper()
	d := t.TempDir()
	must(t, os.WriteFile(filepath.Join(d, "flake.nix"), []byte("{ outputs = _: { chaseModules.default = { }; }; }\n"), 0o644))
	for _, f := range tracked {
		must(t, os.MkdirAll(filepath.Dir(filepath.Join(d, f)), 0o755))
		must(t, os.WriteFile(filepath.Join(d, f), []byte("the project's own\n"), 0o644))
	}
	return d
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// run is chase-copy-tracked WS OUT with paths on stdin, each ended by a NUL.
func run(t *testing.T, ws, out string, paths ...string) (int, string, string) {
	t.Helper()
	var in bytes.Buffer
	for _, p := range paths {
		in.WriteString(p + "\x00")
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{ws, out}, &in, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// leaked is every file under dir that has a host byte in it.
func leaked(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(topsecret)) {
				found = append(found, p)
			}
		}
		return nil
	})
	return found
}

// A tracked prefix/secrets.yaml, prefix then made a link to a host
// directory: the copier refuses at the link, and no host byte is in what it
// copied into, so it did not copy through the link and check afterwards. A
// name the session chose is said with its control bytes made plain, C1 too,
// as UTF-8 and as the raw byte.
func TestALinkAboveATrackedFileIsRefusedAndNothingOfTheHostsIsCopied(t *testing.T) {
	for _, v := range []struct{ what, prefix, said string }{
		{"(a) a link to a host directory", "link", "link"},
		{"(b) the same, a directory deeper", "a/b", "a/b"},
		{"(e) a name with escapes", "x\x1b]0;TITLE\x07y", "x?]0;TITLE?y"},
		{"(e) a name with C1 controls", "x\xc2\x9b1my\x9bz", "x?1my?z"},
	} {
		t.Run(v.what, func(t *testing.T) {
			h := host(t)
			ws := checkout(t, v.prefix+"/secrets.yaml")
			must(t, os.RemoveAll(filepath.Join(ws, v.prefix)))
			must(t, os.Symlink(h, filepath.Join(ws, v.prefix)))
			out := t.TempDir()
			code, stdout, _ := run(t, ws, out, "flake.nix", v.prefix+"/secrets.yaml")
			if code != 1 {
				t.Fatalf("the copier copied through %q: %d %q", v.prefix, code, stdout)
			}
			if want := v.said + " is a link, so what is tracked under it would be copied from wherever it points\n"; stdout != want {
				t.Errorf("the copier did not name the link: %q, want %q", stdout, want)
			}
			if strings.IndexFunc(strings.TrimSuffix(stdout, "\n"), control) >= 0 {
				t.Errorf("a control byte was said: %q", stdout)
			}
			if l := leaked(t, out); len(l) > 0 {
				t.Errorf("a host byte was copied through %q: %v", v.prefix, l)
			}
			if _, err := os.Lstat(filepath.Join(out, v.prefix)); err == nil {
				t.Errorf("%q was copied", v.prefix)
			}
		})
	}
}

// What the library says is what Run printed, before it was cleaned.
func TestCopyTrackedRefusesALinkAboveATrackedFile(t *testing.T) {
	h := host(t)
	ws := checkout(t, "link/secrets.yaml")
	must(t, os.RemoveAll(filepath.Join(ws, "link")))
	must(t, os.Symlink(h, filepath.Join(ws, "link")))
	err := CopyTracked(ws, t.TempDir(), []string{"flake.nix", "link/secrets.yaml"})
	r, ok := err.(*Refused)
	if !ok || r.Reason != "link is a link, so what is tracked under it would be copied from wherever it points" {
		t.Errorf("%#v", err)
	}
}

// What the property below once found, kept as an example: a/a a link to the
// host's a, and a/a/a listed. The copier refuses at a/a, and makes nothing
// for it in the copy -- a is made, since it is a directory of the checkout's,
// but a/a, which only the link would have given, is not.
func TestADirectoryIsNeverMadeInTheCopyForALink(t *testing.T) {
	root := t.TempDir()
	hostA := filepath.Join(root, "host", "a")
	must(t, os.MkdirAll(filepath.Join(hostA, "a"), 0o755))
	must(t, os.WriteFile(filepath.Join(hostA, "a", "a"), []byte(topsecret), 0o644))
	ws, out := filepath.Join(root, "ws"), filepath.Join(root, "out")
	must(t, os.MkdirAll(filepath.Join(ws, "a"), 0o755))
	must(t, os.Mkdir(out, 0o755))
	must(t, os.Symlink(hostA, filepath.Join(ws, "a", "a")))
	err := CopyTracked(ws, out, []string{"a/a/a"})
	r, ok := err.(*Refused)
	if !ok || r.Reason != "a/a is a link, so what is tracked under it would be copied from wherever it points" {
		t.Errorf("%#v", err)
	}
	if st, err := os.Lstat(filepath.Join(out, "a")); err != nil || !st.IsDir() {
		t.Errorf("out/a: %v %v", st, err)
	}
	if _, err := os.Lstat(filepath.Join(out, "a", "a")); !os.IsNotExist(err) {
		t.Errorf("out/a/a was made: %v", err)
	}
	if l := leaked(t, out); len(l) > 0 {
		t.Errorf("the host's bytes are in %v", l)
	}
}

// A directory made a file is refused, and is not called a link; a tracked
// file missing from the work tree is refused, as tar refused it; and what is
// not a file, a link or a directory is refused, whatever it is.
func TestWhatIsNotAsTrackedIsRefused(t *testing.T) {
	ws := checkout(t, "d/secrets.yaml", "gone")
	must(t, os.RemoveAll(filepath.Join(ws, "d")))
	must(t, os.WriteFile(filepath.Join(ws, "d"), []byte("x\n"), 0o644))
	must(t, os.Remove(filepath.Join(ws, "gone")))
	must(t, syscall.Mkfifo(filepath.Join(ws, "fifo"), 0o644))
	sock := filepath.Join(ws, "sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, v := range []struct{ path, said string }{
		{"d/secrets.yaml", "its tracked files could not be copied: d: it is not a directory\n"},
		{"gone", "its tracked files could not be copied: gone: No such file or directory\n"},
		{"gone/f", "its tracked files could not be copied: gone: No such file or directory\n"},
		{"fifo", "its tracked files could not be copied: fifo: it is not a file, a link or a directory\n"},
		{"fifo/f", "its tracked files could not be copied: fifo: it is not a directory\n"},
		// A socket is refused as it cannot be opened.
		{"sock", "its tracked files could not be copied: sock: No such device or address\n"},
	} {
		code, stdout, stderr := run(t, ws, t.TempDir(), v.path)
		if code != 1 || stdout != v.said || stderr != "" {
			t.Errorf("%s: %d %q %q, want %q", v.path, code, stdout, stderr, v.said)
		}
	}
}

// (c) A tracked file that is a link to a host file is a link in the
// snapshot, pointing where it did, and never its target's bytes; a tracked
// file is copied with its exec bit, and a plain one is not made executable.
// The list is git's own, of a real checkout.
func TestATrackedLinkIsCopiedAsItselfAndAFileWithItsExecBit(t *testing.T) {
	h := host(t)
	ws := checkout(t, "tool")
	target := filepath.Join(h, "secrets.yaml")
	must(t, os.Symlink(target, filepath.Join(ws, "secrets.yaml")))
	must(t, os.Chmod(filepath.Join(ws, "tool"), 0o755))
	git(t, ws, "init", "-q")
	git(t, ws, "add", "-A")
	list := git(t, ws, "ls-files", "-z", "--cached")

	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := Run([]string{ws, out}, strings.NewReader(list), &stdout, &stderr); code != 0 {
		t.Fatalf("a checkout with a tracked link was not copied: %d %q %q", code, stdout.String(), stderr.String())
	}
	if got, err := os.Readlink(filepath.Join(out, "secrets.yaml")); err != nil || got != target {
		t.Errorf("a tracked link was not copied as itself: %q %v", got, err)
	}
	if l := leaked(t, out); len(l) > 0 {
		t.Errorf("a tracked link was read through: %v", l)
	}
	fi, err := os.Lstat(filepath.Join(out, "tool"))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		t.Errorf("a tracked file was not copied with its exec bit: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "tool")); string(b) != "the project's own\n" {
		t.Errorf("a tracked file was copied as %q", b)
	}
	fi, err = os.Lstat(filepath.Join(out, "flake.nix"))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 != 0 {
		t.Errorf("a plain file was copied executable: %v %v", fi, err)
	}
}

// Only the exec bit is carried: nothing else of a file's mode, so a file
// the session made group-writable or setuid is 0644 or 0755 in the copy, as
// the umask leaves them.
func TestOnlyTheExecBitIsCarried(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	ws := checkout(t, "x", "w")
	must(t, os.Chmod(filepath.Join(ws, "x"), 0o4775))
	must(t, os.Chmod(filepath.Join(ws, "w"), 0o666))
	out := t.TempDir()
	if code, stdout, stderr := run(t, ws, out, "x", "w"); code != 0 {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
	for name, want := range map[string]fs.FileMode{"x": 0o755, "w": 0o644} {
		fi, err := os.Lstat(filepath.Join(out, name))
		if err != nil || fi.Mode() != want {
			t.Errorf("%s: %v %v, want %v", name, fi.Mode(), err, want)
		}
	}
}

// A tracked directory -- a submodule's gitlink -- is made empty, as tar made
// it, whatever is in it.
func TestATrackedDirectoryIsMadeEmpty(t *testing.T) {
	ws := checkout(t, "vendor/lib/f")
	out := t.TempDir()
	if code, stdout, stderr := run(t, ws, out, "vendor/lib", "flake.nix"); code != 0 {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
	entries, err := os.ReadDir(filepath.Join(out, "vendor/lib"))
	if err != nil || len(entries) != 0 {
		t.Errorf("a tracked directory was not made empty: %v %v", entries, err)
	}
}

// WHAT THE INDEX LISTS is the session's to write, so a path that would leave
// the checkout is refused, whatever it is, and nothing is copied.
func TestAPathThatLeavesTheCheckoutIsRefused(t *testing.T) {
	ws := checkout(t)
	out := t.TempDir()
	for _, p := range []string{"/etc/passwd", "../hostsecret/secrets.yaml", "a/../../x", "a//b", "./flake.nix", "a/.", "", "a/", "..", "."} {
		code, stdout, _ := run(t, ws, out, p)
		if code != 1 {
			t.Errorf("the copier took %q", p)
		}
		if want := "its index lists " + p + ", which is not a path below it\n"; stdout != want {
			t.Errorf("%q was refused for something else: %q", p, stdout)
		}
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("a path that leaves the checkout was copied: %v", entries)
	}
}

// An unmerged path, listed once for each stage, is copied once: a second
// copy would find its first and fail.
func TestAnUnmergedPathIsCopiedOnce(t *testing.T) {
	ws := checkout(t)
	if code, stdout, stderr := run(t, ws, t.TempDir(), "flake.nix", "flake.nix", "flake.nix"); code != 0 {
		t.Errorf("a path listed three times was refused: %d %q %q", code, stdout, stderr)
	}
}

// Paths that share directories are copied through the ones held open, and
// ones that do not, after it, from WS again.
func TestPathsInAndOutOfTheHeldDirectoriesAreAllCopied(t *testing.T) {
	paths := []string{"a/b/c/1", "a/b/c/2", "a/b/3", "a/4", "d/e/5", "a/b/c/6", "7", "a/b/x/8"}
	ws := checkout(t, paths...)
	out := t.TempDir()
	if code, stdout, stderr := run(t, ws, out, paths...); code != 0 {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
	for _, p := range paths {
		if b, err := os.ReadFile(filepath.Join(out, p)); err != nil || string(b) != "the project's own\n" {
			t.Errorf("%s: %q %v", p, b, err)
		}
	}
}

// Nothing listed, or only a list's ending NUL missing, is still a list.
func TestTheListIsEndedByNULs(t *testing.T) {
	ws := checkout(t, "a", "b")
	for in, want := range map[string][]string{"": nil, "a\x00b": {"a", "b"}, "a\x00b\x00": {"a", "b"}} {
		out := t.TempDir()
		var stdout, stderr bytes.Buffer
		if code := Run([]string{ws, out}, strings.NewReader(in), &stdout, &stderr); code != 0 {
			t.Errorf("%q: %d %q %q", in, code, stdout.String(), stderr.String())
		}
		entries, _ := os.ReadDir(out)
		if len(entries) != len(want) {
			t.Errorf("%q: copied %v, want %v", in, entries, want)
		}
	}
}

// What the host could not do is not the checkout's refusal: said on stderr,
// with nothing on stdout, and 1. A destination that already has the file is
// one, since what is created is never opened through what was there.
func TestAFaultOfTheHostsIsNotARefusal(t *testing.T) {
	ws := checkout(t)
	out := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	must(t, os.Symlink(elsewhere, filepath.Join(out, "flake.nix")))
	code, stdout, stderr := run(t, ws, out, "flake.nix")
	if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "chase: copy-tracked: ") {
		t.Errorf("%d %q %q", code, stdout, stderr)
	}
	if _, err := os.Lstat(elsewhere); err == nil {
		t.Errorf("a link in the destination was written through")
	}
	code, stdout, stderr = run(t, filepath.Join(ws, "nope"), out, "flake.nix")
	if code != 1 || stdout != "" || stderr == "" {
		t.Errorf("a missing WS: %d %q %q", code, stdout, stderr)
	}
}

func TestTheUsageIsSaidOnStdout(t *testing.T) {
	for _, args := range [][]string{nil, {"ws"}, {"ws", "out", "x"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, strings.NewReader(""), &stdout, &stderr); code != 2 || stdout.String() != usage || stderr.Len() != 0 {
			t.Errorf("%q: %d %q %q", args, code, stdout.String(), stderr.String())
		}
	}
}

// A live session of the same checkout swaps a directory above a tracked
// file for a link to the host's and back, as fast as it can, while the
// checkout is copied over and over: whatever each copy meets, no host byte
// is ever in what it made.
func TestALinkSwappedInWhileCopyingIsNeverFollowed(t *testing.T) {
	h := host(t)
	ws := checkout(t, "d/secrets.yaml", "d/e/secrets.yaml")
	real := filepath.Join(ws, "d.real")
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		d := filepath.Join(ws, "d")
		for !stop.Load() {
			os.Rename(d, real)
			os.Symlink(h, d)
			os.Remove(d)
			os.Rename(real, d)
		}
	}()
	outs := t.TempDir()
	for i := 0; i < 500; i++ {
		out, err := os.MkdirTemp(outs, "out")
		must(t, err)
		err = CopyTracked(ws, out, []string{"d/secrets.yaml", "d/e/secrets.yaml", "flake.nix"})
		if _, ok := err.(*Refused); err != nil && !ok {
			t.Errorf("a swap was a fault of the host's: %v", err)
		}
	}
	stop.Store(true)
	<-done
	if l := leaked(t, outs); len(l) > 0 {
		t.Errorf("a host byte was copied through a swapped link: %v", l)
	}
}

// control is a C0, DEL or C1 character, or a byte that is not UTF-8.
func control(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0xfffd }

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=x", "-c", "user.email=x@example.com"}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}
