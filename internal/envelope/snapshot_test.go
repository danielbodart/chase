package envelope_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The ported envelope-snapshot check, as far as approve goes (the copier's
// own assertions are internal/snapshot's): A SNAPSHOT FOLLOWS NO LINK. What
// is evaluated and decrypted is the checkout's tracked files, copied; a
// session writes the checkout, and can make a directory above a tracked file
// a link to one of the host's -- another project's sops directory -- so a
// copy through it would put the host's file where the project's was.
// Refused, naming the link, with nothing staged and no host byte anywhere
// chase keeps things. And which files are tracked is read from the index
// alone, so nothing the checkout's git config names is run on the host to
// find out.

type snapshotCase struct {
	*harness
	r, host string
}

func newSnapshotCase(t *testing.T) *snapshotCase {
	h := newHarness(t)
	s := &snapshotCase{harness: h, r: h.root(), host: h.dir + "/hostsecret"}
	write(t, s.host+"/secrets.yaml", "TOPSECRET\n")
	write(t, h.dir+"/hostflake.nix", flake)
	return s
}

// leaked is whether a host byte is anywhere chase keeps things.
func (s *snapshotCase) leaked() bool {
	found := false
	for _, d := range []string{"home", "state", "run"} {
		filepath.Walk(filepath.Join(s.dir, d), func(p string, fi os.FileInfo, err error) error {
			if err == nil && fi.Mode().IsRegular() {
				if b, _ := os.ReadFile(p); strings.Contains(string(b), "TOPSECRET") {
					found = true
				}
			}
			return nil
		})
	}
	return found
}

// refused is DIR MACHINE PREFIX: refused, naming the link, with nothing
// staged and no host byte kept.
func (s *snapshotCase) refused(ws, machine, prefix string) {
	s.t.Helper()
	if s.approve(ws, machine, "trusted", `{"secrets": "`+prefix+`/secrets.yaml", "bindings": {}}`) == 0 {
		s.t.Errorf("%s was approved with %s a link", ws, prefix)
	}
	s.mustSay("chase: " + ws + ": " + prefix + " is a link, so what is tracked under it would be copied from wherever it points")
	if s.isStaged(machine) {
		s.t.Errorf("%s was staged with %s a link", ws, prefix)
	}
	if s.leaked() {
		s.t.Errorf("%s: the host's file was copied", ws)
	}
}

func (s *snapshotCase) stagedText(machine string) any {
	d := s.stagedDoc(machine)
	if d == nil {
		return nil
	}
	sec, _ := d["secrets"].(map[string]any)
	return sec["text"]
}

// What is tracked, as it is, is copied and staged.
func TestWhatIsTrackedIsCopiedAndStaged(t *testing.T) {
	s := newSnapshotCase(t)
	s.checkout(s.r+"/plain", "link/secrets.yaml")
	s.approved(s.r+"/plain", "m0", "trusted", `{"secrets": "link/secrets.yaml", "bindings": {}}`)
	if got := s.stagedText("m0"); got != "the project's own\n" {
		t.Errorf("the project's sops file was not staged: %v", got)
	}
}

// (a) A tracked link/f, link then made a link to a host directory: the
// project's own name for its sops file, and the host's in its place. (b) The
// same, a directory deeper.
func TestALinkAboveATrackedFileIsRefused(t *testing.T) {
	s := newSnapshotCase(t)
	s.checkout(s.r+"/a", "link/secrets.yaml")
	os.RemoveAll(s.r + "/a/link")
	os.Symlink(s.host, s.r+"/a/link")
	s.refused(s.r+"/a", "m1", "link")

	s.checkout(s.r+"/b", "a/b/secrets.yaml")
	os.RemoveAll(s.r + "/b/a/b")
	os.Symlink(s.host, s.r+"/b/a/b")
	s.refused(s.r+"/b", "m2", "a/b")
}

// A directory made a file is refused, and is not called a link; a tracked
// file missing from the work tree is refused, as tar refused it.
func TestWhatIsNotAsTrackedIsRefused(t *testing.T) {
	s := newSnapshotCase(t)
	s.checkout(s.r+"/file", "d/secrets.yaml")
	os.RemoveAll(s.r + "/file/d")
	write(t, s.r+"/file/d", "x\n")
	if s.approve(s.r+"/file", "m3", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("a tracked directory made a file was approved")
	}
	s.mustSay("chase: " + s.r + "/file: its tracked files could not be copied: d: it is not a directory")

	s.checkout(s.r+"/gone", "gone")
	os.Remove(s.r + "/gone/gone")
	if s.approve(s.r+"/gone", "m4", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("a checkout missing a tracked file was approved")
	}
	s.mustSay("chase: " + s.r + "/gone: its tracked files could not be copied: gone: ")
}

// (c) A tracked file that is a link to a host file is a link in the
// snapshot, pointing where it did, and never its target's bytes: named as the
// sops file, it is outside the checkout.
func TestATrackedLinkToAHostFileIsOutsideTheCheckout(t *testing.T) {
	s := newSnapshotCase(t)
	s.checkout(s.r+"/c", "tool")
	os.Symlink(s.host+"/secrets.yaml", s.r+"/c/secrets.yaml")
	os.Chmod(s.r+"/c/tool", 0o755)
	s.fx.Run("-C", s.r+"/c", "add", "-A")
	if s.approve(s.r+"/c", "m5", "trusted", `{"secrets": "secrets.yaml", "bindings": {}}`) == 0 {
		t.Error("a sops file linked to the host's was approved")
	}
	s.mustSay("chase: " + s.r + "/c: secrets.yaml is outside the checkout")
	if s.leaked() {
		t.Error("a tracked link was read through")
	}
}

// (d) A flake.nix made a link, to a flake that says chaseModules, is not the
// checkout's.
func TestAFlakeMadeALinkIsNotTheCheckouts(t *testing.T) {
	s := newSnapshotCase(t)
	s.checkout(s.r + "/d")
	os.Remove(s.r + "/d/flake.nix")
	os.Symlink(s.dir+"/hostflake.nix", s.r+"/d/flake.nix")
	if s.approve(s.r+"/d", "m6", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("a flake.nix made a link was approved")
	}
	s.mustSay("chase: " + s.r + "/d: flake.nix is not a tracked file")
	if s.isStaged("m6") {
		t.Error("a linked flake.nix was staged")
	}
}

// (e) What a session named is said with its control bytes made plain, never
// sent to the terminal: C0, and C1 as UTF-8 and as the raw byte.
func TestWhatASessionNamedIsSaidPlainly(t *testing.T) {
	s := newSnapshotCase(t)
	esc := "x\x1b]0;TITLE\x07y"
	s.checkout(s.r+"/e", esc+"/secrets.yaml")
	os.RemoveAll(s.r + "/e/" + esc)
	os.Symlink(s.host, s.r+"/e/"+esc)
	s.refused(s.r+"/e", "m7", "x?]0;TITLE?y")
	if strings.ContainsAny(s.err, "\x1b\x07") {
		t.Errorf("a control byte reached the terminal: %q", s.err)
	}

	c1 := "x\xc2\x9b1my\x9bz"
	s.checkout(s.r+"/e1", c1+"/secrets.yaml")
	os.RemoveAll(s.r + "/e1/" + c1)
	os.Symlink(s.host, s.r+"/e1/"+c1)
	s.refused(s.r+"/e1", "m8", "x?1my?z")
	for i := 0; i < len(s.err); i++ {
		if s.err[i] >= 0x80 && s.err[i] <= 0x9f {
			t.Fatalf("a C1 control reached the terminal: %q", s.err)
		}
	}
}

// (f) The checkout's git config is the session's: a command it names, as
// core.fsmonitor or a hook under core.hooksPath, is never run by approve.
// The same config does run each when git is asked plainly, so the test would
// see it. An untracked flake.nix is not the checkout's, and a workspace below
// its checkout's root copies what is tracked there, relative to itself.
func TestTheCheckoutsGitConfigIsNeverRun(t *testing.T) {
	s := newSnapshotCase(t)
	pwned := s.dir + "/PWNED"
	f := s.r + "/f"
	s.checkout(f, "tracked", "root-only")
	s.fx.Run("-C", f, "config", "core.fsmonitor", "touch "+pwned+"; false")
	s.fx.Try("-C", f, "ls-files")
	if _, err := os.Stat(pwned); err != nil {
		t.Fatal("core.fsmonitor is not run by a plain git ls-files, so this proves nothing")
	}
	os.Remove(pwned)
	write(t, s.dir+"/hooks/post-index-change", "#!/bin/sh\ntouch "+pwned+"\n")
	os.Chmod(s.dir+"/hooks/post-index-change", 0o755)
	s.fx.Run("-C", f, "config", "core.hooksPath", s.dir+"/hooks")
	past := mustTime(t, "2020-01-01T00:00:00Z")
	os.Chtimes(f+"/tracked", past, past)
	s.fx.Try("-C", f, "-c", "core.fsmonitor=false", "status")
	if _, err := os.Stat(pwned); err != nil {
		t.Fatal("core.hooksPath is not run by a git status that refreshes the index, so this proves nothing of hooks")
	}
	os.Remove(pwned)
	later := mustTime(t, "2021-01-01T00:00:00Z")
	os.Chtimes(f+"/tracked", later, later)
	s.approved(f, "m9", "trusted", `{"secrets": "tracked", "bindings": {}}`)
	if _, err := os.Stat(pwned); err == nil {
		t.Error("approve ran the checkout's core.fsmonitor or core.hooksPath")
	}
	if got := s.stagedText("m9"); got != "the project's own\n" {
		t.Errorf("the checkout with core.fsmonitor set was not staged: %v", got)
	}

	u := s.r + "/untracked"
	s.fx.Run("init", "-q", u)
	write(t, u+"/flake.nix", flake)
	s.fx.Run("-C", u, "config", "core.fsmonitor", "touch "+pwned+"; false")
	if s.approve(u, "m10", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("an untracked flake.nix was approved")
	}
	s.mustSay("chase: " + u + ": flake.nix is not a tracked file")
	if _, err := os.Stat(pwned); err == nil {
		t.Error("approve ran the untracked checkout's core.fsmonitor")
	}
	if s.isStaged("m10") {
		t.Error("an untracked flake.nix was staged")
	}

	write(t, f+"/sub/flake.nix", flake)
	write(t, f+"/sub/tracked", "the sub's own\n")
	s.fx.Run("-C", f, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "add", "sub")
	os.Remove(pwned)
	s.approved(f+"/sub", "m11", "trusted", `{"secrets": "tracked", "bindings": {}}`)
	if _, err := os.Stat(pwned); err == nil {
		t.Error("approve ran core.fsmonitor for a workspace below its root")
	}
	if got := s.stagedText("m11"); got != "the sub's own\n" {
		t.Errorf("a workspace below its root did not copy its own tracked files: %v", got)
	}
}

// A directory in no git checkout has nothing tracked to snapshot; an index
// that needs more than itself is not read: a split index's shared part would
// be read from beside the index, which the session writes, and a sparse
// index would leave out what is under its sparse directories without a word.
func TestAnIndexThatIsNotWholeIsNotRead(t *testing.T) {
	s := newSnapshotCase(t)
	write(t, s.r+"/nogit/flake.nix", flake)
	if s.approve(s.r+"/nogit", "m12", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("a directory outside git was approved")
	}
	s.mustSay("chase: " + s.r + "/nogit: an envelope needs a git checkout")
	if s.isStaged("m12") {
		t.Error("a directory outside git was staged")
	}

	s.checkout(s.r+"/split", "f")
	s.fx.Run("-C", s.r+"/split", "update-index", "--split-index")
	if m, _ := filepath.Glob(s.r + "/split/.git/sharedindex.*"); len(m) == 0 {
		t.Fatal("the split index has no shared part, so it proves nothing")
	}
	if s.approve(s.r+"/split", "m13", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("a split index was approved")
	}
	s.mustSay("chase: " + s.r + "/split: an envelope needs a git checkout, so what is evaluated is what git tracks: the index of " + s.r + "/split cannot be read on its own")

	s.checkout(s.r+"/sparse", "keep/f", "away/f")
	s.fx.Run("-C", s.r+"/sparse", "-c", "user.name=x", "-c", "user.email=x@example.com", "commit", "-qm", "x")
	s.fx.Run("-C", s.r+"/sparse", "sparse-checkout", "set", "--cone", "--sparse-index", "keep")
	if s.approve(s.r+"/sparse", "m14", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("a sparse index was approved")
	}
	s.mustSay("chase: " + s.r + "/sparse: an envelope needs a git checkout, so what is evaluated is what git tracks: the index of " + s.r + "/sparse is sparse, or cannot be read on its own")
}
