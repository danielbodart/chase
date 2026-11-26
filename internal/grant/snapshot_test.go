package grant_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The ported grant-snapshot check, as far as approve goes (the copier's
// own assertions are internal/snapshot's): A SNAPSHOT FOLLOWS NO LINK. What
// is evaluated and decrypted is the checkout's tracked files, copied; a
// session writes the checkout, and can make a directory above a tracked file
// a link to one of the host's -- another project's sops directory -- so a
// copy through it would put the host's file where the project's was.
// Refused, naming the link, with nothing staged and no host byte anywhere
// chase keeps things. Nothing the checkout's git config names is run on
// the host on the way.

type snapshotCase struct {
	*harness
	r, host string
}

func newSnapshotCase(t *testing.T) *snapshotCase {
	h := newHarness(t)
	s := &snapshotCase{harness: h, r: h.root(), host: h.dir + "/hostsecret"}
	write(t, s.host+"/secrets.yaml", "TOPSECRET\n")
	write(t, h.dir+"/hostgrant.json", "{\n  \"version\": 2\n}\n")
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

// refused is DIR MACHINE PREFIX: the sops file named under PREFIX refused,
// naming the link as it is said, with nothing staged and no host byte kept.
func (s *snapshotCase) refused(ws, machine, prefix string) {
	s.t.Helper()
	s.refusedSaying(ws, machine, prefix, prefix)
}

// refusedSaying is refused, of a PREFIX said as SAID.
func (s *snapshotCase) refusedSaying(ws, machine, prefix, said string) {
	s.t.Helper()
	if s.approve(ws, machine, "trusted", `{"version": 2, "chase": {"secrets": `+jqString(prefix+"/secrets.yaml")+`}}`) == 0 {
		s.t.Errorf("%s was approved with %s a link", ws, prefix)
	}
	s.mustSay("chase: " + ws + ": " + said + " is a link, so what is tracked under it would be copied from wherever it points")
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
	s.approved(s.r+"/plain", "m0", "trusted", `{"chase":{"secrets":"link/secrets.yaml"},"version":2}`)
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
// file missing from the work tree is refused, as tar refused it. Only what
// the grant reads is copied, so a tracked file it does not name is nothing
// to it.
func TestWhatIsNotAsTrackedIsRefused(t *testing.T) {
	s := newSnapshotCase(t)
	s.checkout(s.r+"/file", "d/secrets.yaml")
	os.RemoveAll(s.r + "/file/d")
	write(t, s.r+"/file/d", "x\n")
	s.approved(s.r+"/file", "m2", "trusted", `{"version":2}`)
	if s.approve(s.r+"/file", "m3", "trusted", `{"chase":{"secrets":"d/secrets.yaml"},"version":2}`) == 0 {
		t.Error("a tracked directory made a file was approved")
	}
	s.mustSay("chase: " + s.r + "/file: its tracked files could not be copied: d: it is not a directory")

	s.checkout(s.r+"/gone", "gone")
	os.Remove(s.r + "/gone/gone")
	if s.approve(s.r+"/gone", "m4", "trusted", `{"chase":{"secrets":"gone"},"version":2}`) == 0 {
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
	if s.approve(s.r+"/c", "m5", "trusted", `{"chase":{"secrets":"secrets.yaml"},"version":2}`) == 0 {
		t.Error("a sops file linked to the host's was approved")
	}
	s.mustSay("chase: " + s.r + "/c: secrets.yaml is not a plain file")
	if s.leaked() {
		t.Error("a tracked link was read through")
	}
}

// (d) A chase.json made a link, to a file of the host's, is not the
// checkout's.
func TestAChaseJSONMadeALinkIsNotTheCheckouts(t *testing.T) {
	s := newSnapshotCase(t)
	s.checkout(s.r + "/d")
	os.Symlink(s.dir+"/hostgrant.json", s.r+"/d/chase.json")
	if s.approve(s.r+"/d", "m6", "trusted", "") == 0 {
		t.Error("a chase.json made a link was approved")
	}
	s.mustSay("chase: " + s.r + "/d: chase.json is not a plain file")
	if s.isStaged("m6") {
		t.Error("a linked chase.json was staged")
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
	s.refusedSaying(s.r+"/e", "m7", esc, "x?]0;TITLE?y")
	if strings.ContainsAny(s.err, "\x1b\x07") {
		t.Errorf("a control byte reached the terminal: %q", s.err)
	}

	// A name is JSON's, so UTF-8: C1 as the raw byte is term's to make plain
	// (internal/term), and cannot be named in a grant.
	c1 := "x\xc2\x9b1my"
	s.checkout(s.r+"/e1", c1+"/secrets.yaml")
	os.RemoveAll(s.r + "/e1/" + c1)
	os.Symlink(s.host, s.r+"/e1/"+c1)
	s.refusedSaying(s.r+"/e1", "m8", c1, "x?1my")
	for i := 0; i < len(s.err); i++ {
		if s.err[i] >= 0x80 && s.err[i] <= 0x9f {
			t.Fatalf("a C1 control reached the terminal: %q", s.err)
		}
	}
}

// (f) The checkout's git config is the session's: a command it names, as
// core.fsmonitor or a hook under core.hooksPath, is never run by approve.
// The same config does run each when git is asked plainly, so the test would
// see it. A workspace below its checkout's root copies what is tracked
// there, relative to itself.
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
	s.approved(f, "m9", "trusted", `{"chase":{"secrets":"tracked"},"version":2}`)
	if _, err := os.Stat(pwned); err == nil {
		t.Error("approve ran the checkout's core.fsmonitor or core.hooksPath")
	}
	if got := s.stagedText("m9"); got != "the project's own\n" {
		t.Errorf("the checkout with core.fsmonitor set was not staged: %v", got)
	}

	write(t, f+"/sub/tracked", "the sub's own\n")
	s.fx.Run("-C", f, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "add", "sub")
	os.Remove(pwned)
	s.approved(f+"/sub", "m11", "trusted", `{"chase":{"secrets":"tracked"},"version":2}`)
	if _, err := os.Stat(pwned); err == nil {
		t.Error("approve ran core.fsmonitor for a workspace below its root")
	}
	if got := s.stagedText("m11"); got != "the sub's own\n" {
		t.Errorf("a workspace below its root did not copy its own tracked files: %v", got)
	}
}
