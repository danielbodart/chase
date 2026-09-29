package gcloud

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// --bump "" "" is ${1:-...} and ${2:-...}: each commit given empty is its
// repository's head, as if none were given, and never a pin of "".
func TestBumpAtEmptyCommitsIsAtHead(t *testing.T) {
	r := newRepos(t)
	head := func(dir string) string { return gitIn(t, dir, "rev-parse", "HEAD") }
	for _, args := range [][]string{{"--bump", "", ""}, {"--bump", head(r.discovery), ""}, {"--bump", "", head(r.googleapis)}} {
		if code, stdout, stderr := r.main(args...); code != 0 {
			t.Fatalf("%q: exit %d: %s%s", args, code, stdout, stderr)
		}
		if got, want := string(read(t, filepath.Join(r.app, "source.json"))), r.wantSource(head(r.discovery), head(r.googleapis)); got != want {
			t.Errorf("source.json after %q:\n%s\nnot:\n%s", args, got, want)
		}
	}
}

// check is `sha256sum --quiet --strict -c -` of source.json's pins: what
// it prints on stdout and stderr, and whether it passes, are sha256sum's,
// malformed pins included. Held to the sha256sum on PATH where there is
// one (coreutils 9.11 in nix develop and in the build), and to what that
// printed where there is not.
func TestCheckIsSha256sum(t *testing.T) {
	dir := t.TempDir()
	put(t, filepath.Join(dir, "a"), []byte("hi\n"))
	put(t, filepath.Join(dir, "b"), []byte("x\n"))
	a := sum([]byte("hi\n"))
	type pin struct{ name, hash string }
	for _, c := range []struct {
		name           string
		pins           []pin
		stdout, stderr string
	}{
		{"all as pinned", []pin{{"a", a}}, "", ""},
		{"a hash in capitals", []pin{{"a", strings.ToUpper(a)}}, "", ""},
		{"one not as pinned", []pin{{"a", a}, {"b", a}}, "b: FAILED\n",
			"sha256sum: WARNING: 1 computed checksum did NOT match\n"},
		{"one malformed", []pin{{"b", "zz"}, {"a", a}}, "",
			"sha256sum: WARNING: 1 line is improperly formatted\n"},
		{"every one malformed", []pin{{"a", "zz"}, {"b", "yy"}}, "",
			"sha256sum: 'standard input': no properly formatted checksum lines found\n"},
		{"none at all", nil, "",
			"sha256sum: 'standard input': no properly formatted checksum lines found\n"},
		{"malformed, not as pinned and not there", []pin{{"a", "zz"}, {"b", a}, {"c", a}}, "b: FAILED\nc: FAILED open or read\n",
			"sha256sum: c: No such file or directory\nsha256sum: WARNING: 1 line is improperly formatted\n" +
				"sha256sum: WARNING: 1 listed file could not be read\nsha256sum: WARNING: 1 computed checksum did NOT match\n"},
		{"two malformed, two not there", []pin{{"a", "zz"}, {"b", "yy"}, {"c", a}, {"d", a}}, "c: FAILED open or read\nd: FAILED open or read\n",
			"sha256sum: c: No such file or directory\nsha256sum: d: No such file or directory\n" +
				"sha256sum: WARNING: 2 lines are improperly formatted\nsha256sum: WARNING: 2 listed files could not be read\n"},
	} {
		pins := newObject()
		var in strings.Builder
		for _, p := range c.pins {
			pins.set(p.name, p.hash)
			in.WriteString(p.hash + "  " + p.name + "\n")
		}
		var stdout, stderr bytes.Buffer
		ok := (&runner{stdout: &stdout, stderr: &stderr}).check(dir, pins)
		if ok != (c.stdout == "" && c.stderr == "") || stdout.String() != c.stdout || stderr.String() != c.stderr {
			t.Errorf("%s: %v %q %q, not %q %q", c.name, ok, stdout.String(), stderr.String(), c.stdout, c.stderr)
		}
		if _, err := exec.LookPath("sha256sum"); err != nil {
			continue
		}
		cmd := exec.Command("sha256sum", "--quiet", "--strict", "-c", "-")
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(in.String())
		var sout, serr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &sout, &serr
		passed := cmd.Run() == nil
		if strings.Contains(serr.String(), "'standard input'") || !strings.Contains(c.stderr, "'standard input'") {
			// A sha256sum older than 9 names stdin "-"; the rest is the same.
			if passed != ok || sout.String() != stdout.String() || serr.String() != stderr.String() {
				t.Errorf("%s: sha256sum %v %q %q, check %v %q %q", c.name, passed, sout.String(), serr.String(), ok, stdout.String(), stderr.String())
			}
		}
	}
}

// protoc's failure is said once: by protoc where it ran and failed, and
// by the generator where it could not be run or was killed, as xargs said
// it in the script's log.
func TestCompileSaysWhyProtocFailed(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		name, protoc, said string
	}{
		{"failed", script("failed", "echo 'x.proto: bad' >&2\nexit 1\n"), "x.proto: bad\n"},
		{"not there", filepath.Join(dir, "missing"), "gcloud: protoc: fork/exec " + filepath.Join(dir, "missing") + ": no such file or directory\n"},
		{"killed", script("killed", "kill -KILL $$\n"), "gcloud: protoc: signal: killed\n"},
	} {
		var stdout, stderr bytes.Buffer
		r := &runner{ctx: context.Background(), cfg: Config{Protoc: c.protoc}, stdout: &stdout, stderr: &stderr}
		code := exit(r.compile(dir, []string{"x.proto"}, filepath.Join(dir, "out.pb")), &stderr)
		if code != 1 || stderr.String() != c.said {
			t.Errorf("%s: exit %d, said %q, not %q", c.name, code, stderr.String(), c.said)
		}
	}
}

// grep -rl names a directory that is not there and goes on, then exits 2;
// a directory named by a link is searched, under the name it was given,
// and a link met beneath one is not followed.
func TestProtosWithHostsIsGrep(t *testing.T) {
	root, elsewhere := t.TempDir(), t.TempDir()
	host := []byte("option (google.api.default_host) = \"x.googleapis.com\";\n")
	put(t, filepath.Join(elsewhere, "x", "v1", "x.proto"), host)
	put(t, filepath.Join(elsewhere, "x", "v1", "x.txt"), host)
	put(t, filepath.Join(elsewhere, "x", "v1", "none.proto"), []byte("package x.v1;\n"))
	put(t, filepath.Join(t.TempDir(), "outside.proto"), host)
	if err := os.Symlink(elsewhere, filepath.Join(root, "google")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, "x", "v1", "x.proto"), filepath.Join(elsewhere, "linked.proto")); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(root, "grafeas", "g.proto"), host)

	var stderr bytes.Buffer
	got, err := protosWithHosts(root, []string{"google", "grafeas"}, &stderr)
	if err != nil || strings.Join(got, ",") != "google/x/v1/x.proto,grafeas/g.proto" || stderr.Len() != 0 {
		t.Errorf("%q %v %q", got, err, stderr.String())
	}

	stderr.Reset()
	_, err = protosWithHosts(root, []string{"google", "missing"}, &stderr)
	var e *ExitError
	if !errors.As(err, &e) || e.Code != 2 || !e.Said || stderr.String() != "grep: missing: No such file or directory\n" {
		t.Errorf("a directory not there: %v, said %q", err, stderr.String())
	}
}

// A signal ends the run as the script's EXIT trap ended it: what is
// running is stopped, the work directory is removed, and the status is
// 128 and the signal's number. Here git itself sends SIGINT to the test,
// which is where Main is.
func TestInterruptRemovesTheWorkDirectory(t *testing.T) {
	need(t, "sh", "sleep")
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	dir := t.TempDir()
	app := filepath.Join(dir, "app")
	put(t, filepath.Join(app, "source.json"), []byte(`{"discovery": {"repository": "d", "commit": "c", "files": {}}, "googleapis": {"repository": "g", "commit": "c", "files": {}}}`))
	git := filepath.Join(dir, "git")
	if err := os.WriteFile(git, []byte("#!/bin/sh\nkill -INT $PPID\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main(Config{App: app, Git: git}, nil, &stdout, &stderr); code != 130 {
		t.Errorf("exit %d, not 130: %s", code, stderr.String())
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("left in TMPDIR: %v", left)
	}

	// And a run whose context is done before it starts runs nothing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunContext(ctx, Config{App: app, Git: git}, nil, &stdout, &stderr); err == nil {
		t.Error("a cancelled run succeeded")
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("left in TMPDIR: %v", left)
	}
}
