package gcloud

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func umask() os.FileMode {
	m := unix.Umask(0)
	unix.Umask(m)
	return os.FileMode(m)
}

// The three modes against real repositories: the fixture's Discovery
// documents and protos committed to two local repositories, laid out as
// Google's are (discoveries/, google/ and grafeas/), fetched by git as the
// script fetched GitHub's.

type repos struct {
	t                     *testing.T
	discovery, googleapis string
	app                   string
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@example.invalid", "GIT_COMMITTER_NAME=a",
		"GIT_COMMITTER_EMAIL=a@example.invalid", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func put(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newRepos is the fixture as two repositories, and an app whose
// source.json names them and pins nothing yet.
func newRepos(t *testing.T) *repos {
	t.Helper()
	need(t, "git", "protoc")
	fx := filepath.Join("..", "..", "..", "tests", "gcloud")
	root := t.TempDir()
	r := &repos{t: t, discovery: filepath.Join(root, "discovery"), googleapis: filepath.Join(root, "googleapis"), app: filepath.Join(root, "apps", "gcloud")}
	for _, n := range []string{"index.json", "demo.v1.json", "demo.v1beta1.json", "demo.v2.json", "whole.v1.json"} {
		put(t, filepath.Join(r.discovery, "discoveries", n), read(t, filepath.Join(fx, "discoveries", n)))
	}
	put(t, filepath.Join(r.discovery, "README.md"), []byte("not pinned\n"))
	for from, to := range map[string]string{
		"google/api/annotations.proto":        "google/api/annotations.proto",
		"google/api/client.proto":             "google/api/client.proto",
		"google/api/http.proto":               "google/api/http.proto",
		"google/longrunning/operations.proto": "google/longrunning/operations.proto",
		"demo/v1/demo.proto":                  "google/demo/v1/demo.proto",
		"demo/v1/demo_v1.yaml":                "google/demo/v1/demo_v1.yaml",
		"whole/v1/whole.proto":                "google/whole/v1/whole.proto",
		"other/v1/other.proto":                "grafeas/other/v1/other.proto",
		"other/v1beta1/other.proto":           "grafeas/other/v1beta1/other.proto",
	} {
		put(t, filepath.Join(r.googleapis, to), read(t, filepath.Join(fx, "googleapis", from)))
	}
	put(t, filepath.Join(r.googleapis, "google/demo/v1/BUILD.bazel"), []byte("go_gapic_library(\n    transport = \"grpc+rest\",\n)\n"))
	put(t, filepath.Join(r.googleapis, "google/unused/v1/unused.proto"), []byte("syntax = \"proto3\";\npackage unused.v1;\nmessage Unused {}\n"))
	put(t, filepath.Join(r.googleapis, "README.md"), []byte("not pinned\n"))
	for _, d := range []string{r.discovery, r.googleapis} {
		gitIn(t, d, "init", "-q", "-b", "main")
		gitIn(t, d, "add", "-A")
		gitIn(t, d, "commit", "-q", "-m", "fixture")
	}
	put(t, filepath.Join(r.app, "exceptions.json"), read(t, filepath.Join(fx, "app", "exceptions.json")))
	put(t, filepath.Join(r.app, "source.json"), []byte(`{
  "discovery": {
    "repository": "`+r.discovery+`",
    "versions": {}
  },
  "googleapis": {
    "repository": "`+r.googleapis+`"
  }
}
`))
	return r
}

func (r *repos) main(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Main(Config{App: r.app}, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// wantSource is source.json as the script's jq wrote it after a bump:
// the keys it had, in their order, then commit, files and entries as jq
// appends them, each file's sha256.
func (r *repos) wantSource(discoveryCommit, googleapisCommit string) string {
	t := r.t
	var b strings.Builder
	b.WriteString("{\n  \"discovery\": {\n    \"repository\": \"" + r.discovery + "\",\n    \"versions\": {},\n")
	b.WriteString("    \"commit\": \"" + discoveryCommit + "\",\n    \"files\": {\n")
	disc := []string{"discoveries/demo.v1.json", "discoveries/demo.v2.json", "discoveries/index.json", "discoveries/whole.v1.json"}
	for i, f := range disc {
		b.WriteString("      \"" + f + "\": \"" + sum(read(t, filepath.Join(r.discovery, f))) + "\"")
		if i < len(disc)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("    }\n  },\n  \"googleapis\": {\n    \"repository\": \"" + r.googleapis + "\",\n")
	b.WriteString("    \"commit\": \"" + googleapisCommit + "\",\n    \"entries\": [\n")
	entries := []string{"google/demo/v1/demo.proto", "google/longrunning/operations.proto", "google/whole/v1/whole.proto", "grafeas/other/v1/other.proto"}
	for i, e := range entries {
		b.WriteString("      \"" + e + "\"")
		if i < len(entries)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("    ],\n    \"files\": {\n")
	gfiles := []string{"google/api/annotations.proto", "google/api/client.proto", "google/api/http.proto",
		"google/demo/v1/BUILD.bazel", "google/demo/v1/demo.proto", "google/demo/v1/demo_v1.yaml",
		"google/longrunning/operations.proto", "google/whole/v1/whole.proto", "grafeas/other/v1/other.proto"}
	for i, f := range gfiles {
		b.WriteString("      \"" + f + "\": \"" + sum(read(t, filepath.Join(r.googleapis, f))) + "\"")
		if i < len(gfiles)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("    }\n  }\n}\n")
	return b.String()
}

func TestBumpPinsWhatItReadsAndThePinsRegenerate(t *testing.T) {
	r := newRepos(t)
	fx := newFixture(t)
	if code, said := fx.generate(); code != 0 {
		t.Fatalf("the fixture: exit %d: %s", code, said)
	}

	// --bump at each repository's head.
	code, stdout, stderr := r.main("--bump")
	if code != 0 {
		t.Fatalf("--bump: exit %d: %s%s", code, stdout, stderr)
	}
	head := func(dir string) string { return gitIn(t, dir, "rev-parse", "HEAD") }
	if got, want := string(read(t, filepath.Join(r.app, "source.json"))), r.wantSource(head(r.discovery), head(r.googleapis)); got != want {
		t.Errorf("source.json after --bump:\n%s\nnot:\n%s", got, want)
	}
	if info, err := os.Stat(filepath.Join(r.app, "source.json")); err != nil || info.Mode().Perm()&0o077 != 0o666&^umask()&0o077 {
		t.Errorf("source.json is not written as the umask allows: %v %v", info.Mode(), err)
	}
	// The same classification as from the fixture's own layout.
	compareTrees(t, filepath.Join(fx.dir, "app", "apis"), filepath.Join(r.app, "apis"))
	if got, want := read(t, filepath.Join(r.app, "index.json")), read(t, filepath.Join(fx.dir, "app", "index.json")); !bytes.Equal(got, want) {
		t.Errorf("index.json:\n%s\nnot:\n%s", got, want)
	}
	if !strings.Contains(stderr, "gcloud: 3 APIs, 55 rules: ") {
		t.Errorf("no report: %s", stderr)
	}

	// From the pins, fetched by commit: the same again.
	os.RemoveAll(filepath.Join(r.app, "apis"))
	os.Remove(filepath.Join(r.app, "index.json"))
	if code, stdout, stderr := r.main(); code != 0 {
		t.Fatalf("pinned: exit %d: %s%s", code, stdout, stderr)
	}
	compareTrees(t, filepath.Join(fx.dir, "app", "apis"), filepath.Join(r.app, "apis"))

	// From local checkouts: the repositories themselves.
	if code, stdout, stderr := r.main(r.discovery, r.googleapis); code != 0 {
		t.Fatalf("local: exit %d: %s%s", code, stdout, stderr)
	}
	compareTrees(t, filepath.Join(fx.dir, "app", "apis"), filepath.Join(r.app, "apis"))

	// A pinned file that is not as pinned is refused, and nothing is
	// generated from it.
	demo := filepath.Join(r.discovery, "discoveries", "demo.v1.json")
	saved := read(t, demo)
	put(t, demo, bytes.Replace(saved, []byte("Gets a secret."), []byte("Gets a secret!"), 1))
	before := read(t, filepath.Join(r.app, "apis", "demo.json"))
	code, stdout, stderr = r.main(r.discovery, r.googleapis)
	if code != 1 {
		t.Errorf("a file not as pinned: exit %d, not 1", code)
	}
	if stdout != "discoveries/demo.v1.json: FAILED\n" {
		t.Errorf("sha256sum's line: %q", stdout)
	}
	if want := "sha256sum: WARNING: 1 computed checksum did NOT match\ngcloud: the discovery files above are not as pinned in " + filepath.Join(r.app, "source.json") + "\n"; stderr != want {
		t.Errorf("said %q, not %q", stderr, want)
	}
	if !bytes.Equal(before, read(t, filepath.Join(r.app, "apis", "demo.json"))) {
		t.Error("a file not as pinned was generated from")
	}
	put(t, demo, saved)

	// A pinned file that is not there.
	os.Remove(filepath.Join(r.googleapis, "google/demo/v1/BUILD.bazel"))
	if code, _, stderr := r.main(r.discovery, r.googleapis); code != 2 || !strings.Contains(stderr, "google/demo/v1/BUILD.bazel") {
		t.Errorf("a pinned file missing: exit %d: %s", code, stderr)
	}
}

func TestBumpAtCommitsGiven(t *testing.T) {
	r := newRepos(t)
	first := gitIn(t, r.discovery, "rev-parse", "HEAD")
	gfirst := gitIn(t, r.googleapis, "rev-parse", "HEAD")
	// A later commit a bump at the first must not pin.
	put(t, filepath.Join(r.discovery, "discoveries", "demo.v1.json"),
		bytes.Replace(read(t, filepath.Join(r.discovery, "discoveries", "demo.v1.json")), []byte("Gets a secret."), []byte("Gets a secret, later."), 1))
	gitIn(t, r.discovery, "commit", "-q", "-am", "later")
	// A commit that is not a branch's tip is fetched by its hash: the
	// repository must serve it, as GitHub does.
	gitIn(t, r.discovery, "config", "uploadpack.allowAnySHA1InWant", "true")
	later := read(t, filepath.Join(r.discovery, "discoveries", "demo.v1.json"))
	gitIn(t, r.discovery, "checkout", "-q", first)
	want := r.wantSource(first, gfirst)
	gitIn(t, r.discovery, "checkout", "-q", "main")
	if code, stdout, stderr := r.main("--bump", first, gfirst); code != 0 {
		t.Fatalf("--bump COMMITS: exit %d: %s%s", code, stdout, stderr)
	}
	if got := string(read(t, filepath.Join(r.app, "source.json"))); got != want {
		t.Errorf("source.json after --bump COMMITS:\n%s\nnot:\n%s", got, want)
	}
	if strings.Contains(string(read(t, filepath.Join(r.app, "apis", "demo.json"))), "later") {
		t.Errorf("the later commit was generated from: %s", later)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{{"one"}, {"a", "b", "c"}, {"--bump", "one"}, {"--bump", "a", "b", "c"}} {
		var stdout, stderr bytes.Buffer
		if code := Main(Config{App: t.TempDir()}, args, &stdout, &stderr); code != 2 {
			t.Errorf("%q: exit %d, not 2", args, code)
		}
		if stderr.String() != usage+"\n" || stdout.Len() != 0 {
			t.Errorf("%q: said %q", args, stderr.String())
		}
	}
	for _, args := range [][]string{nil, {"generate"}, {"other", "a", "b", "c", "d", "e"}} {
		var stdout, stderr bytes.Buffer
		if code := Tool(args, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "generate APP DISCOVERIES GOOGLEAPIS DESCRIPTORS ENTRIES") {
			t.Errorf("%q: exit %d: %s", args, code, stderr.String())
		}
	}
}
