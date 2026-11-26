package grant_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/grant/signertest"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// THE GRANT AS A TIER RUNS IT, where a test can watch it. A stand-in
// signer signs a project's chase.json (signertest); sops extracts a key
// from a JSON file; systemctl says what it was asked. Each tool is this
// test binary, run by the name of a link to it, as the module runs each
// tool at its path.

// Where the fakes log, and what they are told, all through the environment
// the grant's children inherit.
const (
	logDir    = "CHASE_TEST_LOG_DIR"
	sopsFails = "CHASE_TEST_SOPS_FAILS"
)

func TestMain(m *testing.M) {
	gitsafe.MaybeExec()
	switch filepath.Base(os.Args[0]) {
	case "sops":
		os.Exit(fakeSops())
	case "systemctl":
		os.Exit(fakeSystemctl())
	case "bwrap":
		os.Exit(fakeBwrap())
	case "nix":
		os.Exit(fakeNix())
	}
	os.Exit(m.Run())
}

func appendLog(name, line string) {
	f, err := os.OpenFile(filepath.Join(os.Getenv(logDir), name), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.WriteString(line + "\n")
}

func fakeSops() int {
	appendLog("sops.log", strings.Join(os.Args[1:], " "))
	if os.Getenv(sopsFails) != "" {
		return 1
	}
	// --decrypt --extract ["NAME"] FILE, of a file that is JSON in the clear.
	var path []string
	if len(os.Args) != 5 || json.Unmarshal([]byte(os.Args[3]), &path) != nil || len(path) != 1 {
		return 2
	}
	b, err := os.ReadFile(os.Args[4])
	if err != nil {
		return 1
	}
	var doc map[string]string
	if json.Unmarshal(b, &doc) != nil {
		return 1
	}
	v, ok := doc[path[0]]
	if !ok {
		return 1
	}
	fmt.Print(v)
	return 0
}

func fakeSystemctl() int {
	appendLog("systemctl.log", os.Getenv("XDG_RUNTIME_DIR")+" "+strings.Join(os.Args[1:], " "))
	return 0
}

// diffPath is diffutils' diff, which the module gives the grant: $CHASE_TEST_DIFF
// when set, and otherwise the one on PATH. No diff fails the test: what a
// person is shown is compared here.
func diffPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("CHASE_TEST_DIFF"); p != "" {
		return p
	}
	p, err := exec.LookPath("diff")
	if err != nil {
		t.Fatal("no diff on PATH, and no CHASE_TEST_DIFF: the approval's diffs are diffutils'")
	}
	p, err = filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type harness struct {
	t   *testing.T
	dir string
	cfg grant.Config
	fx  *gitsafetest.Fixture
	// registry is the test's own apps, beside those DefaultApps makes of
	// cfg.
	registry map[string]apps.App
	// out and err are what the last call printed.
	out, err string
	// signer signs what approve writes, as a person would through quoin's.
	signer *signertest.Signer
	// given is what the last launch gave the session.
	given session.Given
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := gitsafetest.Dir(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"bin", "run", "home", "logs", "policies", "root"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sops", "systemctl"} {
		if err := os.Symlink(self, filepath.Join(dir, "bin", name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(logDir, filepath.Join(dir, "logs"))
	t.Setenv(sopsFails, "")
	h := &harness{
		t:   t,
		dir: dir,
		fx:  gitsafetest.NewFixture(t),
		cfg: grant.Config{
			Config:     gitsafetest.Config(t),
			UID:        1000,
			Home:       dir + "/home",
			State:      dir + "/state",
			Runtime:    dir + "/run",
			Policies:   dir + "/policies",
			Checkouts:  map[string][]string{"example/nix-config": {"/home/user/Projects/nix-config"}},
			Apps:       map[string]grant.App{},
			Answerable: []string{"cloudflare", "gcloud", "git", "github", "huggingface", "linear"},
			Sops:       dir + "/bin/sops",
			Diff:       diffPath(t),
		},
	}
	h.signer = signertest.New(t, h.cfg.Home)
	h.cfg.AllowedSigners, h.cfg.SignerAgent = h.signer.AllowedSigners, h.signer.Socket
	return h
}

// root is where the test's checkouts are, every link in its path resolved.
func (h *harness) root() string { return h.dir + "/root" }

// run is `chase internal grant ARGS`: its status, with what it printed kept.
func (h *harness) run(args ...string) int {
	h.t.Helper()
	var out, errb bytes.Buffer
	rc := grant.Run(context.Background(), h.cfg, args, strings.NewReader(""), &out, &errb)
	h.out = out.String()
	h.err = errb.String()
	return rc
}

// launch is the grant's half of `chase internal hook exec TIER` for machine: its
// status, as the hook's would be, with what it said kept, and what it gave
// the session kept in h.given.
func (h *harness) launch(tier, ws, machine string) int {
	h.t.Helper()
	var errb bytes.Buffer
	// The module's apps, saying what they say where this call does, and
	// the test's own in place of any of the same name.
	registry := grant.DefaultApps(h.cfg, &errb)
	maps.Copy(registry, h.registry)
	given, err := grant.Launch(context.Background(), h.cfg, registry, tier, ws, machine, &errb)
	rc := 0
	if err != nil {
		term.Say(&errb, "%v", err)
		rc = 1
	}
	h.out, h.err, h.given = "", errb.String(), given
	return rc
}

// env is what the last launch gave the session's environment, NAME=VALUE
// each, in order.
func (h *harness) env() []string {
	var out []string
	for _, v := range h.given.Env {
		out = append(out, v.Name+"="+v.Value)
	}
	return out
}

// approve is `chase internal grant approve WS MACHINE TIER` with file, when it is
// not "", written to WS's chase.json and signed as `chase sign` signs it,
// with what it derives of the checkout: the sops file's digest, the Docker
// project. The signer is asked only when that differs from what it signed
// last, as a person signs only a change. A file `chase sign` refuses is
// left as it is, unsigned, for the launch to say why.
func (h *harness) approve(ws, machine, tier, file string) int {
	h.t.Helper()
	if file != "" {
		// chase sign reads the file before it derives the digest, so a
		// file naming a sops file gives one to be replaced, as a person
		// writing one does.
		var doc map[string]any
		if json.Unmarshal([]byte(file), &doc) == nil {
			if c, ok := doc["chase"].(map[string]any); ok && c["secrets"] != nil && c["secretsSHA256"] == nil {
				c["secretsSHA256"] = strings.Repeat("0", 64)
				b, _ := json.Marshal(doc)
				file = string(b)
			}
		}
		write(h.t, ws+"/chase.json", file)
		if err := grant.Sign(context.Background(), h.cfg, ws, io.Discard, io.Discard); err != nil {
			h.t.Logf("chase sign: %v", err)
		}
	}
	rc := h.run("approve", ws, machine, tier)
	if rc == 0 {
		// approve prints nothing: what seccompPolicy prints is what it
		// staged, which the harness reads as flong's next hook would.
		if h.out != "" {
			h.t.Errorf("approve printed %q", h.out)
		}
		if l, err := grant.Lines(h.cfg, machine); err == nil {
			h.out = l
		}
	}
	return rc
}

// approveUnsigned is approve with file written as it is and unsigned, as a
// checkout's session could leave it: what the launch refuses before the
// signer is asked, it refuses here.
func (h *harness) approveUnsigned(ws, machine, tier, file string) int {
	h.t.Helper()
	write(h.t, ws+"/chase.json", file)
	os.Remove(ws + "/chase.json.sig")
	return h.run("approve", ws, machine, tier)
}

func (h *harness) approved(ws, machine, tier, env string) {
	h.t.Helper()
	if rc := h.approve(ws, machine, tier, env); rc != 0 {
		h.t.Fatalf("%s was not approved: %s", ws, h.err)
	}
}

func (h *harness) launched(ws, machine, tier, env string) {
	h.t.Helper()
	h.approved(ws, machine, tier, env)
	if rc := h.launch(tier, ws, machine); rc != 0 {
		h.t.Fatalf("%s was not launched: %s", machine, h.err)
	}
}

// asked is how many files the signer has been asked to sign.
func (h *harness) asked() int { return len(h.signer.Asked()) }

// said is whether the last call said line, whole, on stderr.
func (h *harness) said(line string) bool {
	return slices.Contains(strings.Split(h.err, "\n"), line)
}

func (h *harness) mustSay(needle string) {
	h.t.Helper()
	if !strings.Contains(h.err, needle) {
		h.t.Errorf("expected %q in: %s", needle, h.err)
	}
}

// log is a fake's log, a line an entry.
func (h *harness) log(name string) []string {
	b, err := os.ReadFile(filepath.Join(h.dir, "logs", name))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// stagedDoc is what approve staged for machine, or nil.
func (h *harness) stagedDoc(machine string) map[string]any {
	h.t.Helper()
	b, err := os.ReadFile(h.dir + "/run/chase/.grant/" + machine + ".json")
	if err != nil {
		return nil
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		h.t.Fatalf("the stage is not JSON: %s", b)
	}
	return v
}

func (h *harness) isStaged(machine string) bool {
	_, err := os.Lstat(h.dir + "/run/chase/.grant/" + machine + ".json")
	return err == nil
}

func key(ws string) string {
	s := sha256.Sum256([]byte(ws))
	return hex.EncodeToString(s[:])[:32]
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// checkout is a repository at d with each of tracked, all added to its
// index.
func (h *harness) checkout(d string, tracked ...string) {
	h.t.Helper()
	h.fx.Run("init", "-q", d)
	for _, f := range tracked {
		write(h.t, d+"/"+f, "the project's own\n")
	}
	h.fx.Run("-C", d, "add", "-A")
}

// repo is a repository at d with each of urls as origin's, and nothing in it.
func (h *harness) repo(d string, urls ...string) {
	h.t.Helper()
	if err := os.MkdirAll(d, 0o755); err != nil {
		h.t.Fatal(err)
	}
	h.fx.Run("-C", d, "init", "-q")
	for _, u := range urls {
		h.fx.Run("-C", d, "config", "--add", "remote.origin.url", u)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
