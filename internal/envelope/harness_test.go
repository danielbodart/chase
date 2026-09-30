package envelope_test

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
	"github.com/danielbodart/chase/internal/envelope"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// CHASE-ENVELOPE AS A TIER RUNS IT, where a test can watch it: the checks'
// envelopeHarness, with the script's lines a Config. nix prints $ENVELOPE, as
// if the checkout evaluated to it; the approver logs what it is asked and
// approves, unless told to refuse a kind; sops extracts a key from a JSON
// file; systemctl says what it was asked. Each is this test binary, run by
// the name of a link to it, as the module runs each tool at its path.

// Where the fakes log, and what they are told, all through the environment
// the envelope's children inherit.
const (
	logDir     = "CHASE_TEST_LOG_DIR"
	refuseKind = "CHASE_TEST_REFUSE"
	sopsFails  = "CHASE_TEST_SOPS_FAILS"
	nixFails   = "CHASE_TEST_NIX_FAILS"
)

func TestMain(m *testing.M) {
	gitsafe.MaybeExec()
	switch filepath.Base(os.Args[0]) {
	case "nix":
		os.Exit(fakeNix())
	case "approver":
		os.Exit(fakeApprover())
	case "sops":
		os.Exit(fakeSops())
	case "systemctl":
		os.Exit(fakeSystemctl())
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

func fakeNix() int {
	b, _ := json.Marshal(os.Args[1:])
	appendLog("nix.log", string(b))
	if why := os.Getenv(nixFails); why != "" {
		fmt.Fprintln(os.Stderr, why)
		return 1
	}
	fmt.Println(os.Getenv("ENVELOPE"))
	return 0
}

func fakeApprover() int {
	in, _ := io.ReadAll(os.Stdin)
	var asked struct {
		Kind string `json:"kind"`
	}
	json.Unmarshal(in, &asked)
	var compact bytes.Buffer
	json.Compact(&compact, in)
	appendLog("approvals.jsonl", compact.String())
	os.WriteFile(filepath.Join(os.Getenv(logDir), "approver.stdin"), in, 0o600)
	fmt.Println("the approver was asked about", asked.Kind)
	if slices.Contains(strings.Split(os.Getenv(refuseKind), ","), asked.Kind) {
		return 1
	}
	return 0
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

// diffPath is diffutils' diff, which the module gives the envelope: $CHASE_TEST_DIFF
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
	cfg envelope.Config
	fx  *gitsafetest.Fixture
	// registry is the test's own apps, beside those DefaultApps makes of
	// cfg.
	registry map[string]apps.App
	// out and err are what the last call printed.
	out, err string
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
	for _, name := range []string{"nix", "approver", "sops", "systemctl"} {
		if err := os.Symlink(self, filepath.Join(dir, "bin", name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(logDir, filepath.Join(dir, "logs"))
	t.Setenv(refuseKind, "")
	t.Setenv(sopsFails, "")
	t.Setenv(nixFails, "")
	t.Setenv("ENVELOPE", "")
	return &harness{
		t:   t,
		dir: dir,
		fx:  gitsafetest.NewFixture(t),
		cfg: envelope.Config{
			Config:    gitsafetest.Config(t),
			UID:       1000,
			Home:      dir + "/home",
			State:     dir + "/state",
			Runtime:   dir + "/run",
			Hosts:     dir + "/docker-hosts.json",
			Policies:  dir + "/policies",
			Checkouts: map[string][]string{"example/nix-config": {"/home/user/Projects/nix-config"}},
			Apps:      map[string]envelope.App{},
			Approver:  dir + "/bin/approver",
			Evaluator: "/nix/store/00000000000000000000000000000000-chase-envelope-evaluator",
			Nix:       dir + "/bin/nix",
			Sops:      dir + "/bin/sops",
			Diff:      diffPath(t),
		},
	}
}

// root is where the test's checkouts are, every link in its path resolved.
func (h *harness) root() string { return h.dir + "/root" }

// run is `chase envelope ARGS`: its status, with what it printed kept.
func (h *harness) run(args ...string) int {
	h.t.Helper()
	var out, errb bytes.Buffer
	rc := envelope.Run(context.Background(), h.cfg, args, strings.NewReader(""), &out, &errb)
	h.out, h.err = out.String(), errb.String()
	return rc
}

// launch is the envelope's half of `chase hook exec TIER` for machine: its
// status, as the hook's would be, with what it said kept, and what it gave
// the session kept in h.given.
func (h *harness) launch(tier, ws, machine string) int {
	h.t.Helper()
	var errb bytes.Buffer
	// The module's apps, saying what they say where this call does, and
	// the test's own in place of any of the same name.
	registry := envelope.DefaultApps(h.cfg, &errb)
	maps.Copy(registry, h.registry)
	given, err := envelope.Launch(context.Background(), h.cfg, registry, tier, ws, machine, &errb)
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

// approve is `ENVELOPE=E chase envelope approve WS MACHINE TIER`.
func (h *harness) approve(ws, machine, tier, env string) int {
	h.t.Helper()
	h.t.Setenv("ENVELOPE", env)
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

type approval struct {
	Kind      string `json:"kind"`
	Workspace string `json:"workspace"`
	Diff      string `json:"diff"`
}

func (h *harness) approvals(kind string) []approval {
	var out []approval
	for _, line := range h.log("approvals.jsonl") {
		var a approval
		if json.Unmarshal([]byte(line), &a) == nil && (kind == "" || a.Kind == kind) {
			out = append(out, a)
		}
	}
	return out
}

// stagedDoc is what approve staged for machine, or nil.
func (h *harness) stagedDoc(machine string) map[string]any {
	h.t.Helper()
	b, err := os.ReadFile(h.dir + "/run/chase/.envelope/" + machine + ".json")
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
	_, err := os.Lstat(h.dir + "/run/chase/.envelope/" + machine + ".json")
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

const flake = "{ outputs = _: { chaseModules.default = { }; }; }\n"

// checkout is a repository at d with a flake and each of tracked, all added
// to its index.
func (h *harness) checkout(d string, tracked ...string) {
	h.t.Helper()
	h.fx.Run("init", "-q", d)
	write(h.t, d+"/flake.nix", flake)
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

// flake gives d a tracked flake that says chaseModules.
func (h *harness) flake(d string) {
	h.t.Helper()
	write(h.t, d+"/flake.nix", flake)
	h.fx.Run("-C", d, "add", "flake.nix")
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
