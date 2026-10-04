package devshell

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
	"github.com/danielbodart/chase/internal/session"
)

// A REALISATION, where a test can watch it. bwrap, pasta and nix are each
// this test binary, run by the name of a link to it, as the module runs
// each tool at its path. bwrap and pasta write down how they were run and
// run what follows their `--`, bwrap with the environment it was told and
// the paths it binds mapped back to where they are on the host, so nix
// reads real files. nix writes down how it was run, and answers each step
// as knobs say. Their environment is cleared, so what they are told is in
// a file beside them, fake.json.

// knobs is fake.json: where the fakes log, and what nix answers.
type knobs struct {
	Log, Store string
	// Derivation is what `derivation show` prints, Env what print-dev-env
	// does.
	Derivation, Env string
	// FailStep is the step that fails, P, A, B or C, saying FailSaid.
	FailStep, FailSaid string
	// NoDefault is a flake with no devShells.<system>.default.
	NoDefault bool
	// Sleep is how long the evaluation takes, with a child of its own
	// that lives as long.
	Sleep int
}

func TestMain(m *testing.M) {
	gitsafe.MaybeExec()
	switch filepath.Base(os.Args[0]) {
	case "bwrap":
		os.Exit(fakeBwrap())
	case "pasta":
		os.Exit(fakePasta())
	case "nix":
		os.Exit(fakeNix())
	case "sleeper":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func readKnobs() knobs {
	var k knobs
	b, err := os.ReadFile(filepath.Join(filepath.Dir(os.Args[0]), "fake.json"))
	if err != nil || json.Unmarshal(b, &k) != nil {
		panic("no fake.json beside " + os.Args[0])
	}
	return k
}

// run is one fake's run, as it is written down.
type run struct {
	Argv  []string `json:"argv"`
	Env   []string `json:"env"`
	Null  bool     `json:"stdinNull"`
	Lazy  string   `json:"read,omitempty"`
	Error string   `json:"error,omitempty"`
}

func logRun(k knobs, name string, r run) {
	in, _ := os.Stdin.Stat()
	null, _ := os.Stat("/dev/null")
	r.Null = in != nil && null != nil && os.SameFile(in, null)
	b, _ := json.Marshal(r)
	f, err := os.OpenFile(filepath.Join(k.Log, name+".jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

func fakeBwrap() int {
	k := readKnobs()
	logRun(k, "bwrap", run{Argv: os.Args, Env: os.Environ()})
	args := os.Args[1:]
	env := os.Environ()
	type bind struct{ src, dest string }
	var binds []bind
	for len(args) > 0 && args[0] != "--" {
		switch args[0] {
		case "--unshare-all", "--share-net", "--die-with-parent", "--new-session":
			args = args[1:]
		case "--clearenv":
			env = nil
			args = args[1:]
		case "--tmpfs", "--dev", "--proc":
			args = args[2:]
		case "--ro-bind", "--bind", "--ro-bind-try":
			if args[1] != args[2] {
				binds = append(binds, bind{args[1], args[2]})
			}
			args = args[3:]
		case "--setenv":
			env = append(env, args[1]+"="+args[2])
			args = args[3:]
		default:
			fmt.Fprintf(os.Stderr, "bwrap: unknown option %s\n", args[0])
			return 1
		}
	}
	slices.SortFunc(binds, func(a, b bind) int { return len(b.dest) - len(a.dest) })
	mapped := func(s string) string {
		for _, b := range binds {
			s = strings.ReplaceAll(s, b.dest, b.src)
		}
		return s
	}
	cmd := args[1:]
	for i := range cmd {
		cmd[i] = mapped(cmd[i])
	}
	for i := range env {
		env[i] = mapped(env[i])
	}
	err := syscall.Exec(cmd[0], cmd, env)
	fmt.Fprintln(os.Stderr, err)
	return 1
}

func fakePasta() int {
	k := readKnobs()
	logRun(k, "pasta", run{Argv: os.Args, Env: os.Environ()})
	at := slices.Index(os.Args, "--")
	err := syscall.Exec(os.Args[at+1], os.Args[at+1:], os.Environ())
	fmt.Fprintln(os.Stderr, err)
	return 1
}

func fakeNix() int {
	k := readKnobs()
	args := os.Args[1+len(c0):]
	r := run{Argv: os.Args, Env: os.Environ()}
	defer func() { logRun(k, "nix", r) }()
	fail := func(step string) bool {
		if k.FailStep == step {
			fmt.Fprintln(os.Stderr, k.FailSaid)
			return true
		}
		return false
	}
	switch {
	case slices.Equal(args[:2], []string{"flake", "prefetch"}):
		if fail("P") {
			return 1
		}
		fmt.Println(`{"hash":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","storePath":"/nix/store/x-source"}`)
	case slices.Equal(args[:2], []string{"derivation", "show"}):
		// What is evaluated, as it is read: a flake.nix or shell.nix that is
		// a link is read through it here, as nix would.
		target := args[len(args)-1]
		if f, ok := strings.CutPrefix(target, "path:"); ok {
			target, _, _ = strings.Cut(f, "#")
			target += "/flake.nix"
		}
		if b, err := os.ReadFile(target); err == nil {
			r.Lazy = string(b)
		} else {
			r.Error = err.Error()
		}
		if k.Sleep > 0 {
			self, _ := os.Executable()
			c := exec.Command(self)
			c.Args[0] = "sleeper"
			c.Start()
			os.WriteFile(filepath.Join(k.Log, "sleeper.pid"), []byte(strconv.Itoa(c.Process.Pid)), 0o600)
			time.Sleep(time.Duration(k.Sleep) * time.Second)
		}
		if k.NoDefault {
			fmt.Fprintln(os.Stderr, "error: flake 'path:/src/w' does not provide attribute 'devShells.x86_64-linux.default'")
			return 1
		}
		if fail("A") {
			return 1
		}
		fmt.Print(k.Derivation)
	case args[0] == "build":
		if fail("B") {
			return 1
		}
		at := slices.Index(args, "--out-link")
		os.Symlink("/nix/store/x-input", args[at+1])
	case args[0] == "print-dev-env":
		if fail("C") {
			return 1
		}
		profile := args[slices.Index(args, "--profile")+1]
		// The generation after the latest, as nix numbers them.
		n := 1
		links, _ := filepath.Glob(profile + "-*-link")
		for _, l := range links {
			if g, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(l, profile+"-"), "-link")); err == nil && g >= n {
				n = g + 1
			}
		}
		env := filepath.Join(k.Store, fmt.Sprintf("%d-%s-env", n, filepath.Base(filepath.Dir(profile))))
		os.WriteFile(env, []byte(k.Env), 0o444)
		link := fmt.Sprintf("%s-%d-link", profile, n)
		os.Symlink(env, link)
		os.Remove(profile + ".tmp")
		os.Symlink(filepath.Base(link), profile+".tmp")
		os.Rename(profile+".tmp", profile)
		fmt.Print(k.Env)
	default:
		fmt.Fprintf(os.Stderr, "nix: %q\n", args)
		return 1
	}
	return 0
}

// A derivation as nix 2.33 and later print it: one input, of two outputs.
const derivationJSON = `{"derivations":{"aaaa-nix-shell.drv":{"env":{"name":"nix-shell","shellHook":""},` +
	`"inputs":{"drvs":{"bbbb-hello.drv":{"dynamicOutputs":{},"outputs":["out","dev"]}},"srcs":[]},"name":"nix-shell","outputs":{},"system":"x86_64-linux","version":4}},"version":4}`

// An environment as print-dev-env prints it.
const envJSON = `{"bashFunctions":{"greet":"echo hi"},"variables":{` +
	`"PATH":{"type":"exported","value":"/nix/store/hello/bin:/nix/store/jq/bin"},` +
	`"XDG_DATA_DIRS":{"type":"exported","value":"/nix/store/hello/share"},` +
	`"HELLO_FROM_SHELL":{"type":"exported","value":"hi"},` +
	`"SSL_CERT_FILE":{"type":"exported","value":"/no-cert-file.crt"},` +
	`"shellHook":{"type":"exported","value":""},` +
	`"outputs":{"type":"var","value":"out"}}}`

type harness struct {
	t        *testing.T
	dir, bin string
	k        knobs
	n        session.Nix
	r        Request
	fx       *gitsafetest.Fixture
	said     string
}

func newHarness(t *testing.T, egress string) *harness {
	t.Helper()
	dir := gitsafetest.Dir(t)
	h := &harness{t: t, dir: dir, bin: dir + "/bin", fx: gitsafetest.NewFixture(t)}
	for _, d := range []string{"bin", "logs", "store", "state", "w"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bwrap", "pasta", "nix"} {
		if err := os.Symlink(self, filepath.Join(h.bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	h.k = knobs{Log: dir + "/logs", Store: dir + "/store", Derivation: derivationJSON, Env: envJSON}
	h.n = session.Nix{
		Config: gitsafetest.Config(t), DevShell: "automatic", Egress: egress, Timeout: 60,
		Nix: h.bin + "/nix", Nixpkgs: "/nix/store/nixpkgs-src", System: "x86_64-linux",
		Bwrap: h.bin + "/bwrap", Pasta: h.bin + "/pasta", CABundle: "/etc/ssl/certs/ca-bundle.crt",
		Policy: dir + "/policy.json",
	}
	h.policy("github.com", "pypi.org")
	ws := dir + "/w/shop"
	h.r = Request{Tier: "own", Workspace: ws, State: dir + "/state", Dir: dir + "/state/checkouts/" + key(ws), Policy: dir + "/policy.json"}
	return h
}

func key(ws string) string { return fmt.Sprintf("%x", []byte(filepath.Base(ws))) }

// policy is the session's document, allowing names.
func (h *harness) policy(names ...string) {
	h.t.Helper()
	b, _ := json.Marshal(map[string]any{"name": "own", "allow": names})
	if err := os.WriteFile(h.dir+"/policy.json", b, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// checkout is the workspace, a repository with each of files, as name and
// content, tracked.
func (h *harness) checkout(files map[string]string) {
	h.t.Helper()
	ws := h.r.Workspace
	if _, err := os.Stat(ws + "/.git"); err != nil {
		h.fx.Run("init", "-q", ws)
	}
	for name, content := range files {
		p := filepath.Join(ws, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
	h.fx.Run("-C", ws, "add", "-A")
}

// realise is Realise, the knobs as they are now: the devShell, and the
// error, with what it said kept.
func (h *harness) realise() (*session.DevShell, error) {
	h.t.Helper()
	b, _ := json.Marshal(h.k)
	if err := os.WriteFile(h.bin+"/fake.json", b, 0o600); err != nil {
		h.t.Fatal(err)
	}
	var stderr bytes.Buffer
	ds, err := Realise(context.Background(), h.n, h.r, &stderr)
	h.said = stderr.String()
	return ds, err
}

// runs is each run a fake wrote down, in order.
func (h *harness) runs(name string) []run {
	b, err := os.ReadFile(filepath.Join(h.k.Log, name+".jsonl"))
	if err != nil {
		return nil
	}
	var out []run
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r run
		if json.Unmarshal([]byte(l), &r) != nil {
			h.t.Fatalf("a run is not JSON: %s", l)
		}
		out = append(out, r)
	}
	return out
}

// step is nix's runs whose arguments after c0 begin with prefix.
func (h *harness) step(prefix ...string) []run {
	var out []run
	for _, r := range h.runs("nix") {
		if args := r.Argv[1+len(c0):]; len(args) >= len(prefix) && slices.Equal(args[:len(prefix)], prefix) {
			out = append(out, r)
		}
	}
	return out
}

// clear forgets what the fakes wrote down.
func (h *harness) clear() {
	for _, n := range []string{"nix", "bwrap", "pasta"} {
		os.Remove(filepath.Join(h.k.Log, n+".jsonl"))
	}
}

func (h *harness) mustSay(needle string) {
	h.t.Helper()
	if !strings.Contains(h.said, needle) {
		h.t.Errorf("expected %q in: %s", needle, h.said)
	}
}

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

// option is the value after flag in argv, "" for none.
func option(argv []string, flag string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// optionValue is the value of nix's `--option NAME VALUE` in argv.
func optionValue(argv []string, name string) (string, bool) {
	for i := 0; i+2 < len(argv); i++ {
		if argv[i] == "--option" && argv[i+1] == name {
			return argv[i+2], true
		}
	}
	return "", false
}

// realBash is $CHASE_TEST_BASH, or the bash on PATH: declarations are
// read back by bash.
func realBash(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("CHASE_TEST_BASH"); p != "" {
		return p
	}
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal("no bash on PATH, and no CHASE_TEST_BASH")
	}
	return p
}

func bashOutput(bash, script string) (string, error) {
	out, err := exec.Command(bash, "--noprofile", "--norc", "-c", script).Output()
	return string(out), err
}
