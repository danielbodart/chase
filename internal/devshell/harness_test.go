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

// A REALISATION, where a test can watch it. bwrap and nix are each this
// test binary, run by the name of a link to it, as the module runs each at
// its path. bwrap writes down how it was run and runs what follows its
// `--`, with the environment it was told; every path it binds is bound at
// its own, so nix reads the real files. nix writes down how it was run, and
// answers as knobs say. Their environment is cleared, so what they are
// told is in a file beside them, fake.json.

// knobs is fake.json: where the fakes log, and what nix answers.
type knobs struct {
	Log, Store string
	// Env is what print-dev-env prints.
	Env string
	// Fail is whether it fails, saying FailSaid.
	Fail     bool
	FailSaid string
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
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
	Null bool     `json:"stdinNull"`
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
				fmt.Fprintf(os.Stderr, "bwrap: %s is bound at %s\n", args[1], args[2])
				return 1
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
	err := syscall.Exec(args[1], args[1:], env)
	fmt.Fprintln(os.Stderr, err)
	return 1
}

// binds is each path a bwrap run binds, by how: --ro-bind, --bind or
// --ro-bind-try.
func binds(argv []string) map[string][]string {
	out := map[string][]string{}
	for i := 0; i+2 < len(argv) && argv[i] != "--"; i++ {
		switch argv[i] {
		case "--ro-bind", "--bind", "--ro-bind-try":
			out[argv[i]] = append(out[argv[i]], argv[i+1])
			i += 2
		case "--setenv":
			i += 2
		}
	}
	return out
}

func fakeNix() int {
	k := readKnobs()
	args := os.Args[1+len(c0):]
	logRun(k, "nix", run{Argv: os.Args, Env: os.Environ()})
	if args[0] != "print-dev-env" {
		fmt.Fprintf(os.Stderr, "nix: %q\n", args)
		return 1
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
		fmt.Fprintln(os.Stderr, "error: flake 'git+file:///w' does not provide attribute 'devShells.x86_64-linux.default'")
		return 1
	}
	if k.Fail {
		fmt.Fprintln(os.Stderr, k.FailSaid)
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
	env := filepath.Join(k.Store, fmt.Sprintf("%d-%s-env", n, filepath.Base(filepath.Dir(filepath.Dir(profile)))))
	os.WriteFile(env, []byte(k.Env), 0o444)
	link := fmt.Sprintf("%s-%d-link", profile, n)
	os.Symlink(env, link)
	os.Remove(profile + ".tmp")
	os.Symlink(filepath.Base(link), profile+".tmp")
	os.Rename(profile+".tmp", profile)
	fmt.Print(k.Env)
	return 0
}

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

func newHarness(t *testing.T) *harness {
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
	for _, name := range []string{"bwrap", "nix"} {
		if err := os.Symlink(self, filepath.Join(h.bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	h.k = knobs{Log: dir + "/logs", Store: dir + "/store", Env: envJSON}
	h.n = session.Nix{
		Config: gitsafetest.Config(t), Timeout: 60,
		Nix: h.bin + "/nix", Nixpkgs: "/nix/store/nixpkgs-src", System: "x86_64-linux",
		Bwrap: h.bin + "/bwrap", CABundle: "/etc/ssl/certs/ca-bundle.crt",
	}
	ws := dir + "/w/shop"
	h.r = Request{Workspace: ws, State: dir + "/state", Dir: dir + "/state/checkouts/" + key(ws)}
	return h
}

func key(ws string) string { return fmt.Sprintf("%x", []byte(filepath.Base(ws))) }

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

// clear forgets what the fakes wrote down.
func (h *harness) clear() {
	os.Remove(filepath.Join(h.k.Log, "nix.jsonl"))
	os.Remove(filepath.Join(h.k.Log, "bwrap.jsonl"))
}

func (h *harness) mustSay(needle string) {
	h.t.Helper()
	if !strings.Contains(h.said, needle) {
		h.t.Errorf("expected %q in: %s", needle, h.said)
	}
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
