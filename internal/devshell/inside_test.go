package devshell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/chase/internal/session"
)

// A DEVSHELL EVALUATED IN THE SESSION, where a test can watch it.
// chase-devshell is this test binary, run by the name of a link to it, and
// so is the session's nix, as session-nix: it writes down how it was run
// and answers as sessionKnobs, in session.json beside it, say -- failing,
// as a lower path mid-substitution fails, the first Busy times it runs.
// chase-devshell execs the session's real bash, which runs the agent, here
// a bash that prints what the agent would see.

type sessionKnobs struct {
	Log string
	// Env is what print-dev-env prints.
	Env string
	// Busy is how many runs fail as one that met a lower path the host is
	// substituting; Fail fails every run, saying FailSaid.
	Busy     int
	Fail     bool
	FailSaid string
}

func init() {
	switch filepath.Base(os.Args[0]) {
	case "session-nix":
		os.Exit(fakeSessionNix())
	case "chase-devshell":
		os.Exit(Inside(context.Background(), os.Args[1:], os.Environ(), os.Stderr))
	}
}

func fakeSessionNix() int {
	var k sessionKnobs
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(os.Args[0]), "session.json"))
	if json.Unmarshal(b, &k) != nil {
		panic("no session.json beside " + os.Args[0])
	}
	logRun(knobs{Log: k.Log}, "session-nix", run{Argv: os.Args, Env: os.Environ()})
	runs, _ := os.ReadFile(filepath.Join(k.Log, "session-nix.jsonl"))
	if n := bytes.Count(runs, []byte("\n")); n <= k.Busy {
		fmt.Fprintln(os.Stderr, "error: changing mode of '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.40/lib': Operation not permitted")
		return 1
	}
	if k.Fail {
		fmt.Fprintln(os.Stderr, k.FailSaid)
		return 1
	}
	fmt.Print(k.Env)
	return 0
}

// What print-dev-env prints of a shell.nix like pokeranker's: libraries,
// and a shellHook that exports what they need.
const sessionEnvJSON = `{"bashFunctions":{},"variables":{` +
	`"PATH":{"type":"exported","value":"/nix/store/pkgconfig/bin:/nix/store/rustc/bin"},` +
	`"XDG_DATA_DIRS":{"type":"exported","value":"/nix/store/gtk/share"},` +
	`"PKG_CONFIG_PATH":{"type":"exported","value":"/nix/store/webkitgtk/lib/pkgconfig"},` +
	`"OWN":{"type":"exported","value":"the-devshells"},` +
	`"ANTHROPIC_BASE_URL":{"type":"exported","value":"http://elsewhere"},` +
	`"shellHook":{"type":"exported","value":"export LD_LIBRARY_PATH=/nix/store/webkitgtk/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\nexport GIO_MODULE_DIR=/nix/store/glib-networking/lib/gio/modules\nexport HOME=/elsewhere\necho hooked >&2"}}}`

// inSession is a harness for a devShell evaluated in the session: its
// fakes linked, the session's own environment given.
type inSession struct {
	*harness
	sk sessionKnobs
}

func newInSession(t *testing.T) *inSession {
	h := newHarness(t)
	self, _ := os.Executable()
	for _, name := range []string{"session-nix", "chase-devshell"} {
		if err := os.Symlink(self, filepath.Join(h.bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	return &inSession{harness: h, sk: sessionKnobs{Log: h.dir + "/logs", Env: sessionEnvJSON}}
}

func (s *inSession) writeKnobs() {
	b, _ := json.Marshal(s.sk)
	if err := os.WriteFile(s.bin+"/session.json", b, 0o600); err != nil {
		s.t.Fatal(err)
	}
}

// launch is chase-devshell as exec puts it ahead of the agent -- here a
// bash that prints what it sees, one NAME=VALUE a line -- in a session
// whose environment is env and the bash's directory: its status, what the
// agent printed, and what was said.
func (s *inSession) launch(kind, mode string, env ...string) (int, map[string]string, string) {
	s.t.Helper()
	s.writeKnobs()
	bash := realBash(s.t)
	report := `for v in PATH OWN LD_LIBRARY_PATH GIO_MODULE_DIR PKG_CONFIG_PATH XDG_DATA_DIRS HOME ANTHROPIC_BASE_URL NIX_REMOTE; do printf '%s=%s\n' "$v" "${!v-}"; done`
	argv := []string{"-checkout", s.r.Workspace, "-kind", kind, "-nixpkgs", "/nix/store/nixpkgs-src", "-system", "x86_64-linux",
		"-timeout", "60", "-mode", mode, "-nix", s.bin + "/session-nix", "-git", s.n.Git,
		"-front", "/run/wrappers/bin:/home/alice/.local/share/mise/shims", "-keep", "HOME NIX_REMOTE PATH TERM",
		"--", "bash", "-c", report}
	cmd := exec.Command(s.bin+"/chase-devshell", argv...)
	cmd.Env = append([]string{"PATH=/run/wrappers/bin:" + filepath.Dir(bash) + ":/home/alice/.local/share/mise/shims", "HOME=/home/alice",
		"NIX_REMOTE=local-overlay://?real=/nix/store", "NIX_LOG_DIR=/s/state/log", "NIX_USER_CONF_FILES=", "NIX_CONF_DIR=/etc/nix",
		"SSL_CERT_FILE=/etc/frisket/ca-bundle.crt", "SECRET_OF_THE_SESSIONS=x"}, env...)
	var out, said bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &said
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		s.t.Fatal(err)
	}
	seen := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			seen[k] = v
		}
	}
	return code, seen, said.String()
}

// The session evaluates its shell.nix itself, restricted, with nothing of
// its environment but what reaches its store and frisket's CA bundle, and
// no profile; and the agent is given its variables behind the session's
// own, its PATH behind the wrappers and mise's shims, and its shellHook's
// exports -- LD_LIBRARY_PATH and GIO_MODULE_DIR, as pokeranker's -- but
// none that steer the agent, nor a HOME of its own.
func TestTheSessionEvaluatesItsShellNixAndTheAgentGetsItsEnvironment(t *testing.T) {
	s := newInSession(t)
	s.checkout(map[string]string{"shell.nix": "{}"})
	code, seen, said := s.launch(shell, "automatic", "OWN=the-sessions")
	if code != 0 {
		t.Fatalf("status %d: %s", code, said)
	}
	path := strings.Split(seen["PATH"], ":")
	if len(path) < 4 || path[0] != "/run/wrappers/bin" || path[1] != "/home/alice/.local/share/mise/shims" || path[2] != "/nix/store/pkgconfig/bin" || path[3] != "/nix/store/rustc/bin" {
		t.Errorf("PATH is %q", path)
	}
	if seen["LD_LIBRARY_PATH"] != "/nix/store/webkitgtk/lib" || seen["GIO_MODULE_DIR"] != "/nix/store/glib-networking/lib/gio/modules" {
		t.Errorf("the shellHook's exports did not reach the agent: %v", seen)
	}
	if seen["PKG_CONFIG_PATH"] != "/nix/store/webkitgtk/lib/pkgconfig" || seen["XDG_DATA_DIRS"] != "/nix/store/gtk/share" {
		t.Errorf("the devShell's variables did not reach the agent: %v", seen)
	}
	if seen["OWN"] != "the-sessions" || seen["HOME"] != "/home/alice" || seen["ANTHROPIC_BASE_URL"] != "" {
		t.Errorf("the devShell's won over the session's: %v", seen)
	}
	for _, want := range []string{"the devShell's OWN is the session's own", "the devShell's ANTHROPIC_BASE_URL is not given to the agent", "hooked",
		"evaluating the devShell of shell.nix in the session"} {
		if !strings.Contains(said, want) {
			t.Errorf("did not say %q: %s", want, said)
		}
	}
	runs := s.runs("session-nix")
	if len(runs) != 1 {
		t.Fatalf("nix ran %d times", len(runs))
	}
	r := runs[0]
	want := []string{"PATH=" + s.bin + ":" + filepath.Dir(s.n.Git), "NIX_REMOTE=local-overlay://?real=/nix/store", "NIX_LOG_DIR=/s/state/log",
		"NIX_USER_CONF_FILES=", "NIX_CONF_DIR=/etc/nix", "HOME=/home/alice", "SSL_CERT_FILE=/etc/frisket/ca-bundle.crt",
		"NIX_PATH=nixpkgs=/nix/store/nixpkgs-src:" + s.r.Workspace}
	if !slices.Equal(r.Env, want) {
		t.Errorf("nix's environment is %q, not %q", r.Env, want)
	}
	if v, ok := optionValue(r.Argv, "restrict-eval"); !ok || v != "true" {
		t.Errorf("a shell.nix is not evaluated restricted: %q", r.Argv)
	}
	if slices.Contains(r.Argv, "--profile") || !slices.Contains(r.Argv, s.r.Workspace+"/shell.nix") {
		t.Errorf("nix ran as %q", r.Argv)
	}
}

// A flake is evaluated purely, its configuration never taken and its lock
// never written.
func TestTheSessionEvaluatesAFlakePurely(t *testing.T) {
	s := newInSession(t)
	s.checkout(map[string]string{"flake.nix": flakeNix})
	if code, _, said := s.launch(flake, "automatic"); code != 0 {
		t.Fatalf("status %d: %s", code, said)
	}
	r := s.runs("session-nix")[0]
	if v, ok := optionValue(r.Argv, "accept-flake-config"); !ok || v != "false" {
		t.Errorf("a flake's own configuration may be taken: %q", r.Argv)
	}
	if !slices.Contains(r.Argv, "--no-write-lock-file") || !slices.Contains(r.Argv, s.r.Workspace+"#devShells.x86_64-linux.default") {
		t.Errorf("nix ran as %q", r.Argv)
	}
	if _, ok := optionValue(r.Argv, "restrict-eval"); ok || slices.ContainsFunc(r.Env, func(e string) bool { return strings.HasPrefix(e, "NIX_PATH=") }) {
		t.Errorf("a flake was given a path: %q, %q", r.Argv, r.Env)
	}
}

// One that cannot be evaluated is said, and the agent starts without it;
// where the grant asked for it, the session ends before the agent, with
// flong's status for a session that never ran.
func TestAFailureStartsTheAgentWithoutItUnlessTheGrantAskedForIt(t *testing.T) {
	s := newInSession(t)
	s.checkout(map[string]string{"shell.nix": "{}"})
	s.sk.Fail, s.sk.FailSaid = true, "error: attribute 'webkitgtk_4_1' missing"
	code, seen, said := s.launch(shell, "automatic")
	if code != 0 || seen["NIX_REMOTE"] == "" || seen["LD_LIBRARY_PATH"] != "" {
		t.Errorf("status %d, the agent saw %v: %s", code, seen, said)
	}
	if !strings.Contains(said, "the devShell could not be evaluated, and the session starts without it: attribute 'webkitgtk_4_1' missing") {
		t.Errorf("said %s", said)
	}
	code, seen, said = s.launch(shell, "granted")
	if code != Granted || len(seen) != 0 {
		t.Errorf("status %d, the agent saw %v", code, seen)
	}
	if !strings.Contains(said, "the devShell the grant asks for could not be evaluated, and the session ends: attribute 'webkitgtk_4_1' missing") {
		t.Errorf("said %s", said)
	}
}

// A lower path the host is substituting while the session reads it is
// waited on, and tried again; past the last try, the evaluation fails,
// naming the path.
func TestALowerPathMidSubstitutionIsTriedAgain(t *testing.T) {
	was := backoff
	backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { backoff = was })
	s := newInSession(t)
	s.checkout(map[string]string{"shell.nix": "{}"})
	o := &inside{checkout: s.r.Workspace, kind: shell, nixpkgs: "/nix/store/nixpkgs-src", system: "x86_64-linux",
		mode: "automatic", nix: s.bin + "/session-nix", git: s.n.Git, timeout: 60}
	s.sk.Busy = 2
	s.writeKnobs()
	var said bytes.Buffer
	if _, err := o.evaluate(context.Background(), map[string]string{}, &said); err != nil {
		t.Fatalf("%v: %s", err, said.String())
	}
	if n := len(s.runs("session-nix")); n != 3 {
		t.Errorf("nix ran %d times", n)
	}
	if !strings.Contains(said.String(), "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.40/lib is being substituted by the host; trying again") {
		t.Errorf("said %s", said.String())
	}
	os.Remove(s.dir + "/logs/session-nix.jsonl")
	s.sk.Busy = 10
	s.writeKnobs()
	_, err := o.evaluate(context.Background(), map[string]string{}, &said)
	if err == nil || !strings.Contains(err.Error(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.40/lib is still being substituted by the host") {
		t.Errorf("%v", err)
	}
	if n := len(s.runs("session-nix")); n != 1+len(backoff) {
		t.Errorf("nix ran %d times", n)
	}
}

// chase-devshell is given exec's data alone: anything else is refused
// before nix runs.
func TestChaseDevshellRefusesDataNotExecs(t *testing.T) {
	s := newInSession(t)
	for _, argv := range [][]string{
		{"-checkout", "relative", "-kind", shell, "-nix", "/n", "-git", "/g", "--", "bash"},
		{"-checkout", "/w", "-kind", "default.nix", "-nix", "/n", "-git", "/g", "--", "bash"},
		{"-checkout", "/w", "-kind", shell, "-nix", "/n", "-git", "/g", "-mode", "sometimes", "--", "bash"},
		{"-checkout", "/w", "-kind", shell, "-nix", "/n", "-git", "/g"},
	} {
		var said bytes.Buffer
		if code := Inside(context.Background(), argv, nil, &said); code != 2 {
			t.Errorf("%q: status %d", argv, code)
		}
	}
	if s.runs("session-nix") != nil {
		t.Error("nix ran")
	}
}

// WHAT EXEC GIVES A SESSION WHOSE STORE IS ITS OWN, by the tier's devShell
// setting and what the grant asks.
func TestInSessionByTheTierAndTheGrant(t *testing.T) {
	yes, no := true, false
	made := "/w/other:rw\n/nix/store:overlay\n/s/state:rw\n/s/lower"
	for _, c := range []struct {
		name       string
		devShell   string
		asked      *session.NixAsked
		recording  bool
		binds      string
		files      map[string]string
		store      bool
		mode, kind string
		refused    string
		said       string
	}{
		{name: "automatic", devShell: "automatic", binds: made, files: map[string]string{"shell.nix": "{}"}, store: true, mode: "automatic", kind: shell},
		{name: "automatic, a flake", devShell: "automatic", binds: made, files: map[string]string{"flake.nix": flakeNix, "shell.nix": "{}"}, store: true, mode: "automatic", kind: flake},
		{name: "automatic, nothing to evaluate", devShell: "automatic", binds: made, files: map[string]string{"README": "x"}, store: true},
		{name: "automatic, the grant says no devShell", devShell: "automatic", binds: made, asked: &session.NixAsked{DevShell: &no}, files: map[string]string{"shell.nix": "{}"}, store: true},
		{name: "automatic, the grant asks", devShell: "automatic", binds: made, asked: &session.NixAsked{DevShell: &yes}, files: map[string]string{"shell.nix": "{}"}, store: true, mode: "granted", kind: shell},
		{name: "granted, not asked", devShell: "granted", binds: made, files: map[string]string{"shell.nix": "{}"}},
		{name: "granted, the store alone", devShell: "granted", binds: made, asked: &session.NixAsked{Store: &yes}, files: map[string]string{"shell.nix": "{}"}, store: true},
		{name: "granted, asked", devShell: "granted", binds: made, asked: &session.NixAsked{DevShell: &yes}, files: map[string]string{"shell.nix": "{}"}, store: true, mode: "granted", kind: shell},
		{name: "granted, asked, recording", devShell: "granted", binds: made, asked: &session.NixAsked{DevShell: &yes}, recording: true, files: map[string]string{"shell.nix": "{}"}, store: true, mode: "automatic", kind: shell},
		{name: "granted, asked, nothing to evaluate", devShell: "granted", binds: made, asked: &session.NixAsked{DevShell: &yes}, files: map[string]string{"README": "x"},
			refused: "the grant asks for a devShell, and the checkout has no flake.nix or shell.nix"},
		{name: "granted, asked, no store made", devShell: "granted", binds: "/w/other:rw", asked: &session.NixAsked{DevShell: &yes}, files: map[string]string{"shell.nix": "{}"},
			refused: "the grant asks for a devShell, and binds made the session no nix store of its own"},
		{name: "automatic, no store made", devShell: "automatic", binds: "", files: map[string]string{"shell.nix": "{}"},
			said: "binds made the session no nix store of its own, as chase.jsonc did not ask for one when it ran: launch again, and the session starts without it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.checkout(c.files)
			n := h.n
			n.Store, n.DevShell = "session", c.devShell
			n.Session = &session.NixSession{Root: "/home/alice/.cache/chase/nix/sessions", Nix: "/nix/store/nix-ro/bin/nix",
				Devshell: "/nix/store/chase/bin/chase-devshell", ConfDir: "/etc/nix"}
			var said bytes.Buffer
			in, err := InSession(context.Background(), n, SessionRequest{Workspace: h.r.Workspace, Machine: "m1", Binds: c.binds, Asked: c.asked, Recording: c.recording}, &said)
			if c.refused != "" {
				var r *Refusal
				if !errors.As(err, &r) || !strings.Contains(err.Error(), c.refused) {
					t.Fatalf("not refused: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.said != "" && !strings.Contains(said.String(), c.said) {
				t.Errorf("said %q", said.String())
			}
			if (in != nil) != c.store {
				t.Fatalf("a store is %v", in)
			}
			if in == nil {
				return
			}
			if in.Env[0].Name != "NIX_REMOTE" || !strings.Contains(in.Env[0].Value, "/home/alice/.cache/chase/nix/sessions/m1/state") {
				t.Errorf("the store's environment is %v", in.Env)
			}
			if c.mode == "" {
				if in.Devshell != nil {
					t.Errorf("a devShell: %q", in.Devshell)
				}
				return
			}
			want := []string{"/nix/store/chase/bin/chase-devshell", "-checkout", h.r.Workspace, "-kind", c.kind,
				"-nixpkgs", "/nix/store/nixpkgs-src", "-system", "x86_64-linux", "-timeout", strconv.Itoa(n.Timeout),
				"-mode", c.mode, "-nix", "/nix/store/nix-ro/bin/nix", "-git", n.Git}
			if !slices.Equal(in.Devshell, want) {
				t.Errorf("chase-devshell is %q, not %q", in.Devshell, want)
			}
		})
	}
}
