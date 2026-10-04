package grant_test

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/session"
)

// A DEVSHELL, AS EXEC REALISES IT, where a test can watch it: nix is this
// binary, which writes down how it was run and answers as print-dev-env
// would, with an environment rooted at the profile it is told. Its
// environment is cleared, so it logs beside the link to it, in ../logs.
// bwrap is this binary too, which runs what follows its `--`, every path
// bound at its own.

func fakeBwrap() int {
	args := os.Args[1:]
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	syscall.Exec(args[1], args[1:], nil)
	return 1
}

func fakeNix() int {
	logs := filepath.Join(filepath.Dir(os.Args[0]), "..", "logs")
	b, _ := json.Marshal(os.Args)
	f, _ := os.OpenFile(filepath.Join(logs, "nix.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	f.Write(append(b, '\n'))
	f.Close()
	profile := os.Args[slices.Index(os.Args, "--profile")+1]
	env := `{"bashFunctions":{},"variables":{"PATH":{"type":"exported","value":"/nix/store/hello/bin"},"HELLO_FROM_SHELL":{"type":"exported","value":"hi"},"shellHook":{"type":"exported","value":""}}}`
	os.WriteFile(filepath.Join(logs, "env.json"), []byte(env), 0o444)
	os.Symlink(filepath.Join(logs, "env.json"), profile+"-1-link")
	os.Symlink("profile-1-link", profile)
	return 0
}

// nixOf is a tier's apps.nix whose nix is the fake.
func (h *harness) nixOf() *session.Nix {
	self, _ := os.Executable()
	for _, name := range []string{"bwrap", "nix"} {
		if _, err := os.Lstat(h.dir + "/bin/" + name); err != nil {
			os.Symlink(self, h.dir+"/bin/"+name)
		}
	}
	return &session.Nix{
		Config: h.cfg.Config, Timeout: 60,
		Nix: h.dir + "/bin/nix", Nixpkgs: "/nix/store/nixpkgs", System: "x86_64-linux",
		Bwrap: h.dir + "/bin/bwrap", CABundle: "/etc/ssl/certs/ca-bundle.crt",
	}
}

// tracked writes each of files into ws, tracked.
func (h *harness) tracked(ws string, files map[string]string) {
	h.t.Helper()
	for name, content := range files {
		write(h.t, ws+"/"+name, content)
	}
	h.fx.Run("-C", ws, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "add", "-A")
}

// The devShell is realised after the grant and given to the payload: its
// variables first, and a bash ahead of the agent that orders PATH; its
// root kept in the grant's state directory.
func TestTheExecHookRealisesTheDevShellAfterTheGrant(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	s := sessionConfig(h)
	s.Tiers["trusted"] = session.Tier{Nix: h.nixOf()}
	h.tracked(ws, map[string]string{"shell.nix": "{}"})
	h.approved(ws, "m1", "trusted", `{"network": {"allow": ["example.org"]}}`)
	if rc := h.exec(s, true, "trusted", ws, "m1", "shell"); rc != 0 {
		t.Fatalf("refused: %s", h.err)
	}
	got := h.fields()
	if !slices.Contains(got, "env:HELLO_FROM_SHELL=hi") || got[0] != "env:HELLO_FROM_SHELL=hi" {
		t.Errorf("the devShell's variables are not the payload's first: %q", got)
	}
	at := slices.Index(got, "arg:bash")
	if at < 0 || got[at+1] != "arg:--noprofile" || got[len(got)-3] != "arg:bash" || got[len(got)-2] != "arg:-l" {
		t.Errorf("the agent is not wrapped: %q", got)
	}
	if n := len(h.log("nix.jsonl")); n != 1 {
		t.Errorf("nix ran %d times", n)
	}
	if _, err := os.Lstat(h.cfg.State + "/checkouts/" + key(ws) + "/devshell/profile"); err != nil {
		t.Errorf("no root was kept in the checkout's own directory: %v", err)
	}
}

// A tier that takes no grant keeps the devShell in the default state
// directory.
func TestATierWithoutGrantsKeepsItsDevShellInTheDefaultState(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w/shop"
	h.repo(ws)
	h.tracked(ws, map[string]string{"shell.nix": "{}"})
	s := sessionConfig(h)
	s.Tiers["plain"] = session.Tier{Nix: h.nixOf()}
	if rc := h.exec(s, false, "plain", ws, "m1", "shell"); rc != 0 {
		t.Fatalf("refused: %s", h.err)
	}
	if _, err := os.Lstat(h.cfg.Home + "/.local/state/chase/checkouts/" + key(ws) + "/devshell/profile"); err != nil {
		t.Errorf("no root in the default state directory: %v", err)
	}
}

// A tier without nix realises nothing, whatever the checkout has: the
// agent is run with nothing ahead of it.
func TestATierWithoutNixRealisesNothing(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	h.tracked(ws, map[string]string{"shell.nix": "{}"})
	h.approved(ws, "m1", "trusted", `{}`)
	if rc := h.exec(sessionConfig(h), true, "trusted", ws, "m1", "shell"); rc != 0 {
		t.Fatalf("refused: %s", h.err)
	}
	if got := h.fields(); !slices.Equal(got[:2], []string{"arg:bash", "arg:-l"}) || h.log("nix.jsonl") != nil {
		t.Errorf("the payload is %q", got)
	}
}

// sessionNixOf is a tier's apps.nix whose store is the session's own, its
// devShell's setting devShell.
func (h *harness) sessionNixOf(devShell string) *session.Nix {
	n := h.nixOf()
	n.Bwrap, n.CABundle = "", ""
	n.Store, n.DevShell = "session", devShell
	n.Session = &session.NixSession{
		Root: h.cfg.Home + "/.cache/chase/nix/sessions", Nix: "/nix/store/nix-ro/bin/nix", Devshell: "/nix/store/chase/bin/chase-devshell",
		NixStore: "/nix/store/nix/bin/nix-store", Sqlite: "/nix/store/sqlite/bin/sqlite3", SystemdRun: "/nix/store/systemd/bin/systemd-run",
		ConfDir: "/etc/nix", MaxBytes: 1 << 30, MaxInodes: 1000, MaxRoots: 100,
	}
	return n
}

// execBinds is exec, with flong's $binds binds.
func (h *harness) execBinds(s session.Config, tier, ws, machine, binds string, args ...string) int {
	h.t.Helper()
	registry := grant.DefaultApps(h.cfg, &bytes.Buffer{})
	maps.Copy(registry, h.registry)
	var out, errb bytes.Buffer
	rc := grant.Exec(context.Background(), s, &h.cfg, registry, tier, ws, machine, binds, args, &out, &errb)
	h.out, h.err = out.String(), errb.String()
	return rc
}

const madeBinds = "/nix/store:overlay\n/home/alice/.cache/chase/nix/sessions/m1/state:rw\n/home/alice/.cache/chase/nix/sessions/m1/lower"

// Where the tier's store is the session's own, nothing of the checkout's
// Nix is evaluated on the host: the grant's devShell is the session's
// store, told to its nix, and chase-devshell ahead of the agent, which
// ends the session if it cannot evaluate it.
func TestAGrantsDevShellIsEvaluatedInTheSessionOverItsOwnStore(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	s := sessionConfig(h)
	s.Tiers["trusted"] = session.Tier{Nix: h.sessionNixOf("granted")}
	h.tracked(ws, map[string]string{"shell.nix": "{}"})
	h.approved(ws, "m1", "trusted", `{"apps": {"nix": {"devShell": true}}}`)
	if rc := h.execBinds(s, "trusted", ws, "m1", madeBinds, "shell"); rc != 0 {
		t.Fatalf("refused: %s", h.err)
	}
	got := h.fields()
	if !slices.ContainsFunc(got, func(f string) bool {
		return strings.HasPrefix(f, "env:NIX_REMOTE=local-overlay://?real=/nix/store&state="+h.cfg.Home+"/.cache/chase/nix/sessions/m1/state&")
	}) || !slices.Contains(got, "env:NIX_USER_CONF_FILES=") {
		t.Errorf("the session's nix is not told its store: %q", got)
	}
	at := slices.Index(got, "arg:/nix/store/chase/bin/chase-devshell")
	if at < 0 || !slices.Contains(got[at:], "arg:granted") || got[len(got)-4] != "arg:--" || got[len(got)-3] != "arg:bash" {
		t.Errorf("chase-devshell is not ahead of the agent: %q", got)
	}
	if h.log("nix.jsonl") != nil || h.log("bwrap.jsonl") != nil {
		t.Error("nix ran on the host")
	}
}

// A grant that does not ask gives no store in a tier whose devShell waits
// on it; one that asks and finds no store binds made refuses the launch,
// with nothing printed for flong to run.
func TestAGrantedDevShellWithoutTheGrantOrTheStore(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	s := sessionConfig(h)
	s.Tiers["trusted"] = session.Tier{Nix: h.sessionNixOf("granted")}
	h.tracked(ws, map[string]string{"shell.nix": "{}"})
	h.approved(ws, "m1", "trusted", `{}`)
	if rc := h.execBinds(s, "trusted", ws, "m1", madeBinds, "shell"); rc != 0 {
		t.Fatalf("refused: %s", h.err)
	}
	if got := h.fields(); !slices.Equal(got[:2], []string{"arg:bash", "arg:-l"}) || slices.ContainsFunc(got, func(f string) bool { return strings.HasPrefix(f, "env:NIX_") }) {
		t.Errorf("the payload is %q", got)
	}
	h.approved(ws, "m2", "trusted", `{"apps": {"nix": {"devShell": true}}}`)
	if rc := h.execBinds(s, "trusted", ws, "m2", "", "shell"); rc != 1 || h.out != "" {
		t.Errorf("status %d, printed %q", rc, h.out)
	}
	h.mustSay("the grant asks for a devShell, and binds made the session no nix store of its own")
}

// A grant's nix in a tier that has none is said, and the session starts as
// the tier has it.
func TestAGrantsNixInATierWithoutNixIsIgnoredAndSaid(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	h.approved(ws, "m1", "trusted", `{"apps": {"nix": {"store": true}}}`)
	if rc := h.exec(sessionConfig(h), true, "trusted", ws, "m1", "shell"); rc != 0 {
		t.Fatalf("refused: %s", h.err)
	}
	h.mustSay("nix ignored: trusted has no nix")
}

// What binds, before the grant is approved, takes to ask for a store: the
// checkout's chase.jsonc as it is, a devShell or the store alone; nothing
// in a tier that takes no checkout's grant, nor from a file that is no
// grant, a link, or missing.
func TestWhatAsksForANixStoreBeforeTheApproval(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	for doc, want := range map[string]bool{
		`{"apps": {"nix": {"devShell": true}}}`:                    true,
		`{"apps": {"nix": {"store": true}}}`:                       true,
		`/* a comment */ {"apps": {"nix": {"devShell": true,},},}`: true,
		`{"apps": {"nix": {"devShell": false}}}`:                   false,
		`{"apps": {"nix": {}}}`:                                    false,
		`{}`:                                                       false,
		`{"apps": {"nix": {"devShell": "yes"}}}`:                   false,
		`not a grant`:                                              false,
	} {
		write(t, ws+"/chase.jsonc", doc)
		if got := grant.AsksForNixStore(h.cfg, ws, "trusted"); got != want {
			t.Errorf("%s: %v", doc, got)
		}
	}
	write(t, ws+"/chase.jsonc", `{"apps": {"nix": {"devShell": true}}}`)
	h.cfg.Ungranted = []string{"trusted"}
	if grant.AsksForNixStore(h.cfg, ws, "trusted") {
		t.Error("a tier that takes no checkout's grant asked")
	}
	h.cfg.Ungranted = nil
	os.Rename(ws+"/chase.jsonc", ws+"/real.jsonc")
	os.Symlink(ws+"/real.jsonc", ws+"/chase.jsonc")
	if grant.AsksForNixStore(h.cfg, ws, "trusted") {
		t.Error("a link asked")
	}
	os.Remove(ws + "/chase.jsonc")
	if grant.AsksForNixStore(h.cfg, ws, "trusted") {
		t.Error("no file asked")
	}
}

// WHAT A GRANT MAY NAME FOR NIX: whether the devShell is evaluated in the
// session, and whether the store is given alone, booleans and nothing
// else; and nothing of the flake's beside them.
func TestWhatAGrantMayNameForNix(t *testing.T) {
	for _, g := range []string{
		`{"apps": {"nix": {"devShell": "yes"}}}`,
		`{"apps": {"nix": {"store": 1}}}`,
		`{"apps": {"nix": {"devShells": true}}}`,
		`{"apps": {"nix": {"flake": "./other.nix"}}}`,
		`{"apps": {"nix": true}}`,
	} {
		if _, err := grant.ParseFile([]byte(g)); err == nil {
			t.Errorf("%s was taken", g)
		}
	}
	for g, want := range map[string]string{
		`{"apps": {"nix": {"devShell": true}}}`:                 `{"apps":{"nix":{"devShell":true}}}`,
		`{"apps": {"nix": {"devShell": false, "store": true}}}`: `{"apps":{"nix":{"devShell":false,"store":true}}}`,
		`{"apps": {"nix": {}}}`:                                 `{"apps":{"nix":{}}}`,
	} {
		got, err := grant.ParseFile([]byte(g))
		if err != nil || string(got) != want {
			t.Errorf("%s was read as %s, %v, not %s", g, got, err, want)
		}
	}
}
