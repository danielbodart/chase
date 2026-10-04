package grant_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

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
