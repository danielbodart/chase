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

	"github.com/danielbodart/chase/internal/gitsafe/gitsafetest"
	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/session"
)

// A DEVSHELL, AS EXEC REALISES IT, where a test can watch it: bwrap is this
// binary, which writes down the nix it was to run and answers it as nix
// would -- one derivation, and an environment rooted at the profile it is
// told -- and pasta runs what follows its `--`. Their environment is
// cleared, so they log beside the links to them, in ../logs.

func fakeBwrap() int {
	logs := filepath.Join(filepath.Dir(os.Args[0]), "..", "logs")
	b, _ := json.Marshal(os.Args)
	f, _ := os.OpenFile(filepath.Join(logs, "bwrap.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	f.Write(append(b, '\n'))
	f.Close()
	args := os.Args
	at := func(s string) int { return slices.Index(args, s) }
	switch {
	case at("derivation") > 0:
		os.Stdout.WriteString(`{"derivations":{"aaaa-nix-shell.drv":{"env":{},"inputs":{"drvs":{},"srcs":[]}}},"version":4}`)
	case at("print-dev-env") > 0:
		profile := args[at("--profile")+1]
		env := `{"bashFunctions":{},"variables":{"PATH":{"type":"exported","value":"/nix/store/hello/bin"},"HELLO_FROM_SHELL":{"type":"exported","value":"hi"},"shellHook":{"type":"exported","value":""}}}`
		os.WriteFile(filepath.Join(logs, "env.json"), []byte(env), 0o444)
		os.Symlink(filepath.Join(logs, "env.json"), profile+"-1-link")
		os.Symlink("profile-1-link", profile)
	}
	return 0
}

func fakePasta() int {
	at := slices.Index(os.Args, "--")
	syscall.Exec(os.Args[at+1], os.Args[at+1:], os.Environ())
	return 1
}

// nixOf is a tier's apps.nix whose bwrap and pasta are the fakes, and the
// devShell setting and egress given.
func (h *harness) nixOf(devShell, egress, policy string) *session.Nix {
	for _, name := range []string{"bwrap", "pasta"} {
		if _, err := os.Lstat(h.dir + "/bin/" + name); err != nil {
			self, _ := os.Executable()
			os.Symlink(self, h.dir+"/bin/"+name)
		}
	}
	return &session.Nix{
		Config: gitsafetest.Config(h.t), DevShell: devShell, Egress: egress, Timeout: 60,
		Nix: "/nix/store/nix/bin/nix", Nixpkgs: "/nix/store/nixpkgs", System: "x86_64-linux",
		Bwrap: h.dir + "/bin/bwrap", Pasta: h.dir + "/bin/pasta", CABundle: "/etc/ssl/certs/ca-bundle.crt",
		Policy: policy,
	}
}

// evaluations are the allowed-uris each evaluation the fake bwrap ran was
// given.
func (h *harness) evaluations() []string {
	var out []string
	for _, l := range h.log("bwrap.jsonl") {
		var argv []string
		json.Unmarshal([]byte(l), &argv)
		if slices.Contains(argv, "derivation") {
			for i := range argv {
				if argv[i] == "allowed-uris" {
					out = append(out, argv[i+1])
				}
			}
		}
	}
	return out
}

// tracked writes each of files into ws, tracked.
func (h *harness) tracked(ws string, files map[string]string) {
	h.t.Helper()
	for name, content := range files {
		write(h.t, ws+"/"+name, content)
	}
	h.fx.Run("-C", ws, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "add", "-A")
}

// The devShell is realised after the grant, bounded by the session's own
// document -- the tier's allowlist and the names the grant adds -- and
// given to the payload: its variables first, and a bash ahead of the
// agent that orders PATH.
func TestTheExecHookRealisesTheDevShellAfterTheGrant(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	s := sessionConfig(h)
	s.Tiers["trusted"] = session.Tier{Nix: h.nixOf("granted", "frisket", "/etc/frisket/policies/trusted.json")}
	h.tracked(ws, map[string]string{"shell.nix": "{}"})
	h.approved(ws, "m1", "trusted", `{"apps": {"nix": {"devShell": true}}, "network": {"allow": ["example.org"]}}`)
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
	if ev := h.evaluations(); len(ev) != 1 || !strings.Contains(ev[0], "https://example.org/") {
		t.Errorf("the evaluation was bounded by %q, not the session's document", ev)
	}
	if _, err := os.Lstat(h.cfg.State + "/checkouts/" + key(ws) + "/devshell/profile"); err != nil {
		t.Errorf("no root was kept in the checkout's own directory: %v", err)
	}
}

// A grant's devShell in a tier that has no nix is said, and the session
// starts as the tier has it.
func TestAGrantsDevShellInATierWithoutNixIsIgnoredAndSaid(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	h.approved(ws, "m1", "trusted", `{"apps": {"nix": {"devShell": true}}}`)
	if rc := h.exec(sessionConfig(h), true, "trusted", ws, "m1", "shell"); rc != 0 {
		t.Fatalf("refused: %s", h.err)
	}
	h.mustSay("nix ignored: trusted has no nix")
	if got := h.fields(); !slices.Equal(got[:2], []string{"arg:bash", "arg:-l"}) {
		t.Errorf("the payload is %q", got)
	}
}

// A devShell the grant asks for that cannot be realised refuses the
// launch, with nothing printed for flong to run.
func TestARefusedDevShellPrintsNothing(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	s := sessionConfig(h)
	s.Tiers["trusted"] = session.Tier{Nix: h.nixOf("granted", "frisket", "/etc/frisket/policies/trusted.json")}
	h.approved(ws, "m1", "trusted", `{"apps": {"nix": {"devShell": true}}}`)
	if rc := h.exec(s, true, "trusted", ws, "m1", "shell"); rc != 1 || h.out != "" {
		t.Errorf("status %d, printed %q", rc, h.out)
	}
	h.mustSay("the grant asks for a devShell, and the checkout tracks no flake.nix or shell.nix")
}

// A tier that takes no grant bounds its evaluation by its own document, and
// keeps the devShell in the default state directory.
func TestATierWithoutGrantsRealisesFromItsOwnPolicy(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w/shop"
	h.repo(ws)
	h.tracked(ws, map[string]string{"shell.nix": "{}"})
	own := h.dir + "/policies/plain.json"
	write(t, own, `{"name": "plain", "allow": ["pypi.org"]}`)
	s := sessionConfig(h)
	s.Tiers["plain"] = session.Tier{Nix: h.nixOf("automatic", "frisket", own)}
	if rc := h.exec(s, false, "plain", ws, "m1", "shell"); rc != 0 {
		t.Fatalf("refused: %s", h.err)
	}
	if ev := h.evaluations(); len(ev) != 1 || !strings.Contains(ev[0], "https://pypi.org/") {
		t.Errorf("the evaluation was bounded by %q", ev)
	}
	if _, err := os.Lstat(h.cfg.Home + "/.local/state/chase/checkouts/" + key(ws) + "/devshell/profile"); err != nil {
		t.Errorf("no root in the default state directory: %v", err)
	}
}

// Launch prepares nothing of the devShell: what the grant says of it is
// exec's, once the document that bounds it is written.
func TestTheGrantsDevShellIsHandedBackNotPrepared(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	h.launched(ws, "m1", "trusted", `{"apps": {"nix": {"devShell": true}}}`)
	if h.given.DevShell != nil || h.log("bwrap.jsonl") != nil {
		t.Errorf("Launch realised a devShell: %+v", h.given.DevShell)
	}
}

// A recording realises the devShell as the tier's session would, and is
// never refused for it: a lock's hosts the session's allowlist does not
// hold are named, as what network.allow would admit.
func TestARecordingNamesTheLocksHostsAsCandidates(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	s := sessionConfig(h)
	s.Tiers["trusted"] = session.Tier{Nix: h.nixOf("granted", "frisket", "/etc/frisket/policies/trusted.json")}
	h.tracked(ws, map[string]string{
		"flake.nix": "{}",
		"flake.lock": `{"nodes":{"root":{"inputs":{"n":"n"}},"n":{"locked":{"narHash":"sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",` +
			`"owner":"NixOS","repo":"nixpkgs","rev":"0123456789abcdef0123456789abcdef01234567","type":"github"}}},"root":"root","version":7}`,
	})
	h.approved(ws, "m1", "trusted", `{"apps": {"nix": {"devShell": true}}}`)
	registry := grant.DefaultApps(h.cfg, &bytes.Buffer{})
	maps.Copy(registry, h.registry)
	var out, errb bytes.Buffer
	if rc := grant.ExecRecording(context.Background(), s, &h.cfg, registry, grant.Recording{Default: "allow", Base: "tier"}, "trusted", ws, "m1", "", []string{"shell"}, &out, &errb); rc != 0 {
		t.Fatalf("the recording was refused: %s", errb.String())
	}
	h.err = errb.String()
	h.mustSay("flake.lock fetches from names the session's allowlist does not hold: github.com: `network.allow` in its chase.jsonc admits them")
}
