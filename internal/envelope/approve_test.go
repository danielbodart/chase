package envelope_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// What seccompPolicy prints on stdout is the policy flong reads, and nothing
// else: the approved `allow` and `deny` lines. The approver's own output, and
// everything said, goes to stderr.
func TestStdoutIsTheSyscallLinesAlone(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	h.approved(ws, "m1", "trusted", `{"seccomp": {"allow": ["io_uring_setup", "io_uring_enter"], "deny": ["ptrace"]}, "bindings": {}}`)
	if h.out != "allow io_uring_setup io_uring_enter\ndeny ptrace\n" {
		t.Errorf("seccompPolicy printed %q", h.out)
	}
	if !strings.Contains(h.err, "the approver was asked about flake\n") || !strings.Contains(h.err, "the approver was asked about envelope\n") {
		t.Errorf("the approver's output did not go to stderr: %q", h.err)
	}
	// A seccomp section that loosens nothing is none, and prints nothing.
	h.approved(ws, "m2", "trusted", `{"seccomp": {"allow": [], "deny": []}, "bindings": {}}`)
	if h.out != "" {
		t.Errorf("an empty seccomp printed %q", h.out)
	}
	h.approved(ws, "m3", "trusted", `{"seccomp": {"deny": ["ptrace"]}, "bindings": {}}`)
	if h.out != "deny ptrace\n" {
		t.Errorf("a deny alone printed %q", h.out)
	}
}

// THE APPROVER PROTOCOL: {kind, workspace, diff} on stdin, as `jq -n` printed
// it, and the diffs diffutils' `diff -u` with the script's labels -- the
// flake's files with theirs, and the envelope as `jq -S .` of each side --
// byte for byte, since a person reads them.
func TestTheApproverIsShownWhatChanged(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	h.approved(ws, "m1", "trusted", `{"bindings": {}}`)
	asked := h.approvals("")
	if len(asked) != 2 || asked[0].Kind != "flake" || asked[1].Kind != "envelope" {
		t.Fatalf("the approver was asked %+v", asked)
	}
	if want := "--- approved/flake.nix\n+++ flake.nix\n@@ -0,0 +1 @@\n+" + flake; asked[0].Diff != want {
		t.Errorf("the flake's diff is %q, not %q", asked[0].Diff, want)
	}
	if want := "--- approved\n+++ proposed\n@@ -1 +1,3 @@\n-null\n+{\n+  \"bindings\": {}\n+}"; asked[1].Diff != want {
		t.Errorf("the envelope's diff is %q, not %q", asked[1].Diff, want)
	}
	stdin := read(t, h.dir+"/logs/approver.stdin")
	want := "{\n  \"kind\": \"envelope\",\n  \"workspace\": " + jqString(ws) + ",\n  \"diff\": " + jqString(asked[1].Diff) + "\n}\n"
	if stdin != want {
		t.Errorf("the approver was given %q, not %q", stdin, want)
	}
	if got := read(t, h.dir+"/state/approved/"+key(ws)+"/envelope.json"); got != "{\"bindings\":{}}\n" {
		t.Errorf("envelope.json is %q", got)
	}
	if got := read(t, h.dir+"/state/approved/"+key(ws)+"/flake.nix"); got != flake {
		t.Errorf("the approved flake.nix is %q", got)
	}

	// Unchanged, nothing is asked. A new lock and a changed envelope are:
	// the lock alone in the flake's diff, and the envelope's keys sorted.
	h.approved(ws, "m2", "trusted", `{"bindings": {}}`)
	if len(h.approvals("")) != 2 {
		t.Error("an unchanged checkout was asked about")
	}
	write(t, ws+"/flake.lock", "{\"nodes\": {\"root\": {}}, \"root\": \"root\", \"version\": 7}\n")
	h.fx.Run("-C", ws, "add", "flake.lock")
	h.approved(ws, "m3", "trusted", `{"bindings": {"github": {"allow": ["x"]}}, "seccomp": {"allow": ["ptrace"], "deny": []}}`)
	asked = h.approvals("")
	if len(asked) != 4 {
		t.Fatalf("the approver was asked %+v", asked)
	}
	if want := "--- approved/flake.lock\n+++ flake.lock\n@@ -0,0 +1 @@\n+{\"nodes\": {\"root\": {}}, \"root\": \"root\", \"version\": 7}\n"; asked[2].Diff != want {
		t.Errorf("the lock's diff is %q, not %q", asked[2].Diff, want)
	}
	want = "--- approved\n+++ proposed\n@@ -1,3 +1,15 @@\n {\n-  \"bindings\": {}\n+  \"bindings\": {\n+    \"github\": {\n+      \"allow\": [\n+        \"x\"\n+      ]\n+    }\n+  },\n+  \"seccomp\": {\n+    \"allow\": [\n+      \"ptrace\"\n+    ],\n+    \"deny\": []\n+  }\n }"
	if asked[3].Diff != want {
		t.Errorf("the envelope's diff is %q, not %q", asked[3].Diff, want)
	}
	// The envelope as it is written is in its own order, compact.
	if got := read(t, h.dir+"/state/approved/"+key(ws)+"/envelope.json"); got != `{"bindings":{"github":{"allow":["x"]}},"seccomp":{"allow":["ptrace"],"deny":[]}}`+"\n" {
		t.Errorf("envelope.json is %q", got)
	}

	// A changed flake.nix, and a lock gone.
	os.Remove(ws + "/flake.lock")
	h.fx.Run("-C", ws, "rm", "-q", "--cached", "flake.lock")
	write(t, ws+"/flake.nix", "{ outputs = _: { chaseModules.default = { chase.secrets = null; }; }; }\n")
	h.fx.Run("-C", ws, "add", "flake.nix")
	h.approved(ws, "m4", "trusted", `{"bindings": {"github": {"allow": ["x"]}}, "seccomp": {"allow": ["ptrace"], "deny": []}}`)
	asked = h.approvals("")
	want = "--- approved/flake.nix\n+++ flake.nix\n@@ -1 +1 @@\n-" + flake + "+{ outputs = _: { chaseModules.default = { chase.secrets = null; }; }; }\n" +
		"--- approved/flake.lock\n+++ flake.lock\n@@ -1 +0,0 @@\n-{\"nodes\": {\"root\": {}}, \"root\": \"root\", \"version\": 7}\n"
	if len(asked) != 5 || asked[4].Diff != want {
		t.Errorf("the flake's diff is %q, not %q", asked[4].Diff, want)
	}
	if _, err := os.Stat(h.dir + "/state/approved/" + key(ws) + "/flake.lock"); err == nil {
		t.Error("a lock gone from the checkout is still approved")
	}
}

func jqString(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// An envelope with a sops file and no Docker was written as jq wrote it
// without -c, and is still.
func TestAnEnvelopeIsWrittenAsTheScriptHeldIt(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws, "secrets.yaml")
	h.approved(ws, "m1", "trusted", `{"secrets": "secrets.yaml", "bindings": {}}`)
	got := read(t, h.dir+"/state/approved/"+key(ws)+"/envelope.json")
	want := "{\n  \"secrets\": \"secrets.yaml\",\n  \"bindings\": {},\n  \"secretsSHA256\": \"" + sha256Hex("the project's own\n") + "\"\n}\n"
	if got != want {
		t.Errorf("envelope.json is %q, not %q", got, want)
	}
	// And staged as the result it is, beside the sops file.
	d := h.stagedDoc("m1")
	if d["secrets"].(map[string]any)["name"] != "secrets.yaml" || d["result"].(map[string]any)["secretsSHA256"] != sha256Hex("the project's own\n") {
		t.Errorf("the stage is %v", d)
	}
}

// Nothing of the checkout's is evaluated until its flake is approved, and
// nothing is approved without an approver.
func TestNothingIsEvaluatedBeforeTheFlakeIsApproved(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	t.Setenv(refuseKind, "flake")
	if h.approve(ws, "m1", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("a refused flake was approved")
	}
	if h.err != "the approver was asked about flake\nchase: "+ws+": its flake was not approved\n" {
		t.Errorf("a refused flake said %q", h.err)
	}
	if h.log("nix.log") != nil {
		t.Error("a refused flake was evaluated")
	}
	if h.isStaged("m1") {
		t.Error("a refused flake was staged")
	}
	t.Setenv(refuseKind, "")
	h.cfg.Approver = ""
	if h.approve(ws, "m1", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("a flake was approved with no approver")
	}
	if h.err != "chase: "+ws+": its flake has changed, and there is no chase.approver to ask\n" {
		t.Errorf("no approver said %q", h.err)
	}

	// Approved, it is evaluated purely, with the snapshot as its one input.
	h.cfg.Approver = h.dir + "/bin/approver"
	h.approved(ws, "m1", "trusted", `{"bindings": {}}`)
	var args []string
	json.Unmarshal([]byte(h.log("nix.log")[0]), &args)
	snap := args[len(args)-1]
	want := []string{"eval", "--json", "--no-write-lock-file", "--option", "accept-flake-config", "false",
		"--option", "allow-import-from-derivation", "false", "--extra-experimental-features", "nix-command flakes",
		"path:" + h.cfg.Evaluator + "#envelope", "--override-input", "project", snap}
	if !slices.Equal(args, want) || !strings.HasPrefix(snap, "path:"+h.dir+"/home/.cache/chase/snapshot.") {
		t.Errorf("nix was run as %q", args)
	}
	if _, err := os.Stat(strings.TrimPrefix(snap, "path:")); err == nil {
		t.Error("the snapshot outlived the approval")
	}

	// What does not evaluate is refused, with nix's own words.
	t.Setenv(nixFails, "error: attribute 'chase' missing")
	if h.approve(ws, "m2", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("an envelope that does not evaluate was approved")
	}
	if h.err != "error: attribute 'chase' missing\nchase: "+ws+": its chaseModules.default does not evaluate\n" {
		t.Errorf("an envelope that does not evaluate said %q", h.err)
	}
}

// A flake that is not there, or does not say chaseModules, is the tier as it
// is: never evaluated or asked about, and staged as nothing.
func TestAFlakeWithoutChaseModulesIsTheTierAsItIs(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.repo(ws)
	h.approved(ws, "m1", "trusted", `{"bindings": {}}`)
	write(t, ws+"/flake.nix", "{ outputs = _: { }; }\n")
	h.approved(ws, "m2", "trusted", `{"bindings": {}}`)
	for _, m := range []string{"m1", "m2"} {
		if got := read(t, h.dir+"/run/chase/.envelope/"+m+".json"); got != "null\n" {
			t.Errorf("%s was staged as %q", m, got)
		}
	}
	if h.out != "" || h.log("nix.log") != nil || h.log("approvals.jsonl") != nil {
		t.Errorf("the tier as it is was evaluated or asked about: %q", h.out)
	}
	// A chase section of null is the same.
	h.flake(ws)
	h.approved(ws, "m3", "trusted", "null")
	if got := read(t, h.dir+"/run/chase/.envelope/m3.json"); got != "null\n" {
		t.Errorf("a null envelope was staged as %q", got)
	}
}

// Inputs that are files on this machine are refused: the lock names them,
// but what they hold is not in anything that was approved.
func TestALocalInputIsRefused(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	write(t, ws+"/flake.lock", `{"nodes": {
		"root": {"inputs": {"a": "a", "b": "b", "c": "c", "d": "d"}},
		"a": {"locked": {"type": "path", "path": "/home/user/x"}, "original": {"type": "path", "path": "/home/user/x"}},
		"b": {"locked": {"type": "git", "url": "git+file:///srv/y"}},
		"c": {"original": {"type": "github", "owner": "o", "repo": "r"}, "locked": {"type": "github", "owner": "o", "repo": "r", "parent": []}},
		"d": {"locked": {"type": "github", "owner": "o", "repo": "r"}}
	}, "root": "root", "version": 7}`)
	h.fx.Run("-C", ws, "add", "flake.lock")
	if h.approve(ws, "m1", "trusted", `{"bindings": {}}`) == 0 {
		t.Error("a flake with local inputs was approved")
	}
	want := "chase: " + ws + ": its flake has inputs that are files on this machine, which an envelope may not: input: /home/user/x\ninput: a relative path\ninput: git+file:///srv/y\n"
	if h.err != want {
		t.Errorf("local inputs said %q, not %q", h.err, want)
	}
	if h.log("approvals.jsonl") != nil {
		t.Error("a flake with local inputs was asked about")
	}
}

// One name in two of an app's lists says two things: refused before anyone
// is asked to approve it, each name once, in jq's order.
func TestANameInTwoListsIsRefused(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	env := `{"bindings": {
		"github": {"allow": ["y", "x", "x"], "ask": ["x"], "refuse": ["y", "z"]},
		"cloudflare": {"allow": [{"methods": ["GET"], "path": "/a"}], "ask": [{"path": "/a", "methods": ["GET"]}]}
	}}`
	if h.approve(ws, "m1", "trusted", env) == 0 {
		t.Error("a name in two lists was approved")
	}
	want := "chase: " + ws + `: named in two lists: github: "x"` + "\n" + `github: "y"` + "\n" + `cloudflare: {"methods":["GET"],"path":"/a"}` + "\n"
	if !strings.HasSuffix(h.err, want) {
		t.Errorf("two lists said %q, not %q", h.err, want)
	}
	if len(h.approvals("envelope")) != 0 {
		t.Error("a name in two lists was asked about")
	}
}

// What approve writes is the user's alone, and the caller's umask is theirs
// again once it returns.
func TestWhatIsApprovedIsTheUsersAlone(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	old := unix.Umask(0o022)
	defer unix.Umask(old)
	h.approved(ws, "m1", "trusted", `{"bindings": {}}`)
	for p, mode := range map[string]os.FileMode{
		"/run/chase/.envelope":                          0o700,
		"/run/chase/.envelope/m1.json":                  0o600,
		"/state/approved/" + key(ws):                    0o700,
		"/state/approved/" + key(ws) + "/flake.nix":     0o600,
		"/state/approved/" + key(ws) + "/envelope.json": 0o600,
		"/home/.cache/chase":                            0o700,
	} {
		if fi, err := os.Stat(h.dir + p); err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s is not %o: %v", p, mode, fi)
		}
	}
	if now := unix.Umask(0o022); now != 0o022 {
		t.Errorf("the umask was left %o", now)
	}
}

// What approve refuses before it looks at anything.
func TestWhatApproveNeedsFirst(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	for _, c := range []struct {
		args []string
		said string
	}{
		{[]string{"approve", ws}, "chase: no machine: flong names the session before seccompPolicy runs\n"},
		{[]string{"approve", ws, "m1"}, "chase: no tier: the tier's seccompPolicy names it\n"},
	} {
		if rc := h.run(c.args...); rc != 1 || h.err != c.said {
			t.Errorf("%q: %d %q", c.args, rc, h.err)
		}
	}
	h.cfg.Runtime = h.dir + "/nowhere"
	if rc := h.run("approve", ws, "m1", "trusted"); rc != 1 || h.err != "chase: "+h.dir+"/nowhere does not exist: log in first\n" {
		t.Errorf("no runtime directory: %d %q", rc, h.err)
	}
	if rc := h.run("bogus"); rc != 1 || !strings.HasPrefix(h.err, "chase: usage: chase-envelope env-dir WS | approve WS MACHINE TIER") {
		t.Errorf("an unknown subcommand: %d %q", rc, h.err)
	}
}

// env-dir makes and prints the checkout's environment directory; policy is
// the session's own document once its launch wrote one, and the tier's
// before.
func TestEnvDirAndPolicyArePaths(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	if h.run("env-dir", ws) != 0 || h.out != h.dir+"/state/env/"+key(ws)+"\n" {
		t.Errorf("env-dir printed %q: %s", h.out, h.err)
	}
	if fi, err := os.Stat(h.dir + "/state/env/" + key(ws)); err != nil || !fi.IsDir() {
		t.Error("env-dir did not make the directory")
	}
	if h.run("policy", "trusted", "m1") != 0 || h.out != h.dir+"/policies/trusted.json\n" {
		t.Errorf("policy before a launch printed %q", h.out)
	}
	h.launched(ws, "m1", "trusted", `{"bindings": {"probe": {"x": 1}}}`)
	if h.run("policy", "trusted", "m1") != 0 || h.out != h.dir+"/run/chase/m1/policy.json\n" {
		t.Errorf("policy after a launch printed %q", h.out)
	}
}

func sha256Hex(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}
