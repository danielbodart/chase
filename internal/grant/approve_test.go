package grant_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
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
	h.approved(ws, "m1", "trusted", `{"seccomp": {"allow": ["io_uring_setup", "io_uring_enter"], "deny": ["ptrace"]}, "apps": {}}`)
	if h.out != "allow io_uring_setup io_uring_enter\ndeny ptrace\n" {
		t.Errorf("seccompPolicy printed %q", h.out)
	}
	if h.err != "the approver was asked\n" {
		t.Errorf("the approver's output did not go to stderr: %q", h.err)
	}
	// A seccomp section that loosens nothing is none, and prints nothing.
	h.approved(ws, "m2", "trusted", `{"seccomp": {"allow": [], "deny": []}, "apps": {}}`)
	if h.out != "" {
		t.Errorf("an empty seccomp printed %q", h.out)
	}
	h.approved(ws, "m3", "trusted", `{"seccomp": {"deny": ["ptrace"]}, "apps": {}}`)
	if h.out != "deny ptrace\n" {
		t.Errorf("a deny alone printed %q", h.out)
	}
}

// THE APPROVER PROTOCOL: {workspace, diff} on stdin, as `jq -n` printed it,
// and the diff diffutils' `diff -u` of the grant last approved against the
// one proposed, each as `jq -S .` prints it, byte for byte, since a person
// reads it. One question for any change, and none for a change that says
// nothing new: a comment, the order things are given in.
func TestTheApproverIsShownWhatChanged(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	h.approved(ws, "m1", "trusted", "{}")
	asked := h.approvals()
	if len(asked) != 1 {
		t.Fatalf("the approver was asked %+v", asked)
	}
	if want := "--- approved\n+++ proposed\n@@ -1 +1,3 @@\n-null\n+{\n+  \"apps\": {}\n+}"; asked[0].Diff != want {
		t.Errorf("the grant's diff is %q, not %q", asked[0].Diff, want)
	}
	stdin := read(t, h.dir+"/logs/approver.stdin")
	want := "{\n  \"workspace\": " + jqString(ws) + ",\n  \"diff\": " + jqString(asked[0].Diff) + "\n}\n"
	if stdin != want {
		t.Errorf("the approver was given %q, not %q", stdin, want)
	}
	if got := read(t, h.dir+"/state/approved/"+key(ws)+"/grant.json"); got != "{\n  \"apps\": {}\n}\n" {
		t.Errorf("grant.json is %q", got)
	}

	// Unchanged, nothing is asked; nor with only a comment, a trailing
	// comma, or the order changed.
	h.approved(ws, "m2", "trusted", "// the project's own words\n{\"apps\": {},}\n")
	h.approved(ws, "m3", "trusted", `{"seccomp": {"allow": ["ptrace"]}, "apps": {"github": {"allow": ["x"]}}}`)
	h.approved(ws, "m4", "trusted", `{"apps": {"github": {"allow": ["x"] /* often */}}, "seccomp": {"allow": ["ptrace"], "deny": []}}`)
	asked = h.approvals()
	if len(asked) != 2 {
		t.Fatalf("the approver was asked %+v", asked)
	}
	want = "--- approved\n+++ proposed\n@@ -1,3 +1,14 @@\n {\n-  \"apps\": {}\n+  \"apps\": {\n+    \"github\": {\n+      \"allow\": [\n+        \"x\"\n+      ]\n+    }\n+  },\n+  \"seccomp\": {\n+    \"allow\": [\n+      \"ptrace\"\n+    ]\n+  }\n }"
	if asked[1].Diff != want {
		t.Errorf("the grant's diff is %q, not %q", asked[1].Diff, want)
	}
}

func jqString(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// A grant with a sops file is approved with the file's digest, and staged
// as the result it is, beside the file.
func TestTheSecretsDigestIsApproved(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws, "secrets.yaml")
	h.approved(ws, "m1", "trusted", `{"secrets": "secrets.yaml"}`)
	got := read(t, h.dir+"/state/approved/"+key(ws)+"/grant.json")
	want := "{\n  \"secrets\": \"secrets.yaml\",\n  \"apps\": {},\n  \"secretsSHA256\": \"" + sha256Hex("the project's own\n") + "\"\n}\n"
	if got != want {
		t.Errorf("grant.json is %q, not %q", got, want)
	}
	d := h.stagedDoc("m1")
	if d["secrets"].(map[string]any)["name"] != "secrets.yaml" || d["result"].(map[string]any)["secretsSHA256"] != sha256Hex("the project's own\n") {
		t.Errorf("the stage is %v", d)
	}
	// New ciphertext is a new digest, and asked about.
	write(t, ws+"/secrets.yaml", "rotated\n")
	h.approved(ws, "m2", "trusted", "")
	if asked := h.approvals(); len(asked) != 2 || !strings.Contains(asked[1].Diff, "+  \"secretsSHA256\": \""+sha256Hex("rotated\n")) {
		t.Errorf("a rotated secret was asked about as %+v", asked)
	}
	// A sops file that is not tracked is refused.
	h.approve(ws, "m3", "trusted", `{"secrets": "other.yaml"}`)
	if !h.said("chase: " + ws + ": other.yaml is not a tracked file") {
		t.Errorf("an untracked sops file said %q", h.err)
	}
}

// Nothing is approved without an approver, or when the approver refuses,
// and nothing is staged either way.
func TestARefusedGrantIsNotStaged(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	t.Setenv(refuseAll, "1")
	if h.approve(ws, "m1", "trusted", "{}") == 0 {
		t.Error("a refused grant was approved")
	}
	if h.err != "the approver was asked\nchase: "+ws+": its grant was not approved\n" {
		t.Errorf("a refused grant said %q", h.err)
	}
	if h.isStaged("m1") {
		t.Error("a refused grant was staged")
	}
	t.Setenv(refuseAll, "")
	h.cfg.Approver = ""
	if h.approve(ws, "m1", "trusted", "{}") == 0 {
		t.Error("a grant was approved with no approver")
	}
	if h.err != "chase: "+ws+": its grant has changed, and there is no chase.approver to ask\n" {
		t.Errorf("no approver said %q", h.err)
	}
}

// A checkout with no chase.jsonc is the tier as it is: never read or asked
// about, and staged as nothing. One that has it untracked is refused, not
// passed over: a grant that silently did not apply would be a session
// without what the project asked for.
func TestNoChaseJsoncIsTheTierAsItIs(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.repo(ws)
	h.approved(ws, "m1", "trusted", "")
	if got := read(t, h.dir+"/run/chase/.grant/m1.json"); got != "null\n" {
		t.Errorf("m1 was staged as %q", got)
	}
	if h.out != "" || h.log("approvals.jsonl") != nil {
		t.Errorf("the tier as it is was asked about: %q", h.out)
	}
	write(t, ws+"/chase.jsonc", "{}")
	if h.approve(ws, "m2", "trusted", "") == 0 {
		t.Error("an untracked chase.jsonc was approved")
	}
	if !h.said("chase: " + ws + ": chase.jsonc is not a tracked file: what a grant says is what git tracks") {
		t.Errorf("an untracked chase.jsonc said %q", h.err)
	}
}

// WHAT A GRANT MAY SAY: anything else refuses the launch, before anyone is
// asked, saying what and where.
func TestWhatAGrantMayNotSayIsRefused(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	for _, c := range []struct{ grant, said string }{
		{`{"apps": {}, "secret": "x"}`, `json: unknown field "secret"`},
		{`{"apps": {"github": {"allow": ["x"], "alow": []}}}`, `json: unknown field "alow"`},
		{`{"apps": {"slack": {}}}`, `json: unknown field "slack"`},
		{`{"bindings": {"github": {}}}`, `bindings is now apps`},
		{`{"apps": {}, "apps": {"github": {}}}`, `apps is given twice`},
		{`{"apps": {"github": {"allow": ["x"], "allow": ["y"]}}}`, `apps.github.allow is given twice`},
		{`{"apps": {}} {}`, `hujson: line 1, column 14: invalid character '{' after top-level value`},
		{`[]`, `json: cannot unmarshal array into Go value of type grant.File`},
		{`{"secrets": "/etc/secrets.yaml"}`, `secrets: "/etc/secrets.yaml" is not relative to the checkout`},
		{`{"seccomp": {"allow": ["IO URING"]}}`, `seccomp.allow: "IO URING" is not a syscall's name or an @group's`},
		{`{"apps": {"cloudflare": {"accountId": "nope"}}}`, `apps.cloudflare.accountId: "nope" is not 32 lower-case hex digits`},
		{`{"apps": {"cloudflare": {"credential": {"secret": "a/b"}}}}`, `apps.cloudflare.credential.secret: "a/b" is not a key in the sops file`},
		{`{"apps": {"github": {"ask": ["has space"]}}}`, `apps.github.ask: "has space" is not an operation id or a category:<name>`},
		{`{"apps": {"git": {"allow": [{"methods": [], "path": "/x"}]}}}`, `apps.git.allow: /x names no methods`},
		{`{"apps": {"git": {"allow": [{"methods": ["TRACE"], "path": "/x"}]}}}`, `apps.git.allow: "TRACE" is not one of GET, HEAD, POST, PUT, PATCH, DELETE`},
		{`{"apps": {"git": {"allow": [{"methods": ["GET"], "path": "x"}]}}}`, `apps.git.allow: "x" is not a path`},
		{`{"apps": {"git": {"allow": [{"methods": ["GET"], "path": "/x", "host": "y"}]}}}`, `json: unknown field "host"`},
		{`{"apps": {"gcloud": {"serviceAccount": "nobody"}}}`, `apps.gcloud.serviceAccount: "nobody" is not an account's email`},
		{`{"apps": {"gcloud": {"apis": {"add": ["a.b"]}}}}`, `apps.gcloud.apis.add: "a.b" is not a Discovery name`},
		{`{"apps": {"docker": {"ports": [80]}}}`, `apps.docker.ports: 80 is not a port from 1024 to 65535`},
		{`{"apps": {"docker": {"ports": [5432, 5432]}}}`, `apps.docker.ports: 5432 is named twice`},
		{`{"apps": {"docker": {"ports": [15001]}}}`, `apps.docker.ports: 15001 is frisket's own steering listener`},
		{`{"apps": {"docker": {"ports": [5432.5]}}}`, `json: cannot unmarshal number 5432.5 into Go struct field Docker.apps.docker.ports of type int`},
		{`{"apps": {"docker": {"images": ["postgres"]}}}`, `apps.docker.images: postgres is not a familiar name with a :tag or @sha256:<64 hex>`},
	} {
		if h.approve(ws, "m1", "trusted", c.grant) == 0 {
			t.Errorf("%s was approved", c.grant)
			continue
		}
		if want := "chase: " + ws + ": chase.jsonc: " + c.said + "\n"; h.err != want {
			t.Errorf("%s said %q, not %q", c.grant, h.err, want)
		}
	}
	if h.log("approvals.jsonl") != nil {
		t.Error("a grant that may not be was asked about")
	}
	if h.isStaged("m1") {
		t.Error("a grant that may not be was staged")
	}
}

// One name in two of an app's lists says two things: refused before anyone
// is asked to approve it, each name once, the apps in the order of their
// names.
func TestANameInTwoListsIsRefused(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	env := `{"apps": {
		"github": {"allow": ["y", "x", "x"], "ask": ["x"], "refuse": ["y", "z"]},
		"cloudflare": {"allow": [{"methods": ["GET"], "path": "/a"}], "ask": [{"path": "/a", "methods": ["GET"]}]}
	}}`
	if h.approve(ws, "m1", "trusted", env) == 0 {
		t.Error("a name in two lists was approved")
	}
	want := "chase: " + ws + `: named in two lists: cloudflare: {"methods":["GET"],"path":"/a"}` + "\n" + `github: "x"` + "\n" + `github: "y"` + "\n"
	if !strings.HasSuffix(h.err, want) {
		t.Errorf("two lists said %q, not %q", h.err, want)
	}
	if len(h.approvals()) != 0 {
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
	h.approved(ws, "m1", "trusted", `{"apps": {}}`)
	for p, mode := range map[string]os.FileMode{
		"/run/chase/.grant":                          0o700,
		"/run/chase/.grant/m1.json":                  0o600,
		"/state/approved/" + key(ws):                 0o700,
		"/state/approved/" + key(ws) + "/grant.json": 0o600,
		"/home/.cache/chase":                         0o700,
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
	// The launch, and the steps that went with the env file and frisket's
	// policy word, are no subcommands.
	for _, gone := range []string{"bogus", "launch", "env-dir", "policy"} {
		if rc := h.run(gone); rc != 1 || h.err != "chase: usage: chase grant approve WS MACHINE TIER | project WS TIER | docker WS TIER\n" {
			t.Errorf("%s: %d %q", gone, rc, h.err)
		}
	}
}

func sha256Hex(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}
