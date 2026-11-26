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
// else: the signed file's `allow` and `deny` lines. Everything said goes to
// stderr, and a signed file says nothing.
func TestStdoutIsTheSyscallLinesAlone(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	h.approved(ws, "m1", "trusted", `{"flong":{"seccomp":{"syscalls":{"io_uring_enter":"allow","io_uring_setup":"allow","ptrace":"deny"}}},"version":2}`)
	if h.out != "allow io_uring_enter io_uring_setup\ndeny ptrace\n" {
		t.Errorf("seccompPolicy printed %q", h.out)
	}
	if h.err != "" {
		t.Errorf("a signed file said %q", h.err)
	}
	// A seccomp section that loosens nothing is none, and prints nothing.
	h.approved(ws, "m2", "trusted", `{"version":2}`)
	if h.out != "" {
		t.Errorf("an empty seccomp printed %q", h.out)
	}
	h.approved(ws, "m3", "trusted", `{"flong":{"seccomp":{"syscalls":{"ptrace":"deny"}}},"version":2}`)
	if h.out != "deny ptrace\n" {
		t.Errorf("a deny alone printed %q", h.out)
	}
}

func jqString(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// A file with a sops file is signed with the file's digest, and staged as
// it is, beside the file. New ciphertext is refused until it is signed.
func TestTheSecretsDigestIsApproved(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws, "secrets.yaml")
	h.approved(ws, "m1", "trusted", `{"chase":{"secrets":"secrets.yaml"},"version":2}`)
	d := h.stagedDoc("m1")
	if digest, _ := walkAny(d, "file", "chase", "secretsSHA256"); d["secrets"].(map[string]any)["name"] != "secrets.yaml" || digest != sha256Hex("the project's own\n") {
		t.Errorf("the stage is %v", d)
	}
	// New ciphertext is a new digest, which the signed file does not say.
	write(t, ws+"/secrets.yaml", "rotated\n")
	if h.approve(ws, "m2", "trusted", "") == 0 {
		t.Error("a rotated secret was approved unsigned")
	}
	h.mustSay("secrets.yaml's digest is " + sha256Hex("rotated\n"))
	// A sops file that is not there is refused.
	if h.approve(ws, "m3", "trusted", `{"chase":{"secrets":"other.yaml"},"version":2}`) == 0 {
		t.Error("a missing sops file was approved")
	}
	h.mustSay("chase: " + ws + ": its tracked files could not be copied: other.yaml")
}

// A checkout with no chase.json is the tier as it is: never read or asked
// about, and staged as nothing.
func TestNoChaseJSONIsTheTierAsItIs(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.repo(ws)
	h.approved(ws, "m1", "trusted", "")
	if got := read(t, h.dir+"/run/chase/.grant/m1.json"); got != "null\n" {
		t.Errorf("m1 was staged as %q", got)
	}
	if h.out != "" || len(h.signer.Asked()) != 0 {
		t.Errorf("the tier as it is was asked about: %q %v", h.out, h.signer.Asked())
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
	h.approved(ws, "m1", "trusted", `{"version":2}`)
	for p, mode := range map[string]os.FileMode{
		"/run/chase/.grant":         0o700,
		"/run/chase/.grant/m1.json": 0o600,
		"/home/.cache/chase":        0o700,
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
		{[]string{"approve", ws}, "chase: no machine: flong names the session before approve runs\n"},
		{[]string{"approve", ws, "m1"}, "chase: no tier: the tier's approve hook names it\n"},
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
		if rc := h.run(gone); rc != 1 || h.err != "chase: usage: chase internal grant approve WS MACHINE TIER | project WS TIER | docker WS TIER\n" {
			t.Errorf("%s: %d %q", gone, rc, h.err)
		}
	}
}

func sha256Hex(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}
