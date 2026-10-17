package grant_test

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/quoin/projpolicy"

	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/grant/signertest"
)

// v2 is a harness whose checkouts are signed by a stand-in signer.
func v2(t *testing.T) (*harness, *signertest.Signer) {
	t.Helper()
	h := newHarness(t)
	s := signertest.New(t, h.cfg.Home)
	h.cfg.AllowedSigners, h.cfg.SignerAgent = s.AllowedSigners, s.Socket
	write(t, h.cfg.Policies+"/trusted.json", tierDoc("trusted", "github.com"))
	return h, s
}

// canonical is v as chase.json is written.
func canonical(t *testing.T, v string) string {
	t.Helper()
	b, err := projpolicy.Format([]byte(v))
	if err != nil {
		t.Fatalf("%s: %v", v, err)
	}
	return string(b)
}

// project is a checkout at ws with chase.json saying file, signed when
// signed.
func (h *harness) project(s *signertest.Signer, ws, file string, signed bool) {
	h.t.Helper()
	if _, err := os.Stat(ws + "/.git"); err != nil {
		h.checkout(ws)
	}
	write(h.t, ws+"/chase.json", file)
	os.Remove(ws + "/chase.json.sig")
	if signed {
		root, err := grant.Root(ws)
		if err != nil {
			h.t.Fatal(err)
		}
		write(h.t, ws+"/chase.json.sig", string(s.Sign(h.t, root, []byte(file))))
	}
}

// A CHASE.JSON SIGNED as it is launches with nothing asked: neither the
// signer nor the approver, and nothing kept in chase's state.
func TestASignedFileLaunchesUnasked(t *testing.T) {
	h, s := v2(t)
	ws := h.root() + "/w"
	file := canonical(t, `{"version": 2, "flong": {"seccomp": {"syscalls": {"ptrace": "allow", "keyctl": "deny", "userfaultfd": "log"}, "allow": ["@keyring"]}}, "frisket": {"allow": {"pypi.org": true}}}`)
	h.project(s, ws, file, true)
	h.approved(ws, "m1", "trusted", "")
	if len(s.Asked()) != 0 || len(h.approvals()) != 0 {
		t.Errorf("a signed file was asked about: %v %v", s.Asked(), h.approvals())
	}
	if h.out != "allow @keyring ptrace\ndeny keyctl\nlog userfaultfd\n" {
		t.Errorf("seccompPolicy printed %q", h.out)
	}
	if h.migrate || strings.Contains(h.err, "migrate") {
		t.Errorf("a chase.json was told to migrate: %s", h.err)
	}
	if _, err := os.Stat(h.dir + "/state/approved"); err == nil {
		t.Error("a signed file was kept in chase's state")
	}
	if h.launch("trusted", ws, "m1") != 0 {
		t.Fatalf("m1 was not launched: %s", h.err)
	}
	if d := h.policyV2("m1"); !reflect.DeepEqual(d.Allow, map[string]bool{"github.com": true, "pypi.org": true}) {
		t.Errorf("the file's names were not merged: %v", d.Allow)
	}
	frisketCheck(t, h.dir+"/run/chase/m1/policy.json")

	// Signed for another directory, or with its bytes changed after, it
	// does not verify, and is put to the signer.
	other := h.root() + "/other"
	h.project(s, other, file, false)
	root, _ := grant.Root(other)
	write(t, ws+"/chase.json.sig", string(s.Sign(t, root, []byte(file))))
	h.approved(ws, "m2", "trusted", "")
	if len(s.Asked()) != 1 {
		t.Errorf("another directory's signature was taken: %v", s.Asked())
	}
}

// AN UNSIGNED CHASE.JSON is put to the signer, as `quoin policy sign`
// puts one: against what git's HEAD signed, when that verifies, else
// against nothing. Its signature is written beside it, and the launch goes
// on; refused, the launch ends, and nothing is staged.
func TestAnUnsignedFileIsPutToTheSigner(t *testing.T) {
	h, s := v2(t)
	ws := h.root() + "/w"
	first := canonical(t, `{"version": 2, "frisket": {"allow": {"pypi.org": true}}}`)
	h.project(s, ws, first, false)
	h.approved(ws, "m1", "trusted", "")
	asked := s.Asked()
	root, _ := grant.Root(ws)
	if len(asked) != 1 || asked[0].Root != root || asked[0].Name != "chase.json" || string(asked[0].New) != first || asked[0].Old != nil || asked[0].OldSig != nil {
		t.Fatalf("the signer was asked %+v", asked)
	}
	h.mustSay("chase.json is not signed")
	sig, err := os.ReadFile(ws + "/chase.json.sig")
	if err != nil {
		t.Fatal(err)
	}
	if !h.isStaged("m1") || h.launch("trusted", ws, "m1") != 0 {
		t.Fatalf("a file signed at launch was not launched: %s", h.err)
	}

	// Committed, signed, and widened: the signer is shown HEAD's.
	h.fx.Run("-C", ws, "add", "chase.json", "chase.json.sig")
	h.fx.Run("-C", ws, "-c", "user.name=a", "-c", "user.email=a@example.com", "commit", "-qm", "signed")
	second := canonical(t, `{"version": 2, "frisket": {"allow": {"pypi.org": true, "files.pythonhosted.org": true}}}`)
	write(t, ws+"/chase.json", second)
	h.approved(ws, "m2", "trusted", "")
	asked = s.Asked()
	if len(asked) != 2 || string(asked[1].Old) != first || !bytes.Equal(asked[1].OldSig, sig) || string(asked[1].New) != second {
		t.Errorf("the signer was not shown HEAD's: %+v", asked[1])
	}

	// Refused, nothing is staged, and the launch ends.
	s.Refuse(true)
	write(t, ws+"/chase.json", canonical(t, `{"version": 2}`))
	if h.approve(ws, "m3", "trusted", "") == 0 {
		t.Error("a refused signature was approved")
	}
	h.mustSay("chase.json was not signed: the signer: refused")
	if h.isStaged("m3") {
		t.Error("a refused file was staged")
	}
	s.Refuse(false)

	// A signer that fails rather than refuses is still named as the one
	// that failed, though quoin's client returns its failure bare.
	s.Fail(true)
	if h.approve(ws, "m3f", "trusted", "") == 0 {
		t.Error("a failed signature was approved")
	}
	h.mustSay("chase.json was not signed: the signer: agent: generic extension failure")
	s.Fail(false)

	// A file not in its canonical form is not put to anyone.
	write(t, ws+"/chase.json", `{"version":2}`)
	n := len(s.Asked())
	if h.approve(ws, "m4", "trusted", "") == 0 {
		t.Error("a file not canonical was approved unsigned")
	}
	h.mustSay("not in its canonical form to be: run chase sign")
	if len(s.Asked()) != n {
		t.Error("a file not canonical was put to the signer")
	}

	// No signer at all is a refusal too.
	h.cfg.SignerAgent = h.dir + "/no-such-socket"
	write(t, ws+"/chase.json", canonical(t, `{"version": 2, "chase": {"apps": {"nix": {"devShell": true}}}}`))
	if h.approve(ws, "m5", "trusted", "") == 0 {
		t.Error("a file was approved with no signer to sign it")
	}
}

// WHAT THE FILE MUST SAY OF THE CHECKOUT, which its signature covers: the
// digest of its sops file, and the Docker project its origin names. A
// file saying other than the checkout does is refused, whoever signed it.
func TestWhatTheFileSaysOfTheCheckoutIsHeldToIt(t *testing.T) {
	h, s := v2(t)
	r := h.root()
	h.cfg.Checkouts["example/shop"] = []string{r + "/p/shop"}
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:Example/Shop.git")
	write(t, ws+"/secrets.yaml", "ciphertext\n")
	digest := sha256Hex("ciphertext\n")
	file := func(secret, project string) string {
		return canonical(t, `{"version": 2, "chase": {"secrets": "secrets.yaml", "secretsSHA256": "`+secret+`", "apps": {"docker": {"project": "`+project+`", "images": {"postgres:18": true}}}}}`)
	}
	h.project(s, ws, file(digest, "example/shop"), true)
	h.approved(ws, "m1", "trusted", "")
	if got := h.stagedProject("m1"); got != "example/shop" {
		t.Errorf("the project staged is %v", got)
	}
	h.mustSay("Docker as example/shop at 127.101.170.171")

	h.project(s, ws, file(sha256Hex("old\n"), "example/shop"), true)
	if h.approve(ws, "m2", "trusted", "") == 0 {
		t.Error("a sops file of another digest was approved")
	}
	h.mustSay("secrets.yaml's digest is " + digest + ", and chase.json says " + sha256Hex("old\n") + ": chase sign writes the new one")

	h.project(s, ws, file(digest, "example/other"), true)
	if h.approve(ws, "m3", "trusted", "") == 0 {
		t.Error("another project was approved")
	}
	h.mustSay("its origin names the project example/shop, and chase.json's apps.docker.project says example/other")
	if len(s.Asked()) != 0 {
		t.Errorf("a file at odds with its checkout was put to the signer: %v", s.Asked())
	}
}

// `chase sign` writes what is derived of the checkout, puts the file in
// its canonical form, and has it signed; signed already, it asks nothing.
func TestSignWritesWhatIsDerivedAndSigns(t *testing.T) {
	h, s := v2(t)
	r := h.root()
	h.cfg.Checkouts["example/shop"] = []string{r + "/p/shop"}
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:example/shop.git")
	write(t, ws+"/secrets.yaml", "ciphertext\n")
	write(t, ws+"/chase.json", `{"version": 2, "chase": {"secrets": "secrets.yaml", "secretsSHA256": "`+sha256Hex("old\n")+`", "apps": {"docker": {"images": {"postgres:18": true}}}}}`)
	var out, errb bytes.Buffer
	if err := grant.SignCommand(context.Background(), h.cfg, []string{ws}, &out, &errb); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	want := canonical(t, `{"version": 2, "chase": {"secrets": "secrets.yaml", "secretsSHA256": "`+sha256Hex("ciphertext\n")+`", "apps": {"docker": {"project": "example/shop", "images": {"postgres:18": true}}}}}`)
	if got := read(t, ws+"/chase.json"); got != want {
		t.Errorf("chase.json is\n%s\nnot\n%s", got, want)
	}
	for _, said := range []string{"chase.secretsSHA256: secrets.yaml's digest", "chase.apps.docker.project: example/shop"} {
		if !strings.Contains(errb.String(), said) {
			t.Errorf("sign did not say %q: %s", said, errb.String())
		}
	}
	if !strings.Contains(out.String(), "signed, chase.json.sig written") || len(s.Asked()) != 1 {
		t.Errorf("sign said %s, asking %d", out.String(), len(s.Asked()))
	}
	h.approved(ws, "m1", "trusted", "")
	if len(s.Asked()) != 1 {
		t.Error("a file chase sign signed was asked about at launch")
	}
	out.Reset()
	if err := grant.SignCommand(context.Background(), h.cfg, []string{ws + "/chase.json"}, &out, &errb); err != nil || !strings.Contains(out.String(), "signed already") || len(s.Asked()) != 1 {
		t.Errorf("a second sign: %v %s", err, out.String())
	}
}

// THE FRISKET SECTION is a layer of the session's document, merged over
// the tier's and its apps' by frisket's own project-layer check: what it
// answers applies, an operation the route has not, or a host's field, ends
// the launch, and what is the host's is refused before anyone is asked.
func TestTheFrisketSectionIsMergedOverTheTier(t *testing.T) {
	h, s := v2(t)
	write(t, h.cfg.Policies+"/trusted.json", `{"version": 2, "name": "trusted", "allow": {"api.github.com": true}, "routes": {"github": {
		"host": "api.github.com", "upstream": "https://api.github.com", "credentialFile": "/run/secrets/gh", "placeholder": "proxy-injected",
		"writes": "ask", "guarded": "refuse", "unmatched": "ask",
		"paths": {"POST /repos/*/*/pulls": {"operation": {"id": "pulls/create", "summary": "Create a pull request", "class": "write", "category": "pulls"}},
		          "DELETE /repos/*/*": {"operation": {"id": "repos/delete", "summary": "Delete a repository", "class": "guarded", "category": "repos"}}}}}}`)
	ws := h.root() + "/w"
	h.project(s, ws, canonical(t, `{"version": 2, "frisket": {"routes": {"github": {"operations": {"pulls/create": "allow", "POST /repos/me/*/dispatches": "allow"}}, "claude": {"operations": {"GET /**": "allow"}}}}}`), true)
	h.launched(ws, "m1", "trusted", "")
	gh := h.policyV2("m1").Routes["github"]
	if !maps.Equal(gh.Operations, map[string]string{"pulls/create": "allow", "POST /repos/me/*/dispatches": "allow"}) || gh.CredentialFile != "/run/secrets/gh" {
		t.Errorf("the project's answers were not merged: %+v", gh)
	}
	if answerOf(gh, "pulls/create") != "allow" || answerOf(gh, "repos/delete") != "refuse" {
		t.Errorf("pulls/create is %s, repos/delete %s", answerOf(gh, "pulls/create"), answerOf(gh, "repos/delete"))
	}
	h.mustSay("frisket.routes.claude ignored: a project answers none of claude's requests")
	frisketCheck(t, h.dir+"/run/chase/m1/policy.json")

	// An operation the route does not have.
	h.project(s, ws, canonical(t, `{"version": 2, "frisket": {"routes": {"github": {"operations": {"pulls/merge": "allow"}}}}}`), true)
	h.approved(ws, "m2", "trusted", "")
	if h.launch("trusted", ws, "m2") == 0 {
		t.Error("an operation the route has not was launched")
	}
	h.mustSay("its frisket section does not apply in trusted")

	// What only the host says is refused before anyone is asked.
	for _, bad := range []string{
		`{"version": 2, "frisket": {"routes": {"github": {"host": "evil.example"}}}}`,
		`{"version": 2, "frisket": {"routes": {"github": {"ceiling": {"writes": "allow"}}}}}`,
		`{"version": 2, "frisket": {"writes": "allow"}}`,
		`{"version": 2, "frisket": {"allow": {"**": true}}}`,
	} {
		h.project(s, ws, canonical(t, bad), false)
		if h.approve(ws, "m3", "trusted", "") == 0 {
			t.Errorf("%s was approved", bad)
		}
	}
	if n := len(s.Asked()); n != 0 {
		t.Errorf("what a project may not say was put to the signer %d times", n)
	}
}

// What a chase.json may not say, refused when it is read.
func TestWhatAChaseJSONMayNotSayIsRefused(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl server"
	good := `{"version": 2,
		"frisket": {"allow": {"pypi.org": true, "**.pythonhosted.org": true, "old.example": null}, "lan": {"nas.lan": {"ports": [445]}},
		            "routes": {"github": {"operations": {"pulls/create": "allow", "repos/delete": null}, "writes": "ask"}}, "ssh": {"*-ap": {"exec": {"uci show **": "allow"}}}},
		"flong": {"seccomp": {"syscalls": {"ptrace": "allow", "keyctl": "deny"}, "allow": ["@keyring"], "deny": ["@swap"]}},
		"signer": {"ssh": {"hosts": {"gateway": "allow", "*.example": null}}, "sshsig": {"git": "allow"}},
		"sudo": {"exec": {"/run/current-system/sw/bin/systemctl restart foo.service": {"runAs": "root", "answer": "allow"}}},
		"chase": {"secrets": "secrets.yaml", "secretsSHA256": "` + strings.Repeat("a", 64) + `",
		          "apps": {"cloudflare": {"accountId": "023e105f4ecef8ad9ca31a8372d0c353", "credential": {"secret": "cf"}},
		                   "docker": {"project": "owner/repo", "images": {"postgres:18": true}, "ports": {"5432": true}},
		                   "gcloud": {"apis": {"pubsub": true, "storage": false}, "serviceAccount": "a@p.iam.gserviceaccount.com", "credential": {"secret": "g"}},
		                   "nix": {"devShell": true},
		                   "ssh": {"hosts": {"server": {"address": "192.168.1.10", "user": "ops", "hostKeys": ["` + key + `"], "allow": ["service-restart"]}}}}}}`
	if _, _, err := grant.ParseDoc([]byte(good)); err != nil {
		t.Fatalf("a whole file was refused: %v", err)
	}
	for _, c := range []struct{ file, said string }{
		{`{}`, `"version": 2`},
		{`{"version": 1}`, `"version": 2`},
		{`{"version": 2, "grant": {}}`, `unknown field "grant"`},
		{`{"version": 2, "version": 2}`, `key "version" twice`},
		{`{"version": 2, "frisket": {"version": 2}}`, "frisket.version"},
		{`{"version": 2, "frisket": {"routes": {"github": {"upstream": "https://x"}}}}`, "frisket.routes.github.upstream: the host's alone"},
		{`{"version": 2, "frisket": {"routes": {"github": {"paths": {}}}}}`, "frisket.routes.github.paths: the host's alone"},
		{`{"version": 2, "frisket": {"record": {}}}`, "frisket.record: the host's alone"},
		{`{"version": 2, "frisket": {"nope": true}}`, "frisket.nope: no such field"},
		{`{"version": 2, "frisket": {"unmatched": "allow"}}`, "routes.<name>.unmatched"},
		{`{"version": 2, "frisket": {"allow": {"**": true}}}`, "every name"},
		{`{"version": 2, "frisket": {"allow": {"**.com": true}}}`, "public suffix"},
		{`{"version": 2, "frisket": {"allow": {"*.co.uk": true}}}`, "public suffix"},
		{`{"version": 2, "frisket": {"lan": {"*.lan": {}}}}`, "never a wildcard"},
		{`{"version": 2, "frisket": {"lan": {"shop.example.internal": {}}}}`, "a project's name"},
		{`{"version": 2, "flong": {"limits": {}}}`, `unknown field "limits"`},
		{`{"version": 2, "flong": {"seccomp": {"allow": ["ptrace"]}}}`, `seccomp.syscalls names: {"ptrace": "allow"}`},
		{`{"version": 2, "flong": {"seccomp": {"syscalls": {"@debug": "allow"}}}}`, "is not a call's name"},
		{`{"version": 2, "flong": {"seccomp": {"syscalls": {"ptrace": "maybe"}}}}`, "not allow, deny or log"},
		{`{"version": 2, "flong": {"seccomp": {"syscalls": {"ptrace": null}}}}`, "flong.seccomp.syscalls.ptrace is null"},
		{`{"version": 2, "signer": {"sshsig": {"quoin-policy:~": "allow"}}}`, "not a namespace a rule may name"},
		{`{"version": 2, "signer": {"ssh": {"hosts": {"gateway": "refuse"}}}}`, "not allow or ask"},
		{`{"version": 2, "signer": {"user": "dan"}}`, `unknown key "user"`},
		// Keys are matched exactly, case included, as the programs that read
		// a section look it up: encoding/json alone would take "Signer" for
		// signer, and chase would check a section nobody applies.
		{`{"version": 2, "Signer": {"sshsig": {"git": "allow"}}}`, `Signer: no such key, though "signer" is`},
		{`{"version": 2, "SUDO": {}}`, `SUDO: no such key, though "sudo" is`},
		{`{"version": 2, "Frisket": {}}`, `Frisket: no such key, though "frisket" is`},
		{`{"version": 2, "Version": 2}`, `Version: no such key, though "version" is`},
		{`{"version": 2, "sudo": {"Exec": {}}}`, `sudo.Exec: no such key, though "sudo.exec" is`},
		{`{"version": 2, "flong": {"Seccomp": {}}}`, `flong.Seccomp: no such key, though "flong.seccomp" is`},
		{`{"version": 2, "chase": {"apps": {"Docker": {}}}}`, `chase.apps.Docker: no such key, though "chase.apps.docker" is`},
		{`{"version": 2, "chase": {"apps": {"ssh": {"hosts": {"server": {"Address": "192.168.1.10"}}}}}}`, `chase.apps.ssh.hosts.server.Address: no such key`},
		{`{"version": 2, "signer": {"SSH": {"hosts": {"gateway": "allow"}}}}`, `signer: unknown key "SSH"`},
		{`{"version": 2, "signer": {"ssh": {"Hosts": {"gateway": "allow"}}}}`, `signer: ssh: unknown key "Hosts"`},
		{`{"version": 2, "signer": {"sshSig": {"git": "allow"}}}`, `signer: unknown key "sshSig"`},
		{`{"version": 2, "sudo": {"exec": {"systemctl": {"runAs": "root", "answer": "allow"}}}}`, "absolute, clean path"},
		{`{"version": 2, "sudo": {"exec": {"/run/current-system/sw/bin/systemctl": {"answer": "allow"}}}}`, "says whom it runs as"},
		{`{"version": 2, "sudo": {"exec": {"/run/current-system/sw/bin/systemctl": {"runAs": "Root!", "answer": "allow"}}}}`, "is not a user's name"},
		{`{"version": 2, "sudo": {"exec": {"/run/current-system/sw/bin/systemctl": {"runAs": "root", "answer": "maybe"}}}}`, "not allow, ask or refuse"},
		{`{"version": 2, "sudo": {"exec": {"/run/current-system/sw/bin/cat ** [arg shadow]": {"runAs": "root", "answer": "allow"}}}}`, "only asks or refuses"},
		{`{"version": 2, "sudo": {"exec": {"/run/current-system/sw/bin/systemctl ** status": {"runAs": "root", "answer": "allow"}}}}`, "only the last word"},
		{`{"version": 2, "chase": {"secrets": "s.yaml"}}`, "give both or neither"},
		{`{"version": 2, "chase": {"secrets": "/etc/shadow", "secretsSHA256": "` + strings.Repeat("a", 64) + `"}}`, "not relative to the checkout"},
		{`{"version": 2, "chase": {"apps": {"docker": {"images": {"docker.io/library/postgres:18": true}}}}}`, "spells out Docker Hub"},
		{`{"version": 2, "chase": {"apps": {"docker": {"images": {"postgres:18": false}}}}}`, "listed with true"},
		{`{"version": 2, "chase": {"apps": {"docker": {"ports": {"80": true}}}}}`, "1024 to 65535"},
		{`{"version": 2, "chase": {"apps": {"docker": {"ports": {"http": true}}}}}`, "not a port's number"},
		{`{"version": 2, "chase": {"apps": {"docker": {"project": "Owner/Repo"}}}}`, "lower-cased"},
		{`{"version": 2, "chase": {"apps": {"github": {}}}}`, `unknown field "github"`},
		{`{"version": 2, "chase": {"apps": {"ssh": {"hosts": {"server": {"address": "server.lan", "user": "ops", "hostKeys": ["` + key + `"]}}}}}}`, "a literal IP"},
		{`{"version": 2, "chase": null}`, "chase is null"},
		{`{"version": 2, "frisket": {"allow": {"a.example": true}}} {}`, "more than one JSON value"},
		{`{"version": 2.0}`, "not an integer"},
	} {
		_, _, err := grant.ParseDoc([]byte(c.file))
		if err == nil || !strings.Contains(err.Error(), c.said) {
			t.Errorf("%s: %v, not %q", c.file, err, c.said)
		}
	}
}

// `chase fmt` writes the canonical form, the bytes signed; `chase check`
// reads a file as a launch does, refuses one not canonical, and says
// whether it is signed.
func TestFmtAndCheck(t *testing.T) {
	h, s := v2(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	write(t, ws+"/chase.json", `{"version":2,"frisket":{"allow":{"pypi.org":true}}}`)
	var out bytes.Buffer
	if err := grant.CheckCommand(&h.cfg, []string{ws + "/chase.json"}, &out); err == nil || !strings.Contains(err.Error(), "not in its canonical form") {
		t.Errorf("check took a file not canonical: %v", err)
	}
	if err := grant.FmtCommand([]string{"-check", ws + "/chase.json"}, &out); err == nil {
		t.Error("fmt -check took a file not canonical")
	}
	if err := grant.FmtCommand([]string{ws + "/chase.json"}, &out); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"frisket\": {\n    \"allow\": {\n      \"pypi.org\": true\n    }\n  },\n  \"version\": 2\n}\n"
	if got := read(t, ws+"/chase.json"); got != want {
		t.Errorf("fmt wrote %q", got)
	}
	out.Reset()
	if err := grant.CheckCommand(&h.cfg, []string{ws + "/chase.json"}, &out); err != nil || !strings.Contains(out.String(), "not signed") {
		t.Errorf("check: %v %s", err, out.String())
	}
	root, _ := grant.Root(ws)
	write(t, ws+"/chase.json.sig", string(s.Sign(t, root, []byte(want))))
	out.Reset()
	if err := grant.CheckCommand(&h.cfg, []string{ws + "/chase.json"}, &out); err != nil || !strings.HasSuffix(out.String(), ": signed\n") {
		t.Errorf("check of a signed file: %v %s", err, out.String())
	}
	write(t, ws+"/chase.json", canonical(t, `{"version": 2, "frisket": {"routes": {"github": {"host": "x"}}}}`))
	if err := grant.CheckCommand(nil, []string{ws + "/chase.json"}, &out); err == nil || !strings.Contains(err.Error(), "the host's alone") {
		t.Errorf("check took a host field: %v", err)
	}
	if err := grant.FmtCommand([]string{ws + "/missing.json"}, &out); err == nil {
		t.Error("fmt of nothing succeeded")
	}
}

// The schema is the components': frisket's version 2 document's, with
// what is the host's marked, and each of chase's types, every field.
func TestTheSchemaIsTheComponents(t *testing.T) {
	var s map[string]any
	if err := json.Unmarshal(grant.Schema(), &s); err != nil {
		t.Fatal(err)
	}
	props := s["properties"].(map[string]any)
	if got := slices.Sorted(maps.Keys(props)); !slices.Equal(got, []string{"chase", "flong", "frisket", "signer", "sudo", "version"}) {
		t.Errorf("the sections are %q", got)
	}
	route := props["frisket"].(map[string]any)["properties"].(map[string]any)["routes"].(map[string]any)["additionalProperties"].(map[string]any)["properties"].(map[string]any)
	if route["host"].(map[string]any)["x-scope"] != "host" || route["operations"].(map[string]any)["x-scope"] != nil {
		t.Errorf("frisket's scopes are not marked: %v %v", route["host"], route["operations"])
	}
	apps := props["chase"].(map[string]any)["properties"].(map[string]any)["apps"].(map[string]any)["properties"].(map[string]any)
	if got := slices.Sorted(maps.Keys(apps)); !slices.Equal(got, []string{"cloudflare", "docker", "gcloud", "nix", "ssh"}) {
		t.Errorf("the apps are %q", got)
	}
	docker := apps["docker"].(map[string]any)["properties"].(map[string]any)
	if got := slices.Sorted(maps.Keys(docker)); !slices.Equal(got, []string{"images", "ports", "project"}) {
		t.Errorf("docker's keys are %q", got)
	}
	calls := props["flong"].(map[string]any)["properties"].(map[string]any)["seccomp"].(map[string]any)["properties"].(map[string]any)["syscalls"].(map[string]any)
	if !reflect.DeepEqual(calls["additionalProperties"], map[string]any{"enum": []any{"allow", "deny", "log"}}) {
		t.Errorf("syscalls are %v", calls)
	}
}

// MIGRATION: every chase.jsonc chase's own tests and docs hold, as the
// chase.json it migrates to and the comments it cannot keep, each beside
// it in testdata/migrate. CHASE_UPDATE_GOLDEN=1 writes them.
func TestEveryChaseJSONCMigrates(t *testing.T) {
	files, err := filepath.Glob("testdata/migrate/*.jsonc")
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		doc, comments, err := grant.Migrate(b)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		out, err := projpolicy.Encode(doc)
		if err != nil {
			t.Fatal(err)
		}
		// With what chase migrate derives of the checkout, it is one
		// chase reads.
		var derived map[string]any
		json.Unmarshal(out, &derived)
		if c, ok := derived["chase"].(map[string]any); ok {
			if c["secrets"] != nil {
				c["secretsSHA256"] = strings.Repeat("0", 64)
			}
		}
		withDerived, _ := json.Marshal(derived)
		if _, _, err := grant.ParseDoc(withDerived); err != nil {
			t.Errorf("%s migrates to a file chase does not read: %v\n%s", f, err, out)
		}
		said := strings.Join(comments, "\n")
		if len(comments) > 0 {
			said += "\n"
		}
		golden := strings.TrimSuffix(f, ".jsonc")
		if os.Getenv("CHASE_UPDATE_GOLDEN") != "" {
			os.WriteFile(golden+".json", out, 0o644)
			os.WriteFile(golden+".comments", []byte(said), 0o644)
			continue
		}
		if want := read(t, golden+".json"); string(out) != want {
			t.Errorf("%s migrates to\n%s\nnot\n%s", f, out, want)
		}
		if want := read(t, golden+".comments"); said != want {
			t.Errorf("%s's comments are\n%s\nnot\n%s", f, said, want)
		}
	}
	if _, _, err := grant.Migrate([]byte(`{"apps": {"github": {"allow": ["x"], "refuse": ["x"]}}}`)); err == nil || !strings.Contains(err.Error(), "x is in allow and refuse") {
		t.Errorf("one name in two lists migrated: %v", err)
	}
}

// `chase migrate` writes the chase.json, says the comments, removes
// chase.jsonc, and signs the new file; a launch then reads it unasked.
func TestMigrateWritesSignsAndRemoves(t *testing.T) {
	h, s := v2(t)
	r := h.root()
	h.cfg.Checkouts["example/shop"] = []string{r + "/p/shop"}
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:example/shop.git")
	write(t, ws+"/secrets.json", `{"cf": "token"}`)
	write(t, ws+"/chase.jsonc", "// shop's\n{\"secrets\": \"secrets.json\", \"apps\": {\"docker\": {\"images\": [\"postgres:18\"], \"ports\": [64320]}, \"github\": {\"allow\": [\"pulls/create\"]}}, \"seccomp\": {\"allow\": [\"ptrace\"]}}\n")
	var out, errb bytes.Buffer
	if err := grant.MigrateCommand(context.Background(), h.cfg, []string{ws}, &out, &errb); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	if _, err := os.Lstat(ws + "/chase.jsonc"); err == nil {
		t.Error("chase.jsonc was kept")
	}
	if !strings.Contains(errb.String(), "chase.jsonc: dropped comment: // shop's") {
		t.Errorf("the comment was not said: %s", errb.String())
	}
	want := canonical(t, `{"version": 2,
		"chase": {"secrets": "secrets.json", "secretsSHA256": "`+sha256Hex(`{"cf": "token"}`)+`", "apps": {"docker": {"project": "example/shop", "images": {"postgres:18": true}, "ports": {"64320": true}}}},
		"flong": {"seccomp": {"syscalls": {"ptrace": "allow"}}},
		"frisket": {"routes": {"github": {"operations": {"pulls/create": "allow"}}}}}`)
	if got := read(t, ws+"/chase.json"); got != want {
		t.Errorf("chase.json is\n%s\nnot\n%s", got, want)
	}
	if len(s.Asked()) != 1 {
		t.Errorf("the signer was asked %d times", len(s.Asked()))
	}
	h.approved(ws, "m1", "trusted", "")
	if len(s.Asked()) != 1 || h.migrate {
		t.Errorf("a migrated file was asked about, or told to migrate: %s", h.err)
	}
	if err := grant.MigrateCommand(context.Background(), h.cfg, []string{ws}, &out, &errb); err == nil {
		t.Error("a checkout with no chase.jsonc migrated")
	}
	// Beside a chase.json, a chase.jsonc is neither migrated nor read.
	write(t, ws+"/chase.jsonc", "{}")
	if err := grant.MigrateCommand(context.Background(), h.cfg, []string{ws}, &out, &errb); err == nil || !strings.Contains(err.Error(), "has a chase.json already") {
		t.Errorf("a chase.jsonc beside a chase.json: %v", err)
	}
	h.approved(ws, "m2", "trusted", "")
	h.mustSay("chase.jsonc is not read beside chase.json: remove it")
}

// A legacy chase.jsonc alone is approved as it always was, and told to
// migrate.
func TestALegacyFileIsToldToMigrate(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	h.approved(ws, "m1", "trusted", `{"apps": {}}`)
	if !h.migrate {
		t.Error("a chase.jsonc was not told to run chase migrate")
	}
	if len(h.approvals()) != 1 {
		t.Errorf("a chase.jsonc was not approved as ever: %v", h.approvals())
	}
}

// flong's own check of the flong section, against the tier's
// declaration, refuses a call the architecture has no name for -- run
// where the module names flong, here a stand-in that says what it was
// asked.
func TestTheFlongSectionIsCheckedByFlong(t *testing.T) {
	h, s := v2(t)
	stub := h.dir + "/bin/flong"
	write(t, stub, "#!/bin/sh\necho \"$0 $*\" > "+h.dir+"/logs/flong.args\nwhile [ $# -gt 1 ]; do shift; done\ngrep -q nosuchcall \"$1\" && { echo 'flong check: syscalls.nosuchcall: no such call'; exit 1; }\nexit 0\n")
	os.Chmod(stub, 0o755)
	h.cfg.Flong, h.cfg.Declarations = stub, "/etc/flong"
	ws := h.root() + "/w"
	h.project(s, ws, canonical(t, `{"version": 2, "flong": {"seccomp": {"syscalls": {"ptrace": "allow"}}}}`), true)
	h.approved(ws, "m1", "trusted", "")
	args := read(t, h.dir+"/logs/flong.args")
	if !strings.Contains(args, " check --layer project --base /etc/flong/chase-trusted.json ") {
		t.Errorf("flong was run as %q", args)
	}
	h.project(s, ws, canonical(t, `{"version": 2, "flong": {"seccomp": {"syscalls": {"nosuchcall": "allow"}}}}`), true)
	if h.approve(ws, "m2", "trusted", "") == 0 {
		t.Error("a call flong refused was approved")
	}
	h.mustSay("chase.json's flong section: flong check: syscalls.nosuchcall: no such call")
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
}

// `chase sign` and `chase migrate` with no DIR name the working directory
// ".", which the signer's namespace needs absolute, as the kernel names it.
func TestTheRootOfTheWorkingDirectoryIsAbsolute(t *testing.T) {
	ws := t.TempDir()
	t.Chdir(ws)
	root, err := grant.Root(".")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(ws)
	if root != want || !filepath.IsAbs(root) {
		t.Fatalf("Root(\".\") = %q, want %q", root, want)
	}
}

// A GIT WORKTREE's chase.json is signed as its repository's, the namespace
// quoin's courier names it by: the signature committed in the checkout
// launches a worktree of it unasked, and a change made in the worktree is
// put to the signer as the repository's.
func TestAWorktreesFileIsSignedAsItsRepositorys(t *testing.T) {
	h, s := v2(t)
	ws := h.cfg.Home + "/Projects/w"
	file := canonical(t, `{"version": 2, "frisket": {"allow": {"pypi.org": true}}}`)
	h.project(s, ws, file, true)
	h.fx.Run("-C", ws, "add", "-A")
	h.fx.Run("-C", ws, "-c", "user.name=a", "-c", "user.email=a@example.com", "commit", "-qm", "signed")
	wt := ws + "/.claude/worktrees/pi"
	h.fx.Run("-C", ws, "worktree", "add", "-q", wt)

	h.approved(wt, "m1", "trusted", "")
	if len(s.Asked()) != 0 {
		t.Errorf("the repository's signature was not taken in its worktree: %v", s.Asked())
	}

	changed := canonical(t, `{"version": 2, "frisket": {"allow": {"pypi.org": true, "crates.io": true}}}`)
	write(t, wt+"/chase.json", changed)
	h.approved(wt, "m2", "trusted", "")
	root, _ := grant.Root(ws)
	if asked := s.Asked(); len(asked) != 1 || asked[0].Root != root {
		t.Fatalf("asked %+v, want one for %s", asked, root)
	}
	sig, err := os.ReadFile(wt + "/chase.json.sig")
	if err != nil {
		t.Fatal(err)
	}
	signers, err := projpolicy.ReadAllowedSigners(s.AllowedSigners)
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := projpolicy.Namespace(root, h.cfg.Home)
	if _, err := projpolicy.Verify([]byte(changed), sig, ns, signers, "", time.Now()); err != nil {
		t.Errorf("the worktree's new signature is not the repository's: %v", err)
	}
}
