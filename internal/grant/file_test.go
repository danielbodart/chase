package grant_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/grant"
)

// WHAT A GRANT MAY NAME FOR DOCKER (docs/docker.md): each image in the one
// form frisket compares against, never at a registry the host's loopback or
// an address would answer for, and ports frisket can listen on in the
// session.
func TestWhatAGrantMayNameForDocker(t *testing.T) {
	digest := strings.Repeat("0123abcd", 8)
	ports := func(from, to int) string {
		var p []string
		for i := from; i <= to; i++ {
			p = append(p, fmt.Sprint(i))
		}
		return strings.Join(p, ",")
	}
	images := func(s ...string) string {
		return `{"apps": {"docker": {"images": ["` + strings.Join(s, `", "`) + `"]}}}`
	}
	refused := []string{
		images("docker.io/postgres:18"),
		images("index.docker.io/x:1"),
		images("library/postgres:18"),
		images("postgres"),
		images("127.0.0.1:5000/x:1"),
		images("10.0.0.1/x:1"),
		images("localhost/x:1"),
		// Names and spellings that resolve to the host's loopback.
		images("registry.localhost/x:1"),
		images("localhost.localdomain/x:1"),
		images("0x7f.1/x:1"),
		images("127.1/x:1"),
		images("a.internal/x:1"),
		images("127.0.0.1.nip.io/x:1"),
		images("evil.eu.gcr.io.example/x:1"),
		images("a.b-docker.pkg.dev/x:1"),
		// An image's ID, or a prefix of one, for whatever local image has it.
		images("sha256:" + digest),
		images("sha256:0123abcd"),
		images(digest + ":1"),
		images("o/" + digest + ":1"),
		images("o/sha256:1"),
		`{"apps": {"docker": {"ports": [80]}}}`,
		`{"apps": {"docker": {"ports": [0, 99999]}}}`,
		`{"apps": {"docker": {"ports": [15001]}}}`,
		`{"apps": {"docker": {"ports": [5432, 5432]}}}`,
		`{"apps": {"docker": {"ports": [` + ports(2000, 2064) + `]}}}`,
	}
	accepted := []string{
		`{"apps": {"docker": {"images": ["postgres:18", "bitnami/postgresql:16", "ghcr.io/o/x:1", "postgres@sha256:` + digest + `", "eu.gcr.io/p/x:1", "europe-west2-docker.pkg.dev/p/r/x:1"], "ports": [5432]}}}`,
		`{"apps": {"docker": {"ports": [` + ports(2000, 2063) + `]}}}`,
		`{"apps": {"docker": {}}}`,
	}
	for _, g := range refused {
		if _, err := grant.ParseFile([]byte(g)); err == nil {
			t.Errorf("%s was accepted", g)
		}
	}
	for _, g := range accepted {
		if _, err := grant.ParseFile([]byte(g)); err != nil {
			t.Errorf("%s was refused: %v", g, err)
		}
	}
}

// WHAT A GRANT MAY NAME FOR SSH (docs/apps/ssh.md): each machine by an
// address, a user and its own keys, and its rules its own. What a machine
// may be is internal/apps/ssh's to test; this is that it is held to it when
// the grant is read, before anyone is asked, and approved as it is read.
func TestWhatAGrantMayNameForSSH(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl server"
	// host is server with members merged over its own, never after them:
	// a member named twice is refused for that before any rule of the
	// machine's is reached.
	host := func(members string) string {
		h := map[string]any{"address": "192.168.1.10", "user": "ops", "hostKeys": []string{key}}
		if err := json.Unmarshal([]byte(members), &h); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(map[string]any{"apps": map[string]any{"ssh": map[string]any{"hosts": map[string]any{"server": h}}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, tc := range []struct{ grant, said string }{
		{host(`{"address": "server.lan"}`), "apps.ssh.hosts.server.address"},
		{host(`{"address": "server.lan"}`), "a literal IP"},
		{host(`{"hostKeys": []}`), "hostKeys: none"},
		{host(`{"allow": ["rm **"], "refuse": ["rm **"]}`), "rm **"},
		{host(`{"allow": ["time **"]}`), "reserved"},
		{host(`{"unmatched": "never"}`), "unmatched"},
		{host(`{"rules": []}`), "rules"},
		{`{"apps": {"ssh": {"allow": ["remove"]}}}`, "allow"},
		{`{"apps": {"ssh": {"hosts": {"Server": {}}}}}`, "Server"},
	} {
		_, err := grant.ParseFile([]byte(tc.grant))
		if err == nil {
			t.Errorf("%s was accepted", tc.grant)
		} else if strings.Contains(err.Error(), "given twice") || !strings.Contains(err.Error(), tc.said) {
			t.Errorf("%s was refused, but not for %q: %v", tc.grant, tc.said, err)
		}
	}
	got, err := grant.ParseFile([]byte(host(`{"refuse": ["category:packages"], "allow": ["service-restart", "docker compose ps **"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"apps":{"ssh":{"hosts":{"server":{"address":"192.168.1.10","allow":["service-restart","docker compose ps **"],"hostKeys":["` + key + `"],"refuse":["category:packages"],"user":"ops"}}}}}`
	if string(got) != want {
		t.Errorf("read as %s, not %s", got, want)
	}
}

// What a person approves is the grant as chase reads it: written again, in
// File's order, without the project's comments, and with nothing it did not
// say.
func TestAGrantIsApprovedAsChaseReadsIt(t *testing.T) {
	got, err := grant.ParseFile([]byte(`// talebrary's
{
  "seccomp": { "allow": ["io_uring_setup"], "deny": [] },
  "apps": {
    /* often */
    "github": { "allow": ["b", { "path": "/x", "methods": ["GET"] }], },
    "cloudflare": { "credential": { "secret": "t" }, "accountId": "` + strings.Repeat("0", 32) + `" },
    "nix": { "devShell": true },
  },
  "secrets": "secrets.yaml",
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"secrets":"secrets.yaml","apps":{"cloudflare":{"accountId":"` + strings.Repeat("0", 32) + `","credential":{"secret":"t"}},"github":{"allow":["b",{"methods":["GET"],"path":"/x"}]},"nix":{"devShell":true}},"seccomp":{"allow":["io_uring_setup"]}}`
	if string(got) != want {
		t.Errorf("read as %s, not %s", got, want)
	}
}

// WHAT A GRANT MAY NAME FOR NIX: whether the checkout's devShell is given,
// a boolean and nothing else; and nothing of the flake's beside it, which
// is the checkout's at each launch.
func TestWhatAGrantMayNameForNix(t *testing.T) {
	for _, g := range []string{
		`{"apps": {"nix": {"devShell": "yes"}}}`,
		`{"apps": {"nix": {"devShell": 1}}}`,
		`{"apps": {"nix": {"devShells": true}}}`,
		`{"apps": {"nix": {"flake": "./other.nix"}}}`,
		`{"apps": {"nix": true}}`,
	} {
		if _, err := grant.ParseFile([]byte(g)); err == nil {
			t.Errorf("%s was taken", g)
		}
	}
	for g, want := range map[string]string{
		`{"apps": {"nix": {"devShell": true}}}`:  `{"apps":{"nix":{"devShell":true}}}`,
		`{"apps": {"nix": {"devShell": false}}}`: `{"apps":{"nix":{"devShell":false}}}`,
		`{"apps": {"nix": {}}}`:                  `{"apps":{"nix":{}}}`,
	} {
		got, err := grant.ParseFile([]byte(g))
		if err != nil || string(got) != want {
			t.Errorf("%s was read as %s, %v, not %s", g, got, err, want)
		}
	}
}
