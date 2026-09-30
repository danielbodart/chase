package grant_test

import (
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
		return `{"bindings": {"docker": {"images": ["` + strings.Join(s, `", "`) + `"]}}}`
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
		`{"bindings": {"docker": {"ports": [80]}}}`,
		`{"bindings": {"docker": {"ports": [0, 99999]}}}`,
		`{"bindings": {"docker": {"ports": [15001]}}}`,
		`{"bindings": {"docker": {"ports": [5432, 5432]}}}`,
		`{"bindings": {"docker": {"ports": [` + ports(2000, 2064) + `]}}}`,
	}
	accepted := []string{
		`{"bindings": {"docker": {"images": ["postgres:18", "bitnami/postgresql:16", "ghcr.io/o/x:1", "postgres@sha256:` + digest + `", "eu.gcr.io/p/x:1", "europe-west2-docker.pkg.dev/p/r/x:1"], "ports": [5432]}}}`,
		`{"bindings": {"docker": {"ports": [` + ports(2000, 2063) + `]}}}`,
		`{"bindings": {"docker": {}}}`,
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

// What a person approves is the grant as chase reads it: written again, in
// File's order, without the project's comments, and with nothing it did not
// say.
func TestAGrantIsApprovedAsChaseReadsIt(t *testing.T) {
	got, err := grant.ParseFile([]byte(`// talebrary's
{
  "seccomp": { "allow": ["io_uring_setup"], "deny": [] },
  "bindings": {
    /* often */
    "github": { "allow": ["b", { "path": "/x", "methods": ["GET"] }], },
    "cloudflare": { "credential": { "secret": "t" }, "accountId": "` + strings.Repeat("0", 32) + `" },
  },
  "secrets": "secrets.yaml",
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"secrets":"secrets.yaml","bindings":{"cloudflare":{"accountId":"` + strings.Repeat("0", 32) + `","credential":{"secret":"t"}},"github":{"allow":["b",{"methods":["GET"],"path":"/x"}]}},"seccomp":{"allow":["io_uring_setup"]}}`
	if string(got) != want {
		t.Errorf("read as %s, not %s", got, want)
	}
}
