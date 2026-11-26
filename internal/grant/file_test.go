package grant_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/grant"
)

// appsDoc is a chase.json whose chase.apps is v, as JSON.
func appsDoc(t *testing.T, v map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"version": 2, "chase": map[string]any{"apps": v}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// WHAT A FILE MAY NAME FOR DOCKER (docs/docker.md): each image in the one
// form frisket compares against, never at a registry the host's loopback or
// an address would answer for, and ports frisket can listen on in the
// session.
func TestWhatAGrantMayNameForDocker(t *testing.T) {
	digest := strings.Repeat("0123abcd", 8)
	docker := func(images []string, from, to int) string {
		d := map[string]any{}
		if images != nil {
			m := map[string]bool{}
			for _, i := range images {
				m[i] = true
			}
			d["images"] = m
		}
		if from > 0 {
			p := map[string]bool{}
			for i := from; i <= to; i++ {
				p[fmt.Sprint(i)] = true
			}
			d["ports"] = p
		}
		return appsDoc(t, map[string]any{"docker": d})
	}
	images := func(s ...string) string { return docker(s, 0, 0) }
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
		docker(nil, 80, 80),
		docker(nil, 99999, 99999),
		docker(nil, 2000, 2064),
	}
	accepted := []string{
		docker([]string{"postgres:18", "bitnami/postgresql:16", "ghcr.io/o/x:1", "postgres@sha256:" + digest, "eu.gcr.io/p/x:1", "europe-west2-docker.pkg.dev/p/r/x:1"}, 5432, 5432),
		docker(nil, 2000, 2063),
		appsDoc(t, map[string]any{"docker": map[string]any{}}),
	}
	for _, g := range refused {
		if _, _, err := grant.ParseDoc([]byte(g)); err == nil {
			t.Errorf("%s was accepted", g)
		}
	}
	for _, g := range accepted {
		if _, _, err := grant.ParseDoc([]byte(g)); err != nil {
			t.Errorf("%s was refused: %v", g, err)
		}
	}
}

// WHAT A FILE MAY NAME FOR SSH (docs/apps/ssh.md): each machine by an
// address, a user and its own keys, and its rules its own. What a machine
// may be is internal/apps/ssh's to test; this is that it is held to it when
// the file is read, before anyone is asked.
func TestWhatAGrantMayNameForSSH(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl server"
	// host is server with members merged over its own.
	host := func(members string) string {
		h := map[string]any{"address": "192.168.1.10", "user": "ops", "hostKeys": []string{key}}
		if err := json.Unmarshal([]byte(members), &h); err != nil {
			t.Fatal(err)
		}
		return appsDoc(t, map[string]any{"ssh": map[string]any{"hosts": map[string]any{"server": h}}})
	}
	for _, tc := range []struct{ grant, said string }{
		{host(`{"address": "server.lan"}`), "apps.ssh.hosts.server.address"},
		{host(`{"address": "server.lan"}`), "a literal IP"},
		{host(`{"hostKeys": []}`), "hostKeys: none"},
		{host(`{"allow": ["rm **"], "refuse": ["rm **"]}`), "rm **"},
		{host(`{"allow": ["time **"]}`), "reserved"},
		{host(`{"unmatched": "never"}`), "unmatched"},
		{host(`{"rules": []}`), "rules"},
		{appsDoc(t, map[string]any{"ssh": map[string]any{"allow": []string{"remove"}}}), "allow"},
		{appsDoc(t, map[string]any{"ssh": map[string]any{"hosts": map[string]any{"Server": map[string]any{}}}}), "Server"},
	} {
		_, _, err := grant.ParseDoc([]byte(tc.grant))
		if err == nil {
			t.Errorf("%s was accepted", tc.grant)
		} else if !strings.Contains(err.Error(), tc.said) {
			t.Errorf("%s was refused, but not for %q: %v", tc.grant, tc.said, err)
		}
	}
	if _, _, err := grant.ParseDoc([]byte(host(`{"refuse": ["category:packages"], "allow": ["service-restart", "docker compose ps **"]}`))); err != nil {
		t.Errorf("a machine with its own rules was refused: %v", err)
	}
}

// WHAT A FILE MAY SAY OF NIX (docs/apps/nix.md): whether the checkout's
// devShell is given, and nothing else.
func TestWhatAGrantMaySayOfNix(t *testing.T) {
	for _, n := range []map[string]any{
		{"devShell": "yes"},
		{"devShell": true, "flake": "x"},
		{"shell": true},
	} {
		if g := appsDoc(t, map[string]any{"nix": n}); func() error { _, _, err := grant.ParseDoc([]byte(g)); return err }() == nil {
			t.Errorf("%s was accepted", g)
		}
	}
	d, _, err := grant.ParseDoc([]byte(appsDoc(t, map[string]any{"nix": map[string]any{"devShell": true}})))
	if err != nil || d.Chase.Apps.Nix == nil || !d.Chase.Apps.Nix.DevShell {
		t.Errorf("%+v, %v", d, err)
	}
}
