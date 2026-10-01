package grant_test

import (
	"bytes"
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/session"
)

// exec is `chase hook exec TIER ARGS...` for machine, as flong runs it, the
// grant's configuration given when takes: its status, with what it
// printed and said kept in h.out and h.err.
func (h *harness) exec(s session.Config, takes bool, tier, ws, machine string, args ...string) int {
	h.t.Helper()
	var e *grant.Config
	registry := map[string]apps.App{}
	if takes {
		e = &h.cfg
		registry = grant.DefaultApps(h.cfg, &bytes.Buffer{})
		maps.Copy(registry, h.registry)
	}
	var out, errb bytes.Buffer
	rc := grant.Exec(context.Background(), s, e, registry, tier, ws, machine, "", args, &out, &errb)
	h.out, h.err = out.String(), errb.String()
	return rc
}

// fields is what the last exec printed, a field an entry, each checked to
// end with its NUL.
func (h *harness) fields() []string {
	h.t.Helper()
	if !strings.HasSuffix(h.out, "\x00") {
		h.t.Fatalf("the payload does not end with a NUL: %q", h.out)
	}
	return strings.Split(strings.TrimSuffix(h.out, "\x00"), "\x00")
}

func sessionConfig(h *harness) session.Config {
	return session.Config{
		Home:        h.cfg.Home,
		Runtime:     h.cfg.Runtime,
		Placeholder: "proxy-injected",
		Tiers:       map[string]session.Tier{"trusted": {Environment: map[string]string{"SSL_CERT_FILE": "/etc/frisket/ca-bundle.crt"}}},
	}
}

// THE HOOK, WHOLE: the agent judged before anything is done for the launch,
// then the approved grant applied, and what it exports and seeds printed
// as the payload's, in flong's fields and nothing else. A launch refused at
// any step prints nothing at all on stdout, where flong would read it as a
// payload.
func TestTheExecHookAppliesTheGrantAndPrintsItsPayload(t *testing.T) {
	h, p, ws := newProjectLaunch(t)
	s := sessionConfig(h)
	h.cfg.Apps["gcloud"] = grant.App{Credential: no()}
	h.registry["gcloud"] = seeder{}
	given := `{"apps": {"cloudflare": {"accountId": "11111111111111111111111111111111"}, "gcloud": {"serviceAccount": "s@p.iam.gserviceaccount.com"}}}`

	// An agent the tier does not run, or none, is refused before the
	// stage is consumed: nothing is prepared, no directory made, no policy
	// written.
	h.approved(ws, "m1", "trusted", given)
	for args, said := range map[string]string{"claude": "unknown agent 'claude': trusted runs shell", "sh -c id": "unknown agent 'sh'", "": "no agent named"} {
		args := strings.Fields(args)
		if rc := h.exec(s, true, "trusted", ws, "m1", args...); rc != 1 || h.out != "" {
			t.Errorf("%q: status %d, printed %q", args, rc, h.out)
		}
		h.mustSay(said)
		if !h.isStaged("m1") || len(p.requests) != 0 {
			t.Errorf("%q was applied before it was refused: staged %v, prepared %d", args, h.isStaged("m1"), len(p.requests))
		}
		if _, err := os.Stat(h.cfg.Runtime + "/chase/m1"); err == nil {
			t.Errorf("%q made the session's directory before it was refused", args)
		}
	}

	// An agent it runs: the grant applied, once, and its variables and
	// files the payload's, after the program and its arguments.
	if rc := h.exec(s, true, "trusted", ws, "m1", "shell", "-c", "id"); rc != 0 {
		t.Fatalf("the shell was refused: %s", h.err)
	}
	key := h.cfg.Home + "/.config/seeder/key"
	want := []string{"env:PROBE=1", "env:SEEDER_KEY=" + key, "arg:bash", "arg:-l", "arg:-c", "arg:id", "file:0600:" + key, "for " + ws}
	if got := h.fields(); !slices.Equal(got, want) {
		t.Errorf("the payload is %q, not %q", got, want)
	}
	if h.isStaged("m1") || len(p.requests) != 1 {
		t.Errorf("the approval was not applied once: staged %v, prepared %d", h.isStaged("m1"), len(p.requests))
	}
	if _, err := os.Stat(h.cfg.Runtime + "/chase/m1/policy.json"); err != nil {
		t.Errorf("no policy was written: %v", err)
	}
	if _, err := os.Stat(key); err == nil {
		t.Errorf("the launch wrote %s, which is the payload's to seed", key)
	}

	// Nothing approved is a launch refused, silently on stdout.
	if rc := h.exec(s, true, "trusted", ws, "m2", "shell"); rc != 1 || h.out != "" {
		t.Errorf("an unapproved launch: status %d, printed %q", rc, h.out)
	}
	h.mustSay("nothing was approved for this launch")

	// And so is a payload refused after the grant was applied: an
	// export the container sets otherwise.
	h.cfg.Apps["docker"] = grant.App{Credential: no(), Env: map[string]string{"SSL_CERT_FILE": "/elsewhere"}}
	h.approved(ws, "m3", "trusted", `{"apps": {"docker": {"images": ["postgres:18"]}, "cloudflare": {"accountId": "11111111111111111111111111111111"}}}`)
	if rc := h.exec(s, true, "trusted", ws, "m3", "shell"); rc != 1 || h.out != "" {
		t.Errorf("a refused payload: status %d, printed %q", rc, h.out)
	}
	h.mustSay("trusted's container sets SSL_CERT_FILE")
}

// A tier whose sessions publish ports puts them on the checkout's
// project's address, and a checkout with no project leaves them on the
// tier's own: no field, and nothing said.
func TestTheExecHookBindsPublishedPortsToTheProjectsAddress(t *testing.T) {
	h, _, ws := newProjectLaunch(t)
	s := sessionConfig(h)
	s.Tiers["trusted"] = session.Tier{Forward: true}
	h.approved(ws, "m1", "trusted", `{}`)
	if rc := h.exec(s, true, "trusted", ws, "m1", "shell"); rc != 0 {
		t.Fatalf("the shell was refused: %s", h.err)
	}
	if got := h.fields(); got[len(got)-1] != "forward:127.101.170.171" {
		t.Errorf("the payload is %q, with no forward to example/shop's address", got)
	}

	none := h.root() + "/w/none"
	h.repo(none)
	h.approved(none, "m2", "trusted", `{}`)
	if rc := h.exec(s, true, "trusted", none, "m2", "shell"); rc != 0 {
		t.Fatalf("a checkout with no origin was refused: %s", h.err)
	}
	if got := h.fields(); slices.ContainsFunc(got, func(f string) bool { return strings.HasPrefix(f, "forward:") }) {
		t.Errorf("a checkout with no project was given a forward: %q", got)
	}
	if h.err != "" {
		t.Errorf("a checkout with no project said %q", h.err)
	}
}

// A tier that takes no grant is given its payload with nothing applied:
// no stage looked for, no policy written.
func TestAnExecHookWithNoGrantAppliesNone(t *testing.T) {
	h := newHarness(t)
	if rc := h.exec(sessionConfig(h), false, "trusted", "/w", "m1", "shell"); rc != 0 {
		t.Fatalf("the shell was refused: %s", h.err)
	}
	if got := h.fields(); !slices.Equal(got, []string{"arg:bash", "arg:-l"}) {
		t.Errorf("the payload is %q", got)
	}
	if _, err := os.Stat(h.cfg.Runtime + "/chase/m1"); err == nil {
		t.Error("a launch with no grant made a session directory")
	}
}

// What the script and its postStart left on the host, and nothing reads
// now -- each checkout's old environment directory, Google Cloud's old
// session keys among it, and each tier's copy of the Cloudflare account id
// -- is gone once a launch has run, with or without a grant; what is
// kept now is not touched.
func TestTheExecHookRemovesWhatEarlierVersionsLeft(t *testing.T) {
	for _, takes := range []bool{true, false} {
		h := newHarness(t)
		// The grant's state directory, or with none the default one,
		// where it was.
		state := h.cfg.State
		if !takes {
			state = h.cfg.Home + "/.local/state/chase"
		}
		cloudflare := h.cfg.Home + "/.local/state/agents/cloudflare"
		for _, f := range []string{state + "/env/0123/gcloud-key-0.json", state + "/env/0123/env", cloudflare + "/trusted/account-id"} {
			write(t, f, "x")
		}
		kept := []string{state + "/checkouts/0123/gcloud-key-0.json", h.cfg.Home + "/.local/state/agents/codex/-w/auth.json"}
		for _, f := range kept {
			write(t, f, "x")
		}
		// Refused, with a grant, for want of an approval: what is
		// left is removed all the same, before the launch is judged.
		if rc := h.exec(sessionConfig(h), takes, "trusted", "/w", "m1", "shell"); rc != 0 && !takes {
			t.Fatalf("the shell was refused: %s", h.err)
		}
		for _, dir := range []string{state + "/env", cloudflare} {
			if _, err := os.Stat(dir); err == nil {
				t.Errorf("takes=%v: %s was left", takes, dir)
			}
		}
		for _, f := range kept {
			if _, err := os.Stat(f); err != nil {
				t.Errorf("takes=%v: %s was removed: %v", takes, filepath.Base(f), err)
			}
		}
	}
}
