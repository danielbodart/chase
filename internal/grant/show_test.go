package grant_test

import (
	"os"
	"strings"
	"testing"
)

// The ported docker-show check, as far as the grant goes: WHERE A
// PROJECT'S DOCKER IS, SAID (docs/docker.md). `chase docker` prints a
// checkout's project, address, session names and approved ports, and calls a
// name the host's only where the host's map gives it this project at this
// address.

func block(ports string) string {
	return strings.Join([]string{
		"example/shop",
		"  address  127.101.170.171",
		"  names    shop.example.internal",
		"  ports    " + ports,
	}, "\n") + "\n"
}

func (h *harness) shown(dir, tier, want string) {
	h.t.Helper()
	if rc := h.run("docker", dir, tier); rc != 0 {
		h.t.Errorf("%s in %s was not shown: %s", dir, tier, h.err)
		return
	}
	if h.out != want {
		h.t.Errorf("%s in %s was shown as:\n%s\nnot:\n%s", dir, tier, h.out, want)
	}
}

func TestWhereAProjectsDockerIsIsSaid(t *testing.T) {
	h := newHarness(t)
	r := h.root()
	h.cfg.Checkouts["example/shop"] = []string{r + "/p/shop"}
	h.cfg.DockerTiers = []string{"trusted"}
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:Example/Shop.git")
	os.MkdirAll(ws+"/sub", 0o755)
	ports := "64320 64321   (approved)"

	// Nothing approved: no port is the project's yet.
	h.shown(ws, "trusted", block("(none approved)"))

	// Approved, its ports are the project's, from anywhere in the checkout,
	// which is keyed by its root as the launch keys it.
	h.approved(ws, "m1", "trusted", `{"apps": {"docker": {"images": ["postgres:18"], "ports": [64320, 64321]}}}`)
	h.shown(ws, "trusted", block(ports))
	h.shown(ws+"/sub", "trusted", block(ports))

	// A tier without Docker still has the address, and says so.
	h.shown(ws, "plain", "example/shop\n  address  127.101.170.171\n  (no Docker on plain)\n")

	// An approval of the checkout as another project approved none of this
	// one's ports.
	app := r + "/w/app"
	h.repo(app, "git@github.com:acme/app.git")
	h.approved(app, "m2", "trusted", `{"apps": {"docker": {"images": ["postgres:18"], "ports": [5432]}}}`)
	if h.run("docker", app, "trusted") != 0 || !h.hasLine("  ports    5432   (approved)") {
		t.Errorf("acme/app's ports were not shown: %s %s", h.out, h.err)
	}
	h.fx.Run("-C", app, "remote", "set-url", "origin", "git@github.com:acme/app2.git")
	if h.run("docker", app, "trusted") != 0 || !strings.HasPrefix(h.out, "acme/app2\n") || !h.hasLine("  ports    (none approved)") {
		t.Errorf("another project's ports were shown as approved: %s %s", h.out, h.err)
	}

	// NO USABLE ORIGIN: why, and exit 1, with nothing on stdout.
	none := r + "/w/none"
	h.repo(none)
	if h.run("docker", none, "trusted") == 0 {
		t.Errorf("a checkout with no origin was shown: %s", h.out)
	}
	h.mustSay("chase: " + none + ": Docker needs exactly one origin URL")
	if h.out != "" {
		t.Errorf("a checkout with no origin printed: %q", h.out)
	}
	if rc := h.run("docker", ws); rc != 1 || h.err != "chase: usage: chase grant docker WS TIER\n" {
		t.Errorf("docker with one argument: %d %q", rc, h.err)
	}
}

func (h *harness) hasLine(line string) bool {
	for _, l := range strings.Split(h.out, "\n") {
		if l == line {
			return true
		}
	}
	return false
}
