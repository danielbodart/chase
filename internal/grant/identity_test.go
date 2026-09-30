package grant_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The ported docker-identity check: A CHECKOUT'S DOCKER PROJECT
// (docs/docker.md, decision 9), named by its origin on real repositories,
// held both ways to the paths the tiers pin, and approved: with its address
// and names in front of the person approving, and never at an address
// another project holds.

func newIdentity(t *testing.T) *harness {
	h := newHarness(t)
	r := h.root()
	h.cfg.Checkouts["example/shop"] = []string{r + "/p/shop"}
	// As a tier may write it: the module bakes it lower-cased, and a
	// Config that did not is read as if it had.
	h.cfg.Checkouts["Example/Billing"] = []string{r + "/p/billing"}
	return h
}

func (h *harness) names(dir, slug string) {
	h.t.Helper()
	if rc := h.run("project", dir, "trusted"); rc != 0 {
		h.t.Errorf("%s was not named %s: %s", dir, slug, h.err)
		return
	}
	if h.out != slug+"\n" {
		h.t.Errorf("%s is named %q, not %s", dir, h.out, slug)
	}
}

func (h *harness) refusedAs(dir, needle string) {
	h.t.Helper()
	if rc := h.run("project", dir, "trusted"); rc == 0 {
		h.t.Errorf("%s was named %s", dir, h.out)
		return
	}
	h.mustSay(needle)
}

// EACH FORM OF A GITHUB URL names owner/repo, lower-cased; a pinned project
// at its path, anywhere under it, and from a worktree of it kept there; and a
// pinned project kept bare, in the path's .bare, but not a bare repository
// elsewhere with a worktree under the pinned path.
func TestAnOriginNamesItsProject(t *testing.T) {
	h := newIdentity(t)
	r := h.root()
	h.repo(r+"/w/scp", "git@github.com:acme/app.git")
	h.names(r+"/w/scp", "acme/app")
	h.repo(r+"/w/https", "https://github.com/acme/app")
	h.names(r+"/w/https", "acme/app")
	h.repo(r+"/w/ssh", "ssh://git@github.com/acme/app.git/")
	h.names(r+"/w/ssh", "acme/app")
	h.repo(r+"/w/upper", "git@github.com:AcMe/App.Name.git")
	h.names(r+"/w/upper", "acme/app.name")
	os.MkdirAll(r+"/w/scp/deep/er", 0o755)
	h.names(r+"/w/scp/deep/er", "acme/app")

	h.repo(r+"/p/shop", "git@github.com:Example/Shop.git")
	h.fx.Run("-C", r+"/p/shop", "-c", "user.name=x", "-c", "user.email=x@example.com", "commit", "-q", "--allow-empty", "-m", "first")
	h.names(r+"/p/shop", "example/shop")
	os.MkdirAll(r+"/p/shop/sub", 0o755)
	h.names(r+"/p/shop/sub", "example/shop")
	h.fx.Run("-C", r+"/p/shop", "worktree", "add", "-q", r+"/p/shop/.claude/worktrees/feat")
	h.names(r+"/p/shop/.claude/worktrees/feat", "example/shop")

	h.cfg.Checkouts["acme/bare"] = []string{r + "/p/bare"}
	bared := func(gitdir, url string) {
		h.fx.Run("init", "-q", "--bare", gitdir)
		h.fx.Run("--git-dir="+gitdir, "config", "remote.origin.url", url)
		tree := strings.TrimSpace(h.fx.Stdin("", "--git-dir="+gitdir, "mktree"))
		commit := strings.TrimSpace(h.fx.Run("--git-dir="+gitdir, "-c", "user.name=x", "-c", "user.email=x@example.com", "commit-tree", "-m", "first", tree))
		h.fx.Run("--git-dir="+gitdir, "update-ref", "refs/heads/main", commit)
	}
	bared(r+"/p/bare/.bare", "git@github.com:acme/bare.git")
	h.fx.Run("--git-dir="+r+"/p/bare/.bare", "worktree", "add", "-q", r+"/p/bare/main", "main")
	h.names(r+"/p/bare/main", "acme/bare")
	bared(r+"/elsewhere/bare.git", "git@github.com:acme/bare.git")
	h.fx.Run("--git-dir="+r+"/elsewhere/bare.git", "worktree", "add", "-q", r+"/p/bare/other", "main")
	h.refusedAs(r+"/p/bare/other", "is under "+r+"/p/bare, where acme/bare is pinned, but is a ")
}

// NO NAME: two URLs, not GitHub, none, and no repository; GitHub's shape but
// not a project frisket routes; and what a session wrote said with its
// control bytes made plain.
func TestWhatNamesNoProjectIsRefused(t *testing.T) {
	h := newIdentity(t)
	r := h.root()
	h.repo(r+"/w/two", "git@github.com:acme/app.git", "git@github.com:example/shop.git")
	h.refusedAs(r+"/w/two", "exactly one origin URL")
	h.repo(r+"/w/gitlab", "git@gitlab.com:acme/app.git")
	h.refusedAs(r+"/w/gitlab", "is not github.com/owner/repo")
	h.repo(r+"/w/lookalike", "https://github.com.example/acme/app")
	h.refusedAs(r+"/w/lookalike", "is not github.com/owner/repo")
	h.repo(r + "/w/none")
	h.refusedAs(r+"/w/none", "exactly one origin URL, so its project has a name, and it has 0")
	h.repo(r+"/w/dot", "git@github.com:acme/..git")
	h.refusedAs(r+"/w/dot", "origin git@github.com:acme/. names no repository")
	h.repo(r+"/w/hyphen", "git@github.com:-acme/app.git")
	h.refusedAs(r+"/w/hyphen", "-acme/app is not a project frisket can route")
	h.repo(r+"/w/escape", "x\x1b]0;TITLE\x07y")
	h.refusedAs(r+"/w/escape", "origin x?]0;TITLE?y is not github.com/owner/repo")
	if strings.ContainsAny(h.err, "\x1b\x07") {
		t.Errorf("a control byte reached the terminal: %q", h.err)
	}
	os.MkdirAll(r+"/w/plain", 0o755)
	h.refusedAs(r+"/w/plain", "not a git repository")
	if rc := h.run("project", r+"/w/plain"); rc != 1 || h.err != "chase: usage: chase grant project WS TIER\n" {
		t.Errorf("project with one argument: %d %q", rc, h.err)
	}
}

// BOTH WAYS: a pinned project anywhere but its path, and a pinned path
// claiming anything but its project; and WHAT A SESSION COULD WRITE to take
// the pinned project's name: its own config's core.worktree, a .git file into
// the pinned repository, and a clone of its own inside the pinned path,
// whose session writes its origin.
func TestAPinIsHeldBothWays(t *testing.T) {
	h := newIdentity(t)
	r := h.root()
	h.repo(r+"/p/shop", "git@github.com:example/shop.git")
	h.repo(r+"/elsewhere/shop", "git@github.com:example/shop.git")
	h.refusedAs(r+"/elsewhere/shop", "its origin says example/shop, which is pinned at "+r+"/p/shop, not "+r+"/elsewhere/shop")
	// A pin written Example/Billing is example/billing's: at its path it
	// names it, and anywhere else is refused.
	h.repo(r+"/p/billing", "git@github.com:example/billing.git")
	h.names(r+"/p/billing", "example/billing")
	h.repo(r+"/elsewhere/billing", "git@github.com:Example/Billing.git")
	h.refusedAs(r+"/elsewhere/billing", "its origin says example/billing, which is pinned at "+r+"/p/billing, not "+r+"/elsewhere/billing")
	h.fx.Run("-C", r+"/p/billing", "config", "remote.origin.url", "git@github.com:acme/app.git")
	h.refusedAs(r+"/p/billing", "is under "+r+"/p/billing, where example/billing is pinned, but its origin says acme/app")

	h.repo(r+"/forge", "git@github.com:example/shop.git")
	h.fx.Run("-C", r+"/forge", "config", "core.worktree", r+"/p/shop")
	h.refusedAs(r+"/forge", "core.worktree sends git to "+r+"/p/shop")
	write(t, r+"/evil/.git", "gitdir: "+r+"/p/shop/.git\n")
	h.refusedAs(r+"/evil", "which is not a worktree's")
	h.repo(r+"/p/shop/nested", "git@github.com:example/shop.git")
	h.refusedAs(r+"/p/shop/nested", "is a checkout of "+r+"/p/shop/nested, not of "+r+"/p/shop")
}

const dockerGrant = `{"bindings": {"docker": {"images": ["postgres:18"], "ports": [64320, 64321]}}}`

const shopLine = "Docker as example/shop at 127.101.170.171 (shop.internal, shop.example.internal), ports 64320 64321"

func (h *harness) dockerSaid(ws string) string {
	for _, l := range strings.Split(h.err, "\n") {
		if strings.HasPrefix(l, "chase: "+ws+": "+shopLine) {
			return l
		}
	}
	return ""
}

func (h *harness) addresses() string {
	b, err := os.ReadFile(h.dir + "/state/docker/addresses.json")
	if err != nil {
		return ""
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return "not JSON: " + string(b)
	}
	c, _ := json.Marshal(v)
	return string(c)
}

func (h *harness) stagedProject(machine string) any {
	d := h.stagedDoc(machine)
	if d == nil {
		return nil
	}
	return d["result"].(map[string]any)["dockerProject"]
}

// APPROVAL, of a grant that binds Docker: said beside the approval with
// its address and names, and which the host has; asked about once while it
// is unchanged, and again when its origin changes; recorded once.
func TestTheProjectIsApprovedBesideItsAddress(t *testing.T) {
	h := newIdentity(t)
	r := h.root()
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:Example/Shop.git")

	// No hosts file: the names are the session's, and the host has only the
	// address.
	h.approved(ws, "m1", "trusted", dockerGrant)
	if got := h.dockerSaid(ws); got != "chase: "+ws+": "+shopLine+"; on this host, 127.101.170.171 only" {
		t.Errorf("the approval did not say where Docker is: %s", h.err)
	}
	if got := h.stagedProject("m1"); got != "example/shop" {
		t.Errorf("the project was not staged: %v", got)
	}
	if n := len(h.approvals()); n != 1 {
		t.Errorf("the grant was asked about %d times", n)
	}
	if !strings.Contains(h.approvals()[0].Diff, `"dockerProject": "example/shop"`) {
		t.Errorf("the approval's diff does not show the project: %s", h.approvals()[0].Diff)
	}
	if got := h.addresses(); got != `{"example/shop":"127.101.170.171"}` {
		t.Errorf("the address was not recorded: %s", got)
	}

	// The host's names, where the hosts file gives this project them at this
	// address; the address alone where it gives them elsewhere, and only
	// those it gives. Approved again, the same project passes, is not asked
	// about, and is held once.
	write(t, h.cfg.Hosts, `{"example/shop": {"address": "127.101.170.171", "names": ["shop.internal", "shop.example.internal"]}}`)
	h.approved(ws, "m2", "trusted", dockerGrant)
	if got := h.dockerSaid(ws); got != "chase: "+ws+": "+shopLine {
		t.Errorf("the host's names were not recognised: %s", h.err)
	}
	if n := len(h.approvals()); n != 1 {
		t.Error("an unchanged grant was asked about again")
	}
	if got := h.addresses(); got != `{"example/shop":"127.101.170.171"}` {
		t.Errorf("the address is not held once: %s", got)
	}
	if n := strings.Count(read(t, h.dir+"/state/docker/addresses.json"), "example/shop"); n != 1 {
		t.Error("the project is recorded twice")
	}
	write(t, h.cfg.Hosts, `{"example/shop": {"address": "127.9.9.9", "names": ["shop.internal", "shop.example.internal"]}}`)
	h.approved(ws, "m3", "trusted", dockerGrant)
	if got := h.dockerSaid(ws); got != "chase: "+ws+": "+shopLine+"; on this host, 127.101.170.171 only" {
		t.Errorf("names at another address were taken as the host's: %s", h.err)
	}
	write(t, h.cfg.Hosts, `{"example/shop": {"address": "127.101.170.171", "names": ["shop.example.internal"]}}`)
	h.approved(ws, "m4", "trusted", dockerGrant)
	if got := h.dockerSaid(ws); got != "chase: "+ws+": "+shopLine+"; on this host, 127.101.170.171 and shop.example.internal only" {
		t.Errorf("a name the host lacks was taken as the host's: %s", h.err)
	}
	os.Remove(h.cfg.Hosts)

	// A changed origin is a changed grant, asked about again.
	app := r + "/w/scp"
	h.repo(app, "git@github.com:acme/app.git")
	h.approved(app, "m5", "trusted", dockerGrant)
	if n := len(h.approvals()); n != 2 {
		t.Error("acme/app was not asked about")
	}
	h.mustSay("chase: " + app + ": Docker as acme/app at ")
	h.fx.Run("-C", app, "remote", "set-url", "origin", "git@github.com:acme/app2.git")
	h.approved(app, "m6", "trusted", dockerGrant)
	envs := h.approvals()
	if len(envs) != 3 {
		t.Fatal("a changed origin was not asked about")
	}
	if d := envs[2].Diff; !strings.Contains(d, `-  "dockerProject": "acme/app"`) || !strings.Contains(d, `+  "dockerProject": "acme/app2"`) {
		t.Errorf("the diff does not show the origin's change: %s", d)
	}
	if got := h.stagedProject("m6"); got != "acme/app2" {
		t.Errorf("the new project was not staged: %v", got)
	}

	// The workspace is a path a session can name: the line beside the
	// approval says it with its control bytes made plain.
	esc := ws + "/x\x1b]0;PWNED\x07\x1b[8m"
	os.MkdirAll(esc, 0o755)
	h.approved(esc, "m13", "trusted", dockerGrant)
	h.mustSay("chase: " + ws + "/x?]0;PWNED??[8m: Docker as example/shop at 127.101.170.171")
	if strings.ContainsAny(h.err, "\x1b\x07") {
		t.Errorf("a control byte reached the terminal: %q", h.err)
	}
}

// A declined approval holds no address, and stages nothing.
func TestADeclinedProjectHoldsNoAddress(t *testing.T) {
	h := newIdentity(t)
	d := h.root() + "/w/declined"
	h.repo(d, "git@github.com:acme/declined.git")
	// Its source is approved, so what is declined is the grant, the
	// approval the address is recorded after.
	t.Setenv(refuseAll, "1")
	if h.approve(d, "m14", "trusted", dockerGrant) == 0 {
		t.Error("a declined grant was applied")
	}
	h.mustSay("chase: " + d + ": its grant was not approved")
	if h.isStaged("m14") {
		t.Error("a declined grant was staged")
	}
	if strings.Contains(h.addresses(), "acme/declined") {
		t.Errorf("a declined project holds its address: %s", h.addresses())
	}
}

// AN ADDRESS ANOTHER PROJECT HOLDS: in the approved addresses, or only in the
// host's map, or a pinned project's before it is ever approved. Refused,
// naming both, with nothing staged or recorded.
func TestAnAddressAnotherProjectHoldsIsRefused(t *testing.T) {
	h := newIdentity(t)
	r := h.root()
	ws := r + "/p/shop"
	h.repo(ws, "git@github.com:Example/Shop.git")

	write(t, h.dir+"/state/docker/addresses.json", `{"evil/x": "127.101.170.171"}`)
	if h.approve(ws, "m7", "trusted", dockerGrant) == 0 {
		t.Error("shop was approved at an address evil/x holds")
	}
	h.mustSay("chase: " + ws + ": example/shop would be at 127.101.170.171, which evil/x already holds")
	if h.isStaged("m7") {
		t.Error("a collision was staged")
	}
	if got := h.addresses(); got != `{"evil/x":"127.101.170.171"}` {
		t.Errorf("a collision was recorded: %s", got)
	}
	os.RemoveAll(h.dir + "/state/docker")
	write(t, h.cfg.Hosts, `{"evil/x": {"address": "127.101.170.171", "names": ["x.internal"]}}`)
	if h.approve(ws, "m8", "trusted", dockerGrant) == 0 {
		t.Error("shop was approved at an address the host gives evil/x")
	}
	h.mustSay("chase: " + ws + ": example/shop would be at 127.101.170.171, which evil/x already holds")
	if h.isStaged("m8") {
		t.Error("the host's collision was staged")
	}
	if got := h.addresses(); got != `{}` {
		t.Errorf("the host's collision was recorded: %s", got)
	}
	os.Remove(h.cfg.Hosts)

	// collide/x33613042, pinned, hashes to acme/app's address (found once,
	// offline), so acme/app is refused.
	app := r + "/w/scp"
	h.repo(app, "git@github.com:acme/app.git")
	h.cfg.Checkouts["collide/x33613042"] = []string{"/nowhere/collide"}
	os.RemoveAll(h.dir + "/state/docker")
	if h.approve(app, "m12", "trusted", dockerGrant) == 0 {
		t.Error("acme/app was approved at an address a pinned project holds")
	}
	h.mustSay("chase: " + app + ": acme/app would be at 127.95.137.218, which collide/x33613042 already holds")
	if h.isStaged("m12") {
		t.Error("the pinned project's collision was staged")
	}
}

// No usable origin, and Docker: nothing is applied. Without Docker, no
// project is named, or needed. What chase derives is not the grant's to
// say: a module's own dockerProject or secretsSHA256 is dropped, not staged.
func TestOnlyDockerNeedsAProject(t *testing.T) {
	h := newIdentity(t)
	none := h.root() + "/w/none"
	h.repo(none)
	if h.approve(none, "m9", "trusted", dockerGrant) == 0 {
		t.Error("a checkout with no origin was given Docker")
	}
	h.mustSay("exactly one origin URL")
	if h.isStaged("m9") {
		t.Error("a checkout with no origin was staged")
	}

	h.approved(none, "m10", "trusted", `{"bindings": {"github": {"allow": ["x"]}}}`)
	if _, has := h.stagedDoc("m10")["result"].(map[string]any)["dockerProject"]; has {
		t.Error("a grant without Docker gained a project")
	}
	if strings.Contains(h.err, "Docker as") {
		t.Errorf("a grant without Docker printed one: %s", h.err)
	}

	// What chase derives is never the grant's to say.
	for _, own := range []string{`"dockerProject": "example/shop"`, `"secretsSHA256": "0"`} {
		if h.approve(none, "m11", "trusted", `{`+own+`, "bindings": {"github": {"allow": ["x"]}}}`) == 0 {
			t.Errorf("a grant saying %s was approved", own)
		}
		if h.isStaged("m11") {
			t.Errorf("a grant saying %s was staged", own)
		}
	}
}
