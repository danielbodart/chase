package devshell

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/danielbodart/chase/internal/session"
)

const flakeNix = `{ outputs = { self }: { devShells.x86_64-linux.default = throw "evaluated"; }; }`

// A lock with one input from GitHub, pinned.
const githubLock = `{"nodes":{"root":{"inputs":{"nixpkgs":"nixpkgs"}},"nixpkgs":{"locked":{"lastModified":1,` +
	`"narHash":"sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","owner":"NixOS","repo":"nixpkgs",` +
	`"rev":"0123456789abcdef0123456789abcdef01234567","type":"github"},"original":{"owner":"NixOS","repo":"nixpkgs","type":"github"}}},"root":"root","version":7}`

// args is a nix run's arguments after c0.
func args(r run) []string { return r.Argv[1+len(c0):] }

// IN EVERY TIER, a devShell is the approved grant's to turn on, as
// `direnv allow` is: without it nothing of the checkout's is evaluated,
// what an earlier grant kept is let go, and a checkout that looks to have
// one -- a shell.nix, or a flake.nix that names devShells, read and never
// evaluated -- is told in a line what turns it on. One that does not is
// told nothing.
func TestThereIsNoDevShellWithoutTheGrant(t *testing.T) {
	for _, offline := range []bool{false, true} {
		h := newHarness(t)
		h.n.Offline = offline
		h.checkout(map[string]string{"shell.nix": "{}"})
		if ds, err := h.realise(); ds == nil || err != nil {
			t.Fatalf("offline %v, granted: %+v, %v: %s", offline, ds, err, h.said)
		}
		h.r.Granted = false
		h.clear()
		if ds, err := h.realise(); ds != nil || err != nil || h.runs("nix") != nil || h.runs("bwrap") != nil {
			t.Errorf("offline %v, not granted: %+v, %v, ran %d", offline, ds, err, len(h.runs("bwrap")))
		}
		if want := h.r.Workspace + `: its devShell is not given: the checkout's grant turns it on, with "apps": {"nix": {"devShell": true}}`; strings.Count(h.said, "\n") != 1 || !strings.Contains(h.said, want) {
			t.Errorf("offline %v: said %q", offline, h.said)
		}
		if _, err := os.Stat(h.r.Dir + "/devshell"); err == nil {
			t.Errorf("offline %v: what the grant had kept was kept without it", offline)
		}
	}
	for files, says := range map[string]bool{
		flakeNix:                true,
		`{ outputs = _: { }; }`: false,
		"":                      false,
	} {
		h := newHarness(t)
		h.r.Granted = false
		if files == "" {
			h.checkout(map[string]string{"README": "hi"})
		} else {
			h.checkout(map[string]string{"flake.nix": files})
		}
		if ds, err := h.realise(); ds != nil || err != nil || h.runs("bwrap") != nil || (h.said != "") != says {
			t.Errorf("%q: %+v, %v, ran %d, said %q", files, ds, err, len(h.runs("bwrap")), h.said)
		}
	}
}

// A checkout with neither file has no devShell, and nothing is run or
// said, a git checkout or not. One whose flake.nix is there and untracked
// is said to be, as nix develop says it, and not evaluated.
func TestACheckoutWithNoFlakeOrShellNixHasNoDevShell(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"README": "hi"})
	if err := os.WriteFile(h.r.Workspace+"/flake.nix", []byte(flakeNix), 0o644); err != nil {
		t.Fatal(err)
	}
	ds, err := h.realise()
	if ds != nil || err != nil || h.runs("nix") != nil {
		t.Errorf("an untracked flake.nix: %+v, %v, ran %d", ds, err, len(h.runs("nix")))
	}
	h.mustSay("flake.nix is not tracked by git, and nix evaluates what git tracks: `git add` it")
	os.Remove(h.r.Workspace + "/flake.nix")
	if ds, err := h.realise(); ds != nil || err != nil || h.said != "" {
		t.Errorf("no devShell: %+v, %v, said %q", ds, err, h.said)
	}
	if _, err := os.Stat(h.r.Dir + "/devshell"); err == nil {
		t.Error("a checkout with no devShell kept a directory for one")
	}
	h.r.Workspace = h.dir + "/w/plain"
	os.MkdirAll(h.r.Workspace, 0o755)
	if ds, err := h.realise(); ds != nil || err != nil || h.said != "" {
		t.Errorf("a plain directory: %+v, %v, said %q", ds, err, h.said)
	}
}

// A directory that is no git checkout has its flake.nix or shell.nix
// taken as it is, as nix develop and nix-shell take them there.
func TestADirectoryThatIsNoCheckoutIsTakenAsItIs(t *testing.T) {
	for _, kind := range []string{flake, shell} {
		h := newHarness(t)
		h.r.Workspace = h.dir + "/w/plain"
		os.MkdirAll(h.r.Workspace, 0o755)
		os.WriteFile(h.r.Workspace+"/"+kind, []byte("{}"), 0o644)
		if ds, err := h.realise(); ds == nil || err != nil {
			t.Errorf("%s: %+v, %v: %s", kind, ds, err, h.said)
		}
		h.mustSay("realising the devShell of " + kind)
	}
}

// flake.nix is the devShell's when the checkout has both, the checkout's
// own path its flake reference, as nix develop takes it there.
func TestAFlakeIsTakenOverAShellNix(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock, "shell.nix": "{}"})
	ds, err := h.realise()
	if err != nil || ds == nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	runs := h.runs("nix")
	if len(runs) != 1 {
		t.Fatalf("nix ran %d times", len(runs))
	}
	a := args(runs[0])
	if a[len(a)-1] != h.r.Workspace+"#devShells.x86_64-linux.default" {
		t.Errorf("evaluated %q", a)
	}
	h.mustSay("realising the devShell of flake.nix")
}

// NIX RUNS AS THE CALLER, WITH NOTHING OF THE CALLER'S: a HOME of chase's
// own, a PATH of nix and git alone, the daemon, the machine's CA bundle,
// and a shell.nix's NIX_PATH; its stdin /dev/null; the caller's nix, at
// its store path, with flakes and none of a flake's own configuration.
func TestNixRunsWithNothingOfTheCallers(t *testing.T) {
	for _, kind := range []string{flake, shell} {
		h := newHarness(t)
		t.Setenv("SECRET_OF_THE_CALLERS", "x")
		t.Setenv("NIXPKGS_ALLOW_UNFREE", "1")
		if kind == flake {
			h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
		} else {
			h.checkout(map[string]string{"shell.nix": "{}"})
		}
		if _, err := h.realise(); err != nil {
			t.Fatalf("%s: %v: %s", kind, err, h.said)
		}
		runs := h.runs("nix")
		if len(runs) != 1 {
			t.Fatalf("%s: nix ran %d times", kind, len(runs))
		}
		r := runs[0]
		want := []string{"HOME=" + h.r.State + "/devshell/home", "PATH=" + h.bin + ":" + filepath.Dir(h.n.Git), "NIX_REMOTE=daemon", "NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"}
		if kind == shell {
			want = append(want, "NIX_PATH=nixpkgs=/nix/store/nixpkgs-src:"+h.r.Workspace)
		}
		if !slices.Equal(r.Env, want) {
			t.Errorf("%s: nix's environment is %q, not %q", kind, r.Env, want)
		}
		if !r.Null {
			t.Errorf("%s: nix's stdin is not /dev/null", kind)
		}
		if !slices.Equal(r.Argv[1:1+len(c0)], c0) {
			t.Errorf("%s: nix was run as %q", kind, r.Argv)
		}
		if v, ok := optionValue(r.Argv, "accept-flake-config"); !ok || v != "false" {
			t.Errorf("%s: a flake's own configuration may be taken: %q", kind, r.Argv)
		}
	}
}

// A shell.nix is evaluated restricted, <nixpkgs> the system's own and the
// checkout the rest of its path, reaching https alone, told it is in a
// nix-shell; its environment rooted by a profile in chase's state.
func TestAShellNixIsEvaluatedRestrictedWithTheSystemsNixpkgsAndInNixShell(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"shell.nix": "{ inNixShell ? false }: {}"})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	a := args(h.runs("nix")[0])
	want := []string{"print-dev-env", "--json", "--profile", h.r.Dir + "/devshell/profile",
		"--option", "restrict-eval", "true", "--option", "allowed-uris", strings.Join(shellURIs, " "),
		"--arg", "inNixShell", "true", "-f", h.r.Workspace + "/shell.nix"}
	if !slices.Equal(a, want) {
		t.Errorf("a shell.nix was evaluated with %q, not %q", a, want)
	}
	for _, u := range shellURIs {
		if strings.HasPrefix(u, "path:") || strings.HasPrefix(u, "file:") {
			t.Errorf("a shell.nix may fetch %q", u)
		}
	}
}

// A flake is evaluated as nix develop evaluates it, purely, and its lock is
// never written.
func TestAFlakeIsEvaluatedPurelyItsLockNeverWritten(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"flake.nix": flakeNix})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	a := args(h.runs("nix")[0])
	want := []string{"print-dev-env", "--json", "--profile", h.r.Dir + "/devshell/profile",
		"--no-write-lock-file", h.r.Workspace + "#devShells.x86_64-linux.default"}
	if !slices.Equal(a, want) {
		t.Errorf("a flake was evaluated with %q, not %q", a, want)
	}
	if _, ok := optionValue(a, "pure-eval"); ok {
		t.Errorf("a flake's purity was changed: %q", a)
	}
}

// A checkout whose path nix would read as part of a flake reference is
// refused, never evaluated as something else.
func TestACheckoutWhosePathNixWouldMisreadIsRefused(t *testing.T) {
	h := newHarness(t)
	ws := h.dir + "/w/a#b"
	h.r.Workspace, h.r.Dir = ws, h.dir+"/state/checkouts/"+key(ws)
	h.checkout(map[string]string{"flake.nix": flakeNix})
	ds, err := h.realise()
	h.mustRefuse(ds, err, "nix would read the # or ? in "+ws+" as part of a flake reference")
	if h.runs("nix") != nil {
		t.Errorf("ran %d", len(h.runs("nix")))
	}

	// A shell.nix's checkout is an entry of NIX_PATH, which a : or an =
	// would make more of, every one of them readable under restrict-eval.
	h = newHarness(t)
	ws = h.dir + "/w/:x"
	h.r.Workspace, h.r.Dir = ws, h.dir+"/state/checkouts/"+key(ws)
	h.checkout(map[string]string{"shell.nix": "{}"})
	ds, err = h.realise()
	h.mustRefuse(ds, err, "nix would read the : or = in "+ws+" as part of NIX_PATH")
	if h.runs("nix") != nil {
		t.Errorf("ran %d", len(h.runs("nix")))
	}
}

// NIX IS CONFINED: a bubblewrap with nothing of the host's but the store,
// the daemon's socket, the machine's nix configuration and resolver, read
// -only, the checkout read-only -- the whole of it and its git, for a
// flake, and of a worktree its repository's git too -- and nix's own HOME
// and the devshell directory, writable. Never the caller's home, nor the
// rest of chase's state.
func TestNixIsConfinedToTheStoreTheDaemonAndTheCheckout(t *testing.T) {
	h := newHarness(t)
	main := h.dir + "/w/main"
	h.fx.Run("init", "-q", main)
	h.fx.Run("-C", main, "-c", "user.name=a", "-c", "user.email=a@example.com", "commit", "-q", "--allow-empty", "-m", "x")
	h.fx.Run("-C", main, "worktree", "add", "-q", h.r.Workspace)
	h.checkout(map[string]string{"flake.nix": flakeNix})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	runs := h.runs("bwrap")
	if len(runs) != 1 {
		t.Fatalf("bwrap ran %d times", len(runs))
	}
	argv := runs[0].Argv
	for _, flag := range []string{"--unshare-all", "--share-net", "--die-with-parent", "--new-session", "--clearenv"} {
		if !slices.Contains(argv[:slices.Index(argv, "--")], flag) {
			t.Errorf("bwrap is not told %s: %q", flag, argv)
		}
	}
	b := binds(argv)
	want := map[string][]string{
		"--ro-bind":     {"/nix/store", h.r.Workspace, main + "/.git", main + "/.git/worktrees/shop"},
		"--bind":        {"/nix/var/nix/daemon-socket", h.r.State + "/devshell/home", h.r.Dir + "/devshell"},
		"--ro-bind-try": {"/etc/nix", "/etc/static", "/etc/resolv.conf", "/etc/hosts"},
	}
	for how, paths := range want {
		if !slices.Equal(b[how], paths) {
			t.Errorf("%s is %q, not %q", how, b[how], paths)
		}
	}
	if args := argv[slices.Index(argv, "--")+1:]; args[0] != h.n.Nix {
		t.Errorf("bwrap runs %q, not nix", args)
	}

	// A shell.nix is shown its directory alone, all restrict-eval lets it
	// read.
	h = newHarness(t)
	h.checkout(map[string]string{"shell.nix": "{}"})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	if b := binds(h.runs("bwrap")[0].Argv); !slices.Equal(b["--ro-bind"], []string{"/nix/store", h.r.Workspace}) {
		t.Errorf("a shell.nix is shown %q", b["--ro-bind"])
	}
}

// THE CACHE: a second launch of the same files, with the same settings,
// runs no nix at all; a change to the lock, or to the nixpkgs a shell.nix
// is given, realises it again.
func TestTheDevShellIsCachedOnItsFilesAndItsEvaluation(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	first, err := h.realise()
	if err != nil || first == nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	h.clear()
	again, err := h.realise()
	if err != nil || again == nil || h.runs("nix") != nil {
		t.Fatalf("a second launch ran %d nix runs: %v", len(h.runs("nix")), err)
	}
	if strings.Contains(h.said, "realising") {
		t.Errorf("a cached devShell said %q", h.said)
	}
	for what, change := range map[string]func(){
		"the lock": func() {
			h.checkout(map[string]string{"flake.lock": strings.Replace(githubLock, `"lastModified":1`, `"lastModified":2`, 1)})
		},
		"the system": func() { h.n.System = "aarch64-linux" },
		"the nix":    func() { h.n.Nix = h.bin + "/./nix" },
	} {
		change()
		h.clear()
		if _, err := h.realise(); err != nil {
			t.Fatal(err)
		}
		if len(h.runs("nix")) != 1 {
			t.Errorf("a change to %s did not realise it again", what)
		}
	}
}

// Two launches of one checkout at once realise it once: the second waits
// for the first, and finds what it kept.
func TestTwoLaunchesOfOneCheckoutRealiseOnce(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"shell.nix": "{}"})
	b, _ := json.Marshal(h.k)
	os.WriteFile(h.bin+"/fake.json", b, 0o600)
	var wg sync.WaitGroup
	got := make([]*session.DevShell, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = Realise(context.Background(), h.n, h.r, &strings.Builder{})
		}()
	}
	wg.Wait()
	for i := range 2 {
		if errs[i] != nil || got[i] == nil || got[i].Path[0] != "/nix/store/hello/bin" {
			t.Errorf("launch %d: %+v, %v", i, got[i], errs[i])
		}
	}
	if n := len(h.runs("nix")); n != 1 {
		t.Errorf("realised %d times", n)
	}
}

// The GC root is the profile, in chase's state and never the checkout, and
// only its latest generation is kept.
func TestTheGCRootIsKeptInChasesStateAndOlderOnesAreLetGo(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"shell.nix": "{}"})
	for i := range 3 {
		h.checkout(map[string]string{"shell.nix": "{ n = " + strconv.Itoa(i) + "; }"})
		if _, err := h.realise(); err != nil {
			t.Fatal(err)
		}
	}
	links, _ := filepath.Glob(h.r.Dir + "/devshell/profile*")
	if !slices.Equal(links, []string{h.r.Dir + "/devshell/profile", h.r.Dir + "/devshell/profile-3-link"}) {
		t.Errorf("the profile's generations are %q", links)
	}
	if target, _ := os.Readlink(h.r.Dir + "/devshell/profile"); target != "profile-3-link" {
		t.Errorf("the profile is %q", target)
	}
	if found, _ := filepath.Glob(h.r.Workspace + "/*profile*"); found != nil {
		t.Errorf("the checkout holds %q", found)
	}
}

// A checkout that is gone has its devShell let go of at the next launch
// that wants one, of any checkout.
func TestADevShellWhoseCheckoutIsGoneIsSwept(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"shell.nix": "{}"})
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	gone := h.r.Dir + "/devshell"
	os.RemoveAll(h.r.Workspace)
	h.r.Workspace, h.r.Dir = h.dir+"/w/other", h.dir+"/state/checkouts/other"
	h.checkout(map[string]string{"shell.nix": "{}"})
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(gone); err == nil {
		t.Errorf("%s was kept", gone)
	}
}

// A devShell the grant turned on that could not be realised refuses the
// launch, saying how to launch without it, and is never kept: the next
// launch tries again, and once it is realised, it is cached.
func TestAFailureRefusesTheLaunchAndIsTriedAgainAtTheNext(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"shell.nix": "{}"})
	h.k.Fail, h.k.FailSaid = true, "error: undefined variable 'pkgs'"
	ds, err := h.realise()
	h.mustRefuse(ds, err, "undefined variable 'pkgs'")
	h.clear()
	ds, err = h.realise()
	h.mustRefuse(ds, err, "undefined variable 'pkgs'")
	if len(h.runs("nix")) != 1 {
		t.Error("a failure was not tried again at the next launch")
	}
	h.k.Fail = false
	h.clear()
	if ds, err := h.realise(); ds == nil || err != nil || len(h.runs("nix")) != 1 {
		t.Fatalf("fixed: %+v, %v, ran %d: %s", ds, err, len(h.runs("nix")), h.said)
	}
	h.clear()
	if ds, err := h.realise(); ds == nil || err != nil || h.runs("nix") != nil {
		t.Errorf("again: %+v, %v, ran %d", ds, err, len(h.runs("nix")))
	}
}

// A realisation that takes too long is killed, everything it started with
// it, and is a failure.
func TestARealisationThatTakesTooLongIsKilled(t *testing.T) {
	h := newHarness(t)
	h.n.Timeout = 1
	h.k.Sleep = 30
	h.checkout(map[string]string{"shell.nix": "{}"})
	start := time.Now()
	ds, err := h.realise()
	if time.Since(start) > 15*time.Second {
		t.Errorf("it took %v", time.Since(start))
	}
	h.mustRefuse(ds, err, "it took more than 1 s")
	b, err := os.ReadFile(h.k.Log + "/sleeper.pid")
	if err != nil {
		t.Fatal("the evaluation started nothing")
	}
	pid, _ := strconv.Atoi(string(b))
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatal("what the evaluation started is still running")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A flake with no devShell for the system has none, said once, and kept
// as none.
func TestAFlakeWithNoDefaultDevShellIsNoneAndSaidOnce(t *testing.T) {
	h := newHarness(t)
	h.k.NoDefault = true
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	if ds, err := h.realise(); ds != nil || err != nil {
		t.Fatalf("%+v, %v", ds, err)
	}
	h.mustSay("flake.nix has no devShells.x86_64-linux.default")
	if strings.Contains(h.said, "could not be realised") {
		t.Errorf("none was a failure: %s", h.said)
	}
	h.clear()
	if ds, err := h.realise(); ds != nil || err != nil || h.runs("nix") != nil || strings.Contains(h.said, "no devShells") {
		t.Errorf("again: %+v, %v, ran %d, said %q", ds, err, len(h.runs("nix")), h.said)
	}
}

// A flake.nix that is a link keys the cache on nothing nix is sure to read
// the same: refused, and not evaluated.
func TestAFlakeNixThatIsALinkIsRefused(t *testing.T) {
	h := newHarness(t)
	other := h.dir + "/other.nix"
	os.WriteFile(other, []byte(flakeNix), 0o600)
	h.fx.Run("init", "-q", h.r.Workspace)
	os.Symlink(other, h.r.Workspace+"/flake.nix")
	h.fx.Run("-C", h.r.Workspace, "add", "-A")
	ds, err := h.realise()
	h.mustRefuse(ds, err, "flake.nix: a link, not a file of the checkout's")
	if h.runs("nix") != nil {
		t.Errorf("ran %d", len(h.runs("nix")))
	}
}

// What nix says goes to the terminal cleaned: the checkout names what is
// in it.
func TestNixsOutputIsCleanedBeforeTheTerminal(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	h.k.Fail, h.k.FailSaid = true, "error: \u202eevil\x1b]0;title\x07"
	h.realise()
	if strings.ContainsAny(h.said, "\u202e\x1b\x07") {
		t.Errorf("said %q", h.said)
	}
	h.mustSay("?evil?]0;title?")
}

// THE ENVIRONMENT is the devShell's exports, less nix's own, those that
// steer the wrapper's bash and those that steer the agent, which are said;
// PATH and XDG_DATA_DIRS apart; and, for a hook, everything else declared
// as bash would, which bash reads back as it was.
func TestTheEnvironmentIsTheDevShellsExportsWithoutNixsOwn(t *testing.T) {
	doc := `{"bashFunctions":{"greet":"echo \"$greeting\"","cd":"builtin cd \"$@\""},"variables":{"shellHook":{"type":"exported","value":"greet"}}}`
	if _, _, err := parse([]byte(doc)); err == nil || err.Error() != "its functions would replace bash's own: cd" {
		t.Errorf("a function named for a builtin, with a hook: %v", err)
	}
	// With no hook, nothing is declared, nor so refused.
	if _, _, err := parse([]byte(strings.Replace(doc, `"value":"greet"`, `"value":""`, 1))); err != nil {
		t.Errorf("a function named for a builtin, with no hook: %v", err)
	}
	doc = `{"bashFunctions":{"greet":"echo \"$greeting\"","__chase_order":"x","bad name":"x"},"variables":{` +
		`"PATH":{"type":"exported","value":"/a/bin::/b/bin"},` +
		`"XDG_DATA_DIRS":{"type":"exported","value":"/a/share"},` +
		`"HOME":{"type":"exported","value":"/homeless-shelter"},` +
		`"SSL_CERT_FILE":{"type":"exported","value":"/no-cert-file.crt"},` +
		`"TMPDIR":{"type":"exported","value":"/build"},` +
		`"BASH_ENV":{"type":"exported","value":"/x"},` +
		`"BASH_COMPAT":{"type":"exported","value":"3.2"},` +
		`"EXECIGNORE":{"type":"exported","value":"*"},` +
		`"SHELL":{"type":"exported","value":"/nix/store/bash/bin/bash"},` +
		`"TERM":{"type":"exported","value":"xterm-256color"},` +
		`"HOSTTYPE":{"type":"exported","value":"x86_64"},` +
		`"ENV":{"type":"exported","value":"/x"},` +
		`"ANTHROPIC_BASE_URL":{"type":"exported","value":"https://evil.test"},` +
		`"NODE_OPTIONS":{"type":"exported","value":"--require x"},` +
		`"https_proxy":{"type":"exported","value":"http://x"},` +
		`"LD_LIBRARY_PATH":{"type":"exported","value":"/a/lib"},` +
		`"IN_NIX_SHELL":{"type":"exported","value":"impure"},` +
		`"NUL":{"type":"exported","value":"a\u0000b"},` +
		`"__chase_front":{"type":"exported","value":"x"},` +
		`"shellHook":{"type":"exported","value":"greet"},` +
		`"greeting":{"type":"var","value":"it's \"quoted\" $(not run)"},` +
		`"parts":{"type":"array","value":["a b","c'd"]},` +
		`"map":{"type":"associative","value":{"k 1":"v'1"}},` +
		`"BASHPID":{"type":"var","value":"1"},` +
		`"LINENO":{"type":"var","value":"1"}}}`
	ds, dropped, err := parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, v := range ds.Env {
		env = append(env, v.Name+"="+v.Value)
	}
	if want := []string{"IN_NIX_SHELL=impure", "LD_LIBRARY_PATH=/a/lib", "shellHook=greet"}; !slices.Equal(env, want) {
		t.Errorf("Env is %q, not %q", env, want)
	}
	if !slices.Equal(ds.Path, []string{"/a/bin", "/b/bin"}) || !slices.Equal(ds.DataDirs, []string{"/a/share"}) || ds.Hook != "greet" {
		t.Errorf("Path %q, DataDirs %q, Hook %q", ds.Path, ds.DataDirs, ds.Hook)
	}
	if want := []string{"ANTHROPIC_BASE_URL", "NODE_OPTIONS", "https_proxy"}; !slices.Equal(dropped, want) {
		t.Errorf("dropped %q, not %q", dropped, want)
	}
	// What is declared reads back, through bash, as it was.
	script := strings.Join(ds.Declarations, "\n") + "\n" + `greet; printf '%s|' "${parts[@]}" "${map[k 1]}"; declare -F | wc -l`
	bash := realBash(t)
	out, err := bashOutput(bash, script)
	if err != nil {
		t.Fatalf("%v: %s", err, script)
	}
	if want := "it's \"quoted\" $(not run)\na b|c'd|v'1|1\n"; out != want {
		t.Errorf("the declarations read back as %q, not %q", out, want)
	}
	// No hook, nothing to declare.
	ds, _, _ = parse([]byte(strings.Replace(doc, `"value":"greet"`, `"value":""`, 1)))
	if ds.Declarations != nil || ds.Hook != "" {
		t.Errorf("a devShell with no hook declares %q", ds.Declarations)
	}
}

// One larger than a launch carries is a failure, not a launch flong or
// the kernel refuses.
func TestADevShellLargerThanALaunchCarriesIsAFailure(t *testing.T) {
	h := newHarness(t)
	big := strings.Repeat("x", 200<<10)
	h.k.Env = `{"bashFunctions":{},"variables":{"BIG":{"type":"exported","value":"` + big + `"}}}`
	h.checkout(map[string]string{"shell.nix": "{}"})
	ds, err := h.realise()
	h.mustRefuse(ds, err, "more than a launch carries")
	if _, _, err := parse([]byte(h.k.Env)); err == nil || !strings.Contains(err.Error(), "its environment is 204804 bytes") {
		t.Errorf("%v", err)
	}
}

// A launch that is stopped while its devShell is realised -- Ctrl-C, a
// SIGTERM -- is stopped, never launched without it, and nothing of it is
// kept: the next launch realises it, rather than taking it for a failure.
func TestAStoppedLaunchIsNotAFailure(t *testing.T) {
	h := newHarness(t)
	h.k.Sleep = 30
	h.checkout(map[string]string{"shell.nix": "{}"})
	b, _ := json.Marshal(h.k)
	os.WriteFile(h.bin+"/fake.json", b, 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	ds, err := Realise(ctx, h.n, h.r, &strings.Builder{})
	if ds != nil || err == nil || !strings.Contains(err.Error(), "the launch was stopped") {
		t.Errorf("a stopped launch: %+v, %v", ds, err)
	}
	if _, err := os.Stat(h.r.Dir + "/devshell/state.json"); err == nil {
		t.Error("a stopped launch was kept")
	}
	h.k.Sleep = 0
	h.clear()
	if ds, err := h.realise(); ds == nil || err != nil {
		t.Errorf("the next launch: %+v, %v: %s", ds, err, h.said)
	}
}

// A flake.nix git does not track is not taken over a shell.nix, and is
// said.
func TestAnUntrackedFlakeIsSaidAndTheShellNixTaken(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"shell.nix": "{}"})
	os.WriteFile(h.r.Workspace+"/flake.nix", []byte(flakeNix), 0o644)
	if ds, err := h.realise(); ds == nil || err != nil {
		t.Fatalf("%+v, %v", ds, err)
	}
	h.mustSay("flake.nix is not tracked by git")
	if r := h.runs("nix"); len(r) != 1 || !strings.HasSuffix(r[0].Argv[len(r[0].Argv)-1], "/shell.nix") {
		t.Errorf("evaluated %v", r)
	}
}

// A profile that is not the one state.json recorded -- a launch killed
// between switching it and writing state.json -- is not taken for it.
func TestAProfileOfAnotherRealisationIsNotTaken(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"shell.nix": "{}"})
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	other := h.k.Store + "/other-env"
	os.WriteFile(other, []byte(envJSON), 0o444)
	os.Remove(h.r.Dir + "/devshell/profile")
	os.Symlink(other, h.r.Dir+"/devshell/profile")
	h.clear()
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	if len(h.runs("nix")) != 1 {
		t.Error("another realisation's profile was taken")
	}
}

// What the devShell gives that steers the agent is said, by name, when it
// is left out.
func TestWhatIsNotGivenToTheAgentIsSaid(t *testing.T) {
	h := newHarness(t)
	h.k.Env = strings.Replace(envJSON, `"variables":{`, `"variables":{"NODE_OPTIONS":{"type":"exported","value":"--x"},"ANTHROPIC_BASE_URL":{"type":"exported","value":"https://x"},`, 1)
	h.checkout(map[string]string{"shell.nix": "{}"})
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	h.mustSay("the devShell's ANTHROPIC_BASE_URL, NODE_OPTIONS are not given to the agent")
}

// A failure that most devShells working with nix develop and not here have
// in common is told what to do about it.
func TestAFailureTheCleanEnvironmentExplainsIsHinted(t *testing.T) {
	h := newHarness(t)
	h.checkout(map[string]string{"shell.nix": "{}"})
	h.k.Fail, h.k.FailSaid = true, "error: Package 'slack' has an unfree license, refusing to evaluate."
	ds, err := h.realise()
	h.mustRefuse(ds, err, "refusing to evaluate.; the evaluation sees none of your environment, nor your home: set config.allowUnfree in the import, and give private inputs access-tokens in the machine's nix configuration")
}
