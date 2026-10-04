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

// A checkout that tracks neither file has no devShell, and nothing is run
// or said: nor does one that is not a git checkout at all. One whose
// flake.nix is there and untracked is said to be, as nix develop says it.
func TestACheckoutThatTracksNoFlakeOrShellNixHasNoDevShell(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"README": "hi"})
	if err := os.WriteFile(h.r.Workspace+"/flake.nix", []byte(flakeNix), 0o644); err != nil {
		t.Fatal(err)
	}
	ds, err := h.realise()
	if ds != nil || err != nil || h.runs("nix") != nil {
		t.Errorf("an untracked flake.nix: %+v, %v, ran %d", ds, err, len(h.runs("nix")))
	}
	h.mustSay("flake.nix is not tracked by git, and what is evaluated is what git tracks: `git add` it")
	os.Remove(h.r.Workspace + "/flake.nix")
	if ds, err := h.realise(); ds != nil || err != nil || h.said != "" {
		t.Errorf("no devShell: %+v, %v, said %q", ds, err, h.said)
	}
	if _, err := os.Stat(h.r.Dir + "/devshell"); err == nil {
		t.Error("a checkout with no devShell kept a directory for one")
	}
	// Not a checkout, and nothing there: nothing said either.
	h.r.Workspace = h.dir + "/w/plain"
	os.MkdirAll(h.r.Workspace, 0o755)
	if ds, err := h.realise(); ds != nil || err != nil || h.said != "" {
		t.Errorf("a plain directory: %+v, %v, said %q", ds, err, h.said)
	}
	// Not a checkout, with a shell.nix: said, since it would have one.
	os.WriteFile(h.r.Workspace+"/shell.nix", []byte("{}"), 0o644)
	if ds, err := h.realise(); ds != nil || err != nil {
		t.Errorf("a plain directory with a shell.nix: %+v, %v", ds, err)
	}
	h.mustSay("the devShell could not be realised, and the session starts without it: what is evaluated is what git tracks, and " + h.r.Workspace + " is not a git checkout")
}

// flake.nix is the devShell's when the checkout has both.
func TestAFlakeIsTakenOverAShellNix(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock, "shell.nix": "{}"})
	ds, err := h.realise()
	if err != nil || ds == nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	a := h.step("derivation", "show")
	bw := h.runs("bwrap")[0].Argv
	if len(a) != 1 || bw[len(bw)-1] != "path:/src/shop#devShells.x86_64-linux.default" {
		t.Errorf("evaluated %q", bw)
	}
	h.mustSay("realising the devShell of flake.nix")
	if a[0].Lazy != flakeNix {
		t.Errorf("what was evaluated read %q", a[0].Lazy)
	}
}

// EVERY NIX RUN IS CONFINED: bubblewrap, with nothing of the host's but
// the store, the daemon's socket, nix's own configuration, the snapshot
// and nix's HOME, /tmp a tmpfs before any of it; and nothing of the
// caller's environment, nor its stdin.
func TestEveryNixRunsConfinedWithNothingOfTheCallers(t *testing.T) {
	for _, kind := range []string{"flake", "shell"} {
		h := newHarness(t, "direct")
		t.Setenv("SECRET_OF_THE_CALLERS", "x")
		if kind == "flake" {
			h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
		} else {
			h.checkout(map[string]string{"shell.nix": "{}"})
		}
		if _, err := h.realise(); err != nil {
			t.Fatalf("%s: %v: %s", kind, err, h.said)
		}
		bw := h.runs("bwrap")
		if len(bw) != 2 {
			t.Fatalf("%s: bwrap ran %d times", kind, len(bw))
		}
		for i, r := range bw {
			argv := r.Argv[1:]
			at := slices.Index(argv, "--")
			opts := argv[:at]
			if len(r.Env) != 0 {
				t.Errorf("%s: bwrap was given the caller's environment: %q", kind, r.Env)
			}
			if !r.Null {
				t.Errorf("%s: bwrap's stdin is not /dev/null", kind)
			}
			if tmp := slices.Index(opts, "--tmpfs"); tmp < 0 || slices.ContainsFunc(opts[:tmp], func(o string) bool { return strings.Contains(o, "bind") }) {
				t.Errorf("%s: /tmp is not a tmpfs before every bind: %q", kind, opts)
			}
			var binds []string
			for j, o := range opts {
				if o == "--ro-bind" || o == "--bind" {
					binds = append(binds, o+" "+opts[j+1]+" "+opts[j+2])
				}
			}
			want := []string{
				"--ro-bind /nix/store /nix/store",
				"--bind /nix/var/nix/daemon-socket /nix/var/nix/daemon-socket",
				"--ro-bind /etc/nix /etc/nix",
				"--ro-bind /etc/static /etc/static",
			}
			if i == 0 { // A, with a network in a direct tier
				want = append(want, "--ro-bind "+h.r.State+"/nix/resolv.conf /etc/resolv.conf")
			}
			snap := binds[len(want)]
			if !strings.HasPrefix(snap, "--ro-bind "+h.r.Dir+"/devshell-snapshot.") || !strings.HasSuffix(snap, " /src/shop") {
				t.Errorf("%s: the snapshot is bound as %q", kind, snap)
			}
			want = append(want, snap, "--bind "+h.r.State+"/nix/direct /home/nix")
			if i == 1 { // C, which roots the profile
				want = append(want, "--bind "+h.r.Dir+"/devshell "+h.r.Dir+"/devshell")
			}
			if !slices.Equal(binds, want) {
				t.Errorf("%s: step %d binds %q, not %q", kind, i, binds, want)
			}
			var env []string
			for j, o := range opts {
				if o == "--setenv" {
					env = append(env, opts[j+1]+"="+opts[j+2])
				}
			}
			wantEnv := []string{"HOME=/home/nix", "PATH=" + h.bin, "NIX_REMOTE=daemon", "NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"}
			if kind == "shell" {
				wantEnv = append(wantEnv, "NIX_PATH=nixpkgs=/nix/store/nixpkgs-src:/src/shop")
			}
			if !slices.Equal(env, wantEnv) || !slices.Contains(opts, "--clearenv") || !slices.Contains(opts, "--unshare-all") {
				t.Errorf("%s: step %d's environment is %q", kind, i, env)
			}
			if !slices.Equal(argv[at+1:at+2+len(c0)], append([]string{h.n.Nix}, c0...)) {
				t.Errorf("%s: step %d runs %q", kind, i, argv[at+1:])
			}
		}
		for _, r := range h.runs("nix") {
			if slices.ContainsFunc(r.Env, func(e string) bool { return strings.HasPrefix(e, "SECRET_OF_THE_CALLERS=") }) {
				t.Errorf("%s: nix was given the caller's environment", kind)
			}
		}
	}
}

// Only the steps that fetch have a network: a direct tier's evaluation,
// and a filtered tier's prefetch of its lock. pasta keeps the host's
// loopback and gateway out, and forwards no port either way.
func TestOnlyADirectTiersEvaluationHasANetwork(t *testing.T) {
	for egress, networked := range map[string][]string{"direct": {"derivation"}, "frisket": {"flake"}} {
		h := newHarness(t, egress)
		h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
		if _, err := h.realise(); err != nil {
			t.Fatalf("%s: %v: %s", egress, err, h.said)
		}
		pasta := h.runs("pasta")
		if len(pasta) != 1 {
			t.Fatalf("%s: pasta ran %d times", egress, len(pasta))
		}
		argv := pasta[0].Argv
		at := slices.Index(argv, "--")
		if !slices.Equal(argv[1:at], []string{"--quiet", "--config-net", "--no-map-gw", "-t", "none", "-u", "none", "-T", "none", "-U", "none", "--dns-forward", "169.254.1.1"}) {
			t.Errorf("%s: pasta was run as %q", egress, argv)
		}
		if argv[at+1] != h.n.Bwrap || !slices.Contains(argv, "--share-net") {
			t.Errorf("%s: pasta ran %q", egress, argv[at+1:])
		}
		var shared []string
		for _, r := range h.runs("bwrap") {
			if slices.Contains(r.Argv, "--share-net") {
				nix := r.Argv[slices.Index(r.Argv, "--")+2+len(c0)]
				shared = append(shared, nix)
			}
		}
		if !slices.Equal(shared, networked) {
			t.Errorf("%s: the steps with a network are %q, not %q", egress, shared, networked)
		}
	}
}

// A shell.nix is evaluated restricted, <nixpkgs> the system's own and the
// checkout's snapshot the rest of its path, told it is in a nix-shell.
func TestAShellNixIsEvaluatedRestrictedWithTheSystemsNixpkgsAndInNixShell(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"shell.nix": "{ inNixShell ? false }: {}"})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	a := h.step("derivation", "show")
	if len(a) != 1 {
		t.Fatalf("evaluated %d times", len(a))
	}
	// As bwrap was told it, before it mapped /src/shop to the snapshot.
	bw := h.runs("bwrap")[0].Argv
	args := bw[slices.Index(bw, "--")+2+len(c0):]
	want := []string{"derivation", "show", "--arg", "inNixShell", "true", "--option", "restrict-eval", "true",
		"--option", "allowed-uris", strings.Join(directURIs, " "), "-f", "/src/shop/shell.nix"}
	if !slices.Equal(args, want) {
		t.Errorf("a shell.nix was evaluated with %q, not %q", args, want)
	}
	// The fake bwrap maps /src/shop back to the snapshot it binds there.
	if !slices.ContainsFunc(a[0].Env, func(e string) bool {
		return strings.HasPrefix(e, "NIX_PATH=nixpkgs=/nix/store/nixpkgs-src:"+h.r.Dir+"/devshell-snapshot.")
	}) {
		t.Errorf("NIX_PATH is not the system's nixpkgs and the snapshot: %q", a[0].Env)
	}
	if a[0].Lazy != "{ inNixShell ? false }: {}" {
		t.Errorf("what was evaluated read %q (%s)", a[0].Lazy, a[0].Error)
	}
}

// A flake is evaluated restricted too, in either tier, never updating its
// lock.
func TestAFlakeIsEvaluatedRestrictedInEveryTier(t *testing.T) {
	for _, egress := range []string{"direct", "frisket"} {
		h := newHarness(t, egress)
		h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
		if _, err := h.realise(); err != nil {
			t.Fatalf("%s: %v: %s", egress, err, h.said)
		}
		a := h.step("derivation", "show")[0].Argv
		if v, _ := optionValue(a, "restrict-eval"); v != "true" || !slices.Contains(a, "--no-update-lock-file") {
			t.Errorf("%s: a flake was evaluated with %q", egress, a)
		}
	}
}

// What a filtered tier's evaluation may name is never a path or a git
// repository, whatever the allowlist: a path is the host's, and a git
// repository's submodules may name any host.
func TestNoPathOrGitSchemeIsEverAnAllowedURIInAFilteredTier(t *testing.T) {
	for _, allow := range [][]string{{"*"}, {"github.com", "example.com"}, {"*.example.com"}, nil} {
		uris, _ := allowedURIs(allow)
		for _, u := range uris {
			if strings.HasPrefix(u, "path:") || strings.HasPrefix(u, "git+") || strings.HasPrefix(u, "git:") || strings.HasPrefix(u, "file:") {
				t.Errorf("%q allows %q", allow, u)
			}
		}
	}
}

// A filtered tier's evaluation reaches only what the session's allowlist
// holds, exact names alone, with no network and no build of its own; a
// "*.suffix" cannot be said, and is said so.
func TestAFilteredTierEvaluatesReachingOnlyTheSessionsAllowlist(t *testing.T) {
	h := newHarness(t, "frisket")
	h.policy("github.com", "pypi.org", "*.foo.com")
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	a := h.step("derivation", "show")[0].Argv
	uris, _ := optionValue(a, "allowed-uris")
	if want := "file+https://github.com/ file+https://pypi.org/ github: https://github.com/ https://pypi.org/ tarball+https://github.com/ tarball+https://pypi.org/"; uris != want {
		t.Errorf("allowed-uris is %q, not %q", uris, want)
	}
	if option(a, "--max-jobs") != "0" {
		t.Errorf("the evaluation may build: %q", a)
	}
	h.mustSay("the devShell's evaluation fetches from none of *.foo.com: allowed-uris holds exact names only")
}

// "*" is a direct tier's reach less git's.
func TestAnAllowlistOfEveryNameIsADirectTiersReachLessGit(t *testing.T) {
	uris, unsaid := allowedURIs([]string{"*", "*.foo.com"})
	if want := []string{"file+https://", "github:", "gitlab:", "https://", "sourcehut:", "tarball+https://"}; !slices.Equal(uris, want) || unsaid != nil {
		t.Errorf("* allows %q, leaving out %q", uris, unsaid)
	}
}

// A LOCK'S NODES ARE FETCHED BY CHASE, from URLs it builds from the
// node's own fields, each pinned by its narHash, and only where the
// allowlist holds the host; a relative path is in the snapshot already.
func TestALocksNodesArePrefetchedByChaseFromWhatTheAllowlistHolds(t *testing.T) {
	h := newHarness(t, "frisket")
	h.policy("github.com", "releases.example.org")
	lock := `{"nodes":{"root":{"inputs":{"a":"a","b":"b","c":"c"}},` +
		`"a":{"locked":{"narHash":"sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","owner":"NixOS","repo":"nixpkgs","rev":"0123456789abcdef0123456789abcdef01234567","type":"github"}},` +
		`"b":{"locked":{"narHash":"sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=","type":"tarball","url":"https://releases.example.org/x.tar.gz"}},` +
		`"c":{"locked":{"path":"./sub","type":"path"},"parent":[]}},"root":"root","version":7}`
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": lock, "sub/flake.nix": "{}"})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	var fetched []string
	for _, r := range h.step("flake", "prefetch") {
		fetched = append(fetched, r.Argv[len(r.Argv)-1])
	}
	want := []string{
		"github:NixOS/nixpkgs/0123456789abcdef0123456789abcdef01234567?narHash=sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB%3D",
		"tarball+https://releases.example.org/x.tar.gz?narHash=sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC%3D",
	}
	if !slices.Equal(fetched, want) {
		t.Errorf("prefetched %q, not %q", fetched, want)
	}
	// The same nix HOME as the evaluation's, whose fetcher cache it reads.
	for _, r := range h.runs("nix") {
		if !slices.ContainsFunc(r.Env, func(v string) bool { return strings.HasPrefix(v, "HOME="+h.r.State+"/nix/frisket-") }) {
			t.Errorf("a step's HOME is not the filtered tiers': %q", r.Env)
		}
	}
	// A host the allowlist does not hold refuses it, naming the hosts, and
	// in a recording says how a grant would admit them.
	h.policy("pypi.org")
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	h.mustSay("flake.lock fetches from names the session's allowlist does not hold: github.com, releases.example.org")
	h.r.Recording = true
	h.realise()
	h.mustSay("does not hold: github.com, releases.example.org: `network.allow` in its chase.jsonc admits them")
}

// What could name any host -- a forge's ?host=, a git repository, a
// registry's name, a path on the host -- is fetched by nothing.
func TestALockNodeWithAHostOrOfTypeGitOrAnAbsolutePathIsRefused(t *testing.T) {
	for locked, said := range map[string]string{
		`{"narHash":"sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","owner":"o","repo":"r","rev":"0123456789abcdef0123456789abcdef01234567","type":"github","host":"example.org"}`:   "a github archive from example.org",
		`{"narHash":"sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","rev":"0123456789abcdef0123456789abcdef01234567","type":"git","url":"https://github.com/o/r","submodules":true}`: "a lock node of type git, fetched by nothing in a filtered tier: its submodules may name any host",
		`{"path":"/home/alice/.ssh","type":"path"}`:                                  "a path on the host",
		`{"id":"nixpkgs","type":"indirect"}`:                                         "a lock node of type indirect",
		`{"type":"tarball","url":"http://github.com/x.tar.gz","narHash":"sha256-x"}`: "which is not https://<name>/",
	} {
		lock := `{"nodes":{"root":{"inputs":{"a":"a"}},"a":{"locked":` + locked + `}},"root":"root","version":7}`
		if _, err := prefetchOf([]byte(lock), []string{"*"}); err == nil || !strings.Contains(err.Error(), said) {
			t.Errorf("%s: %v", locked, err)
		}
	}
}

// A FILTERED TIER BUILDS NOTHING BUT THE ENVIRONMENT: the inputs come from
// the binary caches alone, rooted until the environment is made, and let
// go of after; then the -env derivation, built in the daemon's sandbox.
func TestAFilteredTierBuildsNothingButTheEnvironment(t *testing.T) {
	h := newHarness(t, "frisket")
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	b := h.step("build")
	if len(b) != 1 {
		t.Fatalf("built %d times", len(b))
	}
	args := b[0].Argv[1+len(c0):]
	if want := []string{"build", "--max-jobs", "0", "--out-link", h.r.Dir + "/devshell/inputs", "/nix/store/bbbb-hello.drv^dev,out"}; !slices.Equal(args, want) {
		t.Errorf("the inputs were built with %q, not %q", args, want)
	}
	c := h.step("print-dev-env")[0].Argv[1+len(c0):]
	if want := []string{"print-dev-env", "--json", "--profile", h.r.Dir + "/devshell/profile", "--max-jobs", "1", "--option", "max-silent-time", "600", "/nix/store/aaaa-nix-shell.drv^*"}; !slices.Equal(c, want) {
		t.Errorf("the environment was made with %q, not %q", c, want)
	}
	if links, _ := filepath.Glob(h.r.Dir + "/devshell/inputs*"); links != nil {
		t.Errorf("the inputs are still rooted: %q", links)
	}
	// A cache that does not have one is a failure, said.
	h.k.FailStep, h.k.FailSaid = "B", "error: a 'x86_64-linux' with features {} is required to build '/nix/store/bbbb-hello.drv', but I am a 'x86_64-linux' and local builds are disabled"
	h.policy("github.com", "example.org")
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	h.mustSay("local builds are disabled")
}

// A direct tier's realisation builds what it must, locally: no inputs
// step, and no limit on the daemon.
func TestADirectTierRealisesWithLocalBuilds(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	if h.step("build") != nil || h.step("flake", "prefetch") != nil {
		t.Error("a direct tier prefetched or built inputs")
	}
	for _, r := range h.runs("nix") {
		if slices.Contains(r.Argv, "--max-jobs") {
			t.Errorf("a direct tier limited builds: %q", r.Argv)
		}
	}
}

// What a flake says of nix's own configuration, the registries that name a
// flake, and an update to its lock are never taken.
func TestAFlakesConfigRegistriesAndLockAreNeverTaken(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	for _, r := range h.runs("nix") {
		for name, want := range map[string]string{"accept-flake-config": "false", "use-registries": "false", "flake-registry": ""} {
			if v, ok := optionValue(r.Argv, name); !ok || v != want {
				t.Errorf("%s is %q in %q", name, v, r.Argv)
			}
		}
	}
	if !slices.Contains(h.step("derivation", "show")[0].Argv, "--no-update-lock-file") {
		t.Error("the evaluation may update the lock")
	}
}

// A devShell built outside the daemon's sandbox, or with what it is not
// given, is refused before anything of it is built.
func TestADevShellAskingForAnUnsandboxedBuildIsRefused(t *testing.T) {
	for _, env := range []string{`"__noChroot":"1"`, `"__impure":"1"`, `"requiredSystemFeatures":"kvm recursive-nix"`, `"__json":"{\"requiredSystemFeatures\":[\"uid-range\"]}"`} {
		h := newHarness(t, "direct")
		h.k.Derivation = `{"derivations":{"aaaa-nix-shell.drv":{"env":{` + env + `},"inputs":{"drvs":{},"srcs":[]}}},"version":4}`
		h.checkout(map[string]string{"shell.nix": "{}"})
		h.realise()
		h.mustSay("the devShell asks nix for what a sandboxed build is not given")
		if h.step("print-dev-env") != nil {
			t.Errorf("%s: it was built", env)
		}
	}
	if _, _, err := derivationOf([]byte(`{"/nix/store/aaaa.drv":{"env":{},"inputDrvs":{"/nix/store/b.drv":["out"]}}}`)); err != nil {
		t.Errorf("a derivation as nix printed one before 2.33: %v", err)
	}
	if _, _, err := derivationOf([]byte(`{"derivations":{}}`)); err == nil || !strings.Contains(err.Error(), "0 derivations") {
		t.Errorf("no derivation: %v", err)
	}
}

// THE CACHE: a second launch of the same files, with the same settings,
// runs no nix at all; a change to the lock, to the tier's egress or to the
// session's allowlist each realise it again.
func TestTheDevShellIsCachedOnItsFilesAndItsEvaluation(t *testing.T) {
	h := newHarness(t, "frisket")
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	first, err := h.realise()
	if err != nil || first == nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	h.clear()
	again, err := h.realise()
	if err != nil || again == nil || h.runs("nix") != nil || h.runs("bwrap") != nil {
		t.Fatalf("a second launch ran %d nix runs: %v", len(h.runs("nix")), err)
	}
	if strings.Contains(h.said, "realising") {
		t.Errorf("a cached devShell said %q", h.said)
	}
	for what, change := range map[string]func(){
		"the lock": func() {
			h.checkout(map[string]string{"flake.lock": strings.Replace(githubLock, `"lastModified":1`, `"lastModified":2`, 1)})
		},
		"the egress":    func() { h.n.Egress = "direct" },
		"the allowlist": func() { h.n.Egress = "frisket"; h.policy("github.com", "example.org") },
	} {
		_ = what
		change()
		h.clear()
		if _, err := h.realise(); err != nil {
			t.Fatal(err)
		}
		if len(h.step("derivation", "show")) != 1 {
			t.Errorf("a change to %s did not realise it again", what)
		}
	}
}

// Two launches of one checkout at once realise it once: the second waits
// for the first, and finds what it kept.
func TestTwoLaunchesOfOneCheckoutRealiseOnce(t *testing.T) {
	h := newHarness(t, "direct")
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
	if n := len(h.step("derivation", "show")); n != 1 {
		t.Errorf("evaluated %d times", n)
	}
}

// The GC root is the profile, in chase's state and never the checkout, and
// only its latest generation is kept.
func TestTheGCRootIsKeptInChasesStateAndOlderOnesAreLetGo(t *testing.T) {
	h := newHarness(t, "direct")
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
	h := newHarness(t, "direct")
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

// A devShell that could not be realised, given automatically, is not
// tried again for an hour; one a grant asks for is tried at every launch.
func TestAnAutomaticFailureIsCachedForAnHourAndAGrantedOneNever(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"shell.nix": "{}"})
	h.k.FailStep, h.k.FailSaid = "A", "error: undefined variable 'pkgs'"
	if ds, err := h.realise(); ds != nil || err != nil {
		t.Fatalf("%+v, %v", ds, err)
	}
	h.mustSay("could not be realised, and the session starts without it: undefined variable 'pkgs'")
	h.clear()
	h.realise()
	if h.runs("nix") != nil {
		t.Error("a failure was tried again within the hour")
	}
	h.mustSay("(as at ")
	defer func(f func() time.Time) { now = f }(now)
	now = func() time.Time { return time.Now().Add(61 * time.Minute) }
	h.realise()
	if len(h.runs("nix")) != 1 {
		t.Error("a failure an hour old was not tried again")
	}
	h.clear()
	h.r.Asked = yes()
	if _, err := h.realise(); err == nil || len(h.runs("nix")) != 1 {
		t.Errorf("a granted devShell was not tried again: %v", err)
	}
}

// A realisation that takes too long is killed, everything it started with
// it, and is a failure.
func TestARealisationThatTakesTooLongIsKilled(t *testing.T) {
	h := newHarness(t, "direct")
	h.n.Timeout = 1
	h.k.Sleep = 30
	h.checkout(map[string]string{"shell.nix": "{}"})
	start := time.Now()
	h.realise()
	if time.Since(start) > 15*time.Second {
		t.Errorf("it took %v", time.Since(start))
	}
	h.mustSay("it took more than 1 s")
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

// Given automatically, a devShell that fails at any step is said, and the
// session starts without it.
func TestAnAutomaticDevShellThatFailsIsSaidAndLeftOut(t *testing.T) {
	for _, step := range []string{"P", "A", "B", "C"} {
		h := newHarness(t, "frisket")
		h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
		h.k.FailStep, h.k.FailSaid = step, "error: step "+step+" failed"
		ds, err := h.realise()
		if ds != nil || err != nil {
			t.Errorf("%s: %+v, %v", step, ds, err)
		}
		h.mustSay("the devShell could not be realised, and the session starts without it")
		h.mustSay("step " + step + " failed")
	}
}

// One a grant asks for that fails refuses the launch: declared but unbound
// refuses, never degrades.
func TestADevShellAGrantAsksForThatFailsRefusesTheLaunch(t *testing.T) {
	h := newHarness(t, "frisket")
	h.n.DevShell = "granted"
	h.r.Asked = yes()
	h.checkout(map[string]string{"shell.nix": "{}"})
	h.k.FailStep, h.k.FailSaid = "C", "error: builder failed"
	if _, err := h.realise(); err == nil || err.Error() != h.r.Workspace+": the devShell the grant asks for could not be realised: builder failed" {
		t.Errorf("refused with %v", err)
	}
	// And so does a checkout with none to give.
	h.r.Workspace = h.dir + "/w/none"
	h.checkout(map[string]string{"README": ""})
	if _, err := h.realise(); err == nil || !strings.Contains(err.Error(), "the grant asks for a devShell, and the checkout tracks no flake.nix or shell.nix") {
		t.Errorf("a grant asking for none: %v", err)
	}
}

// A recording finds what a session needs, and is never refused for its
// devShell: what fails is said.
func TestARecordingNeverRefusesForItsDevShell(t *testing.T) {
	h := newHarness(t, "frisket")
	h.n.DevShell = "granted"
	h.r.Asked, h.r.Recording = yes(), true
	h.checkout(map[string]string{"shell.nix": "{}"})
	h.k.FailStep, h.k.FailSaid = "A", "error: boom"
	if ds, err := h.realise(); ds != nil || err != nil {
		t.Errorf("%+v, %v", ds, err)
	}
	h.mustSay("could not be realised, and the session starts without it: boom")
}

// A grant that says false leaves out what the tier would give.
func TestAGrantThatSaysNoLeavesOutAnAutomaticDevShell(t *testing.T) {
	h := newHarness(t, "direct")
	h.r.Asked = no()
	h.checkout(map[string]string{"shell.nix": "{}"})
	if ds, err := h.realise(); ds != nil || err != nil || h.runs("nix") != nil {
		t.Errorf("%+v, %v, ran %d", ds, err, len(h.runs("nix")))
	}
}

// A tier that gives a devShell only by grant gives none without one.
func TestAGrantedTierRealisesNothingTheGrantDoesNotAskFor(t *testing.T) {
	h := newHarness(t, "frisket")
	h.n.DevShell = "granted"
	h.checkout(map[string]string{"shell.nix": "{}"})
	if ds, err := h.realise(); ds != nil || err != nil || h.runs("nix") != nil {
		t.Errorf("%+v, %v, ran %d", ds, err, len(h.runs("nix")))
	}
	h.r.Asked = yes()
	if ds, err := h.realise(); ds == nil || err != nil {
		t.Errorf("asked for: %+v, %v", ds, err)
	}
}

// A flake with no devShell for the system has none, said once, and kept
// as none; a grant asking for one refuses.
func TestAFlakeWithNoDefaultDevShellIsNoneAndSaidOnce(t *testing.T) {
	h := newHarness(t, "direct")
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
	h.r.Asked = yes()
	if _, err := h.realise(); err == nil || !strings.Contains(err.Error(), "flake.nix has no devShells.x86_64-linux.default") {
		t.Errorf("a grant asking for none: %v", err)
	}
}

// A flake.nix the checkout made a link to a host file is never read on the
// host, nor through the snapshot.
func TestAFlakeNixTheCheckoutLinksOutIsNeverRead(t *testing.T) {
	h := newHarness(t, "direct")
	secret := h.dir + "/secret.nix"
	os.WriteFile(secret, []byte("the host's own"), 0o600)
	h.fx.Run("init", "-q", h.r.Workspace)
	os.Symlink(secret, h.r.Workspace+"/flake.nix")
	h.fx.Run("-C", h.r.Workspace, "add", "-A")
	ds, err := h.realise()
	if ds != nil || err != nil {
		t.Errorf("%+v, %v", ds, err)
	}
	h.mustSay("flake.nix: not a file the checkout tracks, but a link")
	for _, r := range h.runs("nix") {
		if strings.Contains(r.Lazy, "the host's own") {
			t.Error("the host's file was evaluated")
		}
	}
}

// What nix says goes to the terminal cleaned: the checkout names what is
// in it.
func TestNixsOutputIsCleanedBeforeTheTerminal(t *testing.T) {
	h := newHarness(t, "frisket")
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	h.k.FailStep, h.k.FailSaid = "C", "error: ‮evil\x1b]0;title\x07"
	h.realise()
	if strings.ContainsAny(h.said, "‮\x1b\x07") {
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
	h := newHarness(t, "direct")
	big := strings.Repeat("x", 200<<10)
	h.k.Env = `{"bashFunctions":{},"variables":{"BIG":{"type":"exported","value":"` + big + `"}}}`
	h.checkout(map[string]string{"shell.nix": "{}"})
	if ds, err := h.realise(); ds != nil || err != nil {
		t.Errorf("%+v, %v", ds != nil, err)
	}
	h.mustSay("more than a launch carries")
	if _, _, err := parse([]byte(h.k.Env)); err == nil || !strings.Contains(err.Error(), "its environment is 204804 bytes") {
		t.Errorf("%v", err)
	}
}

// A launch that is stopped while its devShell is realised -- Ctrl-C, a
// SIGTERM -- is stopped, never launched without it, and nothing of it is
// kept: the next launch realises it, rather than taking it for a failure.
func TestAStoppedLaunchIsNotAFailure(t *testing.T) {
	h := newHarness(t, "direct")
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

// What the index lists and the work tree no longer has is left out of
// what is evaluated, as nix develop leaves it out, rather than failing it.
func TestATrackedFileTheWorkTreeNoLongerHasIsLeftOut(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"shell.nix": "{}", "old/gone.nix": "{}", "kept.nix": "{}"})
	os.RemoveAll(h.r.Workspace + "/old")
	if ds, err := h.realise(); ds == nil || err != nil {
		t.Errorf("%+v, %v: %s", ds, err, h.said)
	}
	// And a tracked flake.nix that is gone is no flake.
	h.checkout(map[string]string{"flake.nix": flakeNix})
	os.Remove(h.r.Workspace + "/flake.nix")
	h.clear()
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	if r := h.step("derivation", "show"); len(r) != 0 && !strings.HasSuffix(r[0].Argv[len(r[0].Argv)-1], "/shell.nix") {
		t.Errorf("evaluated %q", r[0].Argv)
	}
}

// A flake.nix git does not track is not taken over a shell.nix it does,
// and is said.
func TestAnUntrackedFlakeIsSaidAndTheTrackedShellNixTaken(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"shell.nix": "{}"})
	os.WriteFile(h.r.Workspace+"/flake.nix", []byte(flakeNix), 0o644)
	if ds, err := h.realise(); ds == nil || err != nil {
		t.Fatalf("%+v, %v", ds, err)
	}
	h.mustSay("flake.nix is not tracked by git")
	if r := h.step("derivation", "show"); len(r) != 1 || !strings.HasSuffix(r[0].Argv[len(r[0].Argv)-1], "/shell.nix") {
		t.Errorf("evaluated %v", r)
	}
}

// A profile that is not the one state.json recorded -- a launch killed
// between switching it and writing state.json -- is not taken for it.
func TestAProfileOfAnotherRealisationIsNotTaken(t *testing.T) {
	h := newHarness(t, "direct")
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
	if len(h.step("derivation", "show")) != 1 {
		t.Error("another realisation's profile was taken")
	}
}

// A snapshot a killed launch left behind is removed by the next, once it
// is older than any realisation lasts; one of a launch still running is
// not.
func TestASnapshotAKilledLaunchLeftIsRemoved(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"shell.nix": "{}"})
	os.MkdirAll(h.r.Dir+"/devshell", 0o700)
	old, fresh := h.r.Dir+"/devshell-snapshot.old", h.r.Dir+"/devshell-snapshot.fresh"
	os.MkdirAll(old+"/src", 0o700)
	os.MkdirAll(fresh, 0o700)
	long := time.Now().Add(-3 * time.Duration(h.n.Timeout) * time.Second)
	os.Chtimes(old, long, long)
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err == nil {
		t.Error("a stale snapshot was kept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a snapshot that may be in use was removed")
	}
}

// Every nix run substitutes: nix turns substitution off where it finds no
// network, as a confined step without one does, and a filtered tier,
// which builds nothing, would then be given nothing.
func TestEveryNixRunSubstitutes(t *testing.T) {
	h := newHarness(t, "frisket")
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	for _, r := range h.runs("nix") {
		if v, ok := optionValue(r.Argv, "substitute"); !ok || v != "true" {
			t.Errorf("%q does not substitute", r.Argv)
		}
	}
}

// A filtered tier's fetcher cache is its allowlist's: what a checkout that
// may reach other names fetched is never there for builtins.getFlake,
// which allowed-uris does not hold, to find.
func TestAFilteredTiersFetcherCacheIsItsAllowlists(t *testing.T) {
	h := newHarness(t, "frisket")
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	home := func() string {
		h.t.Helper()
		h.clear()
		if _, err := h.realise(); err != nil {
			t.Fatal(err)
		}
		for _, r := range h.runs("nix") {
			for _, v := range r.Env {
				if home, ok := strings.CutPrefix(v, "HOME="); ok {
					return home
				}
			}
		}
		return ""
	}
	first := home()
	h.policy("github.com", "example.org")
	second := home()
	if second == "" || second == first {
		t.Errorf("two allowlists share a fetcher cache: %q", second)
	}
	h.policy("example.org", "github.com")
	os.Remove(h.r.Dir + "/devshell/state.json")
	if third := home(); third != second {
		t.Errorf("one allowlist, in another order, is another cache: %q, %q", second, third)
	}
}

// A tarball's URL is checked as nix is given it: one that reads back
// otherwise than it was written is refused, never fetched.
func TestATarballURLNixMightReadOtherwiseIsRefused(t *testing.T) {
	for _, u := range []string{
		`https://releases.example.org\@evil.test/x.tar.gz`,
		`https://releases.example.org/a b.tar.gz`,
		`https:releases.example.org/x.tar.gz`,
	} {
		b, _ := json.Marshal(map[string]any{"root": "root", "version": 7, "nodes": map[string]any{
			"root": map[string]any{},
			"x":    map[string]any{"locked": map[string]any{"type": "tarball", "url": u, "narHash": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="}},
		}})
		if urls, err := prefetchOf(b, []string{"releases.example.org"}); err == nil {
			t.Errorf("%s: prefetched %q", u, urls)
		}
	}
}

// What the devShell gives that steers the agent is said, by name, when it
// is left out.
func TestWhatIsNotGivenToTheAgentIsSaid(t *testing.T) {
	h := newHarness(t, "direct")
	h.k.Env = strings.Replace(envJSON, `"variables":{`, `"variables":{"NODE_OPTIONS":{"type":"exported","value":"--x"},"ANTHROPIC_BASE_URL":{"type":"exported","value":"https://x"},`, 1)
	h.checkout(map[string]string{"shell.nix": "{}"})
	if _, err := h.realise(); err != nil {
		t.Fatal(err)
	}
	h.mustSay("the devShell's ANTHROPIC_BASE_URL, NODE_OPTIONS are not given to the agent")
}

// A failure that most devShells working with nix develop and not here have
// in common is told what to do about it.
func TestAFailureTheEvaluationsConfinementExplainsIsHinted(t *testing.T) {
	h := newHarness(t, "direct")
	h.checkout(map[string]string{"shell.nix": "{}"})
	h.k.FailStep, h.k.FailSaid = "A", "error: Package 'slack' has an unfree license, refusing to evaluate."
	h.realise()
	h.mustSay("refusing to evaluate.; the evaluation sees no environment, no ~/.config and no network but its own: set config.allowUnfree in the import, and lock what it fetches")
}
