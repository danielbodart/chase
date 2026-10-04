package devshell

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// confinement is the shape of confine's, bumped when it changes: a
// devShell realised in another is realised again.
const confinement = 2

// job is one checkout's realisation: what is evaluated, and how.
type job struct {
	n    session.Nix
	r    Request
	kind string
	// dir is <Dir>/devshell, snap the snapshot of what the checkout tracks,
	// and src where the snapshot is in the confinement.
	dir, snap, src string
	stderr         io.Writer

	// files are the digests of what the cache is keyed on, by name.
	files map[string]string
	// evaluation is step A's flags, prefetch the URLs step P fetches, and
	// key what the cache is keyed on.
	evaluation []string
	prefetch   []string
	key        string
	// said is what the plan has to say once, when it is realised.
	said []string
	// env is the store path the profile pointed to when C was done.
	env string
	// reach is a digest of the allowlist, in a tier whose egress is
	// frisket's: whose fetcher cache the evaluation reads.
	reach string
}

// c0 is what every nix run is given first: flakes, and nothing the flake
// says of nix's own configuration; no registry, so no flake is found by a
// name; lazy trees, which keep the snapshot out of the world-readable
// store unless a derivation refers to it; and substitution, which nix
// turns off of itself where it finds no network -- as a confined step
// without one does -- and tells the daemon so, though it is the daemon
// that substitutes, on its own network: a filtered tier, which builds
// nothing, would be given nothing, and a direct one would build what the
// caches hold.
var c0 = []string{
	"--extra-experimental-features", "nix-command flakes",
	"--option", "accept-flake-config", "false",
	"--option", "use-registries", "false",
	"--option", "flake-registry", "",
	"--option", "lazy-trees", "true",
	"--option", "substitute", "true",
}

// directURIs is what an evaluation reaches in a tier with direct egress:
// anything over https, as a session could.
var directURIs = []string{"https://", "tarball+https://", "file+https://", "git+https://", "github:", "gitlab:", "sourcehut:"}

// plan is what the job evaluates and how: the digests of the files keyed
// on, step A's flags, step P's URLs, and the key of them all. In a tier
// whose egress is frisket's they are bounded by the session's allowlist,
// which a flake.lock's inputs may not reach beyond.
func (j *job) plan() error {
	j.files = map[string]string{}
	names := []string{j.kind}
	if j.kind == flake {
		names = append(names, lock)
	}
	for _, name := range names {
		b, err := readPlain(j.snap + "/" + name)
		switch {
		case errors.Is(err, os.ErrNotExist) && name == lock:
			j.files[name] = ""
			continue
		case err != nil:
			return fmt.Errorf("%s: %v", name, err)
		}
		d := sha256.Sum256(b)
		j.files[name] = hex.EncodeToString(d[:])
	}
	uris := directURIs
	if j.n.Egress == "frisket" {
		allow, err := allowOf(j.r.Policy)
		if err != nil {
			return err
		}
		d := sha256.Sum256([]byte(strings.Join(slices.Sorted(slices.Values(allow)), "\x00")))
		j.reach = hex.EncodeToString(d[:8])
		var unsaid []string
		uris, unsaid = allowedURIs(allow)
		if len(unsaid) > 0 {
			j.said = append(j.said, fmt.Sprintf("%s: the devShell's evaluation fetches from none of %s: allowed-uris holds exact names only", j.r.Workspace, strings.Join(unsaid, ", ")))
		}
		if j.kind == flake && j.files[lock] != "" {
			b, err := readPlain(j.snap + "/" + lock)
			if err != nil {
				return fmt.Errorf("%s: %v", lock, err)
			}
			if j.prefetch, err = prefetchOf(b, allow); err != nil {
				var off *offList
				if errors.As(err, &off) && j.r.Recording {
					return fmt.Errorf("%v: `network.allow` in its chase.jsonc admits them", err)
				}
				return err
			}
		}
	}
	j.evaluation = []string{"--option", "restrict-eval", "true", "--option", "allowed-uris", strings.Join(uris, " ")}
	if j.n.Egress == "frisket" {
		j.evaluation = append(j.evaluation, "--max-jobs", "0")
	}
	b, err := json.Marshal(struct {
		Version     int               `json:"version"`
		Kind        string            `json:"kind"`
		Files       map[string]string `json:"files"`
		System      string            `json:"system"`
		Nix         string            `json:"nix"`
		Nixpkgs     string            `json:"nixpkgs"`
		Bwrap       string            `json:"bwrap"`
		Pasta       string            `json:"pasta"`
		Confinement int               `json:"confinement"`
		Evaluation  []string          `json:"evaluation"`
		Prefetch    []string          `json:"prefetch"`
	}{1, j.kind, j.files, j.n.System, j.n.Nix, j.n.Nixpkgs, j.n.Bwrap, j.n.Pasta, confinement, j.evaluation, j.prefetch})
	if err != nil {
		return err
	}
	d := sha256.Sum256(b)
	j.key = hex.EncodeToString(d[:])
	return nil
}

// readPlain is the file at p, a plain file and never a link: what a
// checkout's flake.nix links to on the host is not its flake.
func readPlain(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, errors.New("not a file the checkout tracks, but a link")
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a plain file")
	}
	return io.ReadAll(f)
}

// allowOf is the allow list of the frisket document at p.
func allowOf(p string) ([]string, error) {
	if p == "" {
		return nil, errors.New("no policy document bounds what it may fetch")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var d policy.Document
	if err := policy.Decode(b, &d); err != nil {
		return nil, fmt.Errorf("%s: %v", p, err)
	}
	return d.Allow, nil
}

// allowedURIs is allowed-uris in a filtered tier, sorted: each exact name
// on the allowlist over https, as a tarball and as a file; github:,
// gitlab: and sourcehut: where their hosts are allowed; and every name's,
// less git's, whose submodules name any host, where the allowlist is "*".
// A "*.suffix" cannot be said in allowed-uris, which matches by prefix,
// and is left out, returned to be said. Never a path: or git+ entry.
func allowedURIs(allow []string) (uris, unsaid []string) {
	if slices.Contains(allow, "*") {
		return slices.Sorted(slices.Values(slices.DeleteFunc(slices.Clone(directURIs), func(u string) bool { return u == "git+https://" }))), nil
	}
	for _, name := range allow {
		if strings.HasPrefix(name, "*.") {
			unsaid = append(unsaid, name)
			continue
		}
		uris = append(uris, "https://"+name+"/", "tarball+https://"+name+"/", "file+https://"+name+"/")
	}
	for scheme, host := range forges {
		if allows(allow, host) {
			uris = append(uris, scheme+":")
		}
	}
	slices.Sort(uris)
	return slices.Compact(uris), unsaid
}

// forges are the lock types fetched from one host's archives, by the host.
var forges = map[string]string{"github": "github.com", "gitlab": "gitlab.com", "sourcehut": "git.sr.ht"}

// allows is whether an allowlist holds name, as frisket reads one: "*",
// the name itself, or "*.suffix" for a name below suffix.
func allows(allow []string, name string) bool {
	for _, a := range allow {
		if a == "*" || a == name {
			return true
		}
		if suffix, ok := strings.CutPrefix(a, "*"); ok && strings.HasPrefix(suffix, ".") && strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// state is what is kept of a checkout's last realisation, written last.
//
// Env is the store path the profile pointed to when it was realised: the
// profile is switched before state.json is written, so a launch killed
// between the two leaves a profile of another key's, which is not taken
// for this one's.
type state struct {
	Key       string `json:"key"`
	Workspace string `json:"workspace"`
	Result    string `json:"result"`
	Reason    string `json:"reason,omitempty"`
	Env       string `json:"env,omitempty"`
	At        string `json:"at"`
}

// record writes what the realisation came to.
func (j *job) record(result, reason string) {
	b, err := json.Marshal(state{Key: j.key, Workspace: j.r.Workspace, Result: result, Reason: reason, Env: j.env, At: now().UTC().Format(time.RFC3339)})
	if err == nil {
		files.WriteAtomic(j.dir+"/state.json", b, 0o600)
	}
}

// cached is the devShell the last realisation kept, when it is of what is
// evaluated now: its environment, read through the profile that roots it;
// none; or, where the tier gives it automatically, a failure less than
// failedFor old, said as it was. hit is false for anything else, which is
// realised again.
func (j *job) cached() (ds *session.DevShell, err error, hit bool) {
	b, err := os.ReadFile(j.dir + "/state.json")
	if err != nil {
		return nil, nil, false
	}
	var s state
	if json.Unmarshal(b, &s) != nil || s.Key != j.key {
		return nil, nil, false
	}
	switch s.Result {
	case "env":
		// A profile that is gone, is not the one recorded, or no longer
		// reads, is realised again.
		if env, err := filepath.EvalSymlinks(j.dir + "/profile"); err != nil || s.Env == "" || env != s.Env {
			return nil, nil, false
		}
		ds, err := j.load()
		if err != nil {
			return nil, nil, false
		}
		return ds, nil, true
	case "none":
		return nil, &none{line: s.Reason, quiet: true}, true
	case "failed":
		at, err := time.Parse(time.RFC3339, s.At)
		if j.r.Asked != nil || err != nil || now().Sub(at) >= failedFor {
			return nil, nil, false
		}
		return nil, fmt.Errorf("(as at %s) %s", s.At, s.Reason), true
	}
	return nil, nil, false
}

// load is the environment the profile roots, as the session is given it.
func (j *job) load() (*session.DevShell, error) {
	b, err := os.ReadFile(j.dir + "/profile")
	if err != nil {
		return nil, err
	}
	ds, dropped, err := parse(b)
	if err != nil {
		return nil, err
	}
	if len(dropped) > 0 {
		term.Say(j.stderr, "%s: the devShell's %s are not given to the agent", j.r.Workspace, strings.Join(dropped, ", "))
	}
	return ds, nil
}

// realise is steps P to C (confine has each), and the environment that
// comes of them, rooted in dir.
func (j *job) realise(ctx context.Context) (*session.DevShell, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(j.n.Timeout)*time.Second)
	defer cancel()
	ds, err := j.steps(ctx)
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("it took more than %d s", j.n.Timeout)
	}
	return ds, err
}

func (j *job) steps(ctx context.Context) (*session.DevShell, error) {
	frisket := j.n.Egress == "frisket"
	if err := j.prepare(); err != nil {
		return nil, err
	}
	// P: the lock's inputs, into the fetcher cache under nix's HOME, which
	// the evaluation shares.
	for _, url := range j.prefetch {
		if _, err := j.run(ctx, step{name: "P", network: true, args: []string{"flake", "prefetch", "--json", url}}); err != nil {
			return nil, fmt.Errorf("fetching %s: %v", url, err)
		}
	}
	// A: the evaluation, once, to the one derivation it gives.
	var args []string
	if j.kind == flake {
		args = append([]string{"derivation", "show", "--no-update-lock-file"}, j.evaluation...)
		args = append(args, "path:"+j.src+"#devShells."+j.n.System+".default")
	} else {
		args = append([]string{"derivation", "show", "--arg", "inNixShell", "true"}, j.evaluation...)
		args = append(args, "-f", j.src+"/"+shell)
	}
	out, err := j.run(ctx, step{name: "A", network: !frisket, capture: true, args: args})
	if err != nil {
		var f *stepFailure
		if j.kind == flake && errors.As(err, &f) && strings.Contains(f.said, "does not provide attribute") {
			return nil, &none{line: fmt.Sprintf("%s: flake.nix has no devShells.%s.default", j.r.Workspace, j.n.System)}
		}
		if errors.As(err, &f) && f.said != "" {
			io.WriteString(j.stderr, term.Clean(f.said))
			if !strings.HasSuffix(f.said, "\n") {
				io.WriteString(j.stderr, "\n")
			}
		}
		return nil, err
	}
	drv, inputs, err := derivationOf(out)
	if err != nil {
		return nil, err
	}
	// B: in a filtered tier, the inputs, from the binary caches alone, kept
	// rooted until C is done.
	defer removeInputs(j.dir)
	if frisket && len(inputs) > 0 {
		args := append([]string{"build", "--max-jobs", "0", "--out-link", j.dir + "/inputs"}, inputs...)
		if _, err := j.run(ctx, step{name: "B", devshell: true, args: args}); err != nil {
			return nil, err
		}
	}
	// C: the environment, nix's -env derivation built in the daemon's
	// sandbox, rooted by the profile.
	args = []string{"print-dev-env", "--json", "--profile", j.dir + "/profile"}
	if frisket {
		args = append(args, "--max-jobs", "1")
	}
	args = append(args, "--option", "max-silent-time", "600", drv+"^*")
	if _, err := j.run(ctx, step{name: "C", devshell: true, args: args}); err != nil {
		return nil, err
	}
	prune(j.dir)
	if j.env, err = filepath.EvalSymlinks(j.dir + "/profile"); err != nil {
		return nil, err
	}
	ds, err := j.load()
	if err != nil {
		return nil, err
	}
	return ds, nil
}

// prepare makes what the confinement binds: nix's HOME for the tier's
// egress, and the resolver a networked step is told.
func (j *job) prepare() error {
	if err := os.MkdirAll(j.home(), 0o700); err != nil {
		return err
	}
	return files.WriteAtomic(j.r.State+"/nix/resolv.conf", []byte("nameserver "+dnsForward+"\n"), 0o644)
}

// home is nix's HOME, one per egress setting and never per tier, and in
// a filtered tier one per allowlist too: its fetcher cache is shared by
// every checkout that may reach the same names, and never holds what one
// that may reach others fetched -- builtins.getFlake, which allowed-uris
// does not hold, would find it there.
func (j *job) home() string {
	if j.reach != "" {
		return j.r.State + "/nix/" + j.n.Egress + "-" + j.reach
	}
	return j.r.State + "/nix/" + j.n.Egress
}

// removeInputs lets go of what B rooted.
func removeInputs(dir string) {
	links, _ := os.ReadDir(dir)
	for _, l := range links {
		if strings.HasPrefix(l.Name(), "inputs") {
			os.Remove(dir + "/" + l.Name())
		}
	}
}
