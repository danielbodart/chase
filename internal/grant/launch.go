package grant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/frisket/policy"
	"github.com/danielbodart/quoin/hostpattern"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// Launch is the grant's half of flong's exec hook, run on the host after
// seccompPolicy and before the session is built: what seccompPolicy staged
// for this launch, applied. It consumes the stage, so a launch applies one
// approval once; re-checks that the sops file beside it is the one whose
// digest was approved; decrypts the secret each bound app names; prepares
// each bound app, by its code in registry or from its Config.Apps entry;
// merges each into the tier's policy document, with the project's lists for
// each app applied last; and writes the document where frisket reads the
// session's, <runtime>/chase/<machine>/policy.json. What it returns is the
// session's own, for the payload's environment and home: each app's
// variables, in order, and its files.
//
// The document is written for every launch, an approval of the tier as it
// is too, when it is the tier's own: frisket's policyFile names this one
// path for every session of a tier that takes grants, so there is no
// choosing between two when frisket steers the session, and so nothing to
// run then.
//
// Everything written is the user's alone, decrypted secrets above all: the
// process's umask is 077 while it runs, as the script's was.
func Launch(ctx context.Context, c Config, registry map[string]apps.App, tier, ws, machine string, stderr io.Writer) (session.Given, error) {
	return launch(ctx, c, registry, nil, tier, ws, machine, stderr)
}

// launch is Launch, with the record block rec, when it is not nil, written
// into the session's document: a recording session's (Recording).
func launch(ctx context.Context, c Config, registry map[string]apps.App, rec *Recording, tier, ws, machine string, stderr io.Writer) (session.Given, error) {
	old := unix.Umask(0o077)
	defer unix.Umask(old)
	stage := staged(c, machine)
	if !regular(stage) {
		return session.Given{}, refuse("%s: nothing was approved for this launch: the tier's seccompPolicy did not run", ws)
	}
	b, err := os.ReadFile(stage)
	if err != nil {
		return session.Given{}, err
	}
	if err := os.Remove(stage); err != nil && !errors.Is(err, os.ErrNotExist) {
		return session.Given{}, err
	}
	run := c.runtime() + "/chase/" + machine
	if err := os.Mkdir(run, 0o700); err != nil {
		return session.Given{}, err
	}
	pb, err := os.ReadFile(c.Policies + "/" + tier + ".json")
	if err != nil {
		return session.Given{}, err
	}
	pd, err := policy.DecodeV2(pb)
	if err != nil {
		return session.Given{}, fmt.Errorf("%s/%s.json: %w", c.Policies, tier, err)
	}
	// The tier's own machines, in every session of it, before any app a
	// project binds: SSH's Prepare refuses a project's machine of the same
	// name or address, so none of them is replaced.
	if c.SSH != nil {
		routes, err := c.SSH.TierRoutes(tier)
		if err != nil {
			return session.Given{}, refuse("%s: ssh: %v", ws, err)
		}
		if len(routes) > 0 {
			merge(&pd, apps.Patch{SSH: routes})
		}
	}
	var given session.Given
	if strings.TrimRight(string(b), "\n") != "null" {
		if given, err = apply(ctx, c, registry, &pd, b, run, tier, ws, stderr); err != nil {
			return session.Given{}, err
		}
	}
	// A recording's block, in the document frisket serves the session
	// under; any the tier's own document had is replaced, as only a
	// recording has one.
	pd.Record = nil
	if rec != nil {
		pd.Record = rec.block(c, machine)
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(pd); err != nil {
		return session.Given{}, err
	}
	// Replaced whole, never truncated and rewritten: frisket, or anything
	// else, reading it then would read half a document. 0600 is what the
	// umask made of the 0666 it was written with.
	if err := files.WriteAtomic(run+"/policy.json", out.Bytes(), 0o600); err != nil {
		return session.Given{}, err
	}
	return given, nil
}

// merge is an app's patch, a layer of the host's, applied to the session's
// document: its routes and machines in place of any of the same names the
// tier had, whole, and its names added to the allowlist, unless that
// allows every name already.
func merge(pd *policy.DocumentV2, p apps.Patch) {
	if len(p.Routes) > 0 && pd.Routes == nil {
		pd.Routes = map[string]policy.RouteV2{}
	}
	maps.Copy(pd.Routes, p.Routes)
	if len(p.SSH) > 0 && pd.SSH == nil {
		pd.SSH = map[string]policy.SSHRouteV2{}
	}
	maps.Copy(pd.SSH, p.SSH)
	if pd.Allow["**"] {
		return
	}
	for _, n := range p.Allow {
		if pd.Allow == nil {
			pd.Allow = map[string]bool{}
		}
		pd.Allow[n] = true
	}
}

// staging is what approve stages for exec: the project's chase.json, as
// it was signed or approved, and the snapshot's sops file it names.
type staging struct {
	File    map[string]any `json:"file"`
	Secrets *stagedSecrets `json:"secrets"`
}

// apply is the staged file, applied to the tier's document pd for the
// session whose directory is run: its secrets decrypted there, each app it
// binds prepared and merged in, and its frisket section merged last.
func apply(ctx context.Context, c Config, registry map[string]apps.App, pd *policy.DocumentV2, b []byte, run, tier, ws string, stderr io.Writer) (session.Given, error) {
	var given session.Given
	var st staging
	if err := json.Unmarshal(b, &st); err != nil {
		return given, err
	}
	encoded, err := encodeDoc(st.File)
	if err != nil {
		return given, err
	}
	doc, generic, err := ParseDoc(encoded)
	if err != nil {
		return given, refuse("%s: the staged %s: %v", ws, FileName, err)
	}
	section := Section{}
	if doc.Chase != nil {
		section = *doc.Chase
	}
	sectionApps := SectionApps{}
	if section.Apps != nil {
		sectionApps = *section.Apps
	}
	if err := os.Mkdir(run+"/secrets", 0o700); err != nil {
		return given, err
	}
	file := ""
	if section.Secrets != "" {
		if st.Secrets == nil {
			return given, refuse("%s: %s names %s, and none was staged", ws, FileName, section.Secrets)
		}
		dir, err := os.MkdirTemp(run, "sops.")
		if err != nil {
			return given, err
		}
		file = dir + "/" + st.Secrets.Name
		if err := os.WriteFile(file, []byte(st.Secrets.Text), 0o666); err != nil {
			return given, err
		}
		if sha256Hex64([]byte(st.Secrets.Text)) != section.SecretsSHA256 {
			return given, refuse("%s: the staged %s is not the one signed", ws, section.Secrets)
		}
	}

	// The Docker project the file says, which approve held to the one the
	// checkout's origin names: an app is given it, and the session is not.
	project := ""
	if sectionApps.Docker != nil {
		project = sectionApps.Docker.Project
	}
	bindings := map[string]any{}
	if cs, ok := generic.(map[string]any)["chase"].(map[string]any); ok {
		if a, ok := cs["apps"].(map[string]any); ok {
			bindings = a
		}
	}
	names := slices.Sorted(maps.Keys(c.Apps))
	for name := range registry {
		if _, ok := c.Apps[name]; !ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, app := range names {
		raw, ok := bindings[app]
		if !ok || raw == nil {
			continue
		}
		binding, err := parseJSON([]byte(compactJSON(raw)))
		if err != nil {
			return given, err
		}
		code, isCode := registry[app]
		conf := c.Apps[app]
		// An app with a credential is bound only with the project's own,
		// decrypted, and says which; one with none is made by its code from
		// the binding alone, and says nothing.
		var from string
		if conf.hasCredential() {
			cred, err := binding.index("credential")
			if err != nil {
				return given, err
			}
			secret, err := cred.optional("secret")
			if err != nil {
				return given, err
			}
			if secret == "" {
				continue
			}
			if err := decrypt(ctx, c, ws, file, secret, run+"/secrets/"+app, stderr); err != nil {
				return given, err
			}
			from = section.Secrets + ":" + secret
		} else if !isCode {
			return given, refuse("%s: %s has no credential and no prepare", ws, app)
		}
		// The app's routes, in place of any of the same names the tier had:
		// what its code made of the binding, or its own with the project's
		// credential.
		var patch apps.Patch
		if isCode {
			appBinding, err := bindingOf(app, raw)
			if err != nil {
				return given, refuse("%s: %s: %v", ws, app, err)
			}
			patch, err = code.Prepare(ctx, apps.Request{
				Tier: tier, Workspace: ws, Run: run, Dir: checkoutDir(c, ws), Home: c.Home,
				Project: project, Binding: appBinding,
			})
			if err != nil {
				// What the app's own prepare said as it died, and then the
				// launch's own die.
				term.Say(stderr, "%v", err)
				return given, refuse("%s: %s could not be prepared", ws, app)
			}
		} else {
			patch = staticPatch(conf, tier, run+"/secrets/"+app)
		}
		merge(pd, patch)
		vars, err := exportsOf(conf, patch, binding)
		if err != nil {
			return given, err
		}
		given.Env = append(given.Env, vars...)
		given.Files = append(given.Files, patch.Files...)
		if from != "" {
			term.Say(stderr, "%s from %s", app, from)
		}
	}
	if file != "" {
		os.RemoveAll(filepath.Dir(file))
	}
	// The devShell, which exec realises once the document is written:
	// nothing of it is prepared here.
	given.DevShellGranted = sectionApps.Nix != nil && sectionApps.Nix.DevShell
	if doc.Frisket != nil {
		if err := applyLayer(c, pd, doc.Frisket, ws, tier, stderr); err != nil {
			return given, err
		}
	}
	return given, nil
}

// applyLayer is the project's frisket section merged over the session's
// document, as frisket's own project-layer check merges it
// (policy.CheckProjectLayer): a host field set, a pattern that can never
// match, an operation id the route has not, all refuse the launch. What it
// answers for a route or machine the tier does not have here, or a route
// with no credential -- an anonymous app has nobody to ask on its behalf,
// so a project answers none of its requests -- is said and left out
// (PLAN.md, decision 8), as a session of another tier would leave it; and
// so is what it answers for a route that is no app a project answers
// (Config.Answerable): Claude Code's, Codex's, Docker's, whose answers are
// the machine's alone.
func applyLayer(c Config, pd *policy.DocumentV2, layer map[string]any, ws, tier string, stderr io.Writer) error {
	l := maps.Clone(layer)
	// To a tier that allows every name, a name adds nothing.
	if allow, ok := l["allow"].(map[string]any); ok && pd.Allow["**"] {
		kept := map[string]any{}
		for k, v := range allow {
			if v != true {
				kept[k] = v
			}
		}
		l["allow"] = kept
	}
	if routes, ok := l["routes"].(map[string]any); ok {
		kept := map[string]any{}
		for _, name := range slices.Sorted(maps.Keys(routes)) {
			r, ok := pd.Routes[name]
			switch {
			case !slices.Contains(c.Answerable, name):
				term.Say(stderr, "%s: frisket.routes.%s ignored: a project answers none of %s's requests", ws, name, name)
			case !ok:
				term.Say(stderr, "%s: frisket.routes.%s ignored: %s has no %s", ws, name, tier, name)
			case r.CredentialFile == "":
				term.Say(stderr, "%s: frisket.routes.%s ignored: %s is anonymous in %s", ws, name, name, tier)
			default:
				kept[name] = routes[name]
			}
		}
		l["routes"] = kept
	}
	if ssh, ok := l["ssh"].(map[string]any); ok {
		kept := map[string]any{}
		for _, name := range slices.Sorted(maps.Keys(ssh)) {
			p, err := hostpattern.Compile(name)
			if _, ok := pd.SSH[name]; err == nil && p.Literal() && !ok {
				term.Say(stderr, "%s: frisket.ssh.%s ignored: %s has no such machine", ws, name, tier)
				continue
			}
			kept[name] = ssh[name]
		}
		l["ssh"] = kept
	}
	base, err := json.Marshal(pd)
	if err != nil {
		return err
	}
	merged, err := policy.CheckProjectLayer([]byte(compactJSON(l)), base)
	if err != nil {
		term.Say(stderr, "%v", err)
		return refuse("%s: its frisket section does not apply in %s", ws, tier)
	}
	d, err := policy.DecodeV2(merged)
	if err != nil {
		return err
	}
	// A name on the local network that is a route's host, which the
	// session's DNS answers with frisket's own address: refused here,
	// with the file's words, rather than by frisket when the session
	// starts.
	for name := range d.LAN {
		for rname, r := range d.Routes {
			if routeServes(r.Host, name) {
				return refuse("%s: frisket.lan %s is the %s route's host, which frisket answers with its own address", ws, name, rname)
			}
		}
	}
	*pd = d
	return nil
}

// routeServes is whether a route whose host is host serves name: the host
// itself, or a name below a "**.suffix" host.
func routeServes(host, name string) bool {
	if suffix, ok := strings.CutPrefix(host, "**"); ok && strings.HasPrefix(suffix, ".") {
		return strings.HasSuffix(name, suffix)
	}
	return host == name
}

// decrypt is the secret an app binds, decrypted from the staged copy of the
// sops file -- whose digest was approved -- where frisket reads it and the
// session cannot: the runtime directory is bound into no container.
func decrypt(ctx context.Context, c Config, ws, file, secret, out string, stderr io.Writer) error {
	if file == "" {
		return refuse("%s: an app names secret '%s', and the grant names no secrets file", ws, secret)
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, c.Sops, "--decrypt", "--extract", `["`+secret+`"]`, file)
	cmd.Stdout, cmd.Stderr = f, stderr
	err = cmd.Run()
	f.Close()
	if err != nil {
		if _, exited := err.(*exec.ExitError); !exited {
			term.Say(stderr, "%v", err)
		}
		return refuse("%s: could not decrypt '%s'", ws, secret)
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
		return refuse("%s: '%s' is empty", ws, secret)
	}
	return nil
}

// staticPatch is an app's own routes for tier, each with the project's
// decrypted credential, and the names it adds to allow.
func staticPatch(a App, tier, cred string) apps.Patch {
	p := apps.Patch{Allow: a.Allow}
	for name, r := range a.Routes[tier] {
		if p.Routes == nil {
			p.Routes = map[string]policy.RouteV2{}
		}
		r.CredentialFile = cred
		p.Routes[name] = r
	}
	return p
}

// exportsOf is what an app puts in the session's environment: its own env,
// then what its patch adds, then each variable it takes from a field of the
// binding that is there, a later one in place of an earlier of the same
// name. A value that was not a string in the grant is its JSON: a number
// or a boolean as written.
func exportsOf(a App, patch apps.Patch, binding *value) ([]session.Var, error) {
	merged := jobject()
	for _, k := range slices.Sorted(maps.Keys(a.Env)) {
		merged.set(k, jstr(a.Env[k]))
	}
	for _, k := range slices.Sorted(maps.Keys(patch.Env)) {
		merged.set(k, jstr(patch.Env[k]))
	}
	for _, k := range slices.Sorted(maps.Keys(a.EnvFromGrant)) {
		v, err := binding.index(a.EnvFromGrant[k])
		if err != nil {
			return nil, err
		}
		switch v.kind {
		case 'n':
		case '[', '{':
			// One variable is one value: a list has no one way to be a
			// string, and the shell that once exported these made the rest
			// of one names of variables of their own.
			return nil, refuse("%s: %s is not one value, so %s cannot be it", k, a.EnvFromGrant[k], k)
		default:
			merged.set(k, v)
		}
	}
	var env []session.Var
	for _, k := range merged.keys {
		env = append(env, session.Var{Name: k, Value: merged.members[k].tostring()})
	}
	return env, nil
}

// PostStop is the session's end: each app's Stop, to release what its
// Prepare started, whatever each says, and then the session's own directory
// and anything staged for it, removed.
func PostStop(ctx context.Context, c Config, registry map[string]apps.App, machine string) error {
	// Only a session's own name: an empty one would remove every session's
	// directory, and one with a '/' or a leading '.' somewhere else.
	if machine == "" || strings.Contains(machine, "/") || machine[0] == '.' {
		return refuse("%q is not a session's name", machine)
	}
	for _, name := range slices.Sorted(maps.Keys(registry)) {
		registry[name].Stop(ctx, machine)
	}
	os.RemoveAll(c.runtime() + "/chase/" + machine)
	os.RemoveAll(staged(c, machine))
	return nil
}
