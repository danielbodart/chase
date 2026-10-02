package grant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/policydoc"
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
	var pd policy.Document
	if err := policy.Decode(pb, &pd); err != nil {
		return session.Given{}, err
	}
	// The tier's own machines, in every session of it, before any app a
	// grant binds: SSH's Prepare refuses a grant's machine of the same name
	// or address, so none of them is replaced.
	if c.SSH != nil {
		routes, err := c.SSH.TierRoutes(tier)
		if err != nil {
			return session.Given{}, refuse("%s: ssh: %v", ws, err)
		}
		if len(routes) > 0 {
			policydoc.Merge(&pd, apps.Patch{SSH: routes})
		}
	}
	var given session.Given
	if strings.TrimRight(string(b), "\n") != "null" {
		if given, err = apply(ctx, c, registry, &pd, b, run, tier, ws, stderr); err != nil {
			return session.Given{}, err
		}
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	var doc any = pd
	if rec != nil {
		doc = recordedDocument{Document: pd, Record: rec.block(c, machine)}
	}
	if err := enc.Encode(doc); err != nil {
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

// apply is the staged approval b, applied to the tier's document pd for the
// session whose directory is run: its secrets decrypted there, each bound
// app prepared and merged in, and the project's lists applied last.
func apply(ctx context.Context, c Config, registry map[string]apps.App, pd *policy.Document, b []byte, run, tier, ws string, stderr io.Writer) (session.Given, error) {
	var given session.Given
	doc, err := parseJSON(b)
	if err != nil {
		return given, err
	}
	result, err := doc.index("result")
	if err != nil {
		return given, err
	}
	secrets, err := result.optional("secrets")
	if err != nil {
		return given, err
	}
	if err := os.Mkdir(run+"/secrets", 0o700); err != nil {
		return given, err
	}
	file := ""
	if secrets != "" {
		dir, err := os.MkdirTemp(run, "sops.")
		if err != nil {
			return given, err
		}
		staged, err := doc.index("secrets")
		if err != nil {
			return given, err
		}
		name, err := staged.optional("name")
		if err != nil {
			return given, err
		}
		text, err := staged.index("text")
		if err != nil {
			return given, err
		}
		file = dir + "/" + name
		if err := os.WriteFile(file, []byte(text.raw()), 0o666); err != nil {
			return given, err
		}
		approved, err := result.optional("secretsSHA256")
		if err != nil {
			return given, err
		}
		d := sha256.Sum256([]byte(text.raw()))
		if hex.EncodeToString(d[:]) != approved {
			return given, refuse("%s: the staged %s is not the one approved", ws, secrets)
		}
	}

	// The Docker project approve derived and staged, which is what was
	// approved: read, never derived again here. An app is given it, and the
	// session is not.
	project, err := result.optional("dockerProject")
	if err != nil {
		return given, err
	}
	bindings, err := result.index("apps")
	if err != nil {
		return given, err
	}
	names := slices.Sorted(maps.Keys(c.Apps))
	for name := range registry {
		if _, ok := c.Apps[name]; !ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, app := range names {
		binding, err := bindings.index(app)
		if err != nil {
			return given, err
		}
		if !binding.truthy() {
			continue
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
			from = secrets + ":" + secret
		} else {
			if !isCode {
				return given, refuse("%s: %s has no credential and no prepare", ws, app)
			}
		}
		// The app's routes, in place of any of the same names the tier had:
		// what its code made of the binding, or its own with the project's
		// credential.
		var patch apps.Patch
		if isCode {
			patch, err = code.Prepare(ctx, apps.Request{
				Tier: tier, Workspace: ws, Run: run, Dir: checkoutDir(c, ws), Home: c.Home,
				Project: project, Binding: json.RawMessage(binding.compact()),
			})
			if err != nil {
				// What the app's own prepare said as it died, and then the
				// launch's own die.
				term.Say(stderr, "%v", err)
				return given, refuse("%s: %s could not be prepared", ws, app)
			}
		} else if patch, err = staticPatch(conf, tier, run+"/secrets/"+app); err != nil {
			return given, err
		}
		policydoc.Merge(pd, patch)
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
	if err := applyLists(pd, bindings, ws, tier, stderr); err != nil {
		return given, err
	}
	// The names the project reaches beyond its apps', added last, as an
	// app's are: to a tier that allows every name, nothing.
	var named struct {
		Network *Network `json:"network"`
	}
	if err := json.Unmarshal([]byte(result.compact()), &named); err != nil {
		return given, err
	}
	if named.Network != nil && len(named.Network.Allow) > 0 {
		policydoc.Merge(pd, apps.Patch{Allow: named.Network.Allow})
	}
	return given, nil
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
func staticPatch(a App, tier, cred string) (apps.Patch, error) {
	p := apps.Patch{Allow: a.Allow}
	raw, ok := a.Routes[tier]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return p, nil
	}
	var routes []policy.Route
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '[' {
		if err := policy.Decode(t, &routes); err != nil {
			return apps.Patch{}, err
		}
	} else {
		var r policy.Route
		if err := policy.Decode(t, &r); err != nil {
			return apps.Patch{}, err
		}
		routes = []policy.Route{r}
	}
	for i := range routes {
		routes[i].CredentialFile = cred
	}
	p.Routes = routes
	return p, nil
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

// applyLists is what the project names in each app's lists, applied to the
// app's route in this tier: one with the project's credential or the tier's.
// Not to an app the tier does not have, or has anonymously -- with no
// credential, and no one to ask for someone else's code -- which is said
// rather than refused (PLAN.md, decision 8).
func applyLists(pd *policy.Document, bindings *value, ws, tier string, stderr io.Writer) error {
	// `.apps // {} | to_entries[]`.
	keys, vals, err := bindings.or(jobject()).entries()
	if err != nil {
		return err
	}
	for i, app := range keys {
		lists, err := listsOf(vals[i])
		if err != nil {
			return err
		}
		n := 0.0
		for _, l := range lists {
			k, err := l.length()
			if err != nil {
				return err
			}
			n += k
		}
		if n <= 0 {
			continue
		}
		at := slices.IndexFunc(pd.Routes, func(r policy.Route) bool { return r.Name == app })
		switch {
		case at < 0:
			term.Say(stderr, "%s: %s's lists ignored: %s has no %s", ws, app, tier, app)
			continue
		// Anonymous is an empty credentialFile as well as none. jq's
		// `.credentialFile` was true of any string, "" too, so a tier route
		// written with `"credentialFile": ""` had the project's lists
		// applied; frisket's Document cannot tell "" from absent, and the
		// document is written without it, so that route IS anonymous in what
		// frisket loads, and its lists are said to be ignored, as any
		// anonymous route's are. A deliberate change, of an edge the module
		// never writes.
		case pd.Routes[at].CredentialFile == "":
			term.Say(stderr, "%s: %s's lists ignored: %s is anonymous in %s", ws, app, app, tier)
			continue
		}
		// `{allow, ask, refuse} | map_values(. // [])`.
		given := jobject()
		for _, k := range []string{"allow", "ask", "refuse"} {
			l, _ := vals[i].index(k)
			given.set(k, l.or(&value{kind: '['}))
		}
		var ls policydoc.Lists
		err = json.Unmarshal([]byte(given.compact()), &ls)
		if err == nil {
			err = policydoc.Apply(pd, app, ls)
		}
		if err != nil {
			term.Say(stderr, "%v", err)
			return refuse("%s: its %s lists do not apply", ws, app)
		}
	}
	return nil
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
