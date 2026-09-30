package envelope

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
	"github.com/danielbodart/chase/internal/term"
)

// Var is one variable a launch exports into the session's environment.
type Var struct {
	Name  string
	Value string
}

// Env is the session's environment, as the launch exported it: each
// variable, in the order the env file has it. A value that was not a string
// in the envelope is as the shell took it -- a number or a boolean as
// written, a list as its items separated by spaces.
type Env []Var

// Launch is postStart: what seccompPolicy staged for this launch, applied.
// It consumes the stage, so a launch applies one approval once; re-checks
// that the sops file beside it is the one whose digest was approved;
// decrypts the secret each bound app names; prepares each bound app, by its
// code in registry or from its Config.Apps entry; merges each into the
// tier's policy document, with the project's lists for each app applied
// last; and writes the document and the environment. Nothing staged, or an
// approval of the tier as it is, is no document and no environment.
//
// Everything written is the user's alone, decrypted secrets above all: the
// process's umask is 077 while it runs, as the script's was. Only the env
// file is 0644, since a session reads it.
func Launch(ctx context.Context, c Config, registry map[string]apps.App, tier, ws, machine string, stderr io.Writer) (Env, error) {
	old := unix.Umask(0o077)
	defer unix.Umask(old)
	envfile := envDir(c, ws) + "/env"
	stage := staged(c, machine)
	if !regular(stage) {
		return nil, refuse("%s: nothing was approved for this launch: the tier's seccompPolicy did not run", ws)
	}
	b, err := os.ReadFile(stage)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(stage); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if strings.TrimRight(string(b), "\n") == "null" {
		if err := os.Remove(envfile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, nil
	}
	doc, err := parseJSON(b)
	if err != nil {
		return nil, err
	}
	result, err := doc.index("result")
	if err != nil {
		return nil, err
	}
	secrets, err := result.optional("secrets")
	if err != nil {
		return nil, err
	}
	run := c.runtime() + "/chase/" + machine
	for _, d := range []string{run, run + "/secrets"} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return nil, err
		}
	}
	file := ""
	if secrets != "" {
		dir, err := os.MkdirTemp(run, "sops.")
		if err != nil {
			return nil, err
		}
		staged, err := doc.index("secrets")
		if err != nil {
			return nil, err
		}
		name, err := staged.optional("name")
		if err != nil {
			return nil, err
		}
		text, err := staged.index("text")
		if err != nil {
			return nil, err
		}
		file = dir + "/" + name
		if err := os.WriteFile(file, []byte(text.raw()), 0o666); err != nil {
			return nil, err
		}
		approved, err := result.optional("secretsSHA256")
		if err != nil {
			return nil, err
		}
		d := sha256.Sum256([]byte(text.raw()))
		if hex.EncodeToString(d[:]) != approved {
			return nil, refuse("%s: the staged %s is not the one approved", ws, secrets)
		}
	}

	pb, err := os.ReadFile(c.Policies + "/" + tier + ".json")
	if err != nil {
		return nil, err
	}
	var pd policy.Document
	if err := policy.Decode(pb, &pd); err != nil {
		return nil, err
	}
	// The Docker project approve derived and staged, which is what was
	// approved: read, never derived again here. An app is given it, and the
	// session is not.
	project, err := result.optional("dockerProject")
	if err != nil {
		return nil, err
	}
	bindings, err := result.index("bindings")
	if err != nil {
		return nil, err
	}
	names := slices.Sorted(maps.Keys(c.Apps))
	for name := range registry {
		if _, ok := c.Apps[name]; !ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	var exports strings.Builder
	var env Env
	for _, app := range names {
		binding, err := bindings.index(app)
		if err != nil {
			return nil, err
		}
		if !binding.truthy() {
			continue
		}
		code, isCode := registry[app]
		conf := c.Apps[app]
		// An app with a credential is bound only with the project's own,
		// decrypted; one with none is made by its code from the binding
		// alone.
		var from string
		if conf.hasCredential() {
			cred, err := binding.index("credential")
			if err != nil {
				return nil, err
			}
			secret, err := cred.optional("secret")
			if err != nil {
				return nil, err
			}
			if secret == "" {
				continue
			}
			if err := decrypt(ctx, c, ws, file, secret, run+"/secrets/"+app, stderr); err != nil {
				return nil, err
			}
			from = secrets + ":" + secret
		} else {
			if !isCode {
				return nil, refuse("%s: %s has no credential and no prepare", ws, app)
			}
			from = "no credential"
		}
		// The app's routes, in place of any of the same names the tier had:
		// what its code made of the binding, or its own with the project's
		// credential.
		var patch apps.Patch
		if isCode {
			patch, err = code.Prepare(ctx, apps.Request{
				Tier: tier, Workspace: ws, Run: run, EnvDir: envDir(c, ws),
				Project: project, Binding: json.RawMessage(binding.compact()),
			})
			if err != nil {
				// What the app's own prepare said as it died, and then the
				// launch's own die.
				term.Say(stderr, "%v", err)
				return nil, refuse("%s: %s could not be prepared", ws, app)
			}
		} else if patch, err = staticPatch(conf, tier, run+"/secrets/"+app); err != nil {
			return nil, err
		}
		policydoc.Merge(&pd, patch)
		lines, vars, err := exportsOf(conf, patch, binding)
		if err != nil {
			return nil, err
		}
		exports.WriteString(lines + "\n")
		env = append(env, vars...)
		term.Say(stderr, "%s: %s from %s", ws, app, from)
	}
	if file != "" {
		os.RemoveAll(filepath.Dir(file))
	}
	if err := applyLists(&pd, bindings, ws, tier, stderr); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(pd); err != nil {
		return nil, err
	}
	if err := os.WriteFile(run+"/policy.json", out.Bytes(), 0o666); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(envfile), 0o777); err != nil {
		return nil, err
	}
	// Written beside itself under a name of its own, and renamed over, as
	// the stage is: the script's fixed env.new was shared by every launch
	// of the checkout, on any machine, so one launch could truncate what
	// another was renaming into place, and a session source half an
	// environment. 0644, whatever the umask: a session reads it.
	if err := files.WriteAtomic(envfile, []byte(exports.String()), 0o644); err != nil {
		return nil, err
	}
	return env, nil
}

// decrypt is the secret an app binds, decrypted from the staged copy of the
// sops file -- whose digest was approved -- where frisket reads it and the
// session cannot: the runtime directory is bound into no container.
func decrypt(ctx context.Context, c Config, ws, file, secret, out string, stderr io.Writer) error {
	if file == "" {
		return refuse("%s: a binding names secret '%s', and chase.secrets names no file", ws, secret)
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

// exportsOf is what an app puts in the session's environment, as `export
// NAME=<@sh>` lines: its own env, then what its patch adds, then each
// variable it takes from a field of the binding that is there, a later one
// in place of an earlier of the same name.
func exportsOf(a App, patch apps.Patch, binding *value) (string, Env, error) {
	merged := jobject()
	for _, k := range slices.Sorted(maps.Keys(a.Env)) {
		merged.set(k, jstr(a.Env[k]))
	}
	for _, k := range slices.Sorted(maps.Keys(patch.Env)) {
		merged.set(k, jstr(patch.Env[k]))
	}
	for _, k := range slices.Sorted(maps.Keys(a.EnvFromBinding)) {
		v, err := binding.index(a.EnvFromBinding[k])
		if err != nil {
			return "", nil, err
		}
		switch v.kind {
		case 'n':
		case '[', '{':
			// A list would be exported as more than one shell word, the
			// rest of them names of variables of their own.
			return "", nil, refuse("%s: %s is not one value, so %s cannot be it", k, a.EnvFromBinding[k], k)
		default:
			merged.set(k, v)
		}
	}
	var lines []string
	var env Env
	for _, k := range merged.keys {
		v := merged.members[k]
		quoted, err := sh(v)
		if err != nil {
			return "", nil, err
		}
		lines = append(lines, "export "+k+"="+quoted)
		env = append(env, Var{Name: k, Value: shellValue(v)})
	}
	return strings.Join(lines, "\n"), env, nil
}

// shellValue is what a shell makes a variable of from @sh's text.
func shellValue(v *value) string {
	if v.kind != '[' {
		return v.tostring()
	}
	parts := make([]string, len(v.items))
	for i, x := range v.items {
		parts[i] = x.tostring()
	}
	return strings.Join(parts, " ")
}

// applyLists is what the project names in each app's lists, applied to the
// app's route in this tier: one with the project's credential or the tier's.
// Not to an app the tier does not have, or has anonymously -- with no
// credential, and no one to ask for someone else's code -- which is said
// rather than refused (PLAN.md, decision 8).
func applyLists(pd *policy.Document, bindings *value, ws, tier string, stderr io.Writer) error {
	// `.bindings // {} | to_entries[]`.
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
