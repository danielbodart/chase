// Package generate is what a person runs to regenerate what chase reads but
// does not derive at run time: an app's classification from its provider's
// own description of its API, and the version. It is dev-only: the NixOS
// module never runs it, and nothing chase's own binary imports imports it,
// which is why it alone may read YAML and GraphQL.
package generate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/term"
	"golang.org/x/sys/unix"
)

// An app's classification, GENERATED from the provider's own description
// of its API rather than guessed or learned from logs (docs/cloudflare.md,
// decision 2). Shared by every app whose provider publishes one:
//
//	chase-generate operations cloudflare [path/to/openapi.json]
//	chase-generate operations huggingface [path/to/openapi.json]
//	chase-generate operations github [path/to/openapi.json]
//	chase-generate operations docker [path/to/swagger.yaml]
//
// Every operation in the spec becomes one rule: a method, a path template,
// and a class (PLAN.md, decision 18). GET and HEAD are reads, DELETE is
// guarded, and everything else is a write; the app's exceptions.json says,
// by operation id and with a reason each, where that rule is wrong
// (decision 4) -- under `read`, `write` or `guarded`, the class it is
// instead -- and, under `rules`, what the spec does not describe but a
// client needs, written by hand, with a class and a reason each too. A path
// neither describes gets no rule at all, and is decided by the tier's
// `unmatched`.
//
// What a class is ANSWERED with is not decided here: a tier and an app say
// that, per class. This says only what each operation is.
//
// GraphQL is an endpoint the app's exceptions.json declares, under
// `graphql`: its path, what a query there is, and why it is there. A query
// is a read, whatever it reads. Where source.json pins the provider's
// GraphQL schema too, under `graphql`, each field of its mutation and
// subscription types is an operation of its own, named by the field, in the
// schema's own words and category: a write, or guarded where its name says
// it deletes, and otherwise as exceptions.json says, by the same names as
// any other operation. Without a schema an endpoint's mutations are
// unmatched. An endpoint decides every request at its path, so the
// operations the spec has there are replaced, and it names them.
//
// The spec is PINNED by hash, in the app's source.json. A newer one is
// never picked up on its own, because that would let an endpoint be allowed
// without a person deciding it (decision 3). Bumping the pin is a reviewed
// change, and the diff of operations.json is what gets read -- which is why
// it holds one operation per line.
//
// A spec is OpenAPI 3, whose servers url prefixes every template, or
// Swagger 2.0, whose templates are already relative to its basePath:
// source.json says which, by its `server` or its `basePath`, and says JSON
// or YAML by its `format` or else by its url's extension. A basePath is the
// API's version as well (Docker's /v1.56), so a Swagger spec's info.version
// must be the top of source.json's apiVersions: a pin bumped without the
// range fails. YAML is hashed as it was fetched and only then read.
//
// Where the spec comes from, first found: the argument; the app's vendored
// spec.json or spec.yaml (or openapi.json, as the apps before YAML still
// have it), for a provider that publishes its spec at a URL that moves
// rather than at a commit; the pinned URL. Whichever it is, it must hash as
// pinned, so the choice saves a download and changes nothing else. A
// GraphQL schema is the app's vendored schema.graphql, or its pinned URL.
//
// An app with an admit.json is ADMITTED, not classed (Docker,
// docs/docker.md): its route answers no class, and a request passes only
// where admit.json names the operation, with the methods it lists and the
// `docker` block frisket checks the request by, and nothing else admits: an
// exceptions.json with rules, GraphQL or classes fails. Every other
// operation is still a rule, a refusal that carries its operation, so that
// what was refused is named. Its class is kept, because frisket refuses a
// rule of no known class, though nothing answers it. And for each operation
// admitted with a `body` table, known.json lists every field the spec gives
// that body, so that a pin bump shows new fields in its diff.

// ExitError is a failure and the status the command exits with: 2 for how
// it was called, 1 for what it was given, 5 where jq would have stopped
// with an error of its own.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

func exitf(code int, format string, args ...any) error {
	return &ExitError{Code: code, Err: fmt.Errorf(format, args...)}
}

// OperationsOptions is what one run of the generator is for.
type OperationsOptions struct {
	// Apps is the directory holding each app's own: <Apps>/<Name>/source.json
	// and the rest. What the script found beside itself, at ../apps.
	Apps string
	// Name is the app.
	Name string
	// Spec, where not empty, is the spec to read instead of the vendored or
	// pinned one. It must hash as pinned all the same.
	Spec string
	// Client fetches what is neither given nor vendored; nil is
	// http.DefaultClient.
	Client *http.Client
	// Stderr is told what was generated.
	Stderr io.Writer
}

// Operations writes <Apps>/<Name>/operations.json, and for an admitted app
// known.json, from the pinned spec, or refuses with why.
func Operations(ctx context.Context, o OperationsOptions) error {
	app := o.Apps + "/" + o.Name
	source := app + "/source.json"
	if !isFile(source) {
		return exitf(2, "operations: %s does not exist", source)
	}
	exceptionsPath := app + "/exceptions.json"
	admitPath := app + "/admit.json"
	out := app + "/operations.json"
	knownPath := app + "/known.json"

	// What a person writes and reviews is read as they read it. jq, like
	// every JSON reader here, keeps the LAST of a key given twice, so a
	// reviewer could read the first while the second took effect: a key
	// given twice, at any depth, is refused.
	hand := map[string][]any{}
	for _, path := range []string{source, exceptionsPath, admitPath} {
		if !isFile(path) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return exitf(1, "operations: %v", err)
		}
		values, dup, err := parseJSON(data)
		if err != nil {
			return exitf(1, "operations: %s is not JSON: %v", path, err)
		}
		if dup {
			return exitf(1, "operations: %s gives a key twice in one object, and only the last would count", path)
		}
		hand[path] = values
	}

	pinned := hand[source]
	pin := func(orEmpty bool, path ...string) (string, error) { return rawField(pinned, orEmpty, path...) }
	url, err1 := pin(false, "url")
	sha, err2 := pin(false, "sha256")
	server, err3 := pin(true, "server")
	basePath, err4 := pin(true, "basePath")
	version, err5 := pin(true, "apiVersions", "max")
	format, err6 := pin(true, "format")
	if err := errors.Join(err1, err2, err3, err4, err5, err6); err != nil {
		return exitf(5, "operations: %s: %v", source, err)
	}

	work, err := os.MkdirTemp("", "operations.")
	if err != nil {
		return exitf(1, "operations: %v", err)
	}
	defer os.RemoveAll(work)

	// Which kind of spec, and in what: exactly one of server and basePath,
	// and a format that agrees with it where one is given.
	switch format {
	case "", "swagger2-json", "swagger2-yaml", "openapi3-json", "openapi3-yaml":
	default:
		return exitf(1, "operations: %s: format %s is not swagger2-json, swagger2-yaml, openapi3-json or openapi3-yaml", source, format)
	}
	var flavor string
	switch {
	case basePath != "" && server == "":
		flavor = "swagger2"
	case server != "" && basePath == "":
		flavor = "openapi3"
	default:
		return exitf(1, "operations: %s needs exactly one of server (OpenAPI 3) and basePath (Swagger 2.0)", source)
	}
	if format != "" && format[:strings.LastIndex(format, "-")] != flavor {
		by := "server"
		if basePath != "" {
			by = "basePath"
		}
		return exitf(1, "operations: %s: format %s, but a %s spec by its %s", source, format, flavor, by)
	}
	if flavor == "swagger2" && version == "" {
		return exitf(1, "operations: %s: a Swagger spec is its basePath's version, which apiVersions.max must say", source)
	}
	var ext string
	switch {
	case format != "":
		ext = format[strings.Index(format, "-")+1:]
	case strings.HasSuffix(url, ".json"):
		ext = "json"
	case strings.HasSuffix(url, ".yaml"), strings.HasSuffix(url, ".yml"):
		ext = "yaml"
	default:
		return exitf(1, "operations: %s: %s is neither .json nor .yaml, so format must say which", source, url)
	}

	spec := o.Spec
	switch {
	case spec == "" && isFile(app+"/spec."+ext):
		spec = app + "/spec." + ext
	case spec == "" && ext == "json" && isFile(app+"/openapi.json"):
		spec = app + "/openapi.json"
	case spec == "":
		spec = work + "/spec." + ext
		if err := fetch(ctx, o.Client, url, spec); err != nil {
			return exitf(1, "operations: could not fetch %s: %v", url, err)
		}
	}

	// The bytes that were hashed are what is read: YAML only after it is
	// pinned.
	data, err := os.ReadFile(spec)
	if err != nil {
		return exitf(1, "operations: %v", err)
	}
	if actual := sha256Hex(data); actual != sha {
		return exitf(1, "operations: %s is not the pinned spec.\n  expected sha256 %s\n  got             %s\n  (pinned: %s, in %s/source.json)", spec, sha, actual, url, app)
	}
	var root any
	if ext == "yaml" {
		if root, err = readYAML(data); err != nil {
			return exitf(1, "operations: could not read %s as YAML: %v", spec, err)
		}
	} else {
		values, _, err := parseJSON(data)
		if err != nil {
			return exitf(5, "operations: %s is not JSON: %v", spec, err)
		}
		if len(values) != 1 {
			return exitf(1, "operations: %s is %d JSON values, not one", spec, len(values))
		}
		root = values[0]
	}

	// No exceptions is none; no admit.json is an app whose classes are
	// answered. A file with no value in it is null, as --slurpfile read it.
	var exceptions any = NewObject()
	if values, ok := hand[exceptionsPath]; ok {
		exceptions = first(values)
	}
	var admit any
	if values, ok := hand[admitPath]; ok {
		admit = first(values)
	}

	// The GraphQL schema, pinned the same way, read into its operations.
	graphqlPath, err := pin(true, "graphql", "path")
	if err != nil {
		return exitf(5, "operations: %s: %v", source, err)
	}
	var fields []field
	if graphqlPath != "" {
		gURL, err1 := pin(false, "graphql", "url")
		gSHA, err2 := pin(false, "graphql", "sha256")
		if err := errors.Join(err1, err2); err != nil {
			return exitf(5, "operations: %s: %v", source, err)
		}
		sdl := app + "/schema.graphql"
		if !isFile(sdl) {
			sdl = work + "/schema.graphql"
			if err := fetch(ctx, o.Client, gURL, sdl); err != nil {
				return exitf(1, "operations: could not fetch %s: %v", gURL, err)
			}
		}
		text, err := os.ReadFile(sdl)
		if err != nil {
			return exitf(1, "operations: %v", err)
		}
		if actual := sha256Hex(text); actual != gSHA {
			return exitf(1, "operations: %s is not the pinned GraphQL schema.\n  expected sha256 %s\n  got             %s\n  (pinned: %s, in %s/source.json)", sdl, gSHA, actual, gURL, app)
		}
		if !utf8.Valid(text) {
			return exitf(1, "operations: could not read %s: it is not UTF-8", sdl)
		}
		if fields, err = schemaFields(string(text)); err != nil {
			return exitf(1, "operations: could not read %s: %v", sdl, err)
		}
	}

	text, err := classify(classifyInput{
		name: o.Name, root: root, exceptions: exceptions, admit: admit, fields: fields,
		graphqlPath: graphqlPath, flavor: flavor, server: server, basePath: basePath, version: version,
	})
	if err != nil {
		return failed(err)
	}
	mode := creationMode()
	if err := files.WriteAtomic(out, []byte(text), mode); err != nil {
		return exitf(1, "operations: %v", err)
	}

	// The fields of each admitted body, as the spec gives them.
	if isFile(admitPath) {
		k, err := known(o.Name, root, admit)
		if err != nil {
			return failed(err)
		}
		if err := files.WriteAtomic(knownPath, []byte(k), mode); err != nil {
			return exitf(1, "operations: %v", err)
		}
	}

	return summarise(o.Stderr, o.Name, text)
}

// summarise says what was generated: how many operations of each class,
// how many admitted, and how many GraphQL.
func summarise(w io.Writer, name, text string) error {
	values, _, err := parseJSON([]byte(text))
	if err != nil || len(values) != 1 {
		return exitf(1, "operations: %s: what was written does not read back: %v", name, err)
	}
	rules, _ := values[0].([]any)
	q := &eval{}
	class := func(r any) any { return q.get(q.get(r, "operation"), "class") }
	var counts []any
	for _, g := range groupBy(rules, class) {
		counts = append(counts, fmt.Sprintf("%d %s", len(g), interp(class(g[0]))))
	}
	joined, _ := join(counts, ", ")
	say(w, "operations: %s: %d operations: %s.", name, len(rules), joined)
	count := func(key string, in []any) []any {
		var out []any
		for _, r := range in {
			if truthy(q.get(r, key)) {
				out = append(out, r)
			}
		}
		return out
	}
	if admitted := count("docker", rules); len(admitted) > 0 {
		say(w, "operations: %s: of which admitted: %d; the rest are refused.", name, len(admitted))
	}
	if g := count("graphql", rules); len(g) > 0 {
		say(w, "operations: %s: of which GraphQL: %d queries, %d mutations, %d subscriptions.",
			name, len(count("query", g)), len(count("mutation", g)), len(count("subscription", g)))
	}
	return nil
}

// say writes one line to w, cleaned: what it names came from a checkout
// and a provider's spec. The script printed it raw. term.Clean makes a '?'
// of each control byte and of each raw byte from 0x80 to 0x9f, which a
// terminal not reading UTF-8 acts on as C1 -- and which is also the second
// or third byte of many a UTF-8 character: '—', '€', '“', much CJK. So an
// id or summary holding one reads mangled here, as term's own comment
// accepts: a refusal read wrong is better than one that writes.
func say(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprint(w, term.Clean(fmt.Sprintf(format, args...))+"\n")
}

// failed is a classification's refusal as the command's: 1 for a failure
// of the program, 5 for an error jq would have stopped with.
func failed(err error) error {
	var f *Failure
	if errors.As(err, &f) && strings.HasPrefix(f.Message, "jq: error: ") {
		return &ExitError{Code: 5, Err: err}
	}
	return &ExitError{Code: 1, Err: err}
}

func first(values []any) any {
	if len(values) == 0 {
		return nil
	}
	return values[0]
}

// rawField is `jq -r .a.b [// empty]` as a shell's $(...) took it: each
// value's output on its own line, a string as it is and anything else as
// JSON, nothing for null or false where `// empty` says so, and the
// trailing newlines gone.
func rawField(values []any, orEmpty bool, path ...string) (string, error) {
	q := &eval{}
	var lines []string
	for _, v := range values {
		for _, p := range path {
			v = q.get(v, p)
		}
		if orEmpty && !truthy(v) {
			continue
		}
		lines = append(lines, interp(v))
	}
	if q.err != nil {
		return "", q.err
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n"), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// isFile is the shell's [ -f path ]: a regular file, through a link.
func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// creationMode is what a shell's `>` would have created a file with: 0666
// less the umask.
func creationMode() os.FileMode {
	u := unix.Umask(0)
	unix.Umask(u)
	return 0o666 &^ os.FileMode(u)
}
