// Package gcloud is Google Cloud's classification, GENERATED from Google's
// own descriptions of its APIs, as every other app's is generated from its
// published spec (docs/gcloud.md, decision 8):
//
//	chase-generate gcloud                                 from the pinned sources
//	chase-generate gcloud DISCOVERY_DIR GOOGLEAPIS_DIR    from checkouts of them
//	chase-generate gcloud --bump [DISCOVERY_COMMIT GOOGLEAPIS_COMMIT]
//
// REST from the Discovery documents in googleapis/discovery-artifact-manager,
// gRPC from the google.api.http rules in googleapis/googleapis, each pinned
// at a commit in apps/gcloud/source.json with a sha256 for every file read. A
// checkout is only where the files come from: each must hash as pinned, and
// only the pinned files are read. --bump re-pins, at each repository's head
// unless commits are given, and is a reviewed change like any other: the
// diff of apps/gcloud/apis is what gets read.
//
// Writes apps/gcloud/apis/<api>.json, one rule per line, and
// apps/gcloud/index.json, what each API is: its versions, hosts, gRPC
// services and streaming methods. How each is classed comes from
// apps/gcloud/exceptions.json. git fetches and protoc compiles, as they did
// for scripts/gcloud.sh; nothing here parses a .proto.
package gcloud

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/term"
)

// Config is what the generator is given where scripts/gcloud.sh found it
// beside itself. Nothing in it comes from the NixOS module: the generator
// is run by hand, in the devShell, from a checkout of chase.
type Config struct {
	// App is the directory holding source.json and exceptions.json, where
	// apis/ and index.json are written: apps/gcloud in a checkout of chase
	// (the script's "$scripts/../apps/gcloud").
	App string `json:"app"`
	// Git is the git binary that fetches the sources. Empty is "git" on
	// PATH, as the script ran it.
	Git string `json:"git,omitempty"`
	// Protoc is the protoc binary that compiles the protos. Empty is
	// "protoc" on PATH.
	Protoc string `json:"protoc,omitempty"`
}

const usage = "usage: scripts/gcloud.sh [DISCOVERY_DIR GOOGLEAPIS_DIR | --bump [DISCOVERY_COMMIT GOOGLEAPIS_COMMIT]]"

// ExitError is a failure and the status the script exited with for it:
// git's own where git failed (set -e), 2 where tar could not copy a pinned
// file or grep found no directory to search, 1 for the rest. Said is
// whether its words are already on stderr -- git's, protoc's,
// sha256sum's -- so nothing more is said.
type ExitError struct {
	Code int
	Said bool
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// Main is scripts/gcloud.sh whole: Run, then what the script said and the
// status it exited with. A command that wires it exits with what it
// returns.
func Main(cfg Config, args []string, stdout, stderr io.Writer) int {
	return exit(Run(cfg, args, stdout, stderr), stderr)
}

func exit(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	var e *ExitError
	if errors.As(err, &e) {
		if !e.Said {
			fmt.Fprint(stderr, term.Clean("gcloud: "+e.Err.Error())+"\n")
		}
		return e.Code
	}
	fmt.Fprint(stderr, term.Clean("gcloud: "+err.Error())+"\n")
	return 1
}

// Run is scripts/gcloud.sh: args are its arguments. What git, protoc and
// sha256sum's check said reaches stdout and stderr as it did from the
// script. A returned error is how it failed (an *ExitError where the
// status is not 1, or its words are already said); flag.ErrHelp is the
// usage line, already on stderr, and exit 2. Main says the rest.
func Run(cfg Config, args []string, stdout, stderr io.Writer) error {
	bump := false
	if len(args) > 0 && args[0] == "--bump" {
		bump = true
		args = args[1:]
	}
	if len(args) != 0 && len(args) != 2 {
		fmt.Fprintln(stderr, usage)
		return flag.ErrHelp
	}
	r := &runner{cfg: cfg, stdout: stdout, stderr: stderr}
	if r.cfg.Git == "" {
		r.cfg.Git = "git"
	}
	if r.cfg.Protoc == "" {
		r.cfg.Protoc = "protoc"
	}
	app, err := filepath.Abs(cfg.App)
	if err != nil {
		return err
	}
	r.app, r.source = app, filepath.Join(app, "source.json")
	work, err := os.MkdirTemp("", "tmp.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	r.work = work
	return r.run(bump, args)
}

const toolUsage = `Google Cloud's classification, from Google's own descriptions of its APIs.

    generate APP DISCOVERIES GOOGLEAPIS DESCRIPTORS ENTRIES
    pins APP DISCOVERIES GOOGLEAPIS DESCRIPTORS ENTRIES

Run by the gcloud generator, which fetches the pinned sources, checks every
file against its hash and compiles the protos; see docs/gcloud.md.
`

// Tool is scripts/gcloud.py: `generate APP DISCOVERIES GOOGLEAPIS
// DESCRIPTORS ENTRIES` writes the classification from sources already
// fetched, checked and compiled -- what the flake's gcloud check runs on
// its fixtures -- and `pins` prints, as JSON, what a bump would pin. It
// returns the exit status: 2 for its usage, 1 for a refusal, said on
// stderr as "gcloud: " and every problem a line.
func Tool(args []string, stdout, stderr io.Writer) int {
	if len(args) != 6 || (args[0] != "generate" && args[0] != "pins") {
		fmt.Fprint(stderr, toolUsage+"\n")
		return 2
	}
	if args[0] == "pins" {
		p, err := Pins(args[1], args[2], args[3], args[4], args[5])
		if err != nil {
			return exit(err, stderr)
		}
		fmt.Fprint(stdout, p.JSON())
		return 0
	}
	return exit(Generate(args[1], args[2], args[3], args[4], args[5], stderr), stderr)
}

type runner struct {
	cfg               Config
	stdout, stderr    io.Writer
	app, source, work string
	sourceJSON        *object
	discoveryRepo     string
	googleapisRepo    string
}

func (r *runner) run(bump bool, args []string) error {
	if err := r.readSource(); err != nil {
		return err
	}
	if bump {
		if err := r.bump(args); err != nil {
			return err
		}
		args = []string{filepath.Join(r.work, "discovery"), filepath.Join(r.work, "googleapis")}
	}
	if len(args) == 0 {
		for _, repo := range []string{"discovery", "googleapis"} {
			o := asObject(r.sourceJSON.vals[repo])
			fs := asObject(o.vals["files"])
			keys := append([]string(nil), fs.keys...)
			sort.Strings(keys)
			patterns := make([]string, len(keys))
			for i, k := range keys {
				patterns[i] = "/" + k
			}
			repository, err := jqString0(o, "repository")
			if err != nil {
				return err
			}
			commit, err := jqString0(o, "commit")
			if err != nil {
				return err
			}
			if err := r.checkout(repository, commit, filepath.Join(r.work, repo), patterns); err != nil {
				return err
			}
		}
		args = []string{filepath.Join(r.work, "discovery"), filepath.Join(r.work, "googleapis")}
	}

	// Only the pinned files, each as pinned: copied out of the checkout,
	// then hashed where they will be read.
	for i, repo := range []string{"discovery", "googleapis"} {
		from, err := filepath.Abs(args[i])
		if err != nil {
			return err
		}
		pinned := filepath.Join(r.work, "pinned", repo)
		if err := os.MkdirAll(pinned, 0o777); err != nil {
			return err
		}
		fs := asObject(asObject(r.sourceJSON.vals[repo]).vals["files"])
		keys := append([]string(nil), fs.keys...)
		sort.Strings(keys)
		if err := copyPinned(from, pinned, keys, r.stderr); err != nil {
			return err
		}
		if !r.check(pinned, fs) {
			return fmt.Errorf("the %s files above are not as pinned in %s", repo, r.source)
		}
	}

	var entries []string
	if e, ok := asObject(r.sourceJSON.vals["googleapis"]).get("entries"); ok {
		list, _ := e.([]any)
		for _, x := range list {
			s, ok := x.(string)
			if !ok {
				return errors.New("source.json: googleapis.entries holds something that is not a string")
			}
			entries = append(entries, s)
		}
	}
	entriesFile := filepath.Join(r.work, "entries")
	if err := os.WriteFile(entriesFile, []byte(lines(entries)), 0o666); err != nil {
		return err
	}
	descriptors := filepath.Join(r.work, "descriptors.pb")
	if err := r.compile(filepath.Join(r.work, "pinned", "googleapis"), entries, descriptors); err != nil {
		return err
	}
	return Generate(r.app, filepath.Join(r.work, "pinned", "discovery", "discoveries"), filepath.Join(r.work, "pinned", "googleapis"),
		descriptors, entriesFile, r.stderr)
}

func lines(items []string) string {
	var b strings.Builder
	for _, s := range items {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	return b.String()
}

func (r *runner) readSource() error {
	o, err := loadObject(r.source)
	if err != nil {
		return err
	}
	r.sourceJSON = o
	return nil
}

// jqString0 is `jq -r .key` of a string.
func jqString0(o *object, key string) (string, error) {
	v, _ := o.get(key)
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("source.json: %s is not a string", key)
	}
	return s, nil
}

// git runs git, its output passed through as the script's was.
func (r *runner) git(stdin io.Reader, args ...string) error {
	cmd := exec.Command(r.cfg.Git, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, r.stdout, r.stderr
	return said(cmd.Run(), "git "+args[0])
}

// said is a command's failure as the script's set -e ended it: with the
// command's own status, the command having said why.
func said(err error, what string) error {
	if err == nil {
		return nil
	}
	var x *exec.ExitError
	if !errors.As(err, &x) || x.ExitCode() <= 0 {
		return fmt.Errorf("%s: %w", what, err)
	}
	return &ExitError{Code: x.ExitCode(), Said: true, Err: fmt.Errorf("%s: %w", what, err)}
}

// checkout is a sparse checkout of one commit, fetched by its hash,
// holding only what the patterns name.
func (r *runner) checkout(repository, commit, dir string, patterns []string) error {
	if err := r.git(nil, "init", "-q", dir); err != nil {
		return err
	}
	if err := r.git(nil, "-C", dir, "fetch", "-q", "--depth", "1", "--filter=blob:none", repository, commit); err != nil {
		return err
	}
	in := lines(patterns)
	if len(patterns) == 0 {
		// printf '%s\n' with nothing to print prints one empty line.
		in = "\n"
	}
	if err := r.git(strings.NewReader(in), "-C", dir, "sparse-checkout", "set", "--no-cone", "--stdin"); err != nil {
		return err
	}
	return r.git(nil, "-C", dir, "checkout", "-q", "FETCH_HEAD")
}

// compile is the protos compiled: what protobuf's own descriptor reader
// reads, so nothing here parses a .proto. What protoc says is shown only
// when it fails.
func (r *runner) compile(dir string, entries []string, out string) error {
	args := append([]string{"-I", ".", "--include_imports", "--include_source_info", "--descriptor_set_out=" + out}, entries...)
	cmd := exec.Command(r.cfg.Protoc, args...)
	cmd.Dir = dir
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = r.stdout, &log
	if err := cmd.Run(); err != nil {
		r.stderr.Write([]byte(term.Clean(log.String())))
		return &ExitError{Code: 1, Said: true, Err: fmt.Errorf("protoc: %w", err)}
	}
	return nil
}

// copyPinned copies the pinned files out of a checkout, as the script's
// tar did: a file as a file, a link as a link, every file that is there
// though one is not, and then tar's status, 2, having said which were not.
// A name that is not a local path is refused -- tar would have read it
// from outside the checkout.
func copyPinned(from, to string, names []string, stderr io.Writer) error {
	missing := false
	for _, name := range names {
		if !filepath.IsLocal(name) {
			return &ExitError{Code: 2, Err: fmt.Errorf("source.json pins %q, which is not a path in a checkout", name)}
		}
		src, dst := filepath.Join(from, name), filepath.Join(to, name)
		info, err := os.Lstat(src)
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprint(stderr, term.Clean("tar: "+name+": Cannot stat: No such file or directory")+"\n")
			missing = true
			continue
		}
		if err != nil {
			return &ExitError{Code: 2, Err: err}
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o777); err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(src)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, dst); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			b, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dst, b, info.Mode().Perm()); err != nil {
				return err
			}
		default:
			return &ExitError{Code: 2, Err: fmt.Errorf("%s is not a file", name)}
		}
	}
	if missing {
		fmt.Fprintln(stderr, "tar: Exiting with failure status due to previous errors")
		return &ExitError{Code: 2, Said: true, Err: errors.New("a pinned file is not in the checkout")}
	}
	return nil
}

var hexHash = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// check is `sha256sum --quiet --strict -c` of the pinned hashes, in
// source.json's order: what does not match is said as sha256sum says it,
// and false returned.
func (r *runner) check(dir string, pins *object) bool {
	failed, unread, malformed := 0, 0, 0
	for n, name := range pins.keys {
		want, _ := pins.vals[name].(string)
		if !hexHash.MatchString(want) || strings.ContainsAny(name, "\n") {
			fmt.Fprintf(r.stderr, "sha256sum: -: %d: improperly formatted SHA256 checksum line\n", n+1)
			malformed++
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintf(r.stderr, "sha256sum: %s: No such file or directory\n", term.Clean(name))
			fmt.Fprintf(r.stdout, "%s: FAILED open or read\n", term.Clean(name))
			unread++
			continue
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != strings.ToLower(want) {
			fmt.Fprintf(r.stdout, "%s: FAILED\n", term.Clean(name))
			failed++
		}
	}
	plural := func(n int, one, many string) string {
		if n == 1 {
			return one
		}
		return many
	}
	if malformed > 0 {
		fmt.Fprintf(r.stderr, "sha256sum: WARNING: %d %s improperly formatted\n", malformed, plural(malformed, "line is", "lines are"))
	}
	if unread > 0 {
		fmt.Fprintf(r.stderr, "sha256sum: WARNING: %d listed %s could not be read\n", unread, plural(unread, "file", "files"))
	}
	if failed > 0 {
		fmt.Fprintf(r.stderr, "sha256sum: WARNING: %d computed %s did NOT match\n", failed, plural(failed, "checksum", "checksums"))
	}
	if len(pins.keys) == 0 {
		fmt.Fprintln(r.stderr, "sha256sum: -: no properly formatted checksum lines found")
		return false
	}
	return failed == 0 && unread == 0 && malformed == 0
}

var defaultHost = regexp.MustCompile(`google.api.default_host`)

// bump re-pins: each repository at its head, or at the commits given,
// checked out whole under google/ and grafeas/ (and discoveries/), every
// proto that names a default host compiled, the classification run to see
// what it reads, and source.json rewritten to pin that and nothing else.
func (r *runner) bump(args []string) error {
	var err error
	disc, gapi := asObject(r.sourceJSON.vals["discovery"]), asObject(r.sourceJSON.vals["googleapis"])
	if r.discoveryRepo, err = jqString0(disc, "repository"); err != nil {
		return err
	}
	if r.googleapisRepo, err = jqString0(gapi, "repository"); err != nil {
		return err
	}
	discoveryCommit, googleapisCommit := "", ""
	if len(args) == 2 {
		discoveryCommit, googleapisCommit = args[0], args[1]
	} else {
		if discoveryCommit, err = r.head(r.discoveryRepo); err != nil {
			return err
		}
		if googleapisCommit, err = r.head(r.googleapisRepo); err != nil {
			return err
		}
	}
	discovery, googleapis := filepath.Join(r.work, "discovery"), filepath.Join(r.work, "googleapis")
	if err := r.checkout(r.discoveryRepo, discoveryCommit, discovery, []string{"/discoveries/"}); err != nil {
		return err
	}
	if err := r.checkout(r.googleapisRepo, googleapisCommit, googleapis, []string{"/google/", "/grafeas/"}); err != nil {
		return err
	}
	entries, err := protosWithHosts(googleapis, "google", "grafeas")
	if err != nil {
		return err
	}
	entriesFile := filepath.Join(r.work, "entries")
	if err := os.WriteFile(entriesFile, []byte(lines(entries)), 0o666); err != nil {
		return err
	}
	all := filepath.Join(r.work, "all.pb")
	if err := r.compile(googleapis, entries, all); err != nil {
		return err
	}
	pins, err := Pins(r.app, filepath.Join(discovery, "discoveries"), googleapis, all, entriesFile)
	if err != nil {
		return err
	}
	df, err := hashes(discovery, pins.Discovery)
	if err != nil {
		return err
	}
	gf, err := hashes(googleapis, pins.Googleapis)
	if err != nil {
		return err
	}
	entryList := make([]any, len(pins.Entries))
	for i, e := range pins.Entries {
		entryList[i] = e
	}
	disc = r.member(r.sourceJSON, "discovery")
	disc.set("commit", discoveryCommit)
	disc.set("files", df)
	gapi = r.member(r.sourceJSON, "googleapis")
	gapi.set("commit", googleapisCommit)
	gapi.set("entries", entryList)
	gapi.set("files", gf)

	// The script's jq wrote the new source.json beside the old and moved
	// it over: a reader sees one or the other, created as the umask allows.
	mask := unix.Umask(0)
	unix.Umask(mask)
	return files.WriteAtomic(r.source, []byte(jqPretty(r.sourceJSON)), os.FileMode(0o666&^mask))
}

// member is o[key] as an object, made one where it is not: what jq's
// `.key.field = v` does to a missing or null key.
func (r *runner) member(o *object, key string) *object {
	if m, ok := o.vals[key].(*object); ok {
		return m
	}
	m := newObject()
	o.set(key, m)
	return m
}

// head is `git ls-remote REPOSITORY HEAD | cut -f1`: the commit a
// repository's HEAD is.
func (r *runner) head(repository string) (string, error) {
	cmd := exec.Command(r.cfg.Git, "ls-remote", repository, "HEAD")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, r.stderr
	if err := said(cmd.Run(), "git ls-remote"); err != nil {
		return "", err
	}
	var commits []string
	for _, l := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		c, _, _ := strings.Cut(l, "\t")
		commits = append(commits, c)
	}
	return strings.TrimRight(strings.Join(commits, "\n"), "\n"), nil
}

// protosWithHosts is `grep -rl --include='*.proto' google.api.default_host
// DIR... | sort`: every proto under the directories that names a default
// host, which is every API's service, sorted. grep -r follows no link it
// meets, and fails on a directory that is not there or where nothing
// matches.
func protosWithHosts(root string, dirs ...string) ([]string, error) {
	var out []string
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(root, d)); err != nil {
			// grep's status for a file it cannot read.
			return nil, &ExitError{Code: 2, Err: fmt.Errorf("grep: %s: No such file or directory", d)}
		}
		err := filepath.WalkDir(filepath.Join(root, d), func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !e.Type().IsRegular() || !matchGlob(e.Name()) {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if defaultHost.Match(b) {
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		// grep's status where nothing matched, having said nothing.
		return nil, &ExitError{Code: 1, Said: true, Err: errors.New("no proto names google.api.default_host")}
	}
	sort.Strings(out)
	return out, nil
}

func matchGlob(name string) bool {
	ok, _ := filepath.Match("*.proto", name)
	return ok
}

// hashes is `xargs sha256sum | jq ... from_entries`: each file's sha256,
// keyed by its path, in the order given.
func hashes(dir string, names []string) (*object, error) {
	o := newObject()
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		o.set(name, hex.EncodeToString(sum[:]))
	}
	return o, nil
}
