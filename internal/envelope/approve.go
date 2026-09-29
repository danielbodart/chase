package envelope

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/policydoc"
	"github.com/danielbodart/chase/internal/snapshot"
)

// Result is what an approval gives flong: the syscalls the approved envelope
// loosens, each list as seccompPolicy printed it after "allow " and "deny ".
type Result struct {
	Allow []string
	Deny  []string
}

// Lines is the result as seccompPolicy prints it on stdout, and nothing
// else: an `allow` line when there is anything to allow, then a `deny` line
// when there is anything to deny.
func (r Result) Lines() string {
	var b strings.Builder
	if len(r.Allow) > 0 {
		b.WriteString("allow " + strings.Join(r.Allow, " ") + "\n")
	}
	if len(r.Deny) > 0 {
		b.WriteString("deny " + strings.Join(r.Deny, " ") + "\n")
	}
	return b.String()
}

// Approve is seccompPolicy: snapshot, approve, evaluate, approve, stage.
//
// ASK, THEN RUN. Nothing of the checkout's is evaluated until a person has
// approved the bytes that decide what evaluating it reaches: its flake.nix
// and flake.lock, which alone declare and pin its inputs. Approving what an
// envelope evaluates to could not be enough on its own, because evaluating a
// flake resolves its inputs first -- and an input can be any path of the
// user's, or any URL.
//
// All of it is done on a SNAPSHOT: the checkout's tracked files, copied
// once. What is compared, shown, evaluated and decrypted is that copy, so a
// session of the same checkout still running cannot change a file between
// the approval and its use.
//
// Everything it says, and what the approver, nix and diff say, goes to
// stderr: the Result is all flong reads. A *Refusal is the script's die.
//
// Everything written is the user's alone: the process's umask is 077 while
// it runs, as the script's was, and what it runs inherits that.
func Approve(ctx context.Context, c Config, ws, machine, tier string, stderr io.Writer) (Result, error) {
	old := unix.Umask(0o077)
	defer unix.Umask(old)
	if machine == "" {
		return Result{}, refuse("no machine: flong names the session before seccompPolicy runs")
	}
	if tier == "" {
		return Result{}, refuse("no tier: the tier's seccompPolicy names it")
	}
	runtime := c.runtime()
	if fi, err := os.Stat(runtime); err != nil || !fi.IsDir() {
		return Result{}, refuse("%s does not exist: log in first", runtime)
	}
	// 0700, by the umask.
	if fi, err := os.Stat(runtime + "/chase/.envelope"); err != nil || !fi.IsDir() {
		if err := os.MkdirAll(runtime+"/chase/.envelope", 0o777); err != nil {
			return Result{}, err
		}
	}
	stage := staged(c, machine)
	// Only a flake that says chaseModules is looked at at all: any other is
	// the tier as it is, and is never evaluated or asked about.
	if !saysChaseModules(ws + "/flake.nix") {
		return Result{}, files.WriteAtomic(stage, []byte("null\n"), 0o600)
	}
	dir := c.state() + "/approved/" + key(ws)

	if err := os.MkdirAll(c.Home+"/.cache/chase", 0o777); err != nil {
		return Result{}, err
	}
	src, err := os.MkdirTemp(c.Home+"/.cache/chase", "snapshot.")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(src)

	g, err := newGit(c)
	if err != nil {
		return Result{}, err
	}
	defer g.Close()

	if err := takeSnapshot(ctx, g, ws, src, stderr); err != nil {
		return Result{}, err
	}
	refused, err := localInputs(src)
	if err != nil {
		return Result{}, err
	}
	if refused != "" {
		return Result{}, refuse("%s: its flake has inputs that are files on this machine, which an envelope may not: %s", ws, refused)
	}

	if err := approveSource(ctx, c, ws, src, dir, stderr); err != nil {
		return Result{}, err
	}
	out, ok := evaluate(ctx, c, src, stderr)
	if !ok {
		return Result{}, refuse("%s: its chaseModules.default does not evaluate", ws)
	}
	if out == "null" {
		return Result{}, files.WriteAtomic(stage, []byte("null\n"), 0o600)
	}
	normal, err := policydoc.Normal([]byte(out))
	if err != nil {
		return Result{}, err
	}
	result, err := parseJSON(normal)
	if err != nil {
		return Result{}, err
	}
	// The result as the script held it, which is the text envelope.json is
	// written as: jq -c's, until a filter without -c printed it whole.
	pretty := false
	// What chase derives and adds below is never the envelope's to say: a
	// project module can declare options of its own under chase, and one
	// naming dockerProject would otherwise stand, unchecked, where there is
	// no Docker binding to derive it.
	result.del("dockerProject")
	result.del("secretsSHA256")
	// One name in two of an app's lists says two things: refused before
	// anyone is asked to approve it.
	twice, err := namedTwice(result)
	if err != nil {
		return Result{}, err
	}
	if twice != "" {
		return Result{}, refuse("%s: named in two lists: %s", ws, twice)
	}
	secrets, err := result.optional("secrets")
	if err != nil {
		return Result{}, err
	}
	file := ""
	if secrets != "" {
		f, ok := gitsafe.Resolve(src + "/" + secrets)
		if !ok {
			return Result{}, refuse("%s: %s is not a tracked file", ws, secrets)
		}
		if !strings.HasPrefix(f, src+"/") {
			return Result{}, refuse("%s: %s is outside the checkout", ws, secrets)
		}
		file = f
		b, err := os.ReadFile(file)
		if err != nil {
			return Result{}, err
		}
		d := sha256.Sum256(b)
		result.set("secretsSHA256", jstr(hex.EncodeToString(d[:])))
		pretty = true
	}
	// Docker, as the project the checkout's origin names, which is part of
	// what is approved: a changed origin is asked about again. An envelope
	// without Docker gains nothing, so one approved before there was Docker
	// still is.
	slug, addr := "", ""
	// `jq -e '.bindings.docker != null'`, whose failing is false.
	if d, err := result.path("bindings", "docker"); err == nil && d.kind != 'n' {
		if slug, err = project(ctx, g, c, ws, tier, stderr); err != nil {
			return Result{}, err
		}
		who, err := address(slug, stderr)
		if err != nil {
			return Result{}, refuse("%s: %s has no address", ws, slug)
		}
		addr = who.Address
		if err := claim(c, ws, slug, addr, false); err != nil {
			return Result{}, err
		}
		result.set("dockerProject", jstr(slug))
		pretty = false
		if err := dockerLine(c, ws, slug, who, result, stderr); err != nil {
			return Result{}, err
		}
	}
	text := result.compact()
	if pretty {
		text = result.pretty()
	}
	if err := approveEnvelope(ctx, c, ws, result, text, dir, stderr); err != nil {
		return Result{}, err
	}
	if slug != "" {
		if err := claim(c, ws, slug, addr, true); err != nil {
			return Result{}, err
		}
	}

	// What postStart applies is what was approved, with the snapshot's sops
	// file beside it: not the checkout, which a session may be changing.
	doc := jobject()
	doc.set("result", result)
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return Result{}, err
		}
		s := jobject()
		s.set("name", jstr(filepath.Base(file)))
		s.set("text", jstr(string(b)))
		doc.set("secrets", s)
	} else {
		doc.set("secrets", jnull)
	}
	if err := files.WriteAtomic(stage, []byte(doc.pretty()+"\n"), 0o600); err != nil {
		return Result{}, err
	}
	return seccomp(result)
}

// saysChaseModules is `[ -f F ] && grep -q chaseModules F`: read through a
// link, as the script read it, since it only decides whether the checkout is
// looked at, and everything looked at is the snapshot's.
func saysChaseModules(f string) bool {
	if !regular(f) {
		return false
	}
	b, err := os.ReadFile(f)
	return err == nil && bytes.Contains(b, []byte("chaseModules"))
}

// takeSnapshot is the checkout's tracked files, as they are now, in a
// directory of the user's own that no session sees. Copied by
// snapshot.CopyTracked, which follows no link at any component: anything
// that opens WS/dir/f by its path, as tar did, lets the kernel resolve dir,
// so a tracked dir/f whose dir a session has made a link to a host
// directory would copy that host's f into what is evaluated and decrypted.
// A check for such a link before and after the copy is no better, since
// another live session of the same checkout can swap it in and back between.
//
// Which files are tracked is read by checkout.Finder.LsFiles, from the index
// alone: never by a git in the checkout, whose config a session writes, and
// which runs what core.fsmonitor names on any read of the index -- here as
// the user, unsandboxed, before anyone is asked.
//
// Each is called as the script called its command, and what it printed read
// as the script read it: a refusal is its line.
func takeSnapshot(ctx context.Context, g *gitsafe.Git, ws, src string, stderr io.Writer) error {
	var list bytes.Buffer
	if rc := checkout.RunLsFiles(ctx, g, []string{ws}, &list, stderr); rc != 0 {
		return refuse("%s: an envelope needs a git checkout, so what is evaluated is what git tracks: %s", ws, gitsafe.Output(list.Bytes()))
	}
	var why bytes.Buffer
	if rc := snapshot.Run([]string{ws, src}, &list, &why, stderr); rc != 0 {
		said := gitsafe.Output(why.Bytes())
		if said == "" {
			said = "its tracked files could not be copied"
		}
		return refuse("%s: %s", ws, said)
	}
	if !regular(src+"/flake.nix") || gitsafe.IsLink(src+"/flake.nix") {
		return refuse("%s: flake.nix is not a tracked file", ws)
	}
	if gitsafe.IsLink(src + "/flake.lock") {
		return refuse("%s: flake.lock is a link", ws)
	}
	return nil
}

var localURL = regexp.MustCompile(`^(file:|git\+file:|path:)`)

// localInputs is every input of the flake that is a file on this machine,
// one "input: ..." line each, sorted, and each once: the lock names them,
// but what they hold is not in anything that was approved.
func localInputs(src string) (string, error) {
	if !regular(src + "/flake.lock") {
		return "", nil
	}
	b, err := os.ReadFile(src + "/flake.lock")
	if err != nil {
		return "", err
	}
	lock, err := parseJSON(b)
	if err != nil {
		return "", fmt.Errorf("flake.lock: %w", err)
	}
	nodes, err := lock.index("nodes")
	if err != nil {
		return "", err
	}
	_, vals, err := nodes.entries()
	if err != nil {
		return "", err
	}
	var said []string
	for _, n := range vals {
		var refs []*value
		if n.kind == '{' {
			for _, k := range []string{"locked", "original"} {
				if r := n.members[k]; r != nil && r.kind != 'n' {
					refs = append(refs, r)
				}
			}
		}
		for _, r := range refs {
			local, err := isLocal(r)
			if err != nil {
				return "", err
			}
			if !local {
				continue
			}
			where := jstr("a relative path")
			if r.kind == '{' {
				where = r.members["path"].or(r.members["url"].or(where))
			}
			said = append(said, "input: "+where.tostring())
		}
	}
	// `| sort -u`, of what a line of it is.
	lines := strings.Split(strings.Join(said, "\n"), "\n")
	if len(said) == 0 {
		lines = nil
	}
	slices.Sort(lines)
	return strings.Join(slices.Compact(lines), "\n"), nil
}

// isLocal is `.type == "path" or (.url? // "" | test(...)) or
// has("parent")`, of one of a node's locked and original.
func isLocal(r *value) (bool, error) {
	t, err := r.index("type")
	if err != nil {
		return false, err
	}
	if t.kind == '"' && t.text == "path" {
		return true, nil
	}
	url := jstr("")
	if r.kind == '{' {
		url = r.members["url"].or(url)
	}
	if url.kind != '"' {
		return false, fmt.Errorf("%s cannot be matched, as it is not a string", url.describe())
	}
	if localURL.MatchString(url.text) {
		return true, nil
	}
	if r.kind != '{' {
		return false, fmt.Errorf("Cannot check whether %s has a string key", r.typeName())
	}
	_, ok := r.members["parent"]
	return ok, nil
}

// approveSource is stage one: the flake's own two files, against the copies
// approved.
func approveSource(ctx context.Context, c Config, ws, src, dir string, stderr io.Writer) error {
	var diff strings.Builder
	for _, f := range []string{"flake.nix", "flake.lock"} {
		s, d := src+"/"+f, dir+"/"+f
		if same(s, d) || (!gitsafe.ExistsFollowing(s) && !gitsafe.ExistsFollowing(d)) {
			continue
		}
		from, to := "/dev/null", "/dev/null"
		if gitsafe.ExistsFollowing(d) {
			from = d
		}
		if gitsafe.ExistsFollowing(s) {
			to = s
		}
		// `diff+=$(diff ...)$'\n'`: its trailing newlines, then one.
		diff.WriteString(gitsafe.TrimNL(unified(ctx, c, "approved/"+f, f, from, to, stderr)) + "\n")
	}
	if diff.Len() == 0 {
		return nil
	}
	if err := ask(ctx, c, "flake", ws, diff.String(), stderr); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	for _, f := range []string{"flake.nix", "flake.lock"} {
		s, d := src+"/"+f, dir+"/"+f
		if !gitsafe.ExistsFollowing(s) {
			if err := os.Remove(d); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		fi, err := os.Stat(s)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(s)
		if err != nil {
			return err
		}
		// cp's mode: the source's, under the umask.
		if err := os.WriteFile(d+".new", b, fi.Mode().Perm()); err != nil {
			return err
		}
		if err := os.Rename(d+".new", d); err != nil {
			return err
		}
	}
	return nil
}

// same is `cmp -s A B`: both there, and the same bytes.
func same(a, b string) bool {
	x, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	y, err := os.ReadFile(b)
	if err != nil {
		return false
	}
	return bytes.Equal(x, y)
}

// evaluate is the chase section, evaluated purely from the snapshot against
// options.nix only: an option that is not there is an error, not a setting
// applied somewhere else. No nixConfig, no lock written, no
// import-from-derivation. WHAT EVALUATES AN ENVELOPE is a flake of chase's,
// in the store, whose one input is the checkout -- given on the command line,
// never spliced into Nix source -- evaluated PURELY: the checkout is the
// agent's to edit, and this runs before anyone has approved anything, so
// pure evaluation is what keeps an envelope to its own source and locked
// inputs, rather than able to read any file of the user's and fetch a URL
// with it in.
//
// Nix's own chatter -- the project input it was told to use is not in the
// evaluator's lock, which is the point -- is kept unless it fails. It is what
// nix printed on stdout, as a command substitution held it.
func evaluate(ctx context.Context, c Config, src string, stderr io.Writer) (string, bool) {
	var out, log bytes.Buffer
	cmd := exec.CommandContext(ctx, c.Nix, "eval", "--json", "--no-write-lock-file",
		"--option", "accept-flake-config", "false",
		"--option", "allow-import-from-derivation", "false",
		"--extra-experimental-features", "nix-command flakes",
		"path:"+c.Evaluator+"#envelope", "--override-input", "project", "path:"+src)
	cmd.Stdout, cmd.Stderr = &out, &log
	if err := cmd.Run(); err != nil {
		stderr.Write(log.Bytes())
		if _, exited := err.(*exec.ExitError); !exited {
			fmt.Fprintf(stderr, "%v\n", err)
		}
		return "", false
	}
	return gitsafe.Output(out.Bytes()), true
}

// approveEnvelope is stage two: what it evaluated to. The flake's files are
// approved by now, but the chase section can import others, so a change to
// what it says is asked about too. An envelope approved before is read as
// it would be written now, and compared by its content, keys sorted; text is
// the result as it is written, as the script held it.
func approveEnvelope(ctx context.Context, c Config, ws string, result *value, text, dir string, stderr io.Writer) error {
	previous := jnull
	if p := dir + "/envelope.json"; regular(p) {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		n, err := policydoc.Normal(b)
		if err != nil {
			return err
		}
		if previous, err = parseJSON(n); err != nil {
			return err
		}
		if previous.sorted() == result.sorted() {
			return nil
		}
	}
	diff, err := unifiedText(ctx, c, "approved", "proposed", previous.prettySorted()+"\n", result.prettySorted()+"\n", stderr)
	if err != nil {
		return err
	}
	if err := ask(ctx, c, "envelope", ws, gitsafe.TrimNL(diff), stderr); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/envelope.json.new", []byte(text+"\n"), 0o666); err != nil {
		return err
	}
	return os.Rename(dir+"/envelope.json.new", dir+"/envelope.json")
}

// namedTwice is each name an app's lists give twice, as `"<app>: <name as
// JSON>"` lines: each list once over, then every name more than one list
// gives, in jq's order.
func namedTwice(result *value) (string, error) {
	bindings, err := result.index("bindings")
	if err != nil {
		return "", err
	}
	apps, vals, err := bindings.entries()
	if err != nil {
		return "", err
	}
	var lines []string
	for i, app := range apps {
		lists, err := listsOf(vals[i])
		if err != nil {
			return "", err
		}
		var all []*value
		for _, l := range lists {
			items, err := uniqueOf(l)
			if err != nil {
				return "", err
			}
			all = append(all, items...)
		}
		sortValues(all)
		for j := 0; j < len(all); {
			k := j + 1
			for k < len(all) && compare(all[j], all[k]) == 0 {
				k++
			}
			if k-j > 1 {
				lines = append(lines, app+": "+all[j].compact())
			}
			j = k
		}
	}
	return strings.Join(lines, "\n"), nil
}

// listsOf is `(.allow, .ask, .refuse) // []` of a binding: each list it
// has, or one empty list when it has none.
func listsOf(binding *value) ([]*value, error) {
	var out []*value
	for _, k := range []string{"allow", "ask", "refuse"} {
		l, err := binding.index(k)
		if err != nil {
			return nil, err
		}
		if l.truthy() {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		out = []*value{{kind: '['}}
	}
	return out, nil
}

// uniqueOf is jq's `unique[]`: an array's items, sorted, each once.
func uniqueOf(l *value) ([]*value, error) {
	if l.kind != '[' {
		return nil, fmt.Errorf("%s cannot be sorted, as it is not an array", l.describe())
	}
	items := slices.Clone(l.items)
	sortValues(items)
	return slices.CompactFunc(items, func(a, b *value) bool { return compare(a, b) == 0 }), nil
}

// seccomp is the approved `allow` and `deny` lines, as seccompPolicy prints
// them.
func seccomp(result *value) (Result, error) {
	s, err := result.index("seccomp")
	if err != nil {
		return Result{}, err
	}
	var r Result
	if s.kind != '{' {
		return r, nil
	}
	for _, l := range []struct {
		key  string
		into *[]string
	}{{"allow", &r.Allow}, {"deny", &r.Deny}} {
		v := s.members[l.key].or(&value{kind: '['})
		n, err := v.length()
		if err != nil {
			return Result{}, err
		}
		if n <= 0 {
			continue
		}
		items, err := v.iterate()
		if err != nil {
			return Result{}, err
		}
		if _, err := join(items, " "); err != nil {
			return Result{}, err
		}
		for _, x := range items {
			said, _ := join([]*value{x}, "")
			*l.into = append(*l.into, said)
		}
	}
	return r, nil
}
