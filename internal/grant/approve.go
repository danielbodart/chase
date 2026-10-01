package grant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/policydoc"
	"github.com/danielbodart/chase/internal/snapshot"
)

// Result is what an approval gives flong: the syscalls the approved grant
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

// Approve is seccompPolicy: snapshot, read, check, approve, stage.
//
// A grant is DATA. The checkout's chase.jsonc is read and checked by chase
// (ParseFile), never evaluated, so nothing of the checkout's runs to find out
// what it asks for, and one approval covers it: what a person approves is
// what is applied. What chase derives beside it -- the digest of its sops
// file, the Docker project its origin names -- is part of what is approved,
// so a changed secret or origin is asked about too.
//
// All of it is done on a SNAPSHOT: chase.jsonc and the sops file it names,
// copied from what the checkout tracks. What is compared, shown and
// decrypted is that copy, so a session of the same checkout still running
// cannot change a file between the approval and its use.
//
// Everything it says, and what the approver and diff say, goes to stderr:
// the Result is all flong reads. A *Refusal is the script's die.
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
	if fi, err := os.Stat(runtime + "/chase/.grant"); err != nil || !fi.IsDir() {
		if err := os.MkdirAll(runtime+"/chase/.grant", 0o777); err != nil {
			return Result{}, err
		}
	}
	stage := staged(c, machine)
	// A checkout with no chase.jsonc is the tier as it is, and is never read
	// or asked about. Anything there at all -- a link, a directory -- is
	// taken to the snapshot, which refuses what is not a tracked file.
	if _, err := os.Lstat(ws + "/" + FileName); errors.Is(err, os.ErrNotExist) {
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

	tracked, err := trackedFiles(ctx, g, ws, stderr)
	if err != nil {
		return Result{}, err
	}
	if !slices.Contains(tracked, FileName) {
		return Result{}, refuse("%s: %s is not a tracked file: what a grant says is what git tracks", ws, FileName)
	}
	if err := takeSnapshot(ws, src, FileName); err != nil {
		return Result{}, err
	}
	if !regular(src+"/"+FileName) || gitsafe.IsLink(src+"/"+FileName) {
		return Result{}, refuse("%s: %s is not a tracked file", ws, FileName)
	}
	b, err := os.ReadFile(src + "/" + FileName)
	if err != nil {
		return Result{}, err
	}
	out, err := ParseFile(b)
	if err != nil {
		return Result{}, refuse("%s: %s: %v", ws, FileName, err)
	}
	normal, err := policydoc.Normal(out)
	if err != nil {
		return Result{}, err
	}
	result, err := parseJSON(normal)
	if err != nil {
		return Result{}, err
	}
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
		if !slices.Contains(tracked, secrets) {
			return Result{}, refuse("%s: %s is not a tracked file", ws, secrets)
		}
		// chase.jsonc is copied already, should it name itself.
		if secrets != FileName {
			if err := takeSnapshot(ws, src, secrets); err != nil {
				return Result{}, err
			}
		}
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
	}
	// Docker, as the project the checkout's origin names, which is part of
	// what is approved: a changed origin is asked about again. A grant
	// without Docker gains nothing, so one approved before there was Docker
	// still is.
	if d, err := result.path("apps", "docker"); err == nil && d.kind != 'n' {
		slug, err := project(ctx, g, c, ws, tier, stderr)
		if err != nil {
			return Result{}, err
		}
		who, err := address(slug, stderr)
		if err != nil {
			return Result{}, refuse("%s: %s has no address", ws, slug)
		}
		result.set("dockerProject", jstr(slug))
		dockerLine(slug, who, stderr)
	}
	if err := approveGrant(ctx, c, ws, result, dir, stderr); err != nil {
		return Result{}, err
	}

	// What exec applies is what was approved, with the snapshot's sops
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

// trackedFiles is what the checkout tracks, relative to ws, read by
// checkout.Finder.LsFiles from the index alone: never by a git in the
// checkout, whose config a session writes, and which runs what
// core.fsmonitor names on any read of the index -- here as the user,
// unsandboxed, before anyone is asked.
func trackedFiles(ctx context.Context, g *gitsafe.Git, ws string, stderr io.Writer) ([]string, error) {
	var list bytes.Buffer
	if rc := checkout.RunLsFiles(ctx, g, []string{ws}, &list, stderr); rc != 0 {
		return nil, refuse("%s: a grant needs a git checkout, so what it says is what git tracks: %s", ws, gitsafe.Output(list.Bytes()))
	}
	paths := strings.Split(list.String(), "\x00")
	if paths[len(paths)-1] == "" {
		paths = paths[:len(paths)-1]
	}
	return paths, nil
}

// takeSnapshot is the tracked file path, as it is now, copied into src, a
// directory of the user's own that no session sees. Copied by
// snapshot.CopyTracked, which follows no link at any component: anything
// that opens WS/dir/f by its path lets the kernel resolve dir, so a tracked
// dir/f whose dir a session has made a link to a host directory would copy
// that host's f into what is approved and decrypted. A check for such a
// link before and after the copy is no better, since another live session
// of the same checkout can swap it in and back between.
func takeSnapshot(ws, src, path string) error {
	var why bytes.Buffer
	if rc := snapshot.Run([]string{ws, src}, strings.NewReader(path+"\x00"), &why, io.Discard); rc != 0 {
		said := gitsafe.Output(why.Bytes())
		if said == "" {
			said = "its tracked files could not be copied"
		}
		return refuse("%s: %s", ws, said)
	}
	return nil
}

// approveGrant is the one approval: the grant, and what chase derived
// beside it, against what was last approved for this checkout. A grant
// approved before is read as it would be written now, and compared by its
// content, keys sorted, so a change to a comment, or to the order the file
// gives things in, asks nothing.
func approveGrant(ctx context.Context, c Config, ws string, result *value, dir string, stderr io.Writer) error {
	previous := jnull
	if p := dir + "/grant.json"; regular(p) {
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
	if err := ask(ctx, c, ws, gitsafe.TrimNL(diff), stderr); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	// What an earlier chase approved here, a flake's files and what its
	// chase section evaluated to, which nothing reads now.
	for _, f := range []string{"flake.nix", "flake.lock", "envelope.json"} {
		os.Remove(dir + "/" + f)
	}
	// 0600, as the umask made it; under a name of its own and renamed
	// over, so two launches approving at once never leave half of each.
	return files.WriteAtomic(dir+"/grant.json", []byte(result.pretty()+"\n"), 0o600)
}

// namedTwice is each name an app's lists give twice, as `"<app>: <name as
// JSON>"` lines: each list once over, then every name more than one list
// gives, in jq's order.
func namedTwice(result *value) (string, error) {
	bindings, err := result.index("apps")
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
