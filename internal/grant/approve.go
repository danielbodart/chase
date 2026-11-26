package grant

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/quoin/projpolicy"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/snapshot"
	"github.com/danielbodart/chase/internal/term"
)

// Result is what an approval gives flong: the syscalls the approved grant
// loosens, each list as seccompPolicy printed it after "allow " and "deny ",
// and, for a recording session (ApproveRecording), what flong learns with:
// Base "none" to apply the lines to no names in place of the tier's, and
// the calls to Log, those Nolog names taken back out.
type Result struct {
	Base  string
	Allow []string
	Deny  []string
	Log   []string
	Nolog []string
}

// Lines is the result as seccompPolicy prints it on stdout, and nothing
// else: `base none` when the result is from scratch; an `allow` line when
// there is anything to allow, then a `deny` line when there is anything to
// deny; then `log` and `nolog` lines likewise.
func (r Result) Lines() string {
	var b strings.Builder
	if r.Base != "" {
		b.WriteString("base " + r.Base + "\n")
	}
	for _, l := range []struct {
		word  string
		names []string
	}{{"allow", r.Allow}, {"deny", r.Deny}, {"log", r.Log}, {"nolog", r.Nolog}} {
		if len(l.names) > 0 {
			b.WriteString(l.word + " " + strings.Join(l.names, " ") + "\n")
		}
	}
	return b.String()
}

// Approve is seccompPolicy: snapshot, read, check, have it signed or
// approved, stage.
//
// A project's file is DATA, read and checked by chase, never evaluated, so
// nothing of the checkout's runs to find out what it asks for. It is
// chase.json (chasejson.go), applied as it is when its signature verifies
// and put to the signer when it does not (sign.go). What is staged for
// exec is that chase.json, so a launch has one way to apply a project's
// file.
//
// All of it is done on a SNAPSHOT: the file, its signature and the sops
// file it names, copied from the checkout following no link. What is
// verified, shown, decrypted and applied is that copy, so a session of the
// same checkout still running cannot change a file between the signature's
// check and its use.
//
// Everything it says, and what the signer and diff say, goes
// to stderr: the Result is all flong reads. A *Refusal is the script's die.
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
	// A tier launched only for its own SSH machines takes no checkout's
	// file: its sessions are the tier as it is, whatever the checkout
	// says, which is never read.
	if slices.Contains(c.Ungranted, tier) {
		return Result{}, files.WriteAtomic(stage, []byte("null\n"), 0o600)
	}
	// A checkout with no file is the tier as it is, and is never read or
	// asked about. Anything there at all -- a link, a directory -- is
	// taken to the snapshot, which refuses what is not a plain file.
	if _, err := os.Lstat(ws + "/" + FileName); !errors.Is(err, os.ErrNotExist) {
		return approveV2(ctx, c, ws, tier, stage, stderr)
	}
	return Result{}, files.WriteAtomic(stage, []byte("null\n"), 0o600)
}

// snapshotDir is a directory of the user's own for a launch's snapshot,
// which no session sees.
func snapshotDir(c Config) (string, error) {
	if err := os.MkdirAll(c.Home+"/.cache/chase", 0o777); err != nil {
		return "", err
	}
	return os.MkdirTemp(c.Home+"/.cache/chase", "snapshot.")
}

// snapshotFile is the plain file rel of the checkout at ws, copied into
// src and read; or, where absent is allowed and there is nothing at rel,
// nil.
func snapshotFile(ws, src, rel string, optional bool) ([]byte, error) {
	if _, err := os.Lstat(ws + "/" + rel); optional && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := takeSnapshot(ws, src, rel); err != nil {
		return nil, err
	}
	p := src + "/" + rel
	if !regular(p) || gitsafe.IsLink(p) {
		return nil, refuse("%s: %s is not a plain file", ws, rel)
	}
	return os.ReadFile(p)
}

// approveV2 is a checkout's chase.json: snapshotted with its signature
// and its sops file; checked; held to what the checkout says of what it
// derives; its flong section checked by flong; signed by the person
// through the signer unless its signature verifies; and staged.
func approveV2(ctx context.Context, c Config, ws, tier, stage string, stderr io.Writer) (Result, error) {
	src, err := snapshotDir(c)
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(src)
	b, err := snapshotFile(ws, src, FileName, false)
	if err != nil {
		return Result{}, err
	}
	sig, err := snapshotFile(ws, src, SigName, true)
	if err != nil {
		return Result{}, err
	}
	doc, generic, err := ParseDoc(b)
	if err != nil {
		return Result{}, refuse("%s: %s: %v", ws, FileName, err)
	}
	section := Section{}
	if doc.Chase != nil {
		section = *doc.Chase
	}
	apps := SectionApps{}
	if section.Apps != nil {
		apps = *section.Apps
	}
	// SSH's lists are the catalogue's ids and categories, and patterns it
	// may overrule, which only the catalogue says: refused here, before
	// anyone is asked, as Prepare would refuse them at every launch.
	if c.SSH != nil && apps.SSH != nil {
		if err := c.SSH.CheckBinding(tier, *apps.SSH); err != nil {
			return Result{}, refuse("%s: %s: %v", ws, FileName, err)
		}
	}
	// What the file must say of the checkout, which its signature covers:
	// the digest of the sops file it names, and the Docker project its
	// origin names.
	var secrets *stagedSecrets
	if section.Secrets != "" {
		text, err := snapshotFile(ws, src, section.Secrets, false)
		if err != nil {
			return Result{}, err
		}
		if got := sha256Hex64(text); got != section.SecretsSHA256 {
			return Result{}, refuse("%s: %s's digest is %s, and %s says %s: chase sign writes the new one, and signs it", ws, section.Secrets, got, FileName, section.SecretsSHA256)
		}
		secrets = &stagedSecrets{Name: filepath.Base(section.Secrets), Text: string(text)}
	}
	g, err := newGit(c)
	if err != nil {
		return Result{}, err
	}
	defer g.Close()
	served := ""
	if d := apps.Docker; d != nil {
		p, err := project(ctx, g, c, ws, tier, stderr)
		if err != nil {
			return Result{}, err
		}
		if d.Project != p.Slug {
			said := d.Project
			if said == "" {
				said = "none"
			}
			return Result{}, refuse("%s: its origin names the project %s, and %s's apps.docker.project says %s: chase sign writes it, and signs it", ws, p.Slug, FileName, said)
		}
		served = p.Served
	}
	if err := c.flongCheck(ctx, ws, tier, doc.Flong, stderr); err != nil {
		return Result{}, err
	}
	root, err := Root(ws)
	if err != nil {
		return Result{}, err
	}
	if why := c.verify(root, b, sig); why != nil {
		if !projpolicy.Canonical(b) {
			return Result{}, refuse("%s: %s is not signed (%v), and not in its canonical form to be: run chase sign", ws, FileName, why)
		}
		term.Say(stderr, "%s: %s is not signed (%v): the signer asks", ws, FileName, why)
		newSig, err := c.askSigner(ctx, g, root, b)
		if err != nil {
			return Result{}, refuse("%s: %s was not signed: %v", ws, FileName, err)
		}
		if err := writeBeside(root+"/"+SigName, newSig, 0o644); err != nil {
			return Result{}, err
		}
	}
	stageServed(generic, served)
	if err := writeStage(stage, generic, secrets); err != nil {
		return Result{}, err
	}
	return doc.Flong.Lines(), nil
}

// stageServed puts the project the checkout is served as in the staged
// file's apps.docker.project, which the file names as the repository's:
// the same, but in a linked worktree (servedAs). exec gives it the Docker
// app as it is staged, never derived again.
func stageServed(doc any, served string) {
	if served == "" {
		return
	}
	if d, ok := walkMap(doc, "chase", "apps", "docker"); ok {
		d["project"] = served
	}
}

// walkMap is the object at path in v, and whether there is one.
func walkMap(v any, path ...string) (map[string]any, bool) {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		v = m[k]
	}
	m, ok := v.(map[string]any)
	return m, ok
}

// stagedSecrets is the snapshot's sops file, staged for exec beside the
// file that names it.
type stagedSecrets struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

// writeStage stages a launch's chase.json, and its sops file, for exec.
func writeStage(stage string, doc any, secrets *stagedSecrets) error {
	out := map[string]any{"file": doc, "secrets": nil}
	if secrets != nil {
		out["secrets"] = secrets
	}
	return files.WriteAtomic(stage, []byte(compactJSON(out)+"\n"), 0o600)
}

// flongCheck is flong's own check of a project's flong section, as a layer
// over the tier's declaration: `flong check --layer project --base
// /etc/flong/chase-<tier>.json LAYER`, which knows the architecture's
// calls. Nothing, where the module names no flong.
func (c Config) flongCheck(ctx context.Context, ws, tier string, f *FlongLayer, stderr io.Writer) error {
	if f == nil || c.Flong == "" {
		return nil
	}
	dir, err := os.MkdirTemp("", "chase-flong-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	layer := dir + "/layer.json"
	if err := os.WriteFile(layer, []byte(compactJSON(f)+"\n"), 0o600); err != nil {
		return err
	}
	decls := c.Declarations
	if decls == "" {
		decls = "/etc/flong"
	}
	var out bytes.Buffer
	// flong's launcher is the flong binary by another name, which reads a
	// subcommand where its name is flong's.
	cmd := exec.CommandContext(ctx, c.Flong)
	cmd.Args = []string{"flong", "check", "--layer", "project", "--base", decls + "/chase-" + tier + ".json", layer}
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if _, exited := err.(*exec.ExitError); !exited {
			return err
		}
		return refuse("%s: %s's flong section: %s", ws, FileName, gitsafe.Output(out.Bytes()))
	}
	return nil
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
