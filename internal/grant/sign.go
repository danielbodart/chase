package grant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/danielbodart/frisket/projpolicy"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/term"
)

// A SIGNATURE REPLACES THE APPROVAL. A chase.json is a project's own words
// only once a person has signed them: chase.json.sig beside it, an SSHSIG
// over its exact bytes in the namespace frisket-policy:<root>, by a key
// /etc/frisket/allowed_signers allows there. A launch whose file verifies
// asks nothing. One that does not is put to the signer, through its agent
// extension policy-sign@frisket, as `frisket policy sign` puts it: the
// signer shows the change in galley -- against the file git's HEAD signed,
// when that still verifies, or against nothing -- and, allowed, signs the
// new bytes, which chase writes beside the file as chase.json.sig, and the
// launch goes on. Refused, the launch ends.
//
// What the signature covers is the file: so what a launch derives from the
// checkout and must have been seen -- the digest of the sops file, the
// Docker project its origin names -- is written into the file
// (secretsSHA256, apps.docker.project), and a launch refuses a file that
// says other than the checkout does. `chase sign` writes them, puts the
// file in its canonical form, and signs it.

// DefaultAllowedSigners is root's allowed signers file, which frisket's
// module renders.
const DefaultAllowedSigners = "/etc/frisket/allowed_signers"

// policySignExtension is the signer's agent extension (frisket's
// internal/agentsrv), and policySignRequest and policySignResponse its
// wire, as JSON: the project's directory and its file's name, the new
// bytes, and the bytes the old signature was made over with that
// signature.
const policySignExtension = "policy-sign@frisket"

type policySignRequest struct {
	Root   string `json:"root"`
	Name   string `json:"name"`
	New    []byte `json:"new"`
	Old    []byte `json:"old,omitempty"`
	OldSig []byte `json:"oldSig,omitempty"`
}

type policySignResponse struct {
	Sig   []byte `json:"sig,omitempty"`
	Error string `json:"error,omitempty"`
}

func (c Config) allowedSigners() string {
	if c.AllowedSigners != "" {
		return c.AllowedSigners
	}
	return DefaultAllowedSigners
}

// signerAgent is the signer's agent socket: the module's, or the caller's
// SSH_AUTH_SOCK.
func (c Config) signerAgent() string {
	if c.SignerAgent != "" {
		return c.SignerAgent
	}
	return os.Getenv("SSH_AUTH_SOCK")
}

// Root is the directory a project's file is in, as the kernel names it:
// what a process's working directory reads as, and so what the signer and
// the courier name its namespace by.
func Root(ws string) (string, error) {
	abs, err := filepath.Abs(ws)
	if err != nil {
		return "", err
	}
	r, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Clean(r), nil
}

// verify is whether sig is a signature of b in root's namespace by a key
// the allowed signers allow there; nil when it is.
func (c Config) verify(root string, b, sig []byte) error {
	if sig == nil {
		return errors.New("no " + SigName)
	}
	ns, err := projpolicy.Namespace(root, c.Home)
	if err != nil {
		return err
	}
	signers, err := projpolicy.ReadAllowedSigners(c.allowedSigners())
	if err != nil {
		return err
	}
	_, err = projpolicy.Verify(b, sig, ns, signers, "", time.Now())
	return err
}

// askSigner is the person's signature of b, root's chase.json, through the
// signer, shown against what git's HEAD signed: the signer verifies the
// old signature over the old bytes itself, and shows the whole file as new
// when it does not. The signature it returns is checked here too.
func (c Config) askSigner(ctx context.Context, g *gitsafe.Git, root string, b []byte) ([]byte, error) {
	sock := c.signerAgent()
	if sock == "" {
		return nil, errors.New("no signer to ask: the module names no agent, and SSH_AUTH_SOCK is not set")
	}
	req := policySignRequest{Root: root, Name: FileName, New: b}
	if g != nil {
		if old, oldSig := headFiles(ctx, g, root); oldSig != nil {
			req.Old, req.OldSig = old, oldSig
		}
	}
	sig, err := policySign(sock, req)
	if err != nil {
		return nil, err
	}
	if err := c.verify(root, b, sig); err != nil {
		return nil, fmt.Errorf("the signer's signature does not verify: %w", err)
	}
	return sig, nil
}

func policySign(sock string, req policySignRequest) ([]byte, error) {
	contents, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("the signer: %w", err)
	}
	defer conn.Close()
	out, err := agent.NewClient(conn).Extension(policySignExtension, contents)
	if errors.Is(err, agent.ErrExtensionUnsupported) {
		return nil, fmt.Errorf("the agent at %s does not sign policies: it is not frisket-signer", sock)
	}
	if err != nil {
		return nil, fmt.Errorf("the signer: %w", err)
	}
	var resp policySignResponse
	if len(out) < 1 || json.Unmarshal(out[1:], &resp) != nil {
		return nil, fmt.Errorf("the agent's answer is not policy-sign's")
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("the signer: %s", resp.Error)
	}
	if resp.Sig == nil {
		return nil, errors.New("the signer sent no signature")
	}
	return resp.Sig, nil
}

// maxHeadFile is the most of a file git's HEAD has that is read: a
// chase.json is at most what projpolicy reads.
const maxHeadFile = 1 << 20

// headFiles are chase.json and its signature as git's HEAD has them in the
// checkout at root, or nil each where there is none: read by a git that
// never reads the checkout's config, from its objects alone, as the
// selector reads its first commit.
func headFiles(ctx context.Context, g *gitsafe.Git, root string) (old, oldSig []byte) {
	c, err := (&checkout.Finder{Git: g}).Find(ctx, checkout.Query{Dir: root})
	if err != nil {
		return nil, nil
	}
	rel, err := filepath.Rel(c.Root, root)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, nil
	}
	objects := c.GitCommon + "/objects"
	if !gitsafe.IsDir(objects) || gitsafe.IsLink(objects) || gitsafe.Exists(objects+"/info/alternates") || checkout.NotPlain(objects) {
		return nil, nil
	}
	format, err := c.Repo().Config(ctx, g, "extensions.objectFormat")
	if err != nil {
		return nil, nil
	}
	format = gitsafe.LastOf(gitsafe.Output([]byte(format)))
	if format == "" {
		format = "sha1"
	}
	if format != "sha1" && format != "sha256" {
		return nil, nil
	}
	empty, err := g.Empty(format)
	if err != nil {
		return nil, nil
	}
	oid, ok := c.HeadCommit(ctx, g)
	if !ok {
		return nil, nil
	}
	read := func(name string) []byte {
		path := name
		if rel != "." {
			path = filepath.ToSlash(rel) + "/" + name
		}
		res := g.Run(ctx, "GIT_DIR="+empty, "GIT_OBJECT_DIRECTORY="+objects, "cat-file", "blob", oid+":"+path)
		if !res.OK() || len(res.Stdout) > maxHeadFile {
			return nil
		}
		return res.Stdout
	}
	if old = read(FileName); old == nil {
		return nil, nil
	}
	return old, read(SigName)
}

// writeBeside replaces path with b through a temporary file beside it, so
// a reader never sees half of either, and a link a session left at path is
// replaced rather than written through.
func writeBeside(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// derive writes into doc, a decoded chase.json, what a launch holds it to
// of the checkout at ws: the sops file's digest, and the Docker project its
// origin names. It says each it changed.
func (c Config) derive(ctx context.Context, g *gitsafe.Git, ws string, doc map[string]any, stderr io.Writer) error {
	section, _ := doc["chase"].(map[string]any)
	if section == nil {
		return nil
	}
	if secrets, _ := section["secrets"].(string); secrets != "" {
		b, err := readInCheckout(ws, secrets)
		if err != nil {
			return fmt.Errorf("chase.secrets: %w", err)
		}
		digest := sha256Hex64(b)
		if section["secretsSHA256"] != digest {
			section["secretsSHA256"] = digest
			term.Say(stderr, "chase.secretsSHA256: %s's digest, %s", secrets, digest)
		}
	}
	apps, _ := section["apps"].(map[string]any)
	if d, ok := apps["docker"].(map[string]any); ok {
		slug, err := project(ctx, g, c, ws, "", stderr)
		if err != nil {
			return err
		}
		if d["project"] != slug {
			d["project"] = slug
			term.Say(stderr, "chase.apps.docker.project: %s, as the checkout's origin names it", slug)
		}
	}
	return nil
}

// readInCheckout is the file at rel in the checkout at ws, copied as a
// launch copies it, following no link at any component.
func readInCheckout(ws, rel string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "chase-read-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := takeSnapshot(ws, dir, rel); err != nil {
		return nil, err
	}
	p := dir + "/" + rel
	if !regular(p) || gitsafe.IsLink(p) {
		return nil, fmt.Errorf("%s is not a plain file in the checkout", rel)
	}
	return os.ReadFile(p)
}

// SignCommand is `chase sign [DIR | DIR/chase.json]`: the file written with
// what is derived of the checkout and in its canonical form, then signed by
// the person through the signer, and its .sig written beside it. A file
// already signed as it is asks nothing.
func SignCommand(ctx context.Context, c Config, args []string, stdout, stderr io.Writer) error {
	dir := "."
	switch len(args) {
	case 0:
	case 1:
		dir = args[0]
		if filepath.Base(dir) == FileName {
			dir = filepath.Dir(dir)
		}
	default:
		return errors.New("usage: chase sign [DIR | DIR/chase.json]")
	}
	root, err := Root(dir)
	if err != nil {
		return err
	}
	g, err := newGit(c)
	if err != nil {
		return err
	}
	defer g.Close()
	return c.sign(ctx, g, root, stdout, stderr)
}

// sign is chase sign of root's chase.json.
func (c Config) sign(ctx context.Context, g *gitsafe.Git, root string, stdout, stderr io.Writer) error {
	path := root + "/" + FileName
	b, err := projpolicy.ReadFile(path)
	if err != nil {
		return err
	}
	if _, _, err := ParseDoc(b); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	v, _ := projpolicy.Decode(b)
	doc := v.(map[string]any)
	if err := c.derive(ctx, g, root, doc, stderr); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	out, err := encodeDoc(doc)
	if err != nil {
		return err
	}
	if _, _, err := ParseDoc(out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !bytes.Equal(out, b) {
		mode := os.FileMode(0o644)
		if fi, err := os.Lstat(path); err == nil {
			mode = fi.Mode().Perm()
		}
		if err := writeBeside(path, out, mode); err != nil {
			return err
		}
		term.Say(stdout, "%s: written in its canonical form", path)
	}
	if sig, err := projpolicy.ReadFile(root + "/" + SigName); err == nil && c.verify(root, out, sig) == nil {
		term.Say(stdout, "%s: signed already", path)
		return nil
	}
	sig, err := c.askSigner(ctx, g, root, out)
	if err != nil {
		return err
	}
	if err := writeBeside(root+"/"+SigName, sig, 0o644); err != nil {
		return err
	}
	term.Say(stdout, "%s: signed, %s written", path, SigName)
	return nil
}

// Sign is chase sign of the checkout at ws's chase.json, for what else
// writes one: `chase record apply`.
func Sign(ctx context.Context, c Config, ws string, stdout, stderr io.Writer) error {
	root, err := Root(ws)
	if err != nil {
		return err
	}
	g, err := newGit(c)
	if err != nil {
		return err
	}
	defer g.Close()
	return c.sign(ctx, g, root, stdout, stderr)
}
