package envelope

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/term"
)

// Refusal is why an envelope was not applied, in the words the script's die
// said, without its "chase: ": the entry points say it through term.Say, so
// what a session named in it -- a path in its checkout, its origin -- reaches
// the terminal with no control byte but a newline.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

func refuse(format string, args ...any) error {
	return &Refusal{Reason: fmt.Sprintf(format, args...)}
}

// key is a checkout's key: its path, hashed, so a path with anything in it
// is still one plain file name.
func key(ws string) string {
	h := sha256.Sum256([]byte(ws))
	return hex.EncodeToString(h[:])[:32]
}

// checkoutDir is the checkout's own directory, bound into no session, where
// an app keeps what must outlive one launch: Google Cloud's session key,
// which each session is given a copy of in its home.
func checkoutDir(c Config, ws string) string { return c.state() + "/checkouts/" + key(ws) }

// staged is where approve leaves an approved result for launch: one file per
// launch, named for the session flong gives both, under <runtime>/chase,
// which no session sees. Per launch and not per checkout, so two launches of
// one checkout approved at once each get their own. A machine name never
// starts with a dot.
func staged(c Config, machine string) string {
	return c.runtime() + "/chase/.envelope/" + machine + ".json"
}

// regular is `[ -f P ]`: a plain file once links are followed.
func regular(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// ask is the approver protocol (PLAN.md, decision 17): the approver is run
// with one JSON document on stdin, {kind, workspace, diff}, as `jq -n`
// printed it, and exit 0 approves. Its own output goes to stderr: under
// seccompPolicy, stdout is the policy flong reads.
func ask(ctx context.Context, c Config, kind, ws, diff string, stderr io.Writer) error {
	if c.Approver == "" {
		return refuse("%s: its %s has changed, and there is no chase.approver to ask", ws, kind)
	}
	doc := jobject()
	doc.set("kind", jstr(kind))
	doc.set("workspace", jstr(ws))
	doc.set("diff", jstr(diff))
	cmd := exec.CommandContext(ctx, c.Approver)
	cmd.Stdin = strings.NewReader(doc.pretty() + "\n")
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Run(); err != nil {
		if _, exited := err.(*exec.ExitError); !exited {
			// The shell said why it could not run the approver; this says it
			// as chase says anything.
			term.Say(stderr, "%v", err)
		}
		return refuse("%s: its %s was not approved", ws, kind)
	}
	return nil
}

// unified is `diff -u --label A --label B OLD NEW`, as its output was taken,
// whatever diff's status: diffutils' own, at the path the module gives, so
// what a person is shown is what they were always shown. What diff says on
// stderr goes there.
func unified(ctx context.Context, c Config, labelA, labelB, oldPath, newPath string, stderr io.Writer) string {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, c.Diff, "-u", "--label", labelA, "--label", labelB, oldPath, newPath)
	cmd.Stdout, cmd.Stderr = &out, stderr
	if err := cmd.Run(); err != nil {
		if _, exited := err.(*exec.ExitError); !exited {
			term.Say(stderr, "%v", err)
		}
	}
	return out.String()
}

// unifiedText is unified of two texts, each written to a file of its own in
// a private directory, as the script's process substitutions gave diff two
// pipes.
func unifiedText(ctx context.Context, c Config, labelA, labelB, oldText, newText string, stderr io.Writer) (string, error) {
	dir, err := os.MkdirTemp("", "chase-diff-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	a, b := dir+"/a", dir+"/b"
	if err := os.WriteFile(a, []byte(oldText), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(b, []byte(newText), 0o600); err != nil {
		return "", err
	}
	return unified(ctx, c, labelA, labelB, a, b, stderr), nil
}

// newGit is the git every checkout is read with, from the Config's own.
func newGit(c Config) (*gitsafe.Git, error) { return gitsafe.New(c.Config) }
