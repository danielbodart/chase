package grant

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/danielbodart/chase/internal/gitsafe"
)

// Refusal is why a grant was not applied, in the words the script's die
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
	return c.runtime() + "/chase/.grant/" + machine + ".json"
}

// regular is `[ -f P ]`: a plain file once links are followed.
func regular(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// newGit is the git every checkout is read with, from the Config's own.
func newGit(c Config) (*gitsafe.Git, error) { return gitsafe.New(c.Config) }
