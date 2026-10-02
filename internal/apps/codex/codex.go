// Package codex keeps the host's codex login fresh, and the placeholder login
// that sessions hold in its place in step with it.
//
// A session never holds the host's tokens: a shared tier's container binds
// the placeholder over its own ~/.codex/auth.json, an isolated tier's home is
// given a copy of it, and frisket puts the real access token on each request.
// frisket never refreshes, and a session cannot, so the refresh is done here.
package codex

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/term"
)

// PlaceholderJWT is what the container holds in place of the access token.
// The module's own placeholder cannot be it: codex reads its own token as a
// JWT and refreshes 5 minutes before the `exp` it finds, so the placeholder
// has to be JWT-shaped with an expiry far away -- {"alg":"none","typ":"JWT"}
// over {"exp":4102444800,"sub":"frisket-placeholder"}, 4102444800 being
// 2100-01-01. Nothing verifies the signature: not codex, which only splits
// on '.', and not frisket, which compares the whole string to this one.
//
// It is placeholder.jwt, which the module reads too, for frisket's codex
// route: one file, so the placeholder a session sends and the one frisket
// replaces cannot drift.
//
//go:embed placeholder.jwt
var PlaceholderJWT string

// ClientID is the client codex itself logs in as, from its source: without
// it the token endpoint refuses the exchange.
const ClientID = "app_EMoamEEZ73f0CkXaXp7hrann"

// TokenEndpoint is where a refresh token is exchanged.
const TokenEndpoint = "https://auth.openai.com/oauth/token"

// Config is what the NixOS module decides for this package, written as JSON.
type Config struct {
	// Auth is the host's own login, ~/.codex/auth.json.
	Auth string `json:"auth"`
	// StateDir is ~/.local/state/chase/codex, made if missing: it holds
	// the placeholder and each isolated tier's CODEX_HOME, neither of which
	// is the host's own login or state.
	StateDir string `json:"stateDir"`
	// FormerStateDir is where an earlier chase kept StateDir,
	// ~/.local/state/agents/codex, moved to StateDir by MoveState. Empty
	// is nowhere.
	FormerStateDir string `json:"formerStateDir,omitempty"`
	// SQLite is the sqlite3 MoveState repoints each moved home's thread
	// index with. Empty is none, and the index is left as it is.
	SQLite string `json:"sqlite,omitempty"`
	// Placeholder is the placeholder login, StateDir/auth-placeholder.json:
	// the source of a shared tier's bind over auth.json, and what an
	// isolated tier's home is given a copy of.
	Placeholder string `json:"placeholder"`
	// TokenEndpoint is where the refresh token is exchanged. Empty is
	// TokenEndpoint; set only by tests.
	TokenEndpoint string `json:"tokenEndpoint,omitempty"`
}

func (c Config) endpoint() string {
	if c.TokenEndpoint != "" {
		return c.TokenEndpoint
	}
	return TokenEndpoint
}

// LoadConfig reads a Config the module wrote.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// MoveState moves what an earlier chase kept in FormerStateDir to StateDir:
// each workspace's and tier's CODEX_HOME, with its threads and history.
// Done by each command that makes StateDir -- the activation that writes
// the placeholder, and the refresher -- before either does, since one made
// first would leave the old one where nothing reads it. Moved once, by a
// rename: where both are there, both are left as they are and that is said,
// for a person to merge, since neither is chase's to throw away. Then the
// former directory's parent, ~/.local/state/agents, which nothing of
// chase's uses now, goes if it is empty, and each home's thread index is
// repointed (see repoint). Nothing here stops what follows: the placeholder
// is written whatever was moved.
func MoveState(cfg Config, stderr io.Writer) {
	if cfg.FormerStateDir == "" {
		return
	}
	moved, err := files.MoveDir(cfg.FormerStateDir, cfg.StateDir)
	switch {
	case errors.Is(err, files.ErrBothExist):
		term.Say(stderr, "codex: %s is left as it was, beside %s, which is what chase keeps codex's homes in now: merge what you want of it there, and remove it", cfg.FormerStateDir, cfg.StateDir)
		return
	case err != nil:
		term.Say(stderr, "codex: %s was not moved to %s: %v", cfg.FormerStateDir, cfg.StateDir, err)
		return
	case moved:
		term.Say(stderr, "codex: %s is %s now", cfg.FormerStateDir, cfg.StateDir)
	}
	// Removes only an empty directory: anything else of the user's stays.
	os.Remove(filepath.Dir(cfg.FormerStateDir))
	repoint(cfg, stderr)
}

// repoint rewrites, in each home under StateDir, the thread index's paths
// under FormerStateDir to the same paths under StateDir. codex keeps each
// thread's rollout by its absolute path, in state_N.sqlite's
// threads.rollout_path, and opens it by that path alone: a thread whose
// path is gone is still listed, found by scanning sessions/, but is neither
// read nor resumed -- "no rollout found for thread id" -- and codex never
// mends the row. A session mounts a home only at its path under StateDir,
// so after the move every earlier thread would be cut off, its rollout
// still there. Nothing else is rewritten: the paths in a thread's own
// history are what was said, not where anything is.
//
// On every run, not only the one that moved: a session started before the
// move has the home at the former path still, and its codex goes on writing
// rows that name it, which the next run repoints. Rows already repointed
// match nothing, so each run after is a read. A home whose index cannot be
// repointed is said, and the rest are still done.
func repoint(cfg Config, stderr io.Writer) {
	if cfg.SQLite == "" {
		return
	}
	for _, db := range indexes(cfg.StateDir) {
		out, err := exec.Command(cfg.SQLite, repointArgs(db, cfg.FormerStateDir, cfg.StateDir)...).CombinedOutput()
		n := strings.TrimSpace(string(out))
		switch {
		case err != nil:
			term.Say(stderr, "codex: the threads %s indexes still name %s, so codex can neither read nor resume them: %v: %s", db, cfg.FormerStateDir, err, n)
		case n != "0":
			term.Say(stderr, "codex: the threads %s indexes under %s are under %s now (%s of them)", db, cfg.FormerStateDir, cfg.StateDir, n)
		}
	}
}

// indexes are the thread indexes of the homes under dir: each state_N.sqlite
// at most two directories down, as a tier's home, dir/<tier>, or a
// workspace's, dir/<tier>/<workspace>, holds it. No deeper, so a home's own
// sessions/ is not walked, and never through a link.
func indexes(dir string) []string {
	var found []string
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		depth := len(strings.Split(rel, string(filepath.Separator)))
		switch {
		case d.IsDir() && rel != "." && depth > 2:
			return fs.SkipDir
		case d.Type().IsRegular() && stateIndex.MatchString(d.Name()):
			found = append(found, path)
		}
		return nil
	})
	return found
}

// stateIndex is the name codex gives its thread index, numbered by its
// schema's version: state_5.sqlite today.
var stateIndex = regexp.MustCompile(`^state_[0-9]+\.sqlite$`)

// repointArgs is sqlite3's command line to repoint db's rows under from to
// to, printing how many it changed. No ~/.sqliterc is read, and nothing the
// shell's dot-commands could do is allowed. It waits for a codex writing
// the index, rather than failing at once. Each path is matched with its
// trailing /, so a sibling, from+"x", is not another's, and compared and cut
// by sqlite's own lengths, in characters, as it measures the rows.
func repointArgs(db, from, to string) []string {
	src, dst := quote(from+"/"), quote(to+"/")
	return []string{"-init", os.DevNull, "-batch", "-bail", "-safe", "-cmd", ".timeout 10000", db,
		"UPDATE threads SET rollout_path = " + dst + " || substr(rollout_path, length(" + src + ") + 1)" +
			" WHERE substr(rollout_path, 1, length(" + src + ")) = " + src + "; SELECT changes();"}
}

// quote is s as an SQL string literal.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
