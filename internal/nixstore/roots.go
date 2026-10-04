package nixstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// storeName is a store path as nix makes one: its hash, then its name, and
// nothing below it. A name from a session's database or upper is taken
// only when it is this.
var storeName = regexp.MustCompile(`^/nix/store/[0-9a-z]{32}-[^/\x00\n]{1,211}$`)

// maxDB is the largest session database read: past it, the session has
// written something no store of one launch's is.
const maxDB = 1 << 30

// Refresh roots on the host what the session's store at dir looks at of the
// host's: every path its database holds valid that the upper does not,
// which is to say the lower's, each still valid on the host, at most
// maxRoots of them. The host collecting one of those while the session
// uses it would leave the session a path its database calls valid and its
// lower no longer has (flong's PLAN §3).
//
// Nothing the session wrote is read with trust. The database is read by
// sqlite3, read-only, its schema distrusted and defensive, under a time
// limit and only below maxDB; each name is matched as a store path's and
// checked valid by the host's own daemon; and the list is handed to nix as
// JSON, by file, never as Nix source. Its GC root is <dir>/roots, an
// indirect one, the realised list of names, whose references are the
// paths: one root, and one nix build, for any number of them.
func Refresh(ctx context.Context, n session.Nix, dir string, stderr io.Writer) error {
	s := n.Session
	names, err := listed(ctx, s, dir)
	if err != nil {
		return err
	}
	var lower []string
	for _, p := range names {
		if _, err := os.Lstat(filepath.Join(dir, "layers", "upper", filepath.Base(p))); err == nil {
			continue
		}
		lower = append(lower, p)
	}
	if lower, err = valid(ctx, n, dir, lower); err != nil {
		return err
	}
	if len(lower) > s.MaxRoots {
		term.Say(stderr, "%s: the session's nix store looks at %d of the host's paths, more than the %d rooted; %d are left unrooted", dir, len(lower), s.MaxRoots, len(lower)-s.MaxRoots)
		lower = lower[:s.MaxRoots]
	}
	link := filepath.Join(dir, "roots")
	if len(lower) == 0 {
		if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := json.Marshal(lower)
	if err != nil {
		return err
	}
	list := filepath.Join(dir, "roots.json")
	if err := files.WriteAtomic(list, b, 0o600); err != nil {
		return err
	}
	out, err := host(ctx, n, dir, []string{rootsVar + "=" + list}, n.Nix, "eval", "--extra-experimental-features", "nix-command",
		"--impure", "--raw", "--expr", rootsExpr)
	if err != nil {
		return err
	}
	file := strings.TrimSpace(out)
	if !storeName.MatchString(file) {
		return fmt.Errorf("nix made the list of roots %q, which is no store path", file)
	}
	_, err = host(ctx, n, dir, nil, n.Session.NixStore, "--realise", file, "--add-root", link, "--indirect")
	return err
}

// rootsExpr is the list of names in the file rootsVar names, written to the
// store, each a reference of the file: what one indirect root holds every
// one of alive by. It is made by an evaluation and rooted by nix-store
// after it: nix build roots derivations alone, and the moment between the
// two is the same window a session's store has between refreshes.
const (
	rootsVar  = "CHASE_NIX_ROOTS"
	rootsExpr = `builtins.toFile "chase-nix-roots" (builtins.concatStringsSep "\n" (map builtins.storePath (builtins.fromJSON (builtins.readFile (builtins.getEnv "CHASE_NIX_ROOTS")))))`
)

// listed is every name the session's database at dir holds valid, read
// as listed says, or none where it has none yet.
func listed(ctx context.Context, s *session.NixSession, dir string) ([]string, error) {
	db := filepath.Join(dir, "state", "db", "db.sqlite")
	fi, err := os.Lstat(db)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a plain file", db)
	case fi.Size() > maxDB:
		return nil, fmt.Errorf("%s is %d bytes, more than a session's store is read at", db, fi.Size())
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Sqlite, "-readonly", "-safe", "-batch", "-noheader", "-list",
		"-cmd", ".dbconfig defensive on",
		"-cmd", ".dbconfig trusted_schema off",
		"-cmd", ".timeout 2000",
		"-cmd", "PRAGMA query_only=1;",
		"file:"+db+"?mode=ro", "SELECT path FROM ValidPaths")
	cmd.Env = []string{}
	cmd.Stdin = nil
	var out, said bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &said
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("the session's database could not be read: %s", strings.TrimSpace(term.Clean(said.String()+" "+err.Error())))
	}
	var names []string
	for _, l := range strings.Split(out.String(), "\n") {
		if storeName.MatchString(l) {
			names = append(names, l)
		}
	}
	return names, nil
}

// validChunk is how many names one nix-store is given: well below what a
// command line carries.
const validChunk = 512

// valid is those of names the host's store holds valid, in their order,
// as its daemon says: a name the session's database holds and the host's
// does not is no path of the host's to root.
func valid(ctx context.Context, n session.Nix, dir string, names []string) ([]string, error) {
	invalid := map[string]bool{}
	for i := 0; i < len(names); i += validChunk {
		chunk := names[i:min(i+validChunk, len(names))]
		out, err := host(ctx, n, dir, nil, n.Session.NixStore, append([]string{"--check-validity", "--print-invalid"}, chunk...)...)
		if err != nil {
			return nil, err
		}
		for _, l := range strings.Split(out, "\n") {
			invalid[l] = true
		}
	}
	var out []string
	for _, p := range names {
		if !invalid[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// host is one of the host's nix tools, as the caller, through the daemon:
// none of the caller's environment but env, its HOME the session's
// directory, and what it prints returned; what it says is the error's.
func host(ctx context.Context, n session.Nix, dir string, env []string, prog string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Env = append([]string{"NIX_REMOTE=daemon", "HOME=" + dir, "PATH=" + filepath.Dir(n.Nix)}, env...)
	var out, said bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &said
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %s", filepath.Base(prog), strings.TrimSpace(term.Clean(said.String()+" "+err.Error())))
	}
	return out.String(), nil
}
