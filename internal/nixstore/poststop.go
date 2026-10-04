package nixstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// PostStop is what is done of machine's store once its session has ended,
// in order: the promotion queued, when the tier promotes; then the
// directory removed, its root for the host last of all (remove). Nothing
// reads the store once its session has ended, so its roots are not
// refreshed first: the promotion substitutes from the host's caches, and
// needs nothing of the session's held. A store that is not there -- a
// launch whose binds made none, or a postStop run twice -- is nothing to
// do.
func PostStop(ctx context.Context, n session.Nix, machine, runtime string, stderr io.Writer) error {
	dir, err := Dir(n.Session, machine)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if n.Session.Promote {
		if err := Promote(ctx, n, machine, dir, runtime); err != nil {
			term.Say(stderr, "%s: what the session's nix store substituted is not promoted: %v", dir, err)
		}
	}
	return remove(dir)
}

// Most names one promotion is given.
const maxPromoted = 2000

// Promote queues, as a unit of the user's own that outlives the session,
// the realisation on the host of what the session's upper holds, by name
// alone: each top-level entry that is a store path's name, but a
// derivation, which evaluation makes again, and a lock. The host's daemon
// realises each from its own substituters, with no build (max-jobs 0), so
// its require-sigs and its caches are the gate, and nothing of the
// session's -- a tree it wrote, its database -- is read: what it built
// itself, or added unsigned, no cache has, and fails alone (keep-going).
// What the next session finds in the lower is then what cache.nixos.org
// would have given the host, unrooted, to go at the next GC.
//
// Nothing is promoted of an upper larger than the tier's maxBytes: a
// session stopped for it is not followed by its download on the host.
// runtime is the user's runtime directory, where systemd-run finds the
// user's manager.
func Promote(ctx context.Context, n session.Nix, machine, dir, runtime string) error {
	upper := filepath.Join(dir, "layers", "upper")
	entries, err := os.ReadDir(upper)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if bytes, _, err := Usage(upper); err != nil || bytes > n.Session.MaxBytes {
		return fmt.Errorf("its upper is %d bytes, more than the tier's %d", bytes, n.Session.MaxBytes)
	}
	var names []string
	for _, e := range entries {
		p := Store + "/" + e.Name()
		if !storeName.MatchString(p) || strings.HasSuffix(p, ".drv") || strings.HasSuffix(p, ".lock") {
			continue
		}
		names = append(names, p)
		if len(names) == maxPromoted {
			break
		}
	}
	if len(names) == 0 {
		return nil
	}
	if err := files.WriteAtomic(filepath.Join(dir, "promote.list"), []byte(strings.Join(names, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	argv := []string{"--user", "--unit=chase-promote-" + machine, "--collect", "--quiet",
		"-p", "RuntimeMaxSec=1800", "-p", "MemoryMax=1G", "--setenv=NIX_REMOTE=daemon",
		"--", n.Session.NixStore, "--realise", "--keep-going", "--option", "max-jobs", "0", "--option", "substitute", "true"}
	cmd := exec.CommandContext(ctx, n.Session.SystemdRun, append(argv, names...)...)
	cmd.Env = []string{"XDG_RUNTIME_DIR=" + runtime, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtime + "/bus"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(term.Clean(string(out))))
	}
	return nil
}
