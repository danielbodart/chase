package grant

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/term"
)

// stagedLines is where an approval leaves the syscall lines it made, for
// the launch's seccompPolicy to print: beside the stage, released with it.
func stagedLines(c Config, machine string) string {
	return c.runtime() + "/chase/.grant/" + machine + ".seccomp"
}

// StageLines keeps r's lines for machine's seccompPolicy (Lines): flong's
// approve hook, which approves, reads nothing it prints, and seccompPolicy
// runs after binds and the guard.
func StageLines(c Config, machine string, r Result) error {
	if machine == "" {
		return refuse("no machine: flong names the session before approve runs")
	}
	return files.WriteAtomic(stagedLines(c, machine), []byte(r.Lines()), 0o600)
}

// Lines is the syscall lines the launch's approval staged for machine, as
// seccompPolicy prints them. A launch whose approval did not run is
// refused, rather than its filter left as the tier's.
func Lines(c Config, machine string) (string, error) {
	b, err := os.ReadFile(stagedLines(c, machine))
	if errors.Is(err, os.ErrNotExist) {
		return "", refuse("nothing was approved for this launch: the tier's approve hook did not run")
	}
	return string(b), err
}

// With is the directories the approved chase.json staged for machine gives
// the session, chase.with, one PATH:rw or PATH:ro a line as flong's binds
// hook prints them: each relative to ws, the checkout's root, or to home
// as ~/..., or absolute, resolved. It reads the stage, never the
// checkout's file, which may have changed since it was approved: flong
// runs approve before binds so that this is so. A directory that is not
// there is said on stderr and not mounted, since a signed file naming a
// sibling checkout should not stop a launch on a machine without it.
func With(c Config, ws, machine string, stderr io.Writer) ([]string, error) {
	b, err := os.ReadFile(staged(c, machine))
	if errors.Is(err, os.ErrNotExist) {
		return nil, refuse("nothing was approved for this launch: the tier's approve hook did not run")
	} else if err != nil {
		return nil, err
	}
	var st struct {
		File *struct {
			Chase *Section `json:"chase"`
		} `json:"file"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("the approved file: %w", err)
	}
	if st.File == nil || st.File.Chase == nil {
		return nil, nil
	}
	with := st.File.Chase.With
	var out []string
	for _, dir := range slices.Sorted(maps.Keys(with)) {
		p := dir
		switch {
		case p == "~" || strings.HasPrefix(p, "~/"):
			p = filepath.Join(c.Home, strings.TrimPrefix(p, "~"))
		case !filepath.IsAbs(p):
			p = filepath.Join(ws, p)
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			term.Say(stderr, "%s: chase.with names %s, which is not there: not mounted", ws, p)
			continue
		}
		if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
			term.Say(stderr, "%s: chase.with names %s, which is not a directory: not mounted", ws, real)
			continue
		}
		if strings.ContainsAny(real, ":\n") {
			return nil, refuse("%s: chase.with names %s, whose path has a ':' or a newline, which a bind's line cannot carry", ws, real)
		}
		out = append(out, real+":"+with[dir])
	}
	return out, nil
}
