package claude

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/jsonfile"
)

// TrustWorkspaces marks each of cfg.TrustPaths as trusted in ~/.claude.json
// -- projects[path].hasTrustDialogAccepted -- so Claude Code does not raise
// its folder-trust dialog for a checkout the configuration itself put there.
//
// It is a home-manager activation step, and one that must never stop an
// activation over a file that is Claude Code's own: no file, or one that is
// not JSON of the shape it expects, is left alone and is not an error. Only
// failing to write a file it meant to change is. The file is replaced, at
// 0600, only when a path was not already trusted, and says so on stdout.
// Every other member, Claude Code's own, is written back as it was read.
func TrustWorkspaces(cfg Config, stdout io.Writer) error {
	path := cfg.ClaudeJSON
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		path = filepath.Join(home, ".claude.json")
	}
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v, err := jsonfile.Decode(b)
	if err != nil {
		return nil
	}
	doc, ok := jsonfile.Object(v)
	if !ok {
		return nil
	}
	paths := unique(cfg.TrustPaths)
	changed := false
	for _, p := range paths {
		was, ok := trust(doc, p)
		if !ok {
			return nil
		}
		changed = changed || !was
	}
	if !changed {
		return nil
	}
	out, err := jsonfile.Encode(doc)
	if err != nil {
		return err
	}
	if err := files.WriteAtomic(path, out, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "claude: pre-trusted %d workspaces\n", len(paths))
	return nil
}

// trust sets projects[p].hasTrustDialogAccepted in doc, making the project
// and projects where they are missing or null, and says whether it was true
// already -- only true is, not "true" -- and whether doc was a shape it could
// be set in: a projects, or a project, that is something other than an
// object is not, and doc may then be half-changed, which is not written.
func trust(doc map[string]any, p string) (was, ok bool) {
	projects, ok := jsonfile.Object(doc["projects"])
	if !ok {
		return false, false
	}
	project, ok := jsonfile.Object(projects[p])
	if !ok {
		return false, false
	}
	was = project["hasTrustDialogAccepted"] == true
	project["hasTrustDialogAccepted"] = true
	projects[p] = project
	doc["projects"] = projects
	return was, true
}

// unique is lib.unique: the first of each, in order.
func unique(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
