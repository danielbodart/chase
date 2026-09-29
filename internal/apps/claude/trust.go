package claude

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/danielbodart/chase/internal/apps/claude/jsondoc"
	"github.com/danielbodart/chase/internal/files"
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
	doc, err := jsondoc.Parse(b)
	if err != nil {
		return nil
	}
	paths := unique(cfg.TrustPaths)
	changed := false
	for _, p := range paths {
		next, was, err := trust(doc, p)
		if err != nil {
			return nil
		}
		doc = next
		changed = changed || !was
	}
	if !changed {
		return nil
	}
	if err := files.WriteAtomic(path, append(doc.Marshal(), '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "claude: pre-trusted %d workspaces\n", len(paths))
	return nil
}

// trust is jq's `.projects[$p].hasTrustDialogAccepted = true`, and whether
// it was true already.
func trust(doc jsondoc.Value, p string) (jsondoc.Value, bool, error) {
	projects, err := doc.Field("projects")
	if err != nil {
		return doc, false, err
	}
	project, err := projects.Field(p)
	if err != nil {
		return doc, false, err
	}
	cur, err := project.Field("hasTrustDialogAccepted")
	if err != nil {
		return doc, false, err
	}
	if project, err = project.SetField("hasTrustDialogAccepted", jsondoc.True); err != nil {
		return doc, false, err
	}
	if projects, err = projects.SetField(p, project); err != nil {
		return doc, false, err
	}
	if doc, err = doc.SetField("projects", projects); err != nil {
		return doc, false, err
	}
	return doc, cur.Kind == jsondoc.Bool && cur.Bool, nil
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
