package claude

import (
	"os"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/jsonfile"
)

// Trust marks each of dirs as trusted in path, the host's ~/.claude.json --
// projects[dir].hasTrustDialogAccepted -- so Claude Code does not raise its
// folder-trust dialog for a checkout whose tier says to trust it (its
// apps.claude.trust), run on the host or in a session that has the host's
// file.
//
// The file is Claude Code's own, and a launch is never stopped over it: no
// file, or one that is not JSON of the shape it expects, is left alone and
// is not an error. Only failing to write a file it meant to change is. The
// file is replaced, at 0600, only when a dir was not already trusted. Every
// other member, Claude Code's own, is written back as it was read.
func Trust(path string, dirs []string) error {
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
	changed := false
	for _, d := range dirs {
		was, ok := trust(doc, d)
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
	return files.WriteAtomic(path, out, 0o600)
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
