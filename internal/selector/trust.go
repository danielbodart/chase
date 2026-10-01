package selector

import (
	"slices"
	"strings"

	"github.com/danielbodart/chase/internal/apps/claude"
	"github.com/danielbodart/chase/internal/session"
)

// OnHost has a bare tier's apps trust ws, the checkout a wrapper runs agent
// in on the host, as the person would by answering each app's dialog:
// Claude Code in claudeJSON, the host's ~/.claude.json, and codex by an
// override after the first n words of argv, the host command's, before the
// person's own. Each variable in t.Env is set in env to ws, ahead of what
// it held, which is a list of paths. A tier that does not trust is never
// asked.
func (t Trust) OnHost(agent, claudeJSON string, n int, ws string, argv, env []string) ([]string, []string, error) {
	if t.Claude && agent == "claude" && claudeJSON != "" {
		if err := claude.Trust(claudeJSON, []string{ws}); err != nil {
			return nil, nil, err
		}
	}
	if t.Codex && agent == "codex" {
		argv = slices.Concat(argv[:n], session.CodexTrust(ws), argv[n:])
	}
	for _, k := range t.Env {
		v := ws
		env = slices.DeleteFunc(slices.Clone(env), func(e string) bool {
			old, ok := strings.CutPrefix(e, k+"=")
			if ok && old != "" {
				v = ws + ":" + old
			}
			return ok
		})
		env = append(env, k+"="+v)
	}
	return argv, env, nil
}
