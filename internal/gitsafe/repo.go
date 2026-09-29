package gitsafe

import (
	"context"
	"errors"
	"strings"
)

// Repo is a repository as its checkout was found: GitDir the checkout's own
// directory (its HEAD, its config.worktree), GitCommon the repository's
// (its config, objects and refs), the same directory for a checkout of its
// own or a submodule.
type Repo struct {
	GitDir    string
	GitCommon string
}

// ErrUnreadable is a config file that is there and was not read: not a
// plain file of a config's size, or one git could not parse.
var ErrUnreadable = errors.New("a config file cannot be read")

// ConfigFiles is each file git would read the repository's own config from:
// its config, and a worktree's own config.worktree when the repository says
// it has one. Includes are never followed: what finds a checkout refuses a
// config with any.
//
// The list is lines, as the shell passed it from one function to the next,
// so a path with a newline in it is two paths, neither of them there.
func (r Repo) ConfigFiles(ctx context.Context, g *Git) []string {
	var b strings.Builder
	b.WriteString(r.GitCommon + "/config\n")
	common := r.GitCommon + "/config"
	if Small(common, ConfigSize) {
		res := g.Run(ctx, "config", "--file", common, "--no-includes", "--type=bool", "--get", "extensions.worktreeConfig")
		if Output(res.Stdout) == "true" {
			b.WriteString(r.GitDir + "/config.worktree\n")
		}
	}
	return ReadLines(b.String())
}

// Config is KEY's values, in order, in each of ConfigFiles, as `git config
// --get-all` prints them one after another. A file that is not there is
// skipped; one that is there and cannot be read fails the whole, and then
// what was printed before it is not given either.
func (r Repo) Config(ctx context.Context, g *Git, key string) (string, error) {
	var out []byte
	for _, f := range r.ConfigFiles(ctx, g) {
		if !Exists(f) {
			continue
		}
		if !Small(f, ConfigSize) {
			return "", ErrUnreadable
		}
		res := g.Run(ctx, "config", "--file", f, "--no-includes", "--get-all", key)
		if res.Status != 0 && res.Status != 1 {
			return "", ErrUnreadable
		}
		out = append(out, res.Stdout...)
	}
	return string(out), nil
}
