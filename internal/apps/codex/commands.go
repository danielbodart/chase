package codex

import (
	"context"
	"io"

	"github.com/danielbodart/chase/internal/appcmd"
)

func init() {
	// Each moves what an earlier chase kept elsewhere first.
	run := func(name string, f func(ctx context.Context, c Config, stderr io.Writer) error) appcmd.Command {
		return appcmd.Command{Run: func(ctx context.Context, s appcmd.Section, _ []string, stderr io.Writer) int {
			var c Config
			if err := appcmd.Configured(s, "codex", &c); err != nil {
				return appcmd.Errorf(stderr, "codex", name, err)
			}
			MoveState(c, stderr)
			if err := f(ctx, c, stderr); err != nil {
				return appcmd.Errorf(stderr, "codex", name, err)
			}
			return 0
		}}
	}
	refresh := run("refresh", RunRefresh)
	refresh.Help = "systemd: keep Codex's login fresh"
	placeholder := run("placeholder", func(_ context.Context, c Config, _ io.Writer) error { return WritePlaceholder(c) })
	placeholder.Help = "activation: Codex's placeholder login"
	appcmd.Register("codex", "codex", map[string]appcmd.Command{"refresh": refresh, "placeholder": placeholder})
}
