package claude

import (
	"context"
	"io"

	"github.com/danielbodart/chase/internal/appcmd"
)

func init() {
	appcmd.Register("claude", "claude", map[string]appcmd.Command{
		"refresh": {Help: "systemd: keep Claude Code's login fresh", Run: func(ctx context.Context, s appcmd.Section, _ []string, stderr io.Writer) int {
			var c Config
			if err := appcmd.Configured(s, "claude", &c); err != nil {
				return appcmd.Errorf(stderr, "claude", "refresh", err)
			}
			if err := RunRefresh(ctx, c, stderr); err != nil {
				return appcmd.Errorf(stderr, "claude", "refresh", err)
			}
			return 0
		}},
	})
}
