package gcloud

import (
	"context"
	"io"
	"os"

	"github.com/danielbodart/chase/internal/appcmd"
)

func init() {
	appcmd.Register("gcloud", "gcloudRenew", map[string]appcmd.Command{
		"renew": {Args: "mint|loop RUN", Help: "systemd: a session's Google Cloud token", Run: func(ctx context.Context, s appcmd.Section, args []string, stderr io.Writer) int {
			// Empty but for a check's token endpoint: none is Google's.
			var c Config
			if _, err := s(&c); err != nil {
				return appcmd.Errorf(stderr, "gcloud", "renew", err)
			}
			return Run(ctx, args, os.Getenv, stderr, c)
		}},
	})
}
