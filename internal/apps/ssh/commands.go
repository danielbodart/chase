package ssh

import (
	"context"
	"io"

	"github.com/danielbodart/chase/internal/appcmd"
)

func init() {
	appcmd.Register("ssh", "grant.ssh", map[string]appcmd.Command{
		"check": {Help: "the system's build: its SSH catalogues and each tier's own machines, as a launch would check them", Run: func(_ context.Context, s appcmd.Section, _ []string, stderr io.Writer) int {
			var c Config
			if ok, err := s(&c); err != nil {
				return appcmd.Errorf(stderr, "ssh", "check", err)
			} else if !ok {
				return 0 // no tier has SSH: nothing to check
			}
			if err := c.Check(); err != nil {
				return appcmd.Errorf(stderr, "ssh", "check", err)
			}
			return 0
		}},
	})
}
