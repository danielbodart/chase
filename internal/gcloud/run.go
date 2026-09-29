package gcloud

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/term"
)

// Usage is the exit code of a command line that is not `mint RUN` or
// `loop RUN`, as sysexits.h's EX_USAGE.
const Usage = 64

// Run is `chase gcloud-renew mint|loop RUN`, and returns its exit code.
//
//	mint RUN  mints RUN/gcloud-token.json once, and exits with its Outcome:
//	          0 minted, 1 transient, 2 Google refused the grant, 3 the key
//	          is not a usable key of $CHASE_GCLOUD_SA, where that is set.
//	loop RUN  keeps it minted until RUN is gone, as
//	          chase-gcloud-renew@<machine>, and exits 0.
//
// getenv is os.Getenv, or a check's. Everything it writes is the user's
// alone: the process's umask is 077, as the script's was.
func Run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, cfg Config) int {
	usage := func(s string) int {
		fmt.Fprint(stderr, term.Clean("chase-gcloud-renew: usage: "+s)+"\n")
		return Usage
	}
	if len(args) == 0 || (args[0] != "mint" && args[0] != "loop") {
		return usage("chase-gcloud-renew mint|loop RUN")
	}
	if len(args) != 2 {
		return usage(args[0] + " RUN")
	}
	unix.Umask(0o077)
	if args[0] == "mint" {
		return int(Mint(ctx, cfg, args[1], getenv("CHASE_GCLOUD_SA"), stderr))
	}
	Loop(ctx, cfg, args[1], stderr, RealClock{})
	return 0
}
