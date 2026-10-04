// Command chase-devshell evaluates a checkout's devShell inside a session
// whose nix store is its own, and execs the agent in it
// (internal/devshell's Inside): what exec puts ahead of the agent's
// argument list in a tier whose apps.nix.store is "session", so nothing of
// the checkout's Nix is ever evaluated on the host. Its arguments are data
// alone, every one exec's.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/danielbodart/chase/internal/devshell"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	code := devshell.Inside(ctx, os.Args[1:], os.Environ(), os.Stderr)
	stop()
	os.Exit(code)
}
