package envelope

import (
	"context"
	"fmt"
	"io"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/term"
)

const usage = "usage: chase envelope approve WS MACHINE TIER | project WS TIER | docker WS TIER"

// Run is `chase envelope`: its first argument the subcommand, and the rest
// that subcommand's. Every entry point returns the script's exit status,
// prints on stdout exactly what the script printed there, and says
// everything else on stderr through term.Say. Every entry point that reads
// a checkout closes the git it made before it returns (see
// gitsafe.Git.Close); a binary calling one must call gitsafe.MaybeExec first
// thing in main. The launch is not one of them: it is half of flong's exec
// hook, whose stdout is the payload's (Launch).
func Run(ctx context.Context, c Config, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		term.Say(stderr, "%s", usage)
		return 1
	}
	rest := args[1:]
	switch args[0] {
	case "approve":
		return RunApprove(ctx, c, rest, stdin, stdout, stderr)
	case "project":
		return RunProject(ctx, c, rest, stdin, stdout, stderr)
	case "docker":
		return RunDocker(ctx, c, rest, stdin, stdout, stderr)
	}
	term.Say(stderr, "%s", usage)
	return 1
}

// fail says err as the script's die said it, and is its status.
func fail(stderr io.Writer, err error) int {
	if err == nil {
		return 0
	}
	term.Say(stderr, "%s", err.Error())
	return 1
}

// unset is what the script did with an argument it needed and was not
// given: bash's `set -u` stopped it.
func unset(stderr io.Writer, what string) int {
	term.Say(stderr, "%s: no %s was given (%s)", "chase-envelope", what, usage)
	return 1
}

// RunApprove is `approve WS MACHINE TIER`, seccompPolicy: the approval, and
// the approved policy's `allow` and `deny` lines, which are all it prints on
// stdout.
func RunApprove(ctx context.Context, c Config, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		return unset(stderr, "workspace")
	}
	args = append(args, "", "")
	r, err := Approve(ctx, c, args[0], args[1], args[2], stderr)
	if err != nil {
		return fail(stderr, err)
	}
	io.WriteString(stdout, r.Lines())
	return 0
}

// RunProject is `project WS TIER`: the checkout's Docker project, as
// approve derives it, on a line.
func RunProject(ctx context.Context, c Config, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		return fail(stderr, refuse("usage: chase-envelope project WS TIER"))
	}
	slug, err := Project(ctx, c, args[0], args[1], stderr)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s\n", slug)
	return 0
}

// RunDocker is `docker WS TIER`, what `chase docker` prints: the checkout's
// project, address, names and ports.
func RunDocker(ctx context.Context, c Config, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		return fail(stderr, refuse("usage: chase-envelope docker WS TIER"))
	}
	return fail(stderr, Show(ctx, c, args[0], args[1], stdout, stderr))
}

// RunPostStop is `MACHINE`, postStop: each app's Stop, then the session's
// directory and its stage removed. It always succeeds, as the script's
// `stop || true` and `rm -rf` did.
func RunPostStop(ctx context.Context, c Config, registry map[string]apps.App, args []string, _ io.Reader, _, stderr io.Writer) int {
	if len(args) < 1 {
		return unset(stderr, "machine")
	}
	if registry == nil {
		registry = DefaultApps(c, stderr)
	}
	return fail(stderr, PostStop(ctx, c, registry, args[0]))
}
