package envelope

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/term"
)

const usage = "usage: chase-envelope env-dir WS | approve WS MACHINE TIER | launch TIER WS MACHINE | policy TIER MACHINE | project WS TIER | docker WS TIER"

// Run is chase-envelope: its first argument the subcommand, and the rest
// that subcommand's. A nil registry is DefaultApps'. Every entry point
// returns the script's exit status, prints on stdout exactly what the
// script printed there, and says everything else on stderr through
// term.Say. Every entry point that reads a checkout closes the git it made
// before it returns (see gitsafe.Git.Close); a binary calling one must call
// gitsafe.MaybeExec first thing in main.
func Run(ctx context.Context, c Config, registry map[string]apps.App, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		term.Say(stderr, "%s", usage)
		return 1
	}
	rest := args[1:]
	switch args[0] {
	case "env-dir":
		return RunEnvDir(ctx, c, rest, stdin, stdout, stderr)
	case "approve":
		return RunApprove(ctx, c, rest, stdin, stdout, stderr)
	case "project":
		return RunProject(ctx, c, rest, stdin, stdout, stderr)
	case "docker":
		return RunDocker(ctx, c, rest, stdin, stdout, stderr)
	case "launch":
		if registry == nil {
			registry = DefaultApps(c, stderr)
		}
		return RunLaunch(ctx, c, registry, rest, stdin, stdout, stderr)
	case "policy":
		return RunPolicy(ctx, c, rest, stdin, stdout, stderr)
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

// RunEnvDir is `env-dir WS`, binds: the checkout's environment directory,
// made if it is not there, for the session to read, printed on a line.
func RunEnvDir(_ context.Context, c Config, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		return unset(stderr, "workspace")
	}
	dir, err := EnvDir(c, args[0])
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "%s\n", dir)
	return 0
}

// EnvDir is the checkout's environment directory, made if it is not there,
// under the caller's own umask.
func EnvDir(c Config, ws string) (string, error) {
	dir := envDir(c, ws)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return "", err
		}
	}
	return dir, nil
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

// RunLaunch is `launch TIER WS MACHINE`, postStart: the approved envelope,
// applied. Nothing is printed on stdout.
func RunLaunch(ctx context.Context, c Config, registry map[string]apps.App, args []string, _ io.Reader, _, stderr io.Writer) int {
	if len(args) < 3 {
		return unset(stderr, "tier, workspace or machine")
	}
	_, err := Launch(ctx, c, registry, args[0], args[1], args[2], stderr)
	return fail(stderr, err)
}

// RunPolicy is `policy TIER MACHINE`, frisket steer's -policy: the path of
// the session's own document if its launch wrote one, and the tier's
// otherwise, on a line.
func RunPolicy(_ context.Context, c Config, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		return unset(stderr, "tier or machine")
	}
	fmt.Fprintf(stdout, "%s\n", PolicyPath(c, args[0], args[1]))
	return 0
}

// PolicyPath is the policy document frisket steers a session under.
func PolicyPath(c Config, tier, machine string) string {
	if p := c.runtime() + "/chase/" + machine + "/policy.json"; regular(p) {
		return p
	}
	return c.Policies + "/" + tier + ".json"
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
	PostStop(ctx, c, registry, args[0])
	return 0
}
