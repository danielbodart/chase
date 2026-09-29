// Command chase decides which sandbox a checkout gets and what each app in it
// is given, and does, at launch, what the NixOS module cannot do by
// evaluating: read the checkout, ask about what it says, and compose the
// session's policy. The module decides what exists and wires it together;
// every hook it gives flong, every unit it gives systemd, and the agents a
// person runs on the host run this one binary.
//
// It is one binary with many names. Run as `claude` or `codex` (the links
// the module puts on the person's PATH), it is that agent's wrapper; run as
// `agent-tier`, it is `chase tier`; run as anything else, the first argument
// names the command.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/danielbodart/chase/internal/apps/claude"
	"github.com/danielbodart/chase/internal/apps/codex"
	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/config"
	"github.com/danielbodart/chase/internal/dockerproject"
	"github.com/danielbodart/chase/internal/gcloud"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/selector"
	"github.com/danielbodart/chase/internal/snapshot"
)

// version is stamped at build time. A build without it says so rather than
// claiming a number.
var version = "dev"

const usage = `chase -- which sandbox a checkout gets, and which credential each app is given

  chase shell [ARG...]
        A shell where an agent would run in this checkout: in its tier's
        sandbox, or on the host for a bare tier.

  chase tier [DIR] | --if-gone DIR | --dry-run DIR...
        The tier a checkout is sorted into (also run as agent-tier):
        --if-gone, the tier it would be without its own .git; --dry-run, a
        table of each directory's tier and why.

  chase docker-address OWNER/REPO
        A project's Docker identity, as one line of JSON: its owner/repo
        lower-cased, the loopback address everything it publishes is bound
        to, and the .internal names that address is known by.

  chase version
        The version this binary was built as.

  claude [ARG...], codex [ARG...]
        The agents, as the links the module installs: each picks the tier
        of the checkout it is run in and runs there.

What the module runs, rather than a person:

  chase workspace                  flong's workspace: the checkout's root
  chase guard TIER                 flong's guard for a sandbox tier
  chase checkout [--ignoring ROOT] [DIR]
  chase origin DIR
  chase ls-files DIR               a checkout read without running its git
  chase copy-tracked WS DEST       the snapshot copier, paths on stdin
  chase claude-refresh             systemd: keep Claude Code's login fresh
  chase claude-trust               activation: pre-trust the workspaces
  chase codex-refresh              systemd: keep Codex's login fresh
  chase codex-placeholder          activation: Codex's placeholder login
  chase gcloud-renew mint|loop RUN a session's Google Cloud token

Every command that needs the module's configuration reads
/etc/chase/config.json, or the file given before the command as
-config FILE.
`

func main() {
	// Every git call re-executes this binary to set its own resource limits
	// before it becomes git; this is where that happens, before anything
	// else can allocate.
	gitsafe.MaybeExec()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	name := filepath.Base(os.Args[0])
	args := os.Args[1:]
	cfgPath := config.Default
	switch name {
	case "claude", "codex":
		exit(wrap(ctx, cfgPath, name, args))
	case "agent-tier":
		exit(runTier(ctx, cfgPath, args))
	}

	if len(args) >= 2 && args[0] == "-config" {
		cfgPath, args = args[1], args[2:]
	}
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	command, args := args[0], args[1:]
	var err error
	switch command {
	case "shell":
		exit(wrap(ctx, cfgPath, "shell", args))
	case "tier":
		exit(runTier(ctx, cfgPath, args))
	case "workspace":
		err = runWorkspace(ctx, cfgPath, os.Stdout)
	case "guard":
		exit(runGuard(ctx, cfgPath, args))
	case "checkout", "origin", "ls-files":
		exit(runCheckout(ctx, cfgPath, command, args))
	case "copy-tracked":
		exit(snapshot.Run(args, os.Stdin, os.Stdout, os.Stderr))
	case "docker-address":
		err = runDockerAddress(args, os.Stdout)
	case "claude-refresh", "claude-trust":
		err = runClaude(ctx, cfgPath, command)
	case "codex-refresh", "codex-placeholder":
		err = runCodex(ctx, cfgPath, command)
	case "gcloud-renew":
		cfg, lerr := config.Load(cfgPath)
		if lerr != nil {
			err = lerr
			break
		}
		exit(gcloud.Run(ctx, args, os.Getenv, os.Stderr, cfg.GCloudRenew))
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "chase: unknown command %q\n\n%s", command, usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "chase %s: %v\n", command, err)
		os.Exit(1)
	}
}

// exit ends the process with a command's own status, which it has already
// explained.
func exit(code int) { os.Exit(code) }

// selectorOf is the configured selector. A configuration that will not load
// cannot sort anything, and says so.
func selectorOf(cfgPath string) (config.Config, *selector.Selector, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return config.Config{}, nil, err
	}
	s, err := selector.New(cfg.Selector)
	if err != nil {
		return config.Config{}, nil, err
	}
	return cfg, s, nil
}

func runTier(ctx context.Context, cfgPath string, args []string) int {
	_, s, err := selectorOf(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase tier: %v\n", err)
		return 1
	}
	return selector.RunAgentTier(ctx, s, args, os.Stdout, os.Stderr)
}

func runGuard(ctx context.Context, cfgPath string, args []string) int {
	_, s, err := selectorOf(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase guard: %v\n", err)
		return 1
	}
	return selector.RunGuard(ctx, s, args, os.LookupEnv, os.Stderr)
}

// runWorkspace is flong's workspace hook: the root of the checkout the
// launch is in, or the directory itself for a layout that is not sorted.
// flong runs it in the caller's directory.
func runWorkspace(ctx context.Context, cfgPath string, out io.Writer) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	g, err := gitsafe.New(cfg.Selector.Config)
	if err != nil {
		return err
	}
	defer g.Close()
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, (&checkout.Finder{Git: g}).Workspace(ctx, pwd))
	return err
}

func runCheckout(ctx context.Context, cfgPath, command string, args []string) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase %s: %v\n", command, err)
		return 1
	}
	g, err := gitsafe.New(cfg.Selector.Config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase %s: %v\n", command, err)
		return 1
	}
	switch command {
	case "checkout":
		return checkout.RunCheckout(ctx, g, args, os.Stdout, os.Stderr)
	case "origin":
		return checkout.RunOrigin(ctx, g, args, os.Stdout, os.Stderr)
	default:
		return checkout.RunLsFiles(ctx, g, args, os.Stdout, os.Stderr)
	}
}

// wrap runs an agent where the checkout it is run in belongs: on the host
// for a bare tier, in the tier's sandbox otherwise, and in the fallback's
// for anything unexpected. It never returns but to refuse.
func wrap(ctx context.Context, cfgPath, agent string, args []string) int {
	cfg, s, err := selectorOf(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", agent, err)
		return 1
	}
	w := selector.Wrapper{Agent: agent, HostCommand: selector.ShellHostCommand()}
	if agent != "shell" {
		hc, ok := cfg.Wrappers[agent]
		if !ok {
			fmt.Fprintf(os.Stderr, "%s: the module configures no %s\n", agent, agent)
			return 1
		}
		w.HostCommand = hc.HostCommand
	}
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", agent, err)
		return 1
	}
	argv := s.Launch(ctx, pwd, w, args)
	prog := argv[0]
	if filepath.Base(prog) == prog {
		// Only `chase shell`'s $SHELL, or bash, is ever looked up.
		if prog, err = exec.LookPath(prog); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", agent, err)
			return 127
		}
	}
	err = syscall.Exec(prog, argv, os.Environ())
	fmt.Fprintf(os.Stderr, "%s: %s: %v\n", agent, prog, err)
	return 126
}

func runClaude(ctx context.Context, cfgPath, command string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.Claude == nil {
		return errors.New("the module configures no claude")
	}
	if command == "claude-trust" {
		return claude.TrustWorkspaces(*cfg.Claude, os.Stdout)
	}
	return claude.RunRefresh(ctx, *cfg.Claude, os.Stderr)
}

func runCodex(ctx context.Context, cfgPath, command string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.Codex == nil {
		return errors.New("the module configures no codex")
	}
	if command == "codex-placeholder" {
		return codex.WritePlaceholder(*cfg.Codex)
	}
	return codex.RunRefresh(ctx, *cfg.Codex, os.Stderr)
}

func runDockerAddress(argv []string, out io.Writer) error {
	fs := flag.NewFlagSet("docker-address", flag.ContinueOnError)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: chase docker-address OWNER/REPO")
	}
	p, err := dockerproject.Of(fs.Arg(0))
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(p)
}
