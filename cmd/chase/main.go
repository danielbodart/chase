// Command chase decides which sandbox a checkout gets and what each app in it
// is given, and does, at launch, what the NixOS module cannot do by
// evaluating: read the checkout, ask about what it says, and compose the
// session's policy. The module decides what exists and wires it together;
// every hook it gives flong, every unit it gives systemd, and the agents a
// person runs on the host run this one binary.
//
// It is one binary with many names. Run as `claude` or `codex` (the links
// the module puts on the person's PATH), it is that agent's wrapper; run as
// anything else, the first argument names the command.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

	"github.com/danielbodart/chase/internal/apps/claude"
	"github.com/danielbodart/chase/internal/apps/codex"
	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/config"
	"github.com/danielbodart/chase/internal/gcloud"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/nixstore"
	"github.com/danielbodart/chase/internal/projectaddr"
	"github.com/danielbodart/chase/internal/record"
	"github.com/danielbodart/chase/internal/selector"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/snapshot"
	"github.com/danielbodart/chase/internal/term"
)

// version is stamped at build time. A build without it says so rather than
// claiming a number.
var version = "dev"

const usage = `chase -- which sandbox a checkout gets, and which credential each app is given

  chase shell [ARG...]
        A shell where an agent would run in this checkout: in its tier's
        sandbox, or on the host for a bare tier.

  chase tier [DIR] | --if-gone DIR | --dry-run DIR...
        The tier a checkout is sorted into; --if-gone, the tier it would be
        without its own .git; --dry-run, a table of each directory's tier
        and why.

  chase docker [DIR]
        Where a checkout's Docker containers are reached from the host, as
        the tier it would run in has them.

  chase record [--default allow|ask|refuse] [--base tier|none] [--] AGENT [ARG...]
        AGENT -- claude, codex or shell -- in this checkout's tier, as a
        recording: what the tier would refuse or ask about is put to you,
        or answered by --default, and written down; once it ends, a report
        of what it needed and a proposal of the grant entries that would
        give it. --base none learns syscalls against nothing but the
        calls every process makes, rather than the tier's filter.

  chase record apply [--last | MACHINE]
        A recording's proposal, the last one's by default, added to its
        checkout's chase.jsonc.

  chase project-address OWNER/REPO
        A project's address, as one line of JSON: its owner/repo
        lower-cased, the loopback address its dev servers and containers
        are published at, and the .internal names that address is known by.

  chase version
        The version this binary was built as.

  claude [ARG...], codex [ARG...]
        The agents, as the links the module installs: each picks the tier
        of the checkout it is run in and runs there.

What the module runs, rather than a person:

  chase workspace                  flong's workspace: the checkout's root
  chase guard TIER                 flong's guard for a sandbox tier
  chase hook binds TIER            flong's binds: what is bound beside it
  chase hook approve TIER          flong's seccompPolicy: approve the grant
  chase hook record-approve TIER   a record launcher's: the same, and learn
                                   what the session calls
  chase hook record-exec TIER AGENT [ARG...]
                                   a record launcher's exec: the same, the
                                   session's document a recording's
  chase hook exec TIER AGENT [ARG...]
                                   flong's exec: apply what was approved, and
                                   print the payload, its environment and the
                                   files seeded into its home
  chase hook poststop TIER         flong's postStop: release and remove it
  chase hook nix-poststart TIER    flong's postStart where the tier's nix
                                   store is the session's: watch it
  chase hook nix-poststop TIER     flong's postStop there: promote and
                                   remove it
  chase nix-watch TIER MACHINE LEADER
                                   a session's nix store, rooted on the
                                   host and kept within the tier's limits
  chase nix-sweep                  systemd: remove the nix stores of
                                   sessions no container holds
  chase grant approve|project|docker ...
                                   the grant's steps, as a person uses them
  chase checkout [--ignoring ROOT] [DIR]
  chase origin DIR
  chase ls-files DIR               a checkout read without running its git
  chase copy-tracked WS DEST       the snapshot copier, paths on stdin
  chase claude-refresh             systemd: keep Claude Code's login fresh
  chase codex-refresh              systemd: keep Codex's login fresh
  chase codex-placeholder          activation: Codex's placeholder login
  chase gcloud-renew mint|loop RUN a session's Google Cloud token
  chase ssh-check                  the system's build: its SSH catalogues
                                   and each tier's own machines, as a
                                   launch would check them

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
	case "hook":
		exit(runHook(ctx, cfgPath, args))
	case "grant":
		cfg, lerr := config.Load(cfgPath)
		if lerr != nil {
			err = lerr
			break
		}
		if cfg.Grant == nil {
			err = errors.New("the module configures no tier that takes a grant")
			break
		}
		exit(grant.Run(ctx, *cfg.Grant, args, os.Stdin, os.Stdout, os.Stderr))
	case "docker":
		exit(runDocker(ctx, cfgPath, args))
	case "record":
		exit(runRecord(ctx, cfgPath, args))
	case "checkout", "origin", "ls-files":
		exit(runCheckout(ctx, cfgPath, command, args))
	case "copy-tracked":
		exit(snapshot.Run(args, os.Stdin, os.Stdout, os.Stderr))
	case "project-address":
		err = runProjectAddress(args, os.Stdout)
	case "claude-refresh":
		err = runClaude(ctx, cfgPath)
	case "codex-refresh", "codex-placeholder":
		err = runCodex(ctx, cfgPath, command)
	case "gcloud-renew":
		cfg, lerr := config.Load(cfgPath)
		if lerr != nil {
			err = lerr
			break
		}
		exit(gcloud.Run(ctx, args, os.Getenv, os.Stderr, cfg.GCloudRenew))
	case "ssh-check":
		err = runSSHCheck(cfgPath)
	case "nix-watch":
		exit(runNixWatch(ctx, cfgPath, args))
	case "nix-sweep":
		err = runNixSweep(cfgPath)
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

// runSSHCheck is what every launch would refuse of the machine's own SSH
// (apps/ssh.nix's system.checks): nothing, for a machine with none.
func runSSHCheck(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.Grant == nil || cfg.Grant.SSH == nil {
		return nil
	}
	return cfg.Grant.SSH.Check()
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
	return selector.RunTier(ctx, s, args, os.Stdout, os.Stderr)
}

func runGuard(ctx context.Context, cfgPath string, args []string) int {
	_, s, err := selectorOf(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase guard: %v\n", err)
		return 1
	}
	// flong gives every hook the launcher's arguments after its own; the
	// guard is one hook, and reads only its tier.
	if len(args) > 1 {
		args = args[:1]
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
	tier := s.Tier(ctx, pwd)
	argv := s.For(tier, w, args)
	env := os.Environ()
	if t, bare := s.Bare(tier); bare && t.Trust != nil {
		// A bare tier that trusts its checkouts trusts this one -- its root,
		// as a sandbox's workspace is -- in the apps it says, as the person
		// would by answering each app's dialog.
		ws := (&checkout.Finder{Git: s.Git()}).Workspace(ctx, pwd)
		claudeJSON := ""
		if cfg.Claude != nil {
			claudeJSON = cfg.Claude.ClaudeJSON
		}
		argv, env, err = t.Trust.OnHost(agent, claudeJSON, len(w.HostCommand), ws, argv, env)
		if err != nil {
			s.Close()
			fmt.Fprintf(os.Stderr, "%s: %v\n", agent, err)
			return 1
		}
	}
	s.Close()
	prog := argv[0]
	if filepath.Base(prog) == prog {
		// Only `chase shell`'s $SHELL, or bash, is ever looked up.
		if prog, err = exec.LookPath(prog); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", agent, err)
			return 127
		}
	}
	err = syscall.Exec(prog, argv, env)
	fmt.Fprintf(os.Stderr, "%s: %s: %v\n", agent, prog, err)
	return 126
}

// runHook is one of flong's hooks for a sandbox tier. flong runs each as a
// command, never through a shell, with $workspace, $binds and (from
// seccompPolicy on) $machine in its environment, and the launcher's own
// arguments after the hook's, which are exec's alone to read: the agent,
// and its arguments.
func runHook(ctx context.Context, cfgPath string, args []string) int {
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, "usage: chase hook binds|approve|exec|record-approve|record-exec|poststop|nix-poststart|nix-poststop TIER\n")
		return 2
	}
	hook, tier := args[0], args[1]
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase hook %s: %v\n", hook, err)
		return 1
	}
	ws, machine := os.Getenv("workspace"), os.Getenv("machine")
	takes := cfg.Grant != nil && slices.Contains(cfg.GrantTiers, tier)
	switch hook {
	case "binds":
		if err := session.Binds(cfg.Session, tier, ws, os.Stdout); err != nil {
			term.Say(os.Stderr, "%s: %v", ws, err)
			return 1
		}
		// A store of the session's own, where the tier's nix has one: for
		// every session where its devShell is automatic, and otherwise
		// where the checkout's grant asks for it -- read as it is now,
		// before it is approved, to make an empty store nothing uses unless
		// the grant approved after it asks too (internal/devshell).
		if n := cfg.Session.Tiers[tier].Nix; n.InSession() && (!n.Granted() || takes && grant.AsksForNixStore(*cfg.Grant, ws, tier)) {
			if err := nixstore.Binds(n.Session, machine, os.Stdout, os.Stderr); err != nil {
				term.Say(os.Stderr, "%s: the session's nix store: %v", ws, err)
				return 1
			}
		}
		return 0
	case "nix-poststart", "nix-poststop":
		return runNixHook(ctx, cfgPath, cfg, hook, tier, machine)
	case "exec":
		return runExec(ctx, cfg, tier, ws, machine, takes, args[2:])
	case "record-exec", "record-approve":
		if !takes {
			fmt.Fprintf(os.Stderr, "chase hook %s: %s takes no grant, so it does not record\n", hook, tier)
			return 1
		}
		// What to record is the person's who ran `chase record`, from their
		// environment, and never anything a checkout says.
		rec, err := grant.RecordingFromEnv(os.Getenv)
		if err != nil {
			term.Say(os.Stderr, "%v", err)
			return 1
		}
		if hook == "record-exec" {
			return grant.ExecRecording(ctx, cfg.Session, cfg.Grant, nil, rec, tier, ws, machine, os.Getenv("binds"), args[2:], os.Stdout, os.Stderr)
		}
		r, err := grant.ApproveRecording(ctx, *cfg.Grant, ws, machine, tier, rec, os.Stderr)
		if err != nil {
			term.Say(os.Stderr, "%v", err)
			return 1
		}
		io.WriteString(os.Stdout, r.Lines())
		return 0
	case "approve", "poststop":
		if !takes {
			fmt.Fprintf(os.Stderr, "chase hook %s: %s takes no grant\n", hook, tier)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "chase hook: unknown hook %q\n", hook)
		return 2
	}
	e := *cfg.Grant
	switch hook {
	case "approve":
		return grant.RunApprove(ctx, e, []string{ws, machine, tier}, os.Stdin, os.Stdout, os.Stderr)
	default:
		return grant.RunPostStop(ctx, e, nil, []string{machine}, os.Stdin, os.Stdout, os.Stderr)
	}
}

// runExec is flong's exec for a sandbox tier (grant.Exec): the
// payload, printed as flong reads it, for the launcher's arguments args,
// the approved grant applied first for a tier that takes one.
func runExec(ctx context.Context, cfg config.Config, tier, ws, machine string, takes bool, args []string) int {
	var e *grant.Config
	if takes {
		e = cfg.Grant
	}
	return grant.Exec(ctx, cfg.Session, e, nil, tier, ws, machine, os.Getenv("binds"), args, os.Stdout, os.Stderr)
}

// runNixHook is a hook of a tier whose nix store is the session's own
// (internal/nixstore). postStart starts its watcher, `chase nix-watch`,
// for a session whose binds made one: in the session's cgroup, which
// postStart runs in, so it ends with the session, apart from the hook,
// which the entrypoint waits on, its stderr the launcher's, where it says
// what it does. postStop promotes what the store substituted and removes
// it, keyed by $machine alone.
func runNixHook(ctx context.Context, cfgPath string, cfg config.Config, hook, tier, machine string) int {
	n := cfg.Session.Tiers[tier].Nix
	if !n.InSession() {
		fmt.Fprintf(os.Stderr, "chase hook %s: %s's nix store is not the session's\n", hook, tier)
		return 1
	}
	if hook == "nix-poststop" {
		if err := nixstore.PostStop(ctx, *n, machine, cfg.Session.Runtime, os.Stderr); err != nil {
			term.Say(os.Stderr, "the nix store of %s: %v", machine, err)
			return 1
		}
		return 0
	}
	dir, err := nixstore.Dir(n.Session, machine)
	if err != nil {
		term.Say(os.Stderr, "%v", err)
		return 1
	}
	if _, err := os.Lstat(dir); err != nil {
		return 0
	}
	self, err := os.Executable()
	if err != nil {
		term.Say(os.Stderr, "%v", err)
		return 1
	}
	cmd := exec.Command(self, "-config", cfgPath, "nix-watch", tier, machine, os.Getenv("leader"))
	cmd.Env = []string{}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		term.Say(os.Stderr, "the nix store of %s is not watched: %v", machine, err)
		return 1
	}
	cmd.Process.Release()
	return 0
}

// runNixWatch is `chase nix-watch TIER MACHINE LEADER` (nixstore.Watch):
// until the session ends, which ends it too, or it ends the session.
func runNixWatch(ctx context.Context, cfgPath string, args []string) int {
	if len(args) != 3 {
		fmt.Fprint(os.Stderr, "usage: chase nix-watch TIER MACHINE LEADER\n")
		return 2
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase nix-watch: %v\n", err)
		return 1
	}
	n := cfg.Session.Tiers[args[0]].Nix
	if !n.InSession() {
		fmt.Fprintf(os.Stderr, "chase nix-watch: %s's nix store is not the session's\n", args[0])
		return 1
	}
	leader, err := strconv.Atoi(args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase nix-watch: the leader %q is no pid\n", args[2])
		return 2
	}
	if err := nixstore.Watch(ctx, *n, args[1], leader, os.Stderr); err != nil {
		term.Say(os.Stderr, "%v", err)
		return 1
	}
	return 0
}

// runNixSweep is `chase nix-sweep`, the hourly timer's: the stores of
// sessions no container holds, removed, for every tier whose nix store is
// the session's own, as each launch's binds removes them.
func runNixSweep(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(cfg.Session.Tiers)) {
		if n := cfg.Session.Tiers[name].Nix; n.InSession() && !seen[n.Session.Root] {
			seen[n.Session.Root] = true
			nixstore.Sweep(n.Session, os.Stderr)
		}
	}
	return nil
}

// runRecord is `chase record`: a session of the checkout's own tier, as
// the wrapper would pick it, run through the tier's record launcher as a
// child rather than exec'd, so that what it needed is harvested once it
// ends; or `chase record apply`. Only ever a person's: no wrapper runs it,
// and nothing a checkout says starts one.
func runRecord(ctx context.Context, cfgPath string, args []string) int {
	cfg, s, err := selectorOf(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase record: %v\n", err)
		return 1
	}
	if cfg.Grant == nil || cfg.Record == nil {
		s.Close()
		fmt.Fprint(os.Stderr, "chase record: the module configures no tier that records\n")
		return 1
	}
	if len(args) > 0 && args[0] == "apply" {
		s.Close()
		return record.Apply(*cfg.Grant, args[1:], os.Stdout, os.Stderr)
	}
	a, err := record.ParseArgs(args)
	if err != nil {
		s.Close()
		fmt.Fprintf(os.Stderr, "chase record: %v\n%s\n", err, record.Usage)
		return 2
	}
	pwd, err := os.Getwd()
	if err != nil {
		s.Close()
		fmt.Fprintf(os.Stderr, "chase record: %v\n", err)
		return 1
	}
	tier := s.Tier(ctx, pwd)
	launcher, ok := s.Recorder(tier)
	if !ok {
		s.Close()
		term.Say(os.Stderr, "%s is '%s', which records nothing: a bare tier has no sandbox, and a sandbox records with chase.tiers.%s.record.enable", pwd, tier, tier)
		return 1
	}
	ws := (&checkout.Finder{Git: s.Git()}).Workspace(ctx, pwd)
	s.Close()
	return record.Run(record.Session{
		Grant: *cfg.Grant, Config: *cfg.Record, Tier: tier, Workspace: ws, Launcher: launcher, Args: a,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
}

// runDocker is `chase docker [DIR]`: where the checkout's containers are
// reached, as the tier it would run in has them.
func runDocker(ctx context.Context, cfgPath string, args []string) int {
	if len(args) > 1 {
		fmt.Fprint(os.Stderr, "usage: chase docker [DIR]\n")
		return 2
	}
	cfg, s, err := selectorOf(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase docker: %v\n", err)
		return 1
	}
	if cfg.Grant == nil {
		fmt.Fprint(os.Stderr, "chase docker: the module configures no tier that takes a grant\n")
		return 1
	}
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chase docker: %v\n", err)
		return 1
	}
	tier := s.TierOrFallback(ctx, abs)
	s.Close()
	return grant.RunDocker(ctx, *cfg.Grant, []string{abs, tier}, os.Stdin, os.Stdout, os.Stderr)
}

func runClaude(ctx context.Context, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.Claude == nil {
		return errors.New("the module configures no claude")
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
	codex.MoveState(*cfg.Codex, os.Stderr)
	if command == "codex-placeholder" {
		return codex.WritePlaceholder(*cfg.Codex)
	}
	return codex.RunRefresh(ctx, *cfg.Codex, os.Stderr)
}

func runProjectAddress(argv []string, out io.Writer) error {
	fs := flag.NewFlagSet("project-address", flag.ContinueOnError)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: chase project-address OWNER/REPO")
	}
	p, err := projectaddr.Of(fs.Arg(0))
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(p)
}
