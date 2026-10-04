package selector

import (
	"context"
	"os"
)

// Wrapper is one of the commands mkWrapper made: `claude`, `codex` or
// `deepsec` on the host, or `chase shell`. It picks the tier, then runs
// bare or in its container.
type Wrapper struct {
	// Agent is the name the launcher's command is given: claude, codex,
	// deepsec or shell.
	Agent string
	// HostCommand is what a bare tier runs, with the wrapper's arguments
	// after it: the agent itself as it runs on the host, e.g.
	// [".../bin/claude", "--allow-dangerously-skip-permissions"]. For `chase
	// shell` it is the caller's $SHELL, or bash when that is unset or
	// empty.
	HostCommand []string
}

// Bare is tier's entry, and whether it is a bare tier's: what a wrapper
// asks of the tier it runs a session bare in, which is what it trusts.
func (s *Selector) Bare(tier string) (Tier, bool) {
	t, ok := s.cfg.Tiers[tier]
	return t, ok && t.Bare
}

// For is what the wrapper execs for a session of tier with args, as Launch
// says.
func (s *Selector) For(tier string, w Wrapper, args []string) []string {
	return s.launch(tier, w, args)
}

// Launch is what the wrapper execs for a session started in dir with args:
// the host command for a bare tier, its launcher and the agent for a sandbox
// tier, and the fallback's launcher for anything unexpected -- a tier with no
// entry, or one `chase tier` could not give. Argv[0] is an absolute path, or,
// for a bare tier's HostCommand, what exec looks up on PATH. It closes s
// before it returns, since what it returns is exec'd and no deferred call
// of the caller's would run.
func (s *Selector) Launch(ctx context.Context, dir string, w Wrapper, args []string) []string {
	defer s.Close()
	return s.launch(s.Tier(ctx, dir), w, args)
}

func (s *Selector) launch(tier string, w Wrapper, args []string) []string {
	t, ok := s.cfg.Tiers[tier]
	if ok && t.Bare {
		return append(append([]string{}, w.HostCommand...), args...)
	}
	if !ok {
		t = s.cfg.Tiers[s.cfg.Fallback]
	}
	return append([]string{t.Launcher, w.Agent}, args...)
}

// Recorder is the launcher `chase record` runs a session of tier through,
// as launch picks a tier's: the fallback's for a tier with no entry, and
// nothing for a bare tier, which has no sandbox to record, or for one with
// no recording.
func (s *Selector) Recorder(tier string) (string, bool) {
	t, ok := s.cfg.Tiers[tier]
	if !ok {
		t = s.cfg.Tiers[s.cfg.Fallback]
	}
	if t.Bare || t.RecordLauncher == "" {
		return "", false
	}
	return t.RecordLauncher, true
}

// TierOrFallback is `$(chase tier DIR 2>/dev/null) || tier=FALLBACK`, as
// `chase docker` asks it: dir's tier. `chase tier` no longer fails, so it is
// always the tier; the name says what the caller may rely on.
func (s *Selector) TierOrFallback(ctx context.Context, dir string) string {
	return s.Tier(ctx, dir)
}

// ShellHostCommand is `chase shell`'s host command: "${SHELL:-bash}".
func ShellHostCommand() []string {
	if sh := os.Getenv("SHELL"); sh != "" {
		return []string{sh}
	}
	return []string{"bash"}
}
