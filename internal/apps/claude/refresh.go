package claude

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/danielbodart/chase/internal/apps/claude/jsondoc"
	"github.com/danielbodart/chase/internal/term"
)

// Prompt is what the refresher asks: the cheapest request that makes Claude
// Code refresh its own login first, which is the only refresh this does.
const Prompt = "Reply with the single word: ok"

// Args are claude's arguments for that request: haiku, and no session left
// behind in the host's history for it.
var Args = []string{"-p", "--model", "haiku", "--no-session-persistence", Prompt}

const (
	// lead is how long before expiry the refresher wakes: 4 minutes.
	lead = 240000 // milliseconds
	// step is the longest one sleep: short enough that a machine that
	// suspended through the expiry notices soon after it resumes, since a
	// sleep does not count the time suspended.
	step = 300 * time.Second
	// retry is how long after a refresh that did not move expiresAt, or left
	// none to read.
	retry = 60 * time.Second
	// stopGrace is how long claude has to end after being asked to, before
	// it is killed: inside systemd's default TimeoutStopSec of 90 seconds,
	// so it is this and not systemd that kills it.
	stopGrace = 75 * time.Second
)

// RunRefresh is the claude-refresh service: it wakes 4 minutes before the
// host's login expires and has Claude Code refresh it, forever. It returns
// nil when ctx ends, and an error only where the script it replaces would
// have exited -- an expiresAt that is not a whole number -- for systemd to
// restart it.
func RunRefresh(ctx context.Context, cfg Config, stderr io.Writer) error {
	r := &refresher{cfg: cfg, stderr: stderr, now: time.Now, claude: runClaude}
	for {
		d, err := r.step(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		if d > 0 {
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
		}
	}
}

type refresher struct {
	cfg    Config
	stderr io.Writer
	now    func() time.Time
	// claude runs the binary with args and gives its exit status as a shell
	// would report it.
	claude func(ctx context.Context, bin string, args []string) int
}

func (r *refresher) say(format string, args ...any) {
	fmt.Fprint(r.stderr, term.Clean("claude-refresh: "+fmt.Sprintf(format, args...))+"\n")
}

// step is one pass of the loop: how long to sleep before the next.
func (r *refresher) step(ctx context.Context) (time.Duration, error) {
	lit, ok := expiresAt(r.cfg.Credentials)
	if !ok {
		r.say("no expiresAt in %s; looking again in 5 minutes", r.cfg.Credentials)
		return step, nil
	}
	exp, err := strconv.ParseInt(lit, 10, 64)
	if err != nil {
		// Shell arithmetic on it failed, and ended the script.
		return 0, fmt.Errorf("expiresAt %s in %s is not a whole number", lit, r.cfg.Credentials)
	}
	// Wake 4 minutes before expiry, in steps short enough to survive suspend.
	if wait := (exp-lead)/1000 - r.now().Unix(); wait > 0 {
		return sleepFor(wait), nil
	}
	if code := r.claude(ctx, r.cfg.Claude, Args); code != 0 {
		r.say("claude exited %d", code)
	}
	// A credentials file gone, unreadable or without an expiresAt after the
	// run is not a refresh either. The script compared "$(expires)" -- empty
	// then -- to the old number, found them different and said refreshed,
	// and the next pass, with nothing to read, only looked again in 5
	// minutes. This says what it found and tries again in a minute.
	after, ok := expiresAt(r.cfg.Credentials)
	if !ok {
		r.say("no expiresAt in %s after the refresh; trying again in a minute", r.cfg.Credentials)
		return retry, nil
	}
	if after == lit {
		r.say("expiresAt did not move; trying again in a minute")
		return retry, nil
	}
	r.say("refreshed")
	return 0, nil
}

// sleepFor is wait seconds, at most step. Compared before it is made a
// Duration, as the script's `wait < 300` was: an expiresAt far enough away
// would overflow a Duration's nanoseconds and come out negative, which would
// be no sleep at all and a loop that spins without a word.
func sleepFor(wait int64) time.Duration {
	if wait >= int64(step/time.Second) {
		return step
	}
	return time.Duration(wait) * time.Second
}

// expiresAt is claudeAiOauth.expiresAt as written, if it is a number.
func expiresAt(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	doc, err := jsondoc.Parse(b)
	if err != nil {
		return "", false
	}
	oauth, err := doc.Field("claudeAiOauth")
	if err != nil {
		return "", false
	}
	v, err := oauth.Field("expiresAt")
	if err != nil || v.Kind != jsondoc.Number {
		return "", false
	}
	return v.Num, true
}

// runClaude runs claude with nothing in and nothing out, and its status as
// the shell gives it: 128 and the signal for one killed, 127 for one not
// found and 126 for one not runnable.
func runClaude(ctx context.Context, bin string, args []string) int {
	cmd := exec.CommandContext(ctx, bin, args...)
	// Claude Code rotates its refresh token during this run, and a stop
	// that killed it between receiving the new tokens and writing
	// .credentials.json would leave the host logged out. So a stop asks it
	// to end, as systemd's SIGTERM to the whole cgroup did for the script,
	// and only kills it once it has had most of the 90 seconds systemd's
	// default TimeoutStopSec would have given it.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	if errors.Is(err, fs.ErrPermission) {
		return 126
	}
	return 127
}
