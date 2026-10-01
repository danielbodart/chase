package claude

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var epoch = time.Unix(1_800_000_000, 0)

func writeCred(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func credAt(ms int64) string {
	return fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"a","refreshToken":"r","expiresAt":%d}}`, ms)
}

// fakeClaude records each run and does what the test says a refresh does.
type fakeClaude struct {
	runs [][]string
	do   func()
	code int
}

func (f *fakeClaude) run(_ context.Context, bin string, args []string) int {
	f.runs = append(f.runs, append([]string{bin}, args...))
	if f.do != nil {
		f.do()
	}
	return f.code
}

func newRefresher(t *testing.T, fc *fakeClaude) (*refresher, *bytes.Buffer, string) {
	cred := filepath.Join(t.TempDir(), ".credentials.json")
	var errb bytes.Buffer
	return &refresher{
		cfg:    Config{Credentials: cred, Claude: "/nix/store/x-claude/bin/claude"},
		stderr: &errb,
		now:    func() time.Time { return epoch },
		claude: fc.run,
	}, &errb, cred
}

func TestNoExpiryLooksAgainInFiveMinutes(t *testing.T) {
	for name, content := range map[string]string{
		"missing":         "",
		"not JSON":        "{",
		"an array":        `[1]`,
		"no oauth":        `{}`,
		"oauth a string":  `{"claudeAiOauth":"x"}`,
		"no expiresAt":    `{"claudeAiOauth":{}}`,
		"a string":        `{"claudeAiOauth":{"expiresAt":"1800000000000"}}`,
		"null":            `{"claudeAiOauth":{"expiresAt":null}}`,
		"false":           `{"claudeAiOauth":{"expiresAt":false}}`,
		"two documents":   credAt(1) + credAt(2),
		"an empty object": `{"claudeAiOauth":{"expiresAt":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			fc := &fakeClaude{}
			r, errb, cred := newRefresher(t, fc)
			if name != "missing" {
				writeCred(t, cred, content)
			}
			d, err := r.step(context.Background())
			if err != nil || d != 300*time.Second {
				t.Fatalf("slept %v, %v", d, err)
			}
			if want := "claude-refresh: no expiresAt in " + cred + "; looking again in 5 minutes\n"; errb.String() != want {
				t.Errorf("said %q", errb.String())
			}
			if len(fc.runs) != 0 {
				t.Error("ran claude")
			}
		})
	}
}

// Shell arithmetic on anything but a whole number ended the script, for
// systemd to restart.
func TestAnExpiryThatIsNotAWholeNumberEnds(t *testing.T) {
	for _, n := range []string{"1.5", "1e12", "1800000000000.0"} {
		fc := &fakeClaude{}
		r, _, cred := newRefresher(t, fc)
		writeCred(t, cred, `{"claudeAiOauth":{"expiresAt":`+n+`}}`)
		if _, err := r.step(context.Background()); err == nil {
			t.Errorf("%s: carried on", n)
		}
		if len(fc.runs) != 0 {
			t.Errorf("%s: ran claude", n)
		}
	}
}

// Wake 4 minutes before expiry, in steps of at most 5 minutes.
func TestSleepsUntilFourMinutesBefore(t *testing.T) {
	now := epoch.Unix() * 1000
	for _, c := range []struct {
		exp  int64
		want time.Duration
	}{
		{now + 240_000 + 100_000, 100 * time.Second},
		{now + 240_000 + 1_000, time.Second},
		{now + 240_000 + 1_999, time.Second}, // whole seconds, rounded down
		{now + 240_000 + 300_000, 300 * time.Second},
		{now + 240_000 + 86_400_000, 300 * time.Second},
		// Far enough that its seconds overflow a Duration's nanoseconds:
		// still 5 minutes, not a negative sleep and a spin.
		{17_000_000_000_000, 300 * time.Second},
		{1 << 62, 300 * time.Second},
	} {
		fc := &fakeClaude{}
		r, errb, cred := newRefresher(t, fc)
		writeCred(t, cred, credAt(c.exp))
		d, err := r.step(context.Background())
		if err != nil || d != c.want {
			t.Errorf("exp now+%dms: slept %v, %v; want %v", c.exp-now, d, err, c.want)
		}
		if len(fc.runs) != 0 || errb.Len() != 0 {
			t.Errorf("exp now+%dms: ran %v, said %q", c.exp-now, fc.runs, errb.String())
		}
	}
}

func TestRefreshesFromFourMinutesBefore(t *testing.T) {
	now := epoch.Unix() * 1000
	for _, exp := range []int64{now + 240_000 + 999, now + 240_000, now, now - 86_400_000, 0} {
		fc := &fakeClaude{}
		r, errb, cred := newRefresher(t, fc)
		writeCred(t, cred, credAt(exp))
		fc.do = func() { writeCred(t, cred, credAt(now+28_800_000)) }
		d, err := r.step(context.Background())
		if err != nil || d != 0 {
			t.Fatalf("slept %v, %v", d, err)
		}
		want := [][]string{{"/nix/store/x-claude/bin/claude",
			"-p", "--model", "haiku", "--no-session-persistence", "Reply with the single word: ok"}}
		if !reflect.DeepEqual(fc.runs, want) {
			t.Errorf("ran %q", fc.runs)
		}
		if errb.String() != "claude-refresh: refreshed\n" {
			t.Errorf("said %q", errb.String())
		}
	}
}

func TestAnExpiryThatDidNotMoveIsTriedAgainInAMinute(t *testing.T) {
	fc := &fakeClaude{}
	r, errb, cred := newRefresher(t, fc)
	writeCred(t, cred, credAt(1))
	// Rewritten, even reformatted, but the same number.
	fc.do = func() { writeCred(t, cred, `{"claudeAiOauth": {"expiresAt": 1, "accessToken": "b"}}`) }
	d, err := r.step(context.Background())
	if err != nil || d != time.Minute {
		t.Fatalf("slept %v, %v", d, err)
	}
	if errb.String() != "claude-refresh: expiresAt did not move; trying again in a minute\n" {
		t.Errorf("said %q", errb.String())
	}
}

func TestAClaudeThatFailedIsSaidAndStillChecked(t *testing.T) {
	fc := &fakeClaude{code: 3}
	r, errb, cred := newRefresher(t, fc)
	writeCred(t, cred, credAt(1))
	d, _ := r.step(context.Background())
	if d != time.Minute {
		t.Errorf("slept %v", d)
	}
	want := "claude-refresh: claude exited 3\nclaude-refresh: expiresAt did not move; trying again in a minute\n"
	if errb.String() != want {
		t.Errorf("said %q", errb.String())
	}

	// And one that failed but moved it anyway is refreshed.
	fc = &fakeClaude{code: 1}
	r, errb, cred = newRefresher(t, fc)
	writeCred(t, cred, credAt(1))
	fc.do = func() { writeCred(t, cred, credAt(2)) }
	if d, _ := r.step(context.Background()); d != 0 {
		t.Errorf("slept %v", d)
	}
	if want := "claude-refresh: claude exited 1\nclaude-refresh: refreshed\n"; errb.String() != want {
		t.Errorf("said %q", errb.String())
	}
}

// The script compared "$(expires)" to what it had, and a login gone after
// the run -- an empty string -- was not the same number, so it counted as
// refreshed. It is not: with no expiresAt to read, nothing moved.
func TestALoginWithNoExpiryAfterTheRunIsTriedAgainInAMinute(t *testing.T) {
	for name, after := range map[string]func(t *testing.T, cred string){
		"gone":         func(_ *testing.T, cred string) { os.Remove(cred) },
		"unreadable":   func(_ *testing.T, cred string) { os.Remove(cred); os.Mkdir(cred, 0o700) },
		"not JSON":     func(t *testing.T, cred string) { writeCred(t, cred, "{") },
		"no expiresAt": func(t *testing.T, cred string) { writeCred(t, cred, `{"claudeAiOauth":{"accessToken":"b"}}`) },
		"a string":     func(t *testing.T, cred string) { writeCred(t, cred, `{"claudeAiOauth":{"expiresAt":"2"}}`) },
	} {
		t.Run(name, func(t *testing.T) {
			fc := &fakeClaude{}
			r, errb, cred := newRefresher(t, fc)
			writeCred(t, cred, credAt(1))
			fc.do = func() { after(t, cred) }
			d, err := r.step(context.Background())
			if err != nil || d != time.Minute {
				t.Errorf("slept %v, %v", d, err)
			}
			if want := "claude-refresh: no expiresAt in " + cred + " after the refresh; trying again in a minute\n"; errb.String() != want {
				t.Errorf("said %q", errb.String())
			}
		})
	}
}

func TestWhatItSaysHasNoControlBytes(t *testing.T) {
	fc := &fakeClaude{}
	r, errb, _ := newRefresher(t, fc)
	r.cfg.Credentials = filepath.Join(t.TempDir(), "\x1b]0;title\a")
	r.step(context.Background())
	if strings.ContainsAny(errb.String(), "\x1b\a") {
		t.Errorf("said %q", errb.String())
	}
}

func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "claude")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// The status is what the shell's `$?` was.
func TestRunClaudeGivesTheShellsStatus(t *testing.T) {
	notExec := filepath.Join(t.TempDir(), "claude")
	os.WriteFile(notExec, []byte("#!/bin/sh\n"), 0o600)
	for _, c := range []struct {
		name string
		bin  string
		want int
	}{
		{"success", script(t, "exit 0"), 0},
		{"failure", script(t, "exit 7"), 7},
		{"killed", script(t, "kill -9 $$"), 137},
		{"missing", filepath.Join(t.TempDir(), "nothing"), 127},
		{"not executable", notExec, 126},
	} {
		if got := runClaude(context.Background(), c.bin, Args); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// A stop asks claude to end, with SIGTERM, and waits for it: a claude that
// is writing its rotated login finishes the write.
func TestAStopLetsClaudeFinish(t *testing.T) {
	dir := t.TempDir()
	bin := script(t, `trap 'echo written > `+dir+`/cred; exit 3' TERM; touch `+dir+`/started; while :; do sleep 0.01; done`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	go func() { done <- runClaude(ctx, bin, Args) }()
	for {
		if _, err := os.Stat(dir + "/started"); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if got := <-done; got != 3 {
		t.Errorf("exited %d", got)
	}
	if b, _ := os.ReadFile(dir + "/cred"); string(b) != "written\n" {
		t.Errorf("claude did not finish: %q", b)
	}
}

// Killed only once systemd would not have waited any longer itself.
func TestClaudeIsKilledOnlyInsideSystemdsStopTimeout(t *testing.T) {
	if stopGrace <= 0 || stopGrace >= 90*time.Second {
		t.Errorf("grace %v", stopGrace)
	}
}

// Its arguments are the prompt's, it reads nothing, and what it prints goes
// nowhere.
func TestRunClaudeHasNothingInAndNothingOut(t *testing.T) {
	dir := t.TempDir()
	bin := script(t, `printf '%s\n' "$@" > `+dir+`/args; cat > `+dir+`/stdin; echo out; echo err >&2`)
	if got := runClaude(context.Background(), bin, Args); got != 0 {
		t.Fatalf("exited %d", got)
	}
	if b, _ := os.ReadFile(dir + "/args"); string(b) != "-p\n--model\nhaiku\n--no-session-persistence\nReply with the single word: ok\n" {
		t.Errorf("args %q", b)
	}
	if b, _ := os.ReadFile(dir + "/stdin"); len(b) != 0 {
		t.Errorf("stdin %q", b)
	}
}

func TestRunRefreshEndsQuietlyWithItsContext(t *testing.T) {
	cred := filepath.Join(t.TempDir(), ".credentials.json")
	writeCred(t, cred, credAt(time.Now().Add(time.Hour).UnixMilli()))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var errb bytes.Buffer
	if err := RunRefresh(ctx, Config{Credentials: cred, Claude: "/nonexistent"}, &errb); err != nil {
		t.Errorf("ended with %v", err)
	}
	if errb.Len() != 0 {
		t.Errorf("said %q", errb.String())
	}
}

func TestRunRefreshEndsOnAnExpiryItCannotReckonWith(t *testing.T) {
	cred := filepath.Join(t.TempDir(), ".credentials.json")
	writeCred(t, cred, `{"claudeAiOauth":{"expiresAt":1.5}}`)
	if err := RunRefresh(context.Background(), Config{Credentials: cred}, &bytes.Buffer{}); err == nil {
		t.Error("carried on")
	}
}

func TestLoadConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, []byte(`{"credentials":"/h/.claude/.credentials.json","claude":"/b/claude","claudeJSON":"/h/.claude.json"}`), 0o600)
	c, err := LoadConfig(p)
	want := Config{Credentials: "/h/.claude/.credentials.json", Claude: "/b/claude", ClaudeJSON: "/h/.claude.json"}
	if err != nil || !reflect.DeepEqual(c, want) {
		t.Errorf("%+v, %v", c, err)
	}
	os.WriteFile(p, []byte(`{`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Error("loaded a broken config")
	}
}
