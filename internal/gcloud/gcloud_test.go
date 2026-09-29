package gcloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/gcloud/gcloudtest"
)

const sa = "renew@demo.iam.gserviceaccount.com"

// The ported gcloud-renew check: a fake token endpoint that verifies each
// grant against the key's public half, and everything the renewer said,
// looked through at the end for anything secret.
type fixture struct {
	t          *testing.T
	google     *gcloudtest.Google
	cfg        Config
	key, other *rsa.PrivateKey
	said       *syncBuffer
}

// syncBuffer is what the renewer said, from however many goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

var (
	keysOnce   sync.Once
	saKey, alt *rsa.PrivateKey
)

func keys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	keysOnce.Do(func() {
		var err error
		if saKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			t.Fatal(err)
		}
		if alt, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			t.Fatal(err)
		}
	})
	return saKey, alt
}

func newFixture(t *testing.T) *fixture {
	k, o := keys(t)
	f := &fixture{t: t, key: k, other: o, said: &syncBuffer{}}
	f.google = gcloudtest.New(&k.PublicKey, sa)
	t.Cleanup(f.google.Close)
	f.cfg = Config{TokenURL: f.google.TokenURL()}
	t.Cleanup(f.noSecretWasSaid)
	return f
}

// session makes a run directory whose secret is key's, for email.
func (f *fixture) session(key *rsa.PrivateKey, email string) string {
	run := filepath.Join(f.t.TempDir(), "run")
	if err := os.MkdirAll(filepath.Join(run, "secrets"), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "secrets", "gcloud"), gcloudtest.Key(key, email, "demo"), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return run
}

func (f *fixture) mint(want Outcome, run, account string) {
	f.t.Helper()
	if got := Mint(context.Background(), f.cfg, run, account, f.said); got != want {
		lines := strings.Split(strings.TrimSpace(f.said.String()), "\n")
		f.t.Fatalf("mint %s exited %d, not %d: %s", run, got, want, strings.Join(lines[max(0, len(lines)-3):], "\n"))
	}
}

func (f *fixture) last() gcloudtest.Request {
	l := f.google.Log()
	if len(l) == 0 {
		f.t.Fatal("the fake was sent nothing")
	}
	return l[len(l)-1]
}

// Nothing the renewer said holds a line of either private key, a token the
// fake granted, or a signature it was sent.
func (f *fixture) noSecretWasSaid() {
	var secrets []string
	for _, k := range []*rsa.PrivateKey{f.key, f.other} {
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		for _, line := range strings.Split(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "\n") {
			if line != "" && !strings.Contains(line, "-----") {
				secrets = append(secrets, line)
			}
		}
	}
	for _, r := range f.google.Log() {
		if r.Token != "" {
			secrets = append(secrets, r.Token)
		}
		if parts := strings.Split(r.Assertion, "."); len(parts) == 3 && parts[2] != "" {
			secrets = append(secrets, parts[2])
		}
	}
	if len(secrets) <= 20 {
		f.t.Errorf("nothing to look for: %d secrets", len(secrets))
	}
	said := f.said.String()
	for _, s := range secrets {
		if strings.Contains(said, s) {
			f.t.Errorf("a secret was printed: %.80s", s)
		}
	}
}

func TestAMintWritesTheTokenAndItsExpiryFromWhenItWasSent(t *testing.T) {
	f := newFixture(t)
	run := f.session(f.key, sa)
	before := time.Now().UnixMilli()
	f.mint(Minted, run, sa)
	after := time.Now().UnixMilli()

	p := filepath.Join(run, "gcloud-token.json")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the token file is %v, not 0600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	var tok map[string]any
	if err := json.Unmarshal(b, &tok); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range tok {
		got = append(got, k)
	}
	slices.Sort(got)
	exp, _ := tok["expiry"].(float64)
	if !slices.Equal(got, []string{"access_token", "expiry"}) || tok["access_token"] != f.last().Token ||
		int64(exp) < before+3599000 || int64(exp) > after+3599000 {
		t.Errorf("the token file is wrong: %s, sent %d..%d", b, before, after)
	}
	// As jq -c wrote it: one line, compact, integral.
	if want := `{"access_token":"` + f.last().Token + `","expiry":`; !strings.HasPrefix(string(b), want) || !strings.HasSuffix(string(b), "}\n") || strings.Contains(string(b), "e+") {
		t.Errorf("the token file is not as jq wrote it: %q", b)
	}

	// Minted again, with no account named, it is replaced by a rename, and
	// nothing is left beside it.
	f.mint(Minted, run, "")
	fi2, _ := os.Stat(p)
	if fi.Sys().(*syscall.Stat_t).Ino == fi2.Sys().(*syscall.Stat_t).Ino {
		t.Error("the token was not replaced by rename")
	}
	entries, _ := os.ReadDir(run)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"gcloud-token.json", "secrets"}) {
		t.Errorf("the run directory holds more: %v", names)
	}
}

func TestAFailedMintLeavesTheTokenAlone(t *testing.T) {
	f := newFixture(t)
	run := f.session(f.key, sa)
	f.mint(Minted, run, sa)
	kept, _ := os.ReadFile(filepath.Join(run, "gcloud-token.json"))
	n := f.google.Requests()

	// A key of another account is never sent.
	f.mint(BadKey, run, "other@demo.iam.gserviceaccount.com")
	if f.google.Requests() != n {
		t.Error("a key of another account was sent")
	}
	if !strings.Contains(f.said.String(), "the key is "+sa+"'s, not other@demo.iam.gserviceaccount.com's") {
		t.Errorf("the mismatch was not said: %s", f.said)
	}
	for _, code := range []int{400, 401, 403} {
		f.google.Answer(code)
		f.mint(Refused, run, "")
	}
	if !strings.Contains(f.said.String(), "Google refused "+sa+"'s grant (403): invalid_grant: fake says no (403)") {
		t.Errorf("Google's refusal was not said: %s", f.said)
	}
	f.google.Answer(500)
	f.mint(Transient, run, "")
	if now, _ := os.ReadFile(filepath.Join(run, "gcloud-token.json")); !bytes.Equal(now, kept) {
		t.Error("a failed mint touched the token")
	}
}

// The fake is a real check of the grant: a JWT another key signed, or from
// another issuer, is refused as Google would.
func TestTheFakeRefusesWhatGoogleWould(t *testing.T) {
	f := newFixture(t)
	f.mint(Refused, f.session(f.other, sa), "")
	if w := f.last().Wrong; w != "signature" {
		t.Errorf("the fake took a JWT another key signed: %q", w)
	}
	f.mint(Refused, f.session(f.key, "stranger@demo.iam.gserviceaccount.com"), "")
	if w := f.last().Wrong; w != "iss" {
		t.Errorf("the fake took a JWT from another issuer: %q", w)
	}
}

func TestWhatIsNotAKeyIsRefusedBeforeAnythingIsSent(t *testing.T) {
	f := newFixture(t)
	// Every line needs something to look for; this check sends nothing.
	f.mint(Minted, f.session(f.key, sa), "")
	n := f.google.Requests()
	block := func(typ string, der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
	}
	pkcs1 := block("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(f.key))
	for name, c := range map[string]struct {
		secret string // "" is none at all
		said   string
	}{
		"none":               {"", "no key at"},
		"empty object":       {`{}`, "is not a service-account key"},
		"not json":           {`not json`, "is not a service-account key"},
		"an array":           {`[]`, "is not a service-account key"},
		"null":               {`null`, "is not a service-account key"},
		"another type":       {`{"type": "authorized_user", "private_key": "x", "client_email": "a"}`, "is not a service-account key"},
		"no private_key":     {`{"type": "service_account", "client_email": "a"}`, "is not a service-account key"},
		"a numeric email":    {`{"type": "service_account", "private_key": "x", "client_email": 1}`, "is not a service-account key"},
		"a key that is none": {`{"type": "service_account", "private_key": "x", "client_email": "a"}`, "does not sign"},
	} {
		run := filepath.Join(t.TempDir(), "run")
		os.MkdirAll(filepath.Join(run, "secrets"), 0o700)
		if c.secret != "" {
			os.WriteFile(filepath.Join(run, "secrets", "gcloud"), []byte(c.secret), 0o600)
		}
		before := f.said.String()
		f.mint(BadKey, run, "")
		if said := strings.TrimPrefix(f.said.String(), before); !strings.Contains(said, c.said) {
			t.Errorf("%s: expected %q in %q", name, c.said, said)
		}
	}
	// A PKCS#1 key, as openssl also reads, signs.
	run := f.session(f.key, sa)
	k, _ := json.Marshal(map[string]string{"type": "service_account", "private_key": pkcs1, "client_email": sa})
	os.WriteFile(filepath.Join(run, "secrets", "gcloud"), k, 0o600)
	f.mint(Minted, run, sa)
	if f.google.Requests() != n+1 {
		t.Errorf("sent %d requests for keys that were not", f.google.Requests()-n-1)
	}
}

func TestAnUnreachableEndpointIsTransient(t *testing.T) {
	f := newFixture(t)
	f.mint(Minted, f.session(f.key, sa), "")
	f.cfg.TokenURL = "http://127.0.0.1:1/token"
	f.mint(Transient, f.session(f.key, sa), "")
	if !strings.Contains(f.said.String(), "http://127.0.0.1:1/token did not answer") {
		t.Errorf("it was not said: %s", f.said)
	}
}

// A 3xx is an answer, and not Google's: it is not followed.
func TestARedirectIsNotFollowed(t *testing.T) {
	f := newFixture(t)
	f.mint(Minted, f.session(f.key, sa), "")
	f.google.Answer(302)
	f.mint(Transient, f.session(f.key, sa), "")
	if !strings.Contains(f.said.String(), "answered 302") {
		t.Errorf("it was not said: %s", f.said)
	}
}

func TestA200WithoutATokenIsTransient(t *testing.T) {
	for name, body := range map[string]string{
		"not json":      `x`,
		"no token":      `{"expires_in": 3599}`,
		"empty token":   `{"access_token": "", "expires_in": 3599}`,
		"no expiry":     `{"access_token": "t"}`,
		"string expiry": `{"access_token": "t", "expires_in": "3599"}`,
		"zero expiry":   `{"access_token": "t", "expires_in": 0}`,
	} {
		if _, _, ok := granted([]byte(body), 0); ok {
			t.Errorf("%s: granted", name)
		}
	}
	if tok, exp, ok := granted([]byte(`{"access_token": "t", "expires_in": 1.2345}`), 1000); !ok || tok != "t" || exp != 2234 {
		t.Errorf("a fractional expiry is %v %v %v, not t 2234", tok, exp, ok)
	}
}

func TestGooglesRefusalIsSaidAsJqSaidIt(t *testing.T) {
	for body, want := range map[string]string{
		`{"error": "invalid_grant", "error_description": "no"}`: "invalid_grant: no",
		`{"error": "invalid_grant"}`:                            "invalid_grant: ",
		`{}`:                                                    "?: ",
		`null`:                                                  "?: ",
		`"x"`:                                                   "?",
		`<html>`:                                                "?",
		`{"error": {"code": 400}}`:                              `{"code":400}: `,
		`{"error": 7, "error_description": false}`: "7: ",
		// jq given no input says nothing, and succeeds.
		``:       "",
		" \n\t ": "",
	} {
		if got := refusal([]byte(body)); got != want {
			t.Errorf("%s: %q, want %q", body, got, want)
		}
	}
}

// fakeClock moves only when the loop sleeps, and calls tick after each nap
// step so a check can act at a moment of its choosing.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	slept time.Duration
	tick  func(slept time.Duration)
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.slept += d
	s := c.slept
	c.mu.Unlock()
	if c.tick != nil {
		c.tick(s)
	}
}

// runLoop runs the loop and fails if it outlives its run directory.
func runLoop(t *testing.T, f *fixture, run string, clock Clock) {
	done := make(chan struct{})
	go func() {
		Loop(context.Background(), f.cfg, run, "", f.said, clock)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the loop outlived its run directory")
	}
}

// Renewed with ten minutes left, and not before; and gone once its run
// directory is, within one step of a nap.
func TestTheLoopRenewsWithTenMinutesLeft(t *testing.T) {
	f := newFixture(t)
	run := f.session(f.key, sa)
	start := time.Now()
	old, _ := json.Marshal(map[string]any{"access_token": "old", "expiry": start.UnixMilli() + 605000})
	os.WriteFile(filepath.Join(run, "gcloud-token.json"), old, 0o600)
	n := f.google.Requests()
	var sleptBefore time.Duration = -1
	var stepsAfter int
	clock := &fakeClock{now: start}
	clock.tick = func(slept time.Duration) {
		if f.google.Requests() == n {
			sleptBefore = slept
			return
		}
		stepsAfter++
		if stepsAfter == 1 {
			os.RemoveAll(run)
		}
	}
	runLoop(t, f, run, clock)
	if f.google.Requests() != n+1 {
		t.Fatalf("the loop sent %d requests, not 1", f.google.Requests()-n)
	}
	if sleptBefore < 4*time.Second || sleptBefore > 5*time.Second {
		t.Errorf("the loop renewed after %v, not with ten minutes left", sleptBefore)
	}
	if stepsAfter != 1 {
		t.Errorf("the loop napped %d steps once its run directory was gone", stepsAfter)
	}
}

func TestTheLoopWritesItsToken(t *testing.T) {
	f := newFixture(t)
	run := f.session(f.key, sa)
	os.WriteFile(filepath.Join(run, "gcloud-token.json"), []byte(`{"access_token": "old", "expiry": 1}`), 0o600)
	var tok []byte
	clock := &fakeClock{now: time.Now()}
	clock.tick = func(time.Duration) {
		tok, _ = os.ReadFile(filepath.Join(run, "gcloud-token.json"))
		os.RemoveAll(run)
	}
	runLoop(t, f, run, clock)
	var got struct {
		AccessToken string `json:"access_token"`
	}
	json.Unmarshal(tok, &got)
	if got.AccessToken == "old" || got.AccessToken != f.last().Token {
		t.Errorf("the loop did not write its token: %s", tok)
	}
}

// A failure is tried again a minute later, and said.
func TestTheLoopTriesAgainAMinuteLater(t *testing.T) {
	f := newFixture(t)
	run := f.session(f.key, sa)
	f.google.Answer(500)
	var at []time.Duration
	clock := &fakeClock{now: time.Now()}
	n := 0
	clock.tick = func(slept time.Duration) {
		if f.google.Requests() > n {
			n = f.google.Requests()
			at = append(at, slept)
		}
		if _, err := os.Stat(filepath.Join(run, "gcloud-token.json")); err == nil {
			os.RemoveAll(run)
		}
	}
	runLoop(t, f, run, clock)
	l := f.google.Log()
	if len(l) != 2 || l[0].Code != 500 || l[1].Code != 200 {
		t.Fatalf("the loop did not try again: %+v", l)
	}
	// The first request was before any nap; the second after sixty seconds
	// of them, and not sooner.
	if len(at) != 2 || at[0] != 10*time.Second || at[1] != 70*time.Second {
		t.Errorf("the loop tried again after %v", at)
	}
	if !strings.Contains(f.said.String(), "trying again in a minute") {
		t.Errorf("the retry was not said: %s", f.said)
	}
}

// With no run directory, the loop does nothing and ends.
func TestTheLoopEndsWithoutItsRunDirectory(t *testing.T) {
	f := newFixture(t)
	f.mint(Minted, f.session(f.key, sa), "")
	n := f.google.Requests()
	runLoop(t, f, filepath.Join(t.TempDir(), "gone"), &fakeClock{now: time.Now()})
	if f.google.Requests() != n {
		t.Error("the loop minted for a session that is gone")
	}
}

// The loop's waits, from what the token file says: a long way off, a nap of
// five minutes at most, looked at every ten seconds; a token with no expiry
// is minted now.
func TestTheLoopNapsInStepsOfTenSeconds(t *testing.T) {
	f := newFixture(t)
	run := f.session(f.key, sa)
	start := time.Now()
	far, _ := json.Marshal(map[string]any{"access_token": "far", "expiry": start.UnixMilli() + 3600000})
	os.WriteFile(filepath.Join(run, "gcloud-token.json"), far, 0o600)
	var steps int
	clock := &fakeClock{now: start}
	clock.tick = func(slept time.Duration) {
		steps++
		if slept >= 600*time.Second {
			os.RemoveAll(run)
		}
	}
	runLoop(t, f, run, clock)
	if steps != 60 || f.google.Requests() != 0 {
		t.Errorf("%d steps and %d requests for ten minutes of a token with an hour left", steps, f.google.Requests())
	}
	for body, want := range map[string]int64{
		`{"expiry": 5}`:     5,
		`{"expiry": "5"}`:   0,
		`{}`:                0,
		`nope`:              0,
		`{"expiry": 2.9e3}`: 2900,
	} {
		os.MkdirAll(run, 0o700)
		os.WriteFile(filepath.Join(run, "gcloud-token.json"), []byte(body), 0o600)
		if got := expiry(run); got != want {
			t.Errorf("%s: expiry %d, want %d", body, got, want)
		}
	}
}

// A token that cannot be written is transient, and why is said, as mktemp
// said it; the token is not.
func TestAnUnwritableRunIsSaid(t *testing.T) {
	f := newFixture(t)
	run := f.session(f.key, sa)
	if err := os.Chmod(run, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(run, 0o700) })
	if os.WriteFile(filepath.Join(run, "probe"), nil, 0o600) == nil {
		t.Skip("the run directory is writable anyway (root?)")
	}
	f.mint(Transient, run, sa)
	if said := f.said.String(); !strings.Contains(said, run+"/.gcloud-token.json") || !strings.Contains(said, "permission denied") {
		t.Errorf("the failed write was not said: %s", said)
	}
}

// RUN is joined as the script's strings were: an empty one is the root's,
// never the working directory's.
func TestAnEmptyRunIsTheRoots(t *testing.T) {
	f := newFixture(t)
	f.mint(Minted, f.session(f.key, sa), "")
	t.Chdir(f.session(f.key, sa))
	f.mint(BadKey, "", "")
	if !strings.Contains(f.said.String(), "chase-gcloud-renew: no key at /secrets/gcloud\n") {
		t.Errorf("an empty RUN was not the root's: %s", f.said)
	}
	if _, err := os.Stat("gcloud-token.json"); err == nil {
		t.Error("a token was written in the working directory")
	}
}

// A loop given a service account checks it on every mint, as the script's
// loop called the same mint: another account's key is never sent.
func TestTheLoopChecksTheAccountItIsGiven(t *testing.T) {
	f := newFixture(t)
	f.mint(Minted, f.session(f.key, sa), "")
	n := f.google.Requests()
	run := f.session(f.key, sa)
	clock := &fakeClock{now: time.Now()}
	clock.tick = func(slept time.Duration) {
		if slept >= 120*time.Second {
			os.RemoveAll(run)
		}
	}
	done := make(chan struct{})
	go func() {
		Loop(context.Background(), f.cfg, run, "other@demo.iam.gserviceaccount.com", f.said, clock)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the loop outlived its run directory")
	}
	if f.google.Requests() != n {
		t.Error("the loop sent another account's key")
	}
	if c := strings.Count(f.said.String(), "the key is "+sa+"'s, not other@demo.iam.gserviceaccount.com's\nchase-gcloud-renew: trying again in a minute\n"); c != 2 {
		t.Errorf("the loop refused %d times, not twice: %s", c, f.said)
	}
}

// Stopped mid-nap -- systemctl stop's SIGTERM -- the loop ends there, and
// mints nothing more.
func TestTheLoopEndsWhenItIsStopped(t *testing.T) {
	f := newFixture(t)
	f.mint(Minted, f.session(f.key, sa), "")
	run := f.session(f.key, sa)
	start := time.Now()
	soon, _ := json.Marshal(map[string]any{"access_token": "soon", "expiry": start.UnixMilli() + 630000})
	os.WriteFile(filepath.Join(run, "gcloud-token.json"), soon, 0o600)
	n := f.google.Requests()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	steps := 0
	clock := &fakeClock{now: start}
	clock.tick = func(time.Duration) {
		steps++
		cancel()
	}
	Loop(ctx, f.cfg, run, "", f.said, clock)
	if steps != 1 || f.google.Requests() != n {
		t.Errorf("a stopped loop napped %d steps and sent %d requests", steps, f.google.Requests()-n)
	}
}

// `loop RUN` as the unit runs it: to its end, with exit 0, once RUN is gone
// or it is stopped; each of its mints checks $CHASE_GCLOUD_SA; and all of
// it under umask 077.
func TestRunLoopIsTheScriptsLoop(t *testing.T) {
	f := newFixture(t)
	f.mint(Minted, f.session(f.key, sa), "")
	n := f.google.Requests()
	env := func(k string) string {
		if k == "CHASE_GCLOUD_SA" {
			return "other@demo.iam.gserviceaccount.com"
		}
		return ""
	}
	prev := unix.Umask(0o022)
	t.Cleanup(func() { unix.Umask(prev) })

	var b syncBuffer
	if got := Run(context.Background(), []string{"loop", filepath.Join(t.TempDir(), "gone")}, env, &b, f.cfg); got != 0 {
		t.Errorf("a loop without its run directory exited %d", got)
	}
	if got := unix.Umask(0o022); got != 0o077 {
		t.Errorf("the umask was %#o, not 077", got)
	}
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	if got := Run(stopped, []string{"loop", f.session(f.key, sa)}, env, &b, f.cfg); got != 0 {
		t.Errorf("a stopped loop exited %d", got)
	}

	// With the real clock: the first mint refuses the other account's key,
	// and the loop is stopped in the minute's wait that follows.
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	exited := make(chan int)
	go func() { exited <- Run(ctx, []string{"loop", f.session(f.key, sa)}, env, &b, f.cfg) }()
	deadline := time.After(30 * time.Second)
	for !strings.Contains(b.String(), "trying again in a minute") {
		select {
		case <-deadline:
			t.Fatalf("the loop said nothing: %s", b.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	stop()
	select {
	case got := <-exited:
		if got != 0 {
			t.Errorf("the stopped loop exited %d", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the loop outlived its stop")
	}
	if f.google.Requests() != n || !strings.Contains(b.String(), "not other@demo.iam.gserviceaccount.com's") {
		t.Errorf("the loop did not check $CHASE_GCLOUD_SA: %d requests, said %s", f.google.Requests()-n, b.String())
	}
	f.said.Write([]byte(b.String()))
}

func TestRunIsTheScriptsCommandLine(t *testing.T) {
	f := newFixture(t)
	run := f.session(f.key, sa)
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "CHASE_GCLOUD_SA" {
				return v
			}
			return ""
		}
	}
	ctx := context.Background()
	for _, c := range []struct {
		args []string
		sa   string
		want int
		said string
	}{
		{nil, "", Usage, "chase-gcloud-renew: usage: chase-gcloud-renew mint|loop RUN\n"},
		{[]string{"renew", run}, "", Usage, "chase-gcloud-renew: usage: chase-gcloud-renew mint|loop RUN\n"},
		{[]string{"mint"}, "", Usage, "chase-gcloud-renew: usage: mint RUN\n"},
		{[]string{"loop", run, "x"}, "", Usage, "chase-gcloud-renew: usage: loop RUN\n"},
		{[]string{"mint", run}, "other@demo.iam.gserviceaccount.com", int(BadKey), "not other@demo"},
		{[]string{"mint", run}, sa, int(Minted), "minted for " + sa},
	} {
		var b bytes.Buffer
		if got := Run(ctx, c.args, env(c.sa), &b, f.cfg); got != c.want || !strings.Contains(b.String(), c.said) {
			t.Errorf("%q: exited %d saying %q, want %d saying %q", c.args, got, b.String(), c.want, c.said)
		}
		f.said.Write(b.Bytes())
	}
}
