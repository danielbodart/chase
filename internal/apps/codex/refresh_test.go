package codex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var epoch = time.Date(2027, 1, 2, 3, 4, 5, 600_000_000, time.UTC)

// jwt is an access token whose claims are claims, signed by nobody.
func jwt(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(claims)) + ".sig"
}

func authWith(access, refresh string) string {
	return `{
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "aWQ.Y2xhaW1z.c2ln",
    "access_token": "` + access + `",
    "refresh_token": "` + refresh + `",
    "account_id": "acct-1"
  },
  "last_refresh": "2026-12-01T00:00:00.000Z",
  "extra": {"kept": true}
}
`
}

// tokenServer is the token endpoint, holding each refresh token good for
// one exchange, as the real one does: a second use of one is refused.
type tokenServer struct {
	mu       sync.Mutex
	valid    map[string]bool
	next     int
	requests []request
	answer   func(w http.ResponseWriter, r *http.Request, rt string) bool
}

type request struct {
	method, path, contentType, accept string
	body                              string
}

func newTokenServer(t *testing.T, first string) (*tokenServer, *httptest.Server) {
	ts := &tokenServer{valid: map[string]bool{first: true}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		ts.requests = append(ts.requests, request{r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Accept"), string(b)})
		var req struct {
			ClientID     string `json:"client_id"`
			GrantType    string `json:"grant_type"`
			RefreshToken string `json:"refresh_token"`
		}
		json.Unmarshal(b, &req)
		if ts.answer != nil && ts.answer(w, r, req.RefreshToken) {
			return
		}
		if req.ClientID != ClientID || req.GrantType != "refresh_token" || !ts.valid[req.RefreshToken] {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		delete(ts.valid, req.RefreshToken)
		ts.next++
		rt := fmt.Sprintf("refresh-%d", ts.next)
		ts.valid[rt] = true
		fmt.Fprintf(w, `{"id_token":"bmV3.Y2xhaW1zLSVk.c2ln","access_token":%q,"refresh_token":%q,"expires_in":864000}`,
			jwt(fmt.Sprintf(`{"exp":%d}`, epoch.Unix()+10*86400)), rt)
	}))
	t.Cleanup(srv.Close)
	return ts, srv
}

func newRefresher(t *testing.T, endpoint string) (*refresher, *bytes.Buffer, Config) {
	c := config(t)
	c.TokenEndpoint = endpoint
	var errb bytes.Buffer
	return &refresher{cfg: c, stderr: &errb, now: func() time.Time { return epoch }, client: newClient()}, &errb, c
}

// due is an auth.json whose access token expires within the day.
func due(refresh string) string {
	return authWith(jwt(fmt.Sprintf(`{"exp":%d,"sub":"x"}`, epoch.Unix()+3600)), refresh)
}

func TestNoAccessTokenLooksAgainInFiveMinutes(t *testing.T) {
	for name, content := range map[string]string{
		"missing":         "",
		"not JSON":        "{",
		"an array":        "[]",
		"no tokens":       `{}`,
		"tokens a string": `{"tokens":"x"}`,
		"no access token": `{"tokens":{}}`,
		"a number":        `{"tokens":{"access_token":1}}`,
		"one part":        `{"tokens":{"access_token":"abc"}}`,
		"not base64":      `{"tokens":{"access_token":"a.!!!.c"}}`,
		"claims not JSON": `{"tokens":{"access_token":"a.` + base64.RawURLEncoding.EncodeToString([]byte("nope")) + `.c"}}`,
		"claims an array": `{"tokens":{"access_token":"` + jwt(`[1]`) + `"}}`,
		"no exp":          `{"tokens":{"access_token":"` + jwt(`{}`) + `"}}`,
		"exp a string":    `{"tokens":{"access_token":"` + jwt(`{"exp":"1"}`) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			r, errb, c := newRefresher(t, "http://127.0.0.1:1")
			if content != "" {
				writeAuth(t, c, content)
			}
			d, err := r.step(context.Background())
			if err != nil || d != 300*time.Second {
				t.Fatalf("slept %v, %v", d, err)
			}
			if want := "codex-refresh: no access token in " + c.Auth + "; looking again in 5 minutes\n"; errb.String() != want {
				t.Errorf("said %q", errb.String())
			}
		})
	}
}

// Padded or not, url-safe characters or not, as the script decoded it.
func TestReadsExpFromTheAccessToken(t *testing.T) {
	for _, claims := range []string{
		`{"exp":1800000000}`,
		`{"exp":1800000000,"a":"??>>"}`, // + and / in standard base64
		`{"exp":1800000000,"b":"x"}`,
		`{"exp":1800000000,"cc":"xy"}`,
	} {
		c := config(t)
		for _, token := range []string{
			jwt(claims),
			"h." + base64.URLEncoding.EncodeToString([]byte(claims)) + ".s",
		} {
			writeAuth(t, c, `{"tokens":{"access_token":"`+token+`"}}`)
			if exp, ok := accessExpiry(c.Auth); !ok || exp != "1800000000" {
				t.Errorf("%s as %s: %q, %v", claims, token, exp, ok)
			}
		}
	}
}

// Shell arithmetic on anything but a whole number ended the script.
func TestAnExpThatIsNotAWholeNumberEnds(t *testing.T) {
	ts, srv := newTokenServer(t, "r0")
	for _, exp := range []string{"1.5", "1e9", "1800000000.0"} {
		r, _, c := newRefresher(t, srv.URL)
		writeAuth(t, c, authWith(jwt(`{"exp":`+exp+`}`), "r0"))
		if _, err := r.step(context.Background()); err == nil {
			t.Errorf("%s: carried on", exp)
		}
	}
	if len(ts.requests) != 0 {
		t.Errorf("exchanged: %v", ts.requests)
	}
}

// A day early, in steps of at most 5 minutes.
func TestSleepsUntilADayBefore(t *testing.T) {
	ts, srv := newTokenServer(t, "r0")
	for _, c := range []struct {
		exp  int64
		want time.Duration
	}{
		{epoch.Unix() + 86400 + 42, 42 * time.Second},
		{epoch.Unix() + 86400 + 1, time.Second},
		{epoch.Unix() + 86400 + 300, 300 * time.Second},
		{epoch.Unix() + 86400 + 301, 300 * time.Second},
		{epoch.Unix() + 30*86400, 300 * time.Second},
		// Far enough that its seconds overflow a Duration's nanoseconds:
		// still 5 minutes, not a negative sleep and a spin.
		{16_800_000_000, 300 * time.Second},
		{1 << 62, 300 * time.Second},
	} {
		r, errb, cfg := newRefresher(t, srv.URL)
		writeAuth(t, cfg, authWith(jwt(fmt.Sprintf(`{"exp":%d}`, c.exp)), "r0"))
		d, err := r.step(context.Background())
		if err != nil || d != c.want || errb.Len() != 0 {
			t.Errorf("exp now+%d: slept %v, %v, said %q", c.exp-epoch.Unix(), d, err, errb.String())
		}
	}
	if len(ts.requests) != 0 {
		t.Errorf("exchanged early: %v", ts.requests)
	}
}

func TestExchangesTheRefreshTokenADayBefore(t *testing.T) {
	ts, srv := newTokenServer(t, "r0")
	r, errb, c := newRefresher(t, srv.URL)
	// Exactly a day before is due.
	writeAuth(t, c, authWith(jwt(fmt.Sprintf(`{"exp":%d}`, epoch.Unix()+86400)), "r0"))
	before, _ := os.Stat(c.Auth)
	d, err := r.step(context.Background())
	if err != nil || d != 0 {
		t.Fatalf("slept %v, %v", d, err)
	}
	if errb.String() != "codex-refresh: refreshed\n" {
		t.Errorf("said %q", errb.String())
	}

	// The request, byte for byte as jq and curl made it.
	want := request{
		method: "POST", path: "/", contentType: "application/json", accept: "*/*",
		body: "{\n  \"client_id\": \"app_EMoamEEZ73f0CkXaXp7hrann\",\n  \"grant_type\": \"refresh_token\",\n  \"refresh_token\": \"r0\"\n}",
	}
	if len(ts.requests) != 1 || ts.requests[0] != want {
		t.Errorf("sent %+v", ts.requests)
	}

	// Only what came back replaced, in place, everything else kept where it
	// was, and last_refresh made now, to the second.
	after, _ := os.Stat(c.Auth)
	if !os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Errorf("replaced, or mode %v", after.Mode())
	}
	b, _ := os.ReadFile(c.Auth)
	wantAuth := `{
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "bmV3.Y2xhaW1zLSVk.c2ln",
    "access_token": "` + jwt(fmt.Sprintf(`{"exp":%d}`, epoch.Unix()+10*86400)) + `",
    "refresh_token": "refresh-1",
    "account_id": "acct-1"
  },
  "last_refresh": "2027-01-02T03:04:05Z",
  "extra": {
    "kept": true
  }
}
`
	if string(b) != wantAuth {
		t.Errorf("auth.json is\n%s", b)
	}

	// And the placeholder after it, from the new id_token.
	p, _ := os.ReadFile(c.Placeholder)
	if !strings.Contains(string(p), `"id_token": "bmV3.Y2xhaW1zLSVk.frisket"`) ||
		!strings.Contains(string(p), `"last_refresh": "2027-01-02T03:04:05Z"`) ||
		strings.Contains(string(p), "refresh-1") {
		t.Errorf("placeholder is\n%s", p)
	}

	// Next time round it sleeps: the new token is ten days off.
	if d, _ := r.step(context.Background()); d != 300*time.Second {
		t.Errorf("slept %v", d)
	}
}

// A refresh token is good once. Each exchange sends the one the last gave,
// and never one already spent.
func TestEachRefreshTokenIsSpentOnce(t *testing.T) {
	ts, srv := newTokenServer(t, "r0")
	r, errb, c := newRefresher(t, srv.URL)
	writeAuth(t, c, due("r0"))
	// The server's tokens expire ten days after epoch whatever the round,
	// so each round is ten days on, and due.
	for i := range 3 {
		now := epoch.Add(time.Duration(i) * 10 * 86400 * time.Second)
		r.now = func() time.Time { return now }
		if d, err := r.step(context.Background()); d != 0 || err != nil {
			t.Fatalf("round %d: slept %v, %v; said %q", i, d, err, errb.String())
		}
	}
	var sent []string
	for _, q := range ts.requests {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		json.Unmarshal([]byte(q.body), &body)
		sent = append(sent, body.RefreshToken)
	}
	if strings.Join(sent, ",") != "r0,refresh-1,refresh-2" {
		t.Errorf("sent %v", sent)
	}
	if strings.Count(errb.String(), "codex-refresh: refreshed\n") != 3 {
		t.Errorf("said %q", errb.String())
	}
}

// Refused, the login is left as it was -- the refresh token included -- and
// the exchange tried again in a minute.
func TestAFailedExchangeLeavesTheLoginAndTriesAgainInAMinute(t *testing.T) {
	for _, status := range []int{400, 401, 404, 429, 500, 503} {
		ts, srv := newTokenServer(t, "r0")
		ts.answer = func(w http.ResponseWriter, _ *http.Request, _ string) bool {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"access_token":"leaked","refresh_token":"leaked"}`)
			return true
		}
		r, errb, c := newRefresher(t, srv.URL)
		writeAuth(t, c, due("r0"))
		WritePlaceholder(c)
		placeholder, _ := os.ReadFile(c.Placeholder)
		d, err := r.step(context.Background())
		if err != nil || d != time.Minute {
			t.Errorf("%d: slept %v, %v", status, d, err)
		}
		if errb.String() != "codex-refresh: the exchange failed; trying again in a minute\n" {
			t.Errorf("%d: said %q", status, errb.String())
		}
		if b, _ := os.ReadFile(c.Auth); string(b) != due("r0") {
			t.Errorf("%d: auth.json became %s", status, b)
		}
		if b, _ := os.ReadFile(c.Placeholder); string(b) != string(placeholder) {
			t.Errorf("%d: the placeholder became %s", status, b)
		}
	}
}

func TestAnEndpointNotThereIsAFailedExchange(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	r, errb, c := newRefresher(t, url)
	writeAuth(t, c, due("r0"))
	if d, _ := r.step(context.Background()); d != time.Minute {
		t.Errorf("slept %v", d)
	}
	if errb.String() != "codex-refresh: the exchange failed; trying again in a minute\n" {
		t.Errorf("said %q", errb.String())
	}
}

// curl was not told to follow a redirect: what came back is the answer, and
// where it points is never asked.
func TestARedirectIsNotFollowed(t *testing.T) {
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer target.Close()
	ts, srv := newTokenServer(t, "r0")
	ts.answer = func(w http.ResponseWriter, r *http.Request, _ string) bool {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		return true
	}
	r, errb, c := newRefresher(t, srv.URL)
	writeAuth(t, c, due("r0"))
	if d, _ := r.step(context.Background()); d != time.Minute {
		t.Errorf("slept %v", d)
	}
	if followed {
		t.Error("followed the redirect")
	}
	if errb.String() != "codex-refresh: the response held no tokens; trying again in a minute\n" {
		t.Errorf("said %q", errb.String())
	}
}

func TestAResponseThatIsNotJSONLeavesTheLogin(t *testing.T) {
	for _, body := range []string{``, `ok`, `{`, `{} {}`, `[]`, `"s"`, `1`} {
		ts, srv := newTokenServer(t, "r0")
		ts.answer = func(w http.ResponseWriter, _ *http.Request, _ string) bool {
			fmt.Fprint(w, body)
			return true
		}
		r, errb, c := newRefresher(t, srv.URL)
		writeAuth(t, c, due("r0"))
		if d, err := r.step(context.Background()); d != time.Minute || err != nil {
			t.Errorf("%q: slept %v, %v", body, d, err)
		}
		if errb.String() != "codex-refresh: the response held no tokens; trying again in a minute\n" {
			t.Errorf("%q: said %q", body, errb.String())
		}
		if b, _ := os.ReadFile(c.Auth); string(b) != due("r0") {
			t.Errorf("%q: auth.json became %s", body, b)
		}
	}
}

// A token the response leaves out is kept: an exchange that returns no new
// refresh token leaves the old one, which is all the login has.
func TestATokenLeftOutIsKept(t *testing.T) {
	ts, srv := newTokenServer(t, "r0")
	ts.answer = func(w http.ResponseWriter, _ *http.Request, _ string) bool {
		fmt.Fprint(w, `{"access_token":"new-access","refresh_token":null,"id_token":false}`)
		return true
	}
	r, errb, c := newRefresher(t, srv.URL)
	writeAuth(t, c, due("r0"))
	if d, _ := r.step(context.Background()); d != 0 {
		t.Errorf("slept %v", d)
	}
	b, _ := os.ReadFile(c.Auth)
	if !strings.Contains(string(b), `"refresh_token": "r0"`) ||
		!strings.Contains(string(b), `"id_token": "aWQ.Y2xhaW1z.c2ln"`) ||
		!strings.Contains(string(b), `"access_token": "new-access"`) {
		t.Errorf("auth.json is\n%s", b)
	}
	if errb.String() != "codex-refresh: refreshed\n" {
		t.Errorf("said %q", errb.String())
	}
}

// As the script had it: a 200 that holds no token at all -- `{}` or `null` --
// still counts as refreshed, and only last_refresh changes.
func TestAnEmptyAnswerCountsAsRefreshed(t *testing.T) {
	for _, body := range []string{`{}`, `null`} {
		ts, srv := newTokenServer(t, "r0")
		ts.answer = func(w http.ResponseWriter, _ *http.Request, _ string) bool {
			fmt.Fprint(w, body)
			return true
		}
		r, errb, c := newRefresher(t, srv.URL)
		writeAuth(t, c, due("r0"))
		if d, _ := r.step(context.Background()); d != 0 {
			t.Errorf("%s: slept %v", body, d)
		}
		b, _ := os.ReadFile(c.Auth)
		want := strings.Replace(due("r0"), `"2026-12-01T00:00:00.000Z"`, `"2027-01-02T03:04:05Z"`, 1)
		want = strings.Replace(want, `"extra": {"kept": true}`, "\"extra\": {\n    \"kept\": true\n  }", 1)
		if string(b) != want {
			t.Errorf("%s: auth.json is\n%s", body, b)
		}
		if errb.String() != "codex-refresh: refreshed\n" {
			t.Errorf("%s: said %q", body, errb.String())
		}
	}
}

// Where tokens are missing, jq made them, in order, after what was there.
func TestTokensMissingAreMade(t *testing.T) {
	ts, srv := newTokenServer(t, "r0")
	ts.answer = func(w http.ResponseWriter, _ *http.Request, _ string) bool {
		fmt.Fprint(w, `{"refresh_token":"r1"}`)
		return true
	}
	r, _, c := newRefresher(t, srv.URL)
	writeAuth(t, c, `{"tokens":{"refresh_token":"r0","access_token":"`+jwt(`{"exp":1}`)+`"}}`)
	r.step(context.Background())
	b, _ := os.ReadFile(c.Auth)
	want := `{
  "tokens": {
    "refresh_token": "r1",
    "access_token": "` + jwt(`{"exp":1}`) + `",
    "id_token": null
  },
  "last_refresh": "2027-01-02T03:04:05Z"
}
`
	if string(b) != want {
		t.Errorf("auth.json is\n%s", b)
	}
}

func TestNoRefreshTokenTriesAgainInAMinute(t *testing.T) {
	ts, srv := newTokenServer(t, "r0")
	for _, rt := range []string{`null`, `false`, ``} {
		r, errb, c := newRefresher(t, srv.URL)
		tokens := `"access_token":"` + jwt(`{"exp":1}`) + `"`
		if rt != "" {
			tokens += `,"refresh_token":` + rt
		}
		writeAuth(t, c, `{"tokens":{`+tokens+`}}`)
		if d, _ := r.step(context.Background()); d != time.Minute {
			t.Errorf("%s: slept %v", rt, d)
		}
		if errb.String() != "codex-refresh: no refresh token; trying again in a minute\n" {
			t.Errorf("%s: said %q", rt, errb.String())
		}
	}
	if len(ts.requests) != 0 {
		t.Errorf("exchanged: %v", ts.requests)
	}
}

// `jq -r` gave whatever was there as text.
func TestARefreshTokenThatIsNotAStringIsSentAsText(t *testing.T) {
	ts, srv := newTokenServer(t, "123")
	r, _, c := newRefresher(t, srv.URL)
	writeAuth(t, c, `{"tokens":{"access_token":"`+jwt(`{"exp":1}`)+`","refresh_token":123}}`)
	if d, _ := r.step(context.Background()); d != 0 {
		t.Errorf("slept %v", d)
	}
	if len(ts.requests) != 1 || !strings.Contains(ts.requests[0].body, `"refresh_token": "123"`) {
		t.Errorf("sent %v", ts.requests)
	}
}

func TestExchangeBodyEscapesAsJqDid(t *testing.T) {
	got := string(exchangeBody("a\"b\\c\u0001é"))
	want := "{\n  \"client_id\": \"app_EMoamEEZ73f0CkXaXp7hrann\",\n  \"grant_type\": \"refresh_token\",\n  \"refresh_token\": \"a\\\"b\\\\c\\u0001é\"\n}"
	if got != want {
		t.Errorf("%q", got)
	}
}

// codex rewrites auth.json in place, and a container may have it bound: the
// refresh writes the same inode and never through a link. And since the
// refresh token is single-use, a link is refused before it is sent, not
// after: nothing reaches the endpoint, the token is still good, and the
// link's target is as it was.
func TestAuthIsNeverWrittenThroughALink(t *testing.T) {
	ts, srv := newTokenServer(t, "r0")
	r, errb, c := newRefresher(t, srv.URL)
	real := c.Auth + ".real"
	writeAuth(t, c, due("r0"))
	os.Rename(c.Auth, real)
	os.Symlink(real, c.Auth)
	for range 2 {
		d, err := r.step(context.Background())
		if err != nil || d != 60*time.Second {
			t.Fatalf("slept %v, %v", d, err)
		}
	}
	if len(ts.requests) != 0 {
		t.Errorf("the refresh token was sent: %v", ts.requests)
	}
	if !ts.valid["r0"] {
		t.Error("the refresh token was spent")
	}
	if b, _ := os.ReadFile(real); string(b) != due("r0") {
		t.Errorf("the link's target became %s", b)
	}
	want := "codex-refresh: " + c.Auth + " is a link, which is not written through; trying again in a minute\n"
	if errb.String() != want+want {
		t.Errorf("said %q", errb.String())
	}
	// Once the link is gone the login refreshes as ever.
	os.Remove(c.Auth)
	os.Rename(real, c.Auth)
	if d, err := r.step(context.Background()); err != nil || d != 0 {
		t.Fatalf("slept %v, %v", d, err)
	}
	if b, _ := os.ReadFile(c.Auth); !strings.Contains(string(b), "refresh-1") {
		t.Errorf("auth.json is %s", b)
	}
}

// A placeholder it could not write ends the service, after auth.json.
func TestAPlaceholderItCannotWriteEnds(t *testing.T) {
	_, srv := newTokenServer(t, "r0")
	r, errb, c := newRefresher(t, srv.URL)
	writeAuth(t, c, due("r0"))
	os.MkdirAll(c.Placeholder, 0o700)
	if _, err := r.step(context.Background()); err == nil {
		t.Error("carried on")
	}
	if b, _ := os.ReadFile(c.Auth); !strings.Contains(string(b), "refresh-1") {
		t.Errorf("auth.json is %s", b)
	}
	if strings.Contains(errb.String(), "refreshed") {
		t.Errorf("said %q", errb.String())
	}
}

func TestTheExchangeIsBoundedAsCurlsWas(t *testing.T) {
	cl := newClient()
	if cl.Timeout != 60*time.Second {
		t.Errorf("timeout %v", cl.Timeout)
	}
}

func TestRunRefreshEndsQuietlyWithItsContext(t *testing.T) {
	// An exchange held open by the server is abandoned too.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	c := config(t)
	c.TokenEndpoint = srv.URL
	writeAuth(t, c, authWith(jwt(fmt.Sprintf(`{"exp":%d}`, time.Now().Unix()+60)), "r0"))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var errb bytes.Buffer
	if err := RunRefresh(ctx, c, &errb); err != nil {
		t.Errorf("ended with %v", err)
	}
}

func TestRunRefreshEndsOnAnExpItCannotReckonWith(t *testing.T) {
	c := config(t)
	writeAuth(t, c, authWith(jwt(`{"exp":1.5}`), "r0"))
	if err := RunRefresh(context.Background(), c, &bytes.Buffer{}); err == nil {
		t.Error("carried on")
	}
}

func TestWhatItSaysHasNoControlBytes(t *testing.T) {
	r, errb, _ := newRefresher(t, "http://127.0.0.1:1")
	r.cfg.Auth = t.TempDir() + "/\x1b]0;x\a"
	r.step(context.Background())
	if strings.ContainsAny(errb.String(), "\x1b\a") {
		t.Errorf("said %q", errb.String())
	}
}

// The merge is byte for byte the jq program's, refusals included, with its
// clock fixed where it read `now`.
