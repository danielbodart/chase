package codex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/jsonfile"
	"github.com/danielbodart/chase/internal/term"
)

const (
	// early is how long before the access token expires the refresher
	// exchanges it: a day. codex refreshes only in the last 5 minutes, and a
	// refresh token is single-use -- a second refresher racing the first
	// revokes the login -- so this one runs where nothing else is looking.
	early = 86400 // seconds
	// step is the longest one sleep: short enough that a machine that
	// suspended through the day notices soon after it resumes.
	step = 300 * time.Second
	// retry is how long after anything that went wrong on the way.
	retry = 60 * time.Second
	// invalidGrant is the error the token endpoint gives, with a 400, for a
	// refresh token it will not take again: spent, by an exchange that
	// happened even if its answer never arrived, or revoked. Nothing but a
	// new login mends that.
	invalidGrant = "invalid_grant"
	// exchangeTimeout bounds the whole exchange, as curl's --max-time did.
	exchangeTimeout = 60 * time.Second
)

// RunRefresh is the codex-refresh service: it wakes a day before the host's
// access token expires, exchanges the refresh token for new tokens itself,
// writes them into auth.json in place and the placeholder after them,
// forever. It returns nil when ctx ends, and an error only where the script
// it replaces would have exited -- an `exp` that is not a whole number, or a
// write that failed -- for systemd to restart it.
func RunRefresh(ctx context.Context, cfg Config, stderr io.Writer) error {
	r := &refresher{cfg: cfg, stderr: stderr, now: time.Now, client: newClient()}
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

// newClient is curl as the script ran it: no redirect followed, since curl
// was not given -L, and a response that is one is what came back.
func newClient() *http.Client {
	return &http.Client{
		Timeout: exchangeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type refresher struct {
	cfg    Config
	stderr io.Writer
	now    func() time.Time
	client *http.Client
	// refused is the refresh token the endpoint last answered invalid_grant
	// for, and none when it has answered no such thing. It is kept to be
	// compared, and only ever sent once.
	refused    string
	hasRefused bool
}

func (r *refresher) say(format string, args ...any) {
	fmt.Fprint(r.stderr, term.Clean("codex-refresh: "+fmt.Sprintf(format, args...))+"\n")
}

// step is one pass of the loop: how long to sleep before the next.
func (r *refresher) step(ctx context.Context) (time.Duration, error) {
	lit, ok := accessExpiry(r.cfg.Auth)
	if !ok {
		r.say("no access token in %s; looking again in 5 minutes", r.cfg.Auth)
		return step, nil
	}
	exp, err := strconv.ParseInt(lit, 10, 64)
	if err != nil {
		// Shell arithmetic on it failed, and ended the script.
		return 0, fmt.Errorf("exp %s in %s is not a whole number", lit, r.cfg.Auth)
	}
	// Wake a day before expiry, in steps short enough to survive suspend.
	if wait := exp - early - r.now().Unix(); wait > 0 {
		return sleepFor(wait), nil
	}

	// The refresh token is single-use: once it is sent, the tokens that come
	// back are the only login there is, and they must be written. auth.json
	// is written in place and never through a link (a link there would send
	// the host's tokens wherever it points), so a link is refused here,
	// before the exchange, rather than after it with the new tokens lost and
	// the old one spent -- which the next exchange would send, for an
	// invalid_grant and a login to redo. The script's `printf > "$auth"`
	// followed a link; this says so and looks again, until the link is gone.
	if fi, err := os.Lstat(r.cfg.Auth); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		r.say("%s is a link, which is not written through; trying again in a minute", r.cfg.Auth)
		return retry, nil
	}

	refreshToken, ok := readRefreshToken(r.cfg.Auth)
	if !ok {
		r.say("no refresh token; trying again in a minute")
		return retry, nil
	}
	// A refresh token the endpoint has already called invalid_grant is not
	// sent again: it will be refused again, every minute, forever, and what
	// is wrong was said when it was first refused. Only a new login -- which
	// writes a new refresh token into auth.json -- is worth an exchange, so
	// until one does this only looks, every 5 minutes, and says nothing.
	if r.hasRefused {
		if refreshToken == r.refused {
			return step, nil
		}
		r.hasRefused = false
	}
	status, body, err := r.exchange(ctx, refreshToken)
	if err != nil || status >= 400 {
		// The script retried every failure alike, invalid_grant included,
		// and so sent a spent token every minute until someone noticed. That
		// one failure is said once, for what it is, and waited out; any
		// other -- a 5xx, a 429, a network gone -- may pass, and is tried
		// again in a minute.
		if err == nil && status == http.StatusBadRequest && errorIs(body, invalidGrant) {
			r.refused, r.hasRefused = refreshToken, true
			r.say("the refresh token is spent or revoked (invalid_grant); log in again with `codex login` on the host; looking again every 5 minutes")
			return step, nil
		}
		r.say("the exchange failed; trying again in a minute")
		return retry, nil
	}

	// In place, and only what came back: codex writes this file the same
	// way, and a rename would detach the bind covering it in a container.
	// An answer with no access token in it is not a refresh, whatever its
	// status: the script merged `{}` or `null` as one, wrote only
	// last_refresh and said refreshed, and since the access token had not
	// moved the next pass was due at once -- an endpoint answering 200 {}
	// was sent exchange after exchange with no sleep between. So nothing is
	// written, and it is tried again in a minute.
	merged, err := merge(r.cfg.Auth, body, r.now())
	if err != nil {
		r.say("the response held no tokens; trying again in a minute")
		return retry, nil
	}
	if err := files.WriteInPlace(r.cfg.Auth, merged, 0o600); err != nil {
		return 0, err
	}
	if err := WritePlaceholder(r.cfg); err != nil {
		return 0, err
	}
	r.say("refreshed")
	return 0, nil
}

// sleepFor is wait seconds, at most step. Compared before it is made a
// Duration, as the script's `wait < 300` was: an exp far enough away would
// overflow a Duration's nanoseconds and come out negative, which would be no
// sleep at all and a loop that spins without a word.
func sleepFor(wait int64) time.Duration {
	if wait >= int64(step/time.Second) {
		return step
	}
	return time.Duration(wait) * time.Second
}

// accessExpiry is `exp`, as written, out of the access token's own claims.
func accessExpiry(path string) (string, bool) {
	toks, ok := readTokens(path)
	if !ok {
		return "", false
	}
	at, ok := toks["access_token"].(string)
	if !ok {
		return "", false
	}
	parts := strings.Split(at, ".")
	if len(parts) < 2 {
		return "", false
	}
	// base64url, padded or not; standard base64's + and / are read too, as
	// the script read them.
	p := strings.NewReplacer("-", "+", "_", "/").Replace(strings.TrimRight(parts[1], "="))
	claims, err := base64.RawStdEncoding.DecodeString(p)
	if err != nil {
		return "", false
	}
	c, err := jsonfile.Decode(claims)
	if err != nil {
		return "", false
	}
	obj, ok := jsonfile.Object(c)
	if !ok {
		return "", false
	}
	exp, ok := obj["exp"].(json.Number)
	return string(exp), ok
}

// readRefreshToken is tokens.refresh_token: none if it is missing, null or
// false, its text if it is a string, and anything else as its JSON, which
// the token endpoint will refuse, and say why, rather than this guess.
func readRefreshToken(path string) (string, bool) {
	toks, ok := readTokens(path)
	if !ok {
		return "", false
	}
	switch rt := toks["refresh_token"].(type) {
	case nil:
		return "", false
	case bool:
		if !rt {
			return "", false
		}
	case string:
		return rt, true
	}
	b, err := json.Marshal(toks["refresh_token"])
	return string(b), err == nil
}

// readTokens is auth.json's tokens, none when there is no auth.json, or it
// or its tokens is not an object; a null one of either is empty.
func readTokens(path string) (map[string]any, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	doc, err := jsonfile.Decode(b)
	if err != nil {
		return nil, false
	}
	root, ok := jsonfile.Object(doc)
	if !ok {
		return nil, false
	}
	return jsonfile.Object(root["tokens"])
}

// exchange trades the refresh token for new tokens, and gives the status
// and body of whatever answered; an error only for no answer at all.
func (r *refresher) exchange(ctx context.Context, refreshToken string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.endpoint(), bytes.NewReader(exchangeBody(refreshToken)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// errorIs is whether body is a JSON object whose error is code, as an OAuth
// token endpoint says why it refused: `{"error": "invalid_grant", ...}`.
func errorIs(body []byte, code string) bool {
	var answer struct {
		Error any `json:"error"`
	}
	return json.Unmarshal(body, &answer) == nil && answer.Error == code
}

// exchangeBody is the request: codex's client id, the grant, and the token.
func exchangeBody(refreshToken string) []byte {
	b, _ := json.Marshal(struct {
		ClientID     string `json:"client_id"`
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
	}{ClientID, "refresh_token", refreshToken})
	return b
}

// errNoAccessToken is an answer that holds no access token, which is no
// refresh at all.
var errNoAccessToken = errors.New("the response holds no access token")

// errNotAuth is an auth.json, read again, whose tokens cannot be set: it,
// or its tokens, something other than an object.
var errNotAuth = errors.New("auth.json or its tokens is not an object")

// merge is auth.json, read again, with each token the response holds put in
// place of the old and last_refresh made now; a token the response lacks is
// kept, but for the access token, which it must hold, as a string. Every
// other member, codex's own, is written back as it was read.
func merge(path string, body []byte, now time.Time) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := jsonfile.Decode(b)
	if err != nil {
		return nil, err
	}
	a, err := jsonfile.Decode(body)
	if err != nil {
		return nil, err
	}
	resp, ok := a.(map[string]any)
	if !ok {
		return nil, errNoAccessToken
	}
	if _, ok := resp["access_token"].(string); !ok {
		return nil, errNoAccessToken
	}
	doc, ok := jsonfile.Object(v)
	if !ok {
		return nil, errNotAuth
	}
	toks, ok := jsonfile.Object(doc["tokens"])
	if !ok {
		return nil, errNotAuth
	}
	for _, k := range []string{"id_token", "access_token", "refresh_token"} {
		toks[k] = jsonfile.Or(resp[k], toks[k])
	}
	doc["tokens"] = toks
	// UTC, to the second.
	doc["last_refresh"] = now.UTC().Format("2006-01-02T15:04:05Z")
	return jsonfile.Encode(doc)
}
