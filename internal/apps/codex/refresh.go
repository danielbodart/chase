package codex

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/danielbodart/chase/internal/apps/claude/jsondoc"
	"github.com/danielbodart/chase/internal/files"
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
	// the old one spent -- which every retry would then send again, for an
	// invalid_grant, forever. The script's `printf > "$auth"` followed a
	// link; this says so and looks again, until the link is gone.
	if fi, err := os.Lstat(r.cfg.Auth); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		r.say("%s is a link, which is not written through; trying again in a minute", r.cfg.Auth)
		return retry, nil
	}

	refreshToken, ok := readRefreshToken(r.cfg.Auth)
	if !ok {
		r.say("no refresh token; trying again in a minute")
		return retry, nil
	}
	body, err := r.exchange(ctx, refreshToken)
	if err != nil {
		r.say("the exchange failed; trying again in a minute")
		return retry, nil
	}

	// In place, and only what came back: codex writes this file the same
	// way, and a rename would detach the bind covering it in a container.
	merged, err := merge(r.cfg.Auth, body, r.now())
	if err != nil {
		r.say("the response held no tokens; trying again in a minute")
		return retry, nil
	}
	if err := files.WriteInPlace(r.cfg.Auth, append(merged, '\n'), 0o600); err != nil {
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
	doc, ok := readDoc(path)
	if !ok {
		return "", false
	}
	tokens, err := doc.Field("tokens")
	if err != nil {
		return "", false
	}
	at, err := tokens.Field("access_token")
	if err != nil || at.Kind != jsondoc.String {
		return "", false
	}
	parts := jsondoc.Split(at.Str, ".")
	if len(parts) < 2 {
		return "", false
	}
	// base64url, its padding put back, as the script turned it into what
	// jq's @base64d reads.
	p := strings.NewReplacer("-", "+", "_", "/").Replace(parts[1])
	p += strings.Repeat("=", (4-len(p)%4)%4)
	claims, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return "", false
	}
	c, err := jsondoc.Parse(claims)
	if err != nil {
		return "", false
	}
	e, err := c.Field("exp")
	if err != nil || e.Kind != jsondoc.Number {
		return "", false
	}
	return e.Num, true
}

// readRefreshToken is tokens.refresh_token as `jq -er` gave it: none if it
// is null or false, its text if it is a string, and anything else as jq
// prints it.
func readRefreshToken(path string) (string, bool) {
	doc, ok := readDoc(path)
	if !ok {
		return "", false
	}
	tokens, err := doc.Field("tokens")
	if err != nil {
		return "", false
	}
	rt, err := tokens.Field("refresh_token")
	if err != nil || !rt.Truthy() {
		return "", false
	}
	return rt.Raw(), true
}

func readDoc(path string) (jsondoc.Value, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return jsondoc.Value{}, false
	}
	doc, err := jsondoc.Parse(b)
	return doc, err == nil
}

// exchange trades the refresh token for new tokens, and gives the body of
// any response below 400, as `curl -fsS` did.
func (r *refresher) exchange(ctx context.Context, refreshToken string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.endpoint(), bytes.NewReader(exchangeBody(refreshToken)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("the token endpoint answered %s", resp.Status)
	}
	return body, nil
}

// exchangeBody is the request, byte for byte as `jq -n` made it.
func exchangeBody(refreshToken string) []byte {
	return jsondoc.Obj(
		jsondoc.Member{Key: "client_id", Value: jsondoc.Str(ClientID)},
		jsondoc.Member{Key: "grant_type", Value: jsondoc.Str("refresh_token")},
		jsondoc.Member{Key: "refresh_token", Value: jsondoc.Str(refreshToken)},
	).Marshal()
}

// merge is auth.json, read again, with each token the response holds put in
// place of the old and last_refresh made now; a token the response lacks is
// kept.
func merge(path string, body []byte, now time.Time) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := jsondoc.Parse(b)
	if err != nil {
		return nil, err
	}
	resp, err := jsondoc.Parse(body)
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"id_token", "access_token", "refresh_token"} {
		nv, err := resp.Field(k)
		if err != nil {
			return nil, err
		}
		tokens, err := doc.Field("tokens")
		if err != nil {
			return nil, err
		}
		ov, err := tokens.Field(k)
		if err != nil {
			return nil, err
		}
		if tokens, err = tokens.SetField(k, nv.Or(ov)); err != nil {
			return nil, err
		}
		if doc, err = doc.SetField("tokens", tokens); err != nil {
			return nil, err
		}
	}
	// jq's `now | todate`: UTC, to the second.
	doc, err = doc.SetField("last_refresh", jsondoc.Str(now.UTC().Format("2006-01-02T15:04:05Z")))
	if err != nil {
		return nil, err
	}
	return doc.Marshal(), nil
}
