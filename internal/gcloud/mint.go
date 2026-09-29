// Package gcloud is a session's Google token: minted from the project's
// service-account key at RUN/secrets/gcloud, written to RUN/gcloud-token.json
// for frisket to read, and renewed for as long as RUN is there (docs/gcloud.md,
// decision 5).
//
// frisket never refreshes (frisket's decision 10), so this is chase's, beside
// claude-refresh and codex-refresh: once by the launch before the session
// starts, and then as `chase-gcloud-renew@<machine>`, a user unit per session
// that postStop stops before the directory goes.
//
// Nothing here ever says the key or a token. What Google says when it refuses
// a grant is said, cleaned, because it is how a person learns the key was
// deleted; nothing else from the key file or the response is.
package gcloud

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/term"
)

// DefaultTokenURL is Google's token endpoint, where every grant goes unless
// a check moves it.
const DefaultTokenURL = "https://oauth2.googleapis.com/token"

const (
	// audience is the grant's aud, which is Google's token endpoint whatever
	// the grant is posted to: a check that moves TokenURL still expects it.
	audience = "https://oauth2.googleapis.com/token"
	scope    = "https://www.googleapis.com/auth/cloud-platform"
	// grantType is the JWT-bearer grant (RFC 7523).
	grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Config is what the renewer is built with.
type Config struct {
	// TokenURL is where a grant is posted. Empty is DefaultTokenURL; only a
	// check sets it: nothing at run time can move it.
	TokenURL string `json:"tokenURL,omitempty"`
}

func (c Config) tokenURL() string {
	if c.TokenURL == "" {
		return DefaultTokenURL
	}
	return c.TokenURL
}

// Outcome is how a mint ended, as the exit code `chase gcloud-renew mint`
// gives it. The launch switches on it: a refusal, or a key for another
// account, ends the launch; Google out of reach only warns, since the unit
// keeps trying.
type Outcome int

const (
	// Minted: RUN/gcloud-token.json holds a new token.
	Minted Outcome = 0
	// Transient: Google did not answer, or answered in a way that may mend
	// itself -- a 5xx, a 200 with no token -- or the token could not be
	// written. The token file, if any, is as it was.
	Transient Outcome = 1
	// Refused: Google refused the grant, with a 4xx: the key was deleted or
	// disabled, or is not the account's.
	Refused Outcome = 2
	// BadKey: the key at RUN/secrets/gcloud is not a usable service-account
	// key, or not one of the account the caller named. Nothing was sent.
	BadKey Outcome = 3
)

// Mint mints RUN/gcloud-token.json from the key at RUN/secrets/gcloud. A
// non-empty sa is the service account the key must be for, checked before
// anything is sent: a key of another account is never shown to Google.
func Mint(ctx context.Context, cfg Config, run, sa string, stderr io.Writer) Outcome {
	say := func(format string, args ...any) {
		fmt.Fprint(stderr, term.Clean("chase-gcloud-renew: "+fmt.Sprintf(format, args...))+"\n")
	}
	// RUN's paths are joined as the script's strings were, not cleaned: an
	// empty RUN is the root's, as `$run/secrets/gcloud` made it, never the
	// caller's working directory, and a `..` in RUN is the kernel's to
	// resolve, through whatever links it passes.
	keyPath := run + "/secrets/gcloud"
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		say("no key at %s", keyPath)
		return BadKey
	}
	email, signer, ok := parseKey(raw)
	if !ok {
		say("%s is not a service-account key", keyPath)
		return BadKey
	}
	if sa != "" && email != sa {
		say("the key is %s's, not %s's", email, sa)
		return BadKey
	}
	if signer == nil {
		say("the key's private_key does not sign")
		return BadKey
	}

	now := time.Now().Unix()
	jwt, err := assertion(email, now, signer)
	if err != nil {
		say("the key's private_key does not sign")
		return BadKey
	}

	tokenURL := cfg.tokenURL()
	form := url.Values{"grant_type": {grantType}, "assertion": {jwt}}.Encode()
	// curl, which this was, gave up after 60 seconds and followed no
	// redirect: a 3xx is an answer, and not Google's.
	client := &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form))
	if err != nil {
		say("%s did not answer", tokenURL)
		return Transient
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The token's life is counted from when the request was sent, not when
	// the answer came: a slow answer leaves less of the hour, never more.
	sent := time.Now().UnixMilli()
	resp, err := client.Do(req)
	if err != nil {
		say("%s did not answer", tokenURL)
		return Transient
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		say("%s did not answer", tokenURL)
		return Transient
	}
	switch code := resp.StatusCode; {
	case code == http.StatusOK:
	case code >= 400 && code <= 499:
		say("Google refused %s's grant (%d): %s", email, code, refusal(body))
		return Refused
	default:
		say("%s answered %d", tokenURL, code)
		return Transient
	}

	token, expiry, ok := granted(body, sent)
	if !ok {
		say("%s answered 200 without a token", tokenURL)
		return Transient
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		AccessToken string  `json:"access_token"`
		Expiry      float64 `json:"expiry"`
	}{token, expiry}); err != nil {
		return Transient
	}
	// frisket re-reads the file when it is replaced, and must never read
	// half of one: it is written beside itself and renamed over, the
	// user's alone.
	//
	// What could not be written is said, as mktemp and mv said it: a full
	// disk or an unwritable RUN is otherwise only "trying again in a
	// minute" in the unit's journal. The error names paths, never the token.
	if err := files.WriteAtomic(run+"/gcloud-token.json", out.Bytes(), 0o600); err != nil {
		say("%v", err)
		return Transient
	}
	say("minted for %s, expiring %s", email, time.Unix(int64(expiry/1000), 0).Format("2006-01-02T15:04:05-07:00"))
	return Minted
}

// parseKey is the key's client_email and its private key, if the file is a
// service_account key with a private_key and a client_email that are
// strings. ok is false if it is not; signer is nil if it is, but its
// private_key is not an RSA key that signs.
func parseKey(raw []byte) (email string, signer *rsa.PrivateKey, ok bool) {
	var k map[string]json.RawMessage
	if json.Unmarshal(raw, &k) != nil || k == nil {
		return "", nil, false
	}
	var typ, pk string
	if json.Unmarshal(k["type"], &typ) != nil || typ != "service_account" ||
		!isString(k["private_key"]) || !isString(k["client_email"]) {
		return "", nil, false
	}
	json.Unmarshal(k["private_key"], &pk)
	json.Unmarshal(k["client_email"], &email)
	// The shell this was read the email through a command substitution,
	// which drops trailing newlines: the email is compared, and claimed,
	// without them.
	email = strings.TrimRight(email, "\n")
	return email, rsaKey(pk), true
}

func isString(raw json.RawMessage) bool {
	var s string
	return len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &s) == nil
}

// rsaKey is the RSA key in a PEM block, PKCS#8 or PKCS#1, or nil.
func rsaKey(p string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		r, _ := k.(*rsa.PrivateKey)
		return r
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k
	}
	return nil
}

// assertion is the grant's JWT: RS256, as the service account, for the
// cloud-platform scope, for an hour from now -- the longest Google allows.
func assertion(email string, now int64, key *rsa.PrivateKey) (string, error) {
	header := b64url([]byte(`{"alg":"RS256","typ":"JWT"}`))
	var c bytes.Buffer
	enc := json.NewEncoder(&c)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		Iss   string `json:"iss"`
		Scope string `json:"scope"`
		Aud   string `json:"aud"`
		Iat   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	}{email, scope, audience, now, now + 3600}); err != nil {
		return "", err
	}
	signing := header + "." + b64url(bytes.TrimSuffix(c.Bytes(), []byte("\n")))
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64url(sig), nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// granted is the token and its expiry, in epoch milliseconds counted from
// sent, if the body is a token Google granted: a non-empty access_token and
// a positive expires_in.
func granted(body []byte, sent int64) (token string, expiry float64, ok bool) {
	var g map[string]any
	if json.Unmarshal(body, &g) != nil {
		return "", 0, false
	}
	token, _ = g["access_token"].(string)
	in, isNum := g["expires_in"].(float64)
	if token == "" || !isNum || !(in > 0) {
		return "", 0, false
	}
	return token, float64(sent) + math.Floor(in*1000), true
}

// refusal is Google's error and its description, as its error envelope
// gives them, or "?" if the body is not one. An empty body is nothing at
// all: jq read no input, said nothing, and exited 0, so the script's
// refusal ended at its colon.
func refusal(body []byte) string {
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return "?"
	}
	switch m := v.(type) {
	case nil:
		return "?: "
	case map[string]any:
		e, d := "?", ""
		if x, ok := m["error"]; ok && x != nil && x != false {
			e = jqString(x)
		}
		if x, ok := m["error_description"]; ok && x != nil && x != false {
			d = jqString(x)
		}
		return e + ": " + d
	default:
		return "?"
	}
}

// jqString is a value as jq's string interpolation gives it: a string as
// itself, anything else as its JSON.
func jqString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if f, ok := v.(float64); ok && f == math.Trunc(f) && math.Abs(f) < 1e17 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	return string(b)
}
