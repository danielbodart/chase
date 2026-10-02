package codex

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/jsonfile"
)

// sameJSON is whether a and b are one JSON value, whatever their layout and
// key order, numbers compared as written.
func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	x, err := jsonfile.Decode([]byte(a))
	if err != nil {
		t.Fatalf("%q: %v", a, err)
	}
	y, err := jsonfile.Decode([]byte(b))
	if err != nil {
		t.Fatalf("%q: %v", b, err)
	}
	return reflect.DeepEqual(x, y)
}

func config(t *testing.T) Config {
	home := t.TempDir()
	state := filepath.Join(home, ".local", "state", "chase", "codex")
	return Config{
		Auth:        filepath.Join(home, ".codex", "auth.json"),
		StateDir:    state,
		Placeholder: filepath.Join(state, "auth-placeholder.json"),
	}
}

func writeAuth(t *testing.T, c Config, content string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(c.Auth), 0o700)
	if err := os.WriteFile(c.Auth, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestThePlaceholderJWTIsWhatItSays(t *testing.T) {
	parts := strings.Split(PlaceholderJWT, ".")
	if len(parts) != 3 || parts[2] != "frisket" {
		t.Fatalf("%q", PlaceholderJWT)
	}
	for i, want := range []string{`{"alg":"none","typ":"JWT"}`, `{"exp":4102444800,"sub":"frisket-placeholder"}`} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || string(b) != want {
			t.Errorf("part %d: %q, %v", i, b, err)
		}
	}
	// And the refresher reads the same expiry from it: 2100-01-01.
	c := config(t)
	writeAuth(t, c, `{"tokens":{"access_token":"`+PlaceholderJWT+`"}}`)
	if exp, ok := accessExpiry(c.Auth); !ok || exp != "4102444800" {
		t.Errorf("exp %q, %v", exp, ok)
	}
}

func TestTheClientIDIsCodexsOwn(t *testing.T) {
	if ClientID != "app_EMoamEEZ73f0CkXaXp7hrann" || TokenEndpoint != "https://auth.openai.com/oauth/token" {
		t.Error("changed")
	}
}

func TestPlaceholderKeepsTheClaimsAndReplacesTheTokens(t *testing.T) {
	c := config(t)
	writeAuth(t, c, `{
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "aGVhZGVy.Y2xhaW1z.c2lnbmF0dXJl",
    "access_token": "real-access",
    "refresh_token": "real-refresh",
    "account_id": "acct-1"
  },
  "last_refresh": "2026-09-01T10:00:00.123Z",
  "auth_mode": "chatgpt"
}`)
	if err := WritePlaceholder(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(c.Placeholder)
	want := `{
  "auth_mode": "chatgpt",
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "aGVhZGVy.Y2xhaW1z.frisket",
    "access_token": "` + PlaceholderJWT + `",
    "refresh_token": "frisket-placeholder",
    "account_id": "acct-1"
  },
  "last_refresh": "2026-09-01T10:00:00.123Z"
}
`
	if !sameJSON(t, string(b), want) {
		t.Errorf("wrote\n%s", b)
	}
	for _, secret := range []string{"real-access", "real-refresh", "c2lnbmF0dXJl"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("the placeholder holds %s", secret)
		}
	}
}

// Logged in or not, the file must exist: flong refuses a missing bind source.
func TestNoLoginIsAPlaceholderAllTheSame(t *testing.T) {
	c := config(t)
	if err := WritePlaceholder(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(c.Placeholder)
	want := `{
  "auth_mode": "chatgpt",
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "frisket",
    "access_token": "` + PlaceholderJWT + `",
    "refresh_token": "frisket-placeholder",
    "account_id": ""
  },
  "last_refresh": "2000-01-01T00:00:00Z"
}
`
	if !sameJSON(t, string(b), want) {
		t.Errorf("wrote\n%s", b)
	}
	fi, _ := os.Stat(c.Placeholder)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	// Nor is a directory where the login would be one.
	os.MkdirAll(c.Auth, 0o700)
	if err := WritePlaceholder(c); err != nil {
		t.Error(err)
	}
}

// What codex takes for a default -- a member missing, null or false -- is
// the placeholder's default; anything else of the host's is carried over as
// it was, whatever JSON it is, numbers as written.
func TestPlaceholderDefaultsAndCarriesOver(t *testing.T) {
	// placeholderOf is the placeholder with these members, each raw JSON.
	placeholderOf := func(authMode, idToken, accountID, lastRefresh string) string {
		return `{"auth_mode":` + authMode + `,"OPENAI_API_KEY":null,"tokens":{"id_token":` + idToken +
			`,"access_token":"` + PlaceholderJWT + `","refresh_token":"frisket-placeholder","account_id":` + accountID +
			`},"last_refresh":` + lastRefresh + `}`
	}
	defaults := placeholderOf(`"chatgpt"`, `"frisket"`, `""`, `"2000-01-01T00:00:00Z"`)
	for in, want := range map[string]string{
		`null`: defaults,
		`{}`:   defaults,
		`{"auth_mode":false,"tokens":null,"last_refresh":null}`:                                                     defaults,
		`{"tokens":{"id_token":"","account_id":false}}`:                                                             defaults,
		`{"tokens":{"id_token":"."}}`:                                                                               placeholderOf(`"chatgpt"`, `"..frisket"`, `""`, `"2000-01-01T00:00:00Z"`),
		`{"tokens":{"id_token":"a.b.c.d","account_id":{"x":[1]}}}`:                                                  placeholderOf(`"chatgpt"`, `"a.b.frisket"`, `{"x":[1]}`, `"2000-01-01T00:00:00Z"`),
		`{"auth_mode":"apikey","tokens":{"id_token":"a","account_id":12345678901234567890123},"last_refresh":1.50}`: placeholderOf(`"apikey"`, `"a.frisket"`, `12345678901234567890123`, `1.50`),
	} {
		c := config(t)
		writeAuth(t, c, in)
		if err := WritePlaceholder(c); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if b, _ := os.ReadFile(c.Placeholder); !sameJSON(t, string(b), want) {
			t.Errorf("%s: wrote\n%s", in, b)
		}
	}
}

// A login it cannot read leaves the last placeholder as it was, rather than
// truncating what a running session has bound.
func TestALoginItCannotReadLeavesThePlaceholder(t *testing.T) {
	for _, bad := range []string{``, `{`, `{} {}`, `{"tokens":{"id_token":1}}`, `{"tokens":{"id_token":true}}`, `{"tokens":[]}`, `[]`, `"s"`} {
		c := config(t)
		if err := WritePlaceholder(c); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(c.Placeholder)
		writeAuth(t, c, bad)
		if err := WritePlaceholder(c); err == nil {
			t.Errorf("%q: no error", bad)
		}
		if after, _ := os.ReadFile(c.Placeholder); string(after) != string(before) {
			t.Errorf("%q: the placeholder became %q", bad, after)
		}
		if entries, _ := os.ReadDir(c.StateDir); len(entries) != 1 {
			t.Errorf("%q: left beside it: %v", bad, entries)
		}
	}
}

// A container binds this file over its own auth.json: a rename would detach
// the bind, so the same inode is rewritten, and made 0600 whatever it was.
func TestThePlaceholderIsRewrittenInPlace(t *testing.T) {
	c := config(t)
	os.MkdirAll(c.StateDir, 0o700)
	if err := os.WriteFile(c.Placeholder, []byte(strings.Repeat("x", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(c.Placeholder)
	writeAuth(t, c, `{"tokens":{"account_id":"acct-1"}}`)
	if err := WritePlaceholder(c); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(c.Placeholder)
	if !os.SameFile(before, after) {
		t.Error("replaced, not rewritten")
	}
	if after.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", after.Mode())
	}
	b, _ := os.ReadFile(c.Placeholder)
	if !json.Valid(b) || !strings.Contains(string(b), "acct-1") {
		t.Errorf("wrote %q", b)
	}
	if entries, _ := os.ReadDir(c.StateDir); len(entries) != 1 {
		t.Errorf("left beside it: %v", entries)
	}
}

// An open descriptor -- what a bind is, in effect -- sees the new placeholder.
func TestAnOpenPlaceholderSeesTheNewOne(t *testing.T) {
	c := config(t)
	if err := WritePlaceholder(c); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(c.Placeholder)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	writeAuth(t, c, `{"tokens":{"account_id":"acct-2"}}`)
	if err := WritePlaceholder(c); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4096)
	n, _ := f.ReadAt(b, 0)
	if !strings.Contains(string(b[:n]), "acct-2") {
		t.Errorf("the open file holds %q", b[:n])
	}
}

func TestThePlaceholderIsNeverWrittenThroughALink(t *testing.T) {
	c := config(t)
	os.MkdirAll(c.StateDir, 0o700)
	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte("keep"), 0o644)
	os.Symlink(target, c.Placeholder)
	if err := WritePlaceholder(c); err == nil {
		t.Error("no error")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("the link's target became %q", b)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o644 {
		t.Errorf("the link's target was made %v", fi.Mode())
	}
}

func TestLoadConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, []byte(`{"auth":"/h/.codex/auth.json","stateDir":"/h/s","placeholder":"/h/s/auth-placeholder.json"}`), 0o600)
	c, err := LoadConfig(p)
	want := Config{Auth: "/h/.codex/auth.json", StateDir: "/h/s", Placeholder: "/h/s/auth-placeholder.json"}
	if err != nil || !reflect.DeepEqual(c, want) || c.endpoint() != TokenEndpoint {
		t.Errorf("%+v, %v", c, err)
	}
	os.WriteFile(p, []byte(`[`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Error("loaded a broken config")
	}
}
