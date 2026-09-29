package codex

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// originalFilter is codex-placeholder's jq program, as the module had it.
const originalFilter = `$real as $r
 | {
     auth_mode: ($r.auth_mode // "chatgpt"),
     OPENAI_API_KEY: null,
     tokens: {
       id_token: (($r.tokens.id_token // "") | split(".")[0:2] + ["frisket"] | join(".")),
       access_token: $access,
       refresh_token: "frisket-placeholder",
       account_id: ($r.tokens.account_id // "")
     },
     last_refresh: ($r.last_refresh // "2000-01-01T00:00:00Z")
   }`

func original(t *testing.T, real string) (string, bool) {
	t.Helper()
	bin, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("no jq to compare against")
	}
	out, err := exec.Command(bin, "-n", "--argjson", "real", real, "--arg", "access", PlaceholderJWT, originalFilter).Output()
	return string(out), err == nil
}

func config(t *testing.T) Config {
	home := t.TempDir()
	state := filepath.Join(home, ".local", "state", "agents", "codex")
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
	if string(b) != want {
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
	if string(b) != want {
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

// Byte for byte what the jq program made, for every shape of login it
// accepted, and refused where it refused.
func TestPlaceholderMatchesTheOriginal(t *testing.T) {
	for _, real := range []string{
		`{}`,
		`null`,
		`{"auth_mode":false,"tokens":null,"last_refresh":null}`,
		`{"auth_mode":"apikey","OPENAI_API_KEY":"sk-x"}`,
		`{"auth_mode":{"odd":[1,2]},"tokens":{"account_id":7}}`,
		`{"tokens":{"id_token":""}}`,
		`{"tokens":{"id_token":"a"}}`,
		`{"tokens":{"id_token":"a.b"}}`,
		`{"tokens":{"id_token":"a.b.c.d"}}`,
		`{"tokens":{"id_token":"a..b"}}`,
		`{"tokens":{"id_token":"."}}`,
		`{"tokens":{"id_token":false,"account_id":false}}`,
		`{"tokens":{"id_token":"é.\u0001"},"last_refresh":"x\"y"}`,
		`{"tokens":{"id_token":1}}`,
		`{"tokens":{"id_token":["a"]}}`,
		`{"tokens":"x"}`,
		`[]`,
		`"s"`,
		`1`,
	} {
		want, ok := original(t, real)
		c := config(t)
		writeAuth(t, c, real)
		err := WritePlaceholder(c)
		if (err == nil) != ok {
			t.Errorf("%s: error %v, jq accepted %v", real, err, ok)
			continue
		}
		if !ok {
			continue
		}
		if b, _ := os.ReadFile(c.Placeholder); string(b) != want {
			t.Errorf("%s:\n got %s\nwant %s", real, b, want)
		}
	}
}

// A login it cannot read leaves the last placeholder as it was, rather than
// truncating what a running session has bound.
func TestALoginItCannotReadLeavesThePlaceholder(t *testing.T) {
	for _, bad := range []string{``, `{`, `{} {}`, `{"tokens":{"id_token":1}}`, `[]`} {
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
