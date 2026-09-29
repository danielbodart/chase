// Package codex keeps the host's codex login fresh, and the placeholder login
// that sessions hold in its place in step with it.
//
// A session never holds the host's tokens: a shared tier's container binds
// the placeholder over its own ~/.codex/auth.json, an isolated tier's home is
// given a copy of it, and frisket puts the real access token on each request.
// frisket never refreshes, and a session cannot, so the refresh is done here.
package codex

import (
	"encoding/json"
	"fmt"
	"os"
)

// PlaceholderJWT is what the container holds in place of the access token.
// The module's own placeholder cannot be it: codex reads its own token as a
// JWT and refreshes 5 minutes before the `exp` it finds, so the placeholder
// has to be JWT-shaped with an expiry far away -- {"alg":"none","typ":"JWT"}
// over {"exp":4102444800,"sub":"frisket-placeholder"}, 4102444800 being
// 2100-01-01. Nothing verifies the signature: not codex, which only splits
// on '.', and not frisket, which compares the whole string to this one. The
// module gives frisket's codex route this same string as its placeholder, so
// the two must not drift.
const PlaceholderJWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjQxMDI0NDQ4MDAsInN1YiI6ImZyaXNrZXQtcGxhY2Vob2xkZXIifQ.frisket"

// ClientID is the client codex itself logs in as, from its source: without
// it the token endpoint refuses the exchange.
const ClientID = "app_EMoamEEZ73f0CkXaXp7hrann"

// TokenEndpoint is where a refresh token is exchanged.
const TokenEndpoint = "https://auth.openai.com/oauth/token"

// Config is what the NixOS module decides for this package, written as JSON.
type Config struct {
	// Auth is the host's own login, ~/.codex/auth.json.
	Auth string `json:"auth"`
	// StateDir is ~/.local/state/agents/codex, made if missing: it holds
	// the placeholder and each isolated tier's CODEX_HOME, neither of which
	// is the host's own login or state.
	StateDir string `json:"stateDir"`
	// Placeholder is the placeholder login, StateDir/auth-placeholder.json:
	// the source of a shared tier's bind over auth.json, and what an
	// isolated tier's home is given a copy of.
	Placeholder string `json:"placeholder"`
	// TokenEndpoint is where the refresh token is exchanged. Empty is
	// TokenEndpoint; set only by tests.
	TokenEndpoint string `json:"tokenEndpoint,omitempty"`
}

func (c Config) endpoint() string {
	if c.TokenEndpoint != "" {
		return c.TokenEndpoint
	}
	return TokenEndpoint
}

// LoadConfig reads a Config the module wrote.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}
