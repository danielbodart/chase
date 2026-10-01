// Package claude keeps the host's Claude Code login usable by the sessions
// that never see it, and trusts the checkouts a tier says to trust.
//
// A session holds a placeholder login that never expires, so it never tries
// to refresh, and frisket puts the host's real token on each request and
// never refreshes it either. So the host's login is kept fresh here, by the
// claude-refresh user service, and nowhere else.
package claude

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is what the NixOS module decides for this package, written as JSON.
type Config struct {
	// Credentials is the host's own login, ~/.claude/.credentials.json,
	// whose claudeAiOauth.expiresAt (milliseconds since the epoch) is what
	// the refresher watches.
	Credentials string `json:"credentials"`
	// Claude is the claude binary itself, ${package}/bin/claude: the
	// unwrapped one, since the wrapper would put the refresh in a sandbox
	// holding only a placeholder.
	Claude string `json:"claude"`
	// ClaudeJSON is the host's ~/.claude.json, where a bare tier that
	// trusts its checkouts trusts them (Trust).
	ClaudeJSON string `json:"claudeJSON"`
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
