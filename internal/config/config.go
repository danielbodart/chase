// Package config is the one file the NixOS module writes for the chase
// binary: everything the module used to splice into script text, as data.
//
// It is read from /etc/chase/config.json, where the module puts it, or from
// the path a hook or a check names with -config. Never from the
// environment: a checkout's .envrc could set a variable, and a config it
// named would decide its own tier, as a GIT_DIR it set would have decided
// its own origin (chase-checkout refuses those for the same reason).
//
// Each section is its package's own Config, decoded strictly: a key the
// binary does not know is a setting that silently does not apply, and is
// refused instead.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/danielbodart/chase/internal/apps/claude"
	"github.com/danielbodart/chase/internal/apps/codex"
	"github.com/danielbodart/chase/internal/gcloud"
	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/record"
	"github.com/danielbodart/chase/internal/selector"
	"github.com/danielbodart/chase/internal/session"
)

// Default is where the module installs the file.
const Default = "/etc/chase/config.json"

// Config is the whole file.
type Config struct {
	// Selector is what sorts a checkout into a tier, and what launches a
	// session of each: chase.order, chase.fallback and chase.tiers, with
	// the git every git call runs.
	Selector selector.Config `json:"selector"`

	// Wrappers are the agents a person runs on the host, by the name they
	// run them as (claude, codex, deepsec): what runs for a bare tier.
	// `chase shell` is one too, and needs no entry.
	Wrappers map[string]Wrapper `json:"wrappers,omitempty"`

	// Claude is Claude Code's login refresher and its workspace trust, when
	// the module enables it.
	Claude *claude.Config `json:"claude,omitempty"`

	// Codex is Codex's login refresher and its placeholder login, when the
	// module enables it.
	Codex *codex.Config `json:"codex,omitempty"`

	// GCloudRenew is the Google Cloud token renewer's: empty, but for a
	// check that points it at a fake token endpoint.
	GCloudRenew gcloud.Config `json:"gcloudRenew,omitzero"`

	// Session is what a sandbox tier's sessions are given on the host
	// before they start: flong's binds.
	Session session.Config `json:"session"`

	// Grant is how a checkout's own grant is approved and applied,
	// for the tiers that take one.
	Grant *grant.Config `json:"grant,omitempty"`

	// GrantTiers are the tiers that take a checkout's grant.
	GrantTiers []string `json:"grantTiers,omitempty"`

	// Record is `chase record`'s, when any tier records: the tools it
	// runs, and what each recording tier's filter allows.
	Record *record.Config `json:"record,omitempty"`
}

// Wrapper is what one agent runs as on a bare tier.
type Wrapper struct {
	// HostCommand is the agent's argv on the host, before the person's own
	// arguments, its program an absolute path.
	HostCommand []string `json:"hostCommand"`
}

// Load reads the file at path.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := decode(b, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Selector.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: selector: %w", path, err)
	}
	for name, t := range c.Session.Tiers {
		if t.Nix != nil {
			if err := t.Nix.Validate(); err != nil {
				return Config{}, fmt.Errorf("%s: session: %s: %w", path, name, err)
			}
		}
	}
	if c.Grant != nil {
		if err := grant.Validate(*c.Grant, grant.DefaultApps(*c.Grant, io.Discard)); err != nil {
			return Config{}, fmt.Errorf("%s: grant: %w", path, err)
		}
	}
	if c.Record != nil {
		if err := c.Record.Validate(); err != nil {
			return Config{}, fmt.Errorf("%s: record: %w", path, err)
		}
	}
	for name, w := range c.Wrappers {
		if len(w.HostCommand) == 0 || w.HostCommand[0] == "" || w.HostCommand[0][0] != '/' {
			return Config{}, fmt.Errorf("%s: wrapper %q runs no absolute program", path, name)
		}
	}
	return c, nil
}

func decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("more than one JSON value")
	}
	return nil
}
