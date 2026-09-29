// Package gcloud is Google Cloud as a project binds it (docs/gcloud.md): at
// launch, the tier's APIs and the project's changes to them, answered as the
// tier says; the session's own key, made once and never the real one; the
// first token, and the renewer that keeps it; and the routes that carry it.
//
// The real key, the project's, is at RUN/secrets/gcloud, decrypted by the
// launch. It never leaves RUN: the renewer signs with it, and a session sees
// only the key chase made for it.
package gcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/apps"
	renew "github.com/danielbodart/chase/internal/gcloud"
	"github.com/danielbodart/chase/internal/term"
)

// Units starts and stops the user's systemd units: systemctl --user, or a
// check's stand-in.
type Units interface {
	Start(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
}

// Systemctl is Units as `systemctl --user`, with XDG_RUNTIME_DIR set, which
// is how both hooks reach the user's manager: postStop's environment does
// not have it (measured).
type Systemctl struct {
	// Path is the systemctl to run.
	Path string
	// RuntimeDir is the user's runtime directory, /run/user/<uid>.
	RuntimeDir string
	// Output is where what systemctl says goes, never the patch.
	Output io.Writer
}

func (s Systemctl) Start(ctx context.Context, unit string) error { return s.run(ctx, "start", unit) }
func (s Systemctl) Stop(ctx context.Context, unit string) error  { return s.run(ctx, "stop", unit) }

func (s Systemctl) run(ctx context.Context, verb, unit string) error {
	cmd := exec.CommandContext(ctx, s.Path, "--user", verb, unit)
	cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+s.RuntimeDir)
	cmd.Stdout, cmd.Stderr = s.Output, s.Output
	return cmd.Run()
}

// Minter mints a session's first token, as renew.Mint does: sa is the
// service account the key at RUN/secrets/gcloud must be for.
type Minter func(ctx context.Context, run, sa string) renew.Outcome

// App is Google Cloud as an apps.App.
type App struct {
	Config Config
	// Stderr is where the launch's person is told what happened: an API
	// binding ignored, Google out of reach, and what the minter says.
	Stderr io.Writer
	// Units starts and stops the renewer. Nil is Systemctl, from Config.
	Units Units
	// Mint mints the first token. Nil is renew.Mint, at Config.TokenURL.
	Mint Minter
}

var _ apps.App = (*App)(nil)

// New is the App the launch runs, with systemctl and Google's own endpoint.
func New(cfg Config, stderr io.Writer) *App {
	return &App{Config: cfg, Stderr: stderr}
}

func (a *App) units() Units {
	if a.Units != nil {
		return a.Units
	}
	return Systemctl{Path: a.Config.Systemctl, RuntimeDir: a.Config.RuntimeDir, Output: a.Stderr}
}

func (a *App) mint(ctx context.Context, run, sa string) renew.Outcome {
	if a.Mint != nil {
		return a.Mint(ctx, run, sa)
	}
	return renew.Mint(ctx, renew.Config{TokenURL: a.Config.TokenURL}, run, sa, a.Stderr)
}

// renewer is the renewer's unit for a session: `chase-gcloud-renew@<machine>`,
// one per session, started by its launch and stopped before its run
// directory is removed.
func renewer(machine string) string { return "chase-gcloud-renew@" + machine + ".service" }

// refusal is Google's own error envelope, which its clients read.
var refusal = policy.Refusal{
	ContentType: "application/json",
	Body:        `{"error":{"code":403,"message":"{{message}}","status":"PERMISSION_DENIED"}}`,
}

// grants are where a Google client trades an assertion its key signed for a
// token: frisket answers them itself, with the placeholder. Node's storage
// library uses the second, whatever the key file says.
var grants = []string{"oauth2.googleapis.com/token", "www.googleapis.com/oauth2/v4/token"}

// Prepare makes the session's Google routes from its binding. An error ends
// the launch, and reads as the script's refusal did, "<workspace>: gcloud:
// <why>", for the caller to say after "chase: ".
func (a *App) Prepare(ctx context.Context, r apps.Request) (apps.Patch, error) {
	die := func(format string, args ...any) (apps.Patch, error) {
		return apps.Patch{}, fmt.Errorf("%s: gcloud: %s", r.Workspace, fmt.Sprintf(format, args...))
	}
	machine := filepath.Base(r.Run)
	real := filepath.Join(r.Run, "secrets", "gcloud")

	s, ok := a.Config.Tiers[r.Tier]
	if !ok {
		// A tier without Google keeps no Google secret: the launch
		// decrypted it before it knew.
		term.Say(a.Stderr, "%s: gcloud ignored: %s has no gcloud", r.Workspace, r.Tier)
		os.Remove(real)
		return apps.Patch{}, nil
	}

	var binding map[string]json.RawMessage
	json.Unmarshal(r.Binding, &binding)
	sa := jqRaw(binding["serviceAccount"])
	if sa == "" {
		return die("no serviceAccount: say which service account the key is for")
	}
	var key map[string]json.RawMessage
	if b, err := os.ReadFile(real); err != nil || json.Unmarshal(b, &key) != nil || key == nil ||
		jqRaw(key["type"]) != "service_account" || !isJSONString(key["type"]) || !isJSONString(key["private_key"]) {
		return die("the secret is not a service-account key")
	}
	email := jqRaw(key["client_email"])
	if email != sa {
		return die("the key is for '%s', not %s", email, sa)
	}
	project := jqRaw(key["project_id"])

	known, err := known(a.Config.Catalogue)
	if err != nil {
		return die("%v", err)
	}
	c, err := changes(binding)
	if err != nil {
		return die("its APIs do not resolve: %v", err)
	}
	selected, err := resolve(s.APIs, c, known)
	if err != nil {
		return die("its APIs do not resolve: %v", err)
	}
	var carried []policy.PathRule
	for _, api := range selected {
		rules, err := rulesOf(filepath.Join(a.Config.Catalogue, "apis", api+".json"))
		if err != nil {
			return die("%v", err)
		}
		carried = append(carried, rules...)
	}
	floor, err := Floor(a.Config.Catalogue)
	if err != nil {
		return die("%v", err)
	}
	rules := paths(s, a.Config.Every, carried, floor)

	keyFile, public, err := sessionKey(r.EnvDir, email, project)
	if err != nil {
		return die("the session's key: %v", err)
	}

	// A first token before the session starts, and a renewer for as long
	// as it runs. Google refusing the key ends the launch; Google out of
	// reach does not, since the renewer keeps trying.
	switch rc := a.mint(ctx, r.Run, sa); rc {
	case renew.Minted:
	case renew.Transient:
		term.Say(a.Stderr, "%s: gcloud: no token yet, Google did not answer; the renewer keeps trying", r.Workspace)
	case renew.Refused:
		return die("Google refused %s's key: was it deleted or disabled?", sa)
	case renew.BadKey:
		return die("the key is not %s's", sa)
	default:
		return die("the renewer failed (%d)", rc)
	}
	if err := a.units().Start(ctx, renewer(machine)); err != nil {
		return die("could not start chase-gcloud-renew@%s", machine)
	}

	unmatched := "refuse"
	if s.Unmatched == "ask" {
		unmatched = "ask"
	}
	return apps.Patch{
		Routes: []policy.Route{
			{
				Name:           "gcloud",
				Host:           "*.googleapis.com",
				Upstream:       "https://*.googleapis.com",
				CredentialFile: filepath.Join(r.Run, "gcloud-token.json"),
				CredentialJSON: &policy.CredentialJSON{Token: "access_token", ExpiresMillis: "expiry"},
				Placeholder:    a.Config.Placeholder,
				SessionKey:     &policy.SessionKey{PublicKey: public, Issuer: sa, Grants: append([]string(nil), grants...)},
				Paths:          rules,
				Unmatched:      unmatched,
				Refusal:        &policy.Refusal{ContentType: refusal.ContentType, Body: refusal.Body},
			},
			// Those hosts want a client certificate frisket does not have,
			// and they are aliases the path rules must not be the only
			// thing guarding (docs/gcloud.md, decision 6).
			{
				Name:      "gcloud-mtls",
				Host:      "*.mtls.googleapis.com",
				Upstream:  "https://*.mtls.googleapis.com",
				Paths:     []policy.PathRule{{Methods: append([]string(nil), a.Config.Every...), Prefix: "/", Refuse: true}},
				Unmatched: "refuse",
			},
		},
		Allow: []string{"*.googleapis.com"},
		Env: map[string]string{
			"GOOGLE_APPLICATION_CREDENTIALS": keyFile,
			// gcloud reads only this.
			"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": keyFile,
		},
	}, nil
}

// Stop stops the session's renewer, if it had one: a session whose launch
// kept a Google secret.
func (a *App) Stop(ctx context.Context, machine string) error {
	if _, err := os.Stat(filepath.Join(a.Config.RuntimeDir, "chase", machine, "secrets", "gcloud")); err != nil {
		return nil
	}
	return a.units().Stop(ctx, renewer(machine))
}

// jqRaw is a value as `jq -r '.x // empty'` printed it into a command
// substitution: nothing for absent, null or false; a string as itself;
// anything else as jq's JSON; and no newline at the end, which the
// substitution drops.
func jqRaw(raw json.RawMessage) string {
	if absent(raw) {
		return ""
	}
	var s string
	if isJSONString(raw) {
		json.Unmarshal(raw, &s)
	} else if t := bytes.TrimSpace(raw); len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		var b bytes.Buffer
		if json.Indent(&b, t, "", "  ") != nil {
			return string(t)
		}
		s = b.String()
	} else {
		s = string(t)
	}
	return strings.TrimRight(s, "\n")
}

func isJSONString(raw json.RawMessage) bool {
	var s string
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '"' && json.Unmarshal(t, &s) == nil
}
