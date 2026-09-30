package codex

import (
	"errors"
	"os"
	"strings"

	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/jsonfile"
	"golang.org/x/sys/unix"
)

// WritePlaceholder writes the placeholder auth.json, made from the host's
// login: codex decides what to offer from the plan and account claims in the
// id_token, and sends account_id as the ChatGPT-Account-ID header, so those
// are the host's own. Only the tokens are replaced. The id_token keeps its
// claims and loses its signature, which nothing checks.
//
// Logged in on the host or not, the file must exist: flong refuses to start
// when a bind's source is missing. So no auth.json is a placeholder with
// empty claims, and only an auth.json that is not JSON codex could have
// written is an error, which leaves the last placeholder as it was.
//
// Written in place, never by rename: a container binds this file over its
// own auth.json, and a rename over a mountpoint detaches that bind in every
// other namespace -- which would uncover whatever is underneath.
func WritePlaceholder(cfg Config) error {
	if err := os.MkdirAll(cfg.StateDir, 0o777); err != nil {
		return err
	}
	var real any
	if fi, err := os.Stat(cfg.Auth); err == nil && fi.Mode().IsRegular() {
		b, err := os.ReadFile(cfg.Auth)
		if err != nil {
			return err
		}
		if real, err = jsonfile.Decode(b); err != nil {
			return err
		}
	}
	out, err := placeholder(real)
	if err != nil {
		return err
	}
	// An existing file keeps its mode through a write in place, so it is
	// made 0600 first -- before it holds the host's claims, where the script
	// chmodded after -- and through the file it opened, never through a
	// path looked up again, which a link swapped in between would redirect.
	if err := tighten(cfg.Placeholder); err != nil {
		return err
	}
	return files.WriteInPlace(cfg.Placeholder, out, 0o600)
}

// tighten makes path 0600, creating it empty if it is not there, by the
// file it opens and not by its name, and follows no link at path.
func tighten(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// auth is the placeholder auth.json. A struct and not a map, since it is
// made whole rather than edited: only what is named here is written, so
// nothing else of the host's login -- its real tokens least of all -- can
// reach a container through it. auth_mode, account_id and last_refresh are
// the host's own, whatever JSON they are, and are carried as they were read.
type auth struct {
	AuthMode     any    `json:"auth_mode"`
	OpenAIAPIKey any    `json:"OPENAI_API_KEY"`
	Tokens       tokens `json:"tokens"`
	LastRefresh  any    `json:"last_refresh"`
}

type tokens struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    any    `json:"account_id"`
}

// errNotLogin is a host auth.json that is not the shape codex writes: not
// an object, tokens not one, or an id_token that is not a string.
var errNotLogin = errors.New("auth.json is not a codex login: not an object, or tokens not one, or tokens.id_token not a string")

// placeholder is the placeholder made from the host's login r, null for
// none. A member that is missing, null or false takes its default.
func placeholder(r any) ([]byte, error) {
	root, ok := jsonfile.Object(r)
	if !ok {
		return nil, errNotLogin
	}
	toks, ok := jsonfile.Object(root["tokens"])
	if !ok {
		return nil, errNotLogin
	}
	idToken, ok := jsonfile.Or(toks["id_token"], "").(string)
	if !ok {
		return nil, errNotLogin
	}
	// The signature dropped, the claims kept. No id_token is no claims, and
	// the placeholder's is the signature alone.
	var parts []string
	if idToken != "" {
		parts = strings.Split(idToken, ".")
	}
	if len(parts) > 2 {
		parts = parts[:2]
	}
	parts = append(parts, "frisket")
	return jsonfile.Encode(auth{
		AuthMode: jsonfile.Or(root["auth_mode"], "chatgpt"),
		Tokens: tokens{
			IDToken:      strings.Join(parts, "."),
			AccessToken:  PlaceholderJWT,
			RefreshToken: "frisket-placeholder",
			AccountID:    jsonfile.Or(toks["account_id"], ""),
		},
		LastRefresh: jsonfile.Or(root["last_refresh"], "2000-01-01T00:00:00Z"),
	})
}
