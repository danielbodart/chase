package codex

import (
	"fmt"
	"os"
	"strings"

	"github.com/danielbodart/chase/internal/apps/claude/jsondoc"
	"github.com/danielbodart/chase/internal/files"
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
	real := jsondoc.Obj()
	if fi, err := os.Stat(cfg.Auth); err == nil && fi.Mode().IsRegular() {
		b, err := os.ReadFile(cfg.Auth)
		if err != nil {
			return err
		}
		if real, err = jsondoc.Parse(b); err != nil {
			return err
		}
	}
	out, err := placeholder(real)
	if err != nil {
		return err
	}
	if err := files.WriteInPlace(cfg.Placeholder, append(out, '\n'), 0o600); err != nil {
		return err
	}
	// An existing file keeps its mode through a write in place.
	return os.Chmod(cfg.Placeholder, 0o600)
}

// placeholder is the placeholder made from the host's login r.
func placeholder(r jsondoc.Value) ([]byte, error) {
	authMode, err := r.Field("auth_mode")
	if err != nil {
		return nil, err
	}
	tokens, err := r.Field("tokens")
	if err != nil {
		return nil, err
	}
	idToken, err := tokens.Field("id_token")
	if err != nil {
		return nil, err
	}
	idToken = idToken.Or(jsondoc.Str(""))
	if idToken.Kind != jsondoc.String {
		return nil, errNotString("tokens.id_token", idToken)
	}
	accountID, err := tokens.Field("account_id")
	if err != nil {
		return nil, err
	}
	lastRefresh, err := r.Field("last_refresh")
	if err != nil {
		return nil, err
	}
	// The signature dropped, the claims kept.
	parts := jsondoc.Split(idToken.Str, ".")
	if len(parts) > 2 {
		parts = parts[:2]
	}
	parts = append(parts, "frisket")
	doc := jsondoc.Obj(
		jsondoc.Member{Key: "auth_mode", Value: authMode.Or(jsondoc.Str("chatgpt"))},
		jsondoc.Member{Key: "OPENAI_API_KEY", Value: jsondoc.Value{Kind: jsondoc.Null}},
		jsondoc.Member{Key: "tokens", Value: jsondoc.Obj(
			jsondoc.Member{Key: "id_token", Value: jsondoc.Str(strings.Join(parts, "."))},
			jsondoc.Member{Key: "access_token", Value: jsondoc.Str(PlaceholderJWT)},
			jsondoc.Member{Key: "refresh_token", Value: jsondoc.Str("frisket-placeholder")},
			jsondoc.Member{Key: "account_id", Value: accountID.Or(jsondoc.Str(""))},
		)},
		jsondoc.Member{Key: "last_refresh", Value: lastRefresh.Or(jsondoc.Str("2000-01-01T00:00:00Z"))},
	)
	return doc.Marshal(), nil
}

// errNotString is jq's refusal to split what is not a string.
func errNotString(what string, v jsondoc.Value) error {
	return fmt.Errorf("%s is a %s, not a string", what, v.Kind)
}
