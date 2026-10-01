package grant

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/session"
)

// Only a session's own name is removed: an empty one would be every
// session's directory, and one with a '/' or a leading '.' something else.
func TestPostStopRemovesOnlyASessionsOwnDirectory(t *testing.T) {
	run := t.TempDir()
	for _, m := range []string{"strict-1-2", "strict-3-4"} {
		os.MkdirAll(filepath.Join(run, "chase", m, "secrets"), 0o700)
	}
	c := Config{Runtime: run}
	for _, bad := range []string{"", "a/b", "../x", ".grant"} {
		if err := PostStop(context.Background(), c, map[string]apps.App{}, bad); err == nil {
			t.Errorf("%q was taken for a session's name", bad)
		}
	}
	for _, m := range []string{"strict-1-2", "strict-3-4"} {
		if _, err := os.Stat(filepath.Join(run, "chase", m)); err != nil {
			t.Fatalf("%s was removed by a refused postStop", m)
		}
	}
	if err := PostStop(context.Background(), c, map[string]apps.App{}, "strict-1-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(run, "chase", "strict-1-2")); !os.IsNotExist(err) {
		t.Error("the session's own directory is still there")
	}
	if _, err := os.Stat(filepath.Join(run, "chase", "strict-3-4")); err != nil {
		t.Error("another session's directory went with it")
	}
}

// A binding's field that is a list or an object cannot be one variable's
// value: it has no one way to be a string.
func TestAnEnvFromGrantThatIsNotOneValueIsRefused(t *testing.T) {
	a := App{EnvFromGrant: map[string]string{"ACCOUNT": "accountId"}}
	for _, b := range []string{`{"accountId": ["a", "b"]}`, `{"accountId": {"x": 1}}`} {
		v, err := parseJSON([]byte(b))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := exportsOf(a, apps.Patch{}, v); err == nil {
			t.Errorf("%s was exported", b)
		}
	}
	// A string is itself, and a number or a boolean its JSON.
	for b, want := range map[string]string{`{"accountId": "0123"}`: "0123", `{"accountId": 1.50}`: "1.50", `{"accountId": true}`: "true"} {
		v, _ := parseJSON([]byte(b))
		if env, err := exportsOf(a, apps.Patch{}, v); err != nil || len(env) != 1 || env[0] != (session.Var{Name: "ACCOUNT", Value: want}) {
			t.Errorf("%s: %v, %v", b, env, err)
		}
	}
	// null is no variable at all.
	v, _ := parseJSON([]byte(`{"accountId": null}`))
	if env, err := exportsOf(a, apps.Patch{}, v); err != nil || len(env) != 0 {
		t.Errorf("null: %v, %v", env, err)
	}
}
