package appcmd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// A registered command runs with its own section, decoded strictly from
// its dotted key; an app or command that is not registered, or no command
// at all, is a usage and 2; a section that is absent or null is none.
func TestRunGivesACommandItsSection(t *testing.T) {
	type cfg struct {
		Name string `json:"name"`
	}
	var got cfg
	var had bool
	Register("test-app", "grant.test", map[string]Command{
		"show": {Help: "shows", Run: func(_ context.Context, s Section, args []string, _ io.Writer) int {
			var err error
			got = cfg{}
			if had, err = s(&got); err != nil {
				return 3
			}
			return len(args)
		}},
	})
	defer delete(apps, "test-app")
	var stderr bytes.Buffer
	if rc := Run(context.Background(), []byte(`{"grant":{"test":{"name":"x"}}}`), []string{"test-app", "show", "a"}, &stderr); rc != 1 || !had || got.Name != "x" {
		t.Errorf("rc %d had %v got %+v", rc, had, got)
	}
	for _, c := range []string{`{"grant":{"test":null}}`, `{"grant":{}}`, `{}`} {
		if rc := Run(context.Background(), []byte(c), []string{"test-app", "show"}, &stderr); rc != 0 || had {
			t.Errorf("%s: rc %d had %v", c, rc, had)
		}
	}
	if rc := Run(context.Background(), []byte(`{"grant":{"test":{"name":"x","extra":1}}}`), []string{"test-app", "show"}, &stderr); rc != 3 {
		t.Errorf("an unknown key was decoded: %d", rc)
	}
	for _, args := range [][]string{nil, {"test-app"}, {"nope", "show"}, {"test-app", "nope"}} {
		stderr.Reset()
		if rc := Run(context.Background(), []byte(`{}`), args, &stderr); rc != 2 || !strings.Contains(stderr.String(), "test-app show") {
			t.Errorf("%q: rc %d said %q", args, rc, stderr.String())
		}
	}
}
