package generate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/term"
)

// Each case under testdata/parity is an app -- a source.json, a spec, and
// what exceptions.json, admit.json and schema.graphql it has -- with what
// scripts/operations.sh did with it, recorded before the port: its exit
// status, what it said (the app's directory as $APP), and the
// operations.json and known.json it left. The port must do the same, byte
// for byte: the refusals word for word, and the edges jq and PyYAML have --
// YAML 1.1's booleans, octals and merge keys, number literals as jq prints
// them, a GraphQL field with an empty description, a hand rule that is the
// same operation as the spec's -- as they had them. Where the script stopped
// with an error of jq's own or a Python traceback, only the status is
// held: those words were never the script's.
func TestParity(t *testing.T) {
	root := filepath.Join("testdata", "parity")
	cases, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no parity cases")
	}
	for _, c := range cases {
		name := c.Name()
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, name)
			apps := filepath.Join(t.TempDir(), "apps")
			app := filepath.Join(apps, name)
			copyDir(t, filepath.Join(dir, "app"), app)

			var stderr bytes.Buffer
			err := Operations(context.Background(), OperationsOptions{Apps: apps, Name: name, Stderr: &stderr})
			code := 0
			if err != nil {
				code = 1
				var ee *ExitError
				if errors.As(err, &ee) {
					code = ee.Code
				}
				stderr.WriteString(term.Clean(err.Error()) + "\n")
			}

			want := strings.TrimSpace(read(t, filepath.Join(dir, "exit")))
			if strconv.Itoa(code) != want {
				t.Fatalf("exit %d, want %s: %s", code, want, stderr.String())
			}
			if said, ok := readIf(t, filepath.Join(dir, "stderr")); ok {
				got := strings.ReplaceAll(stderr.String(), app, "$APP")
				if got != said {
					t.Fatalf("said\n%s\nwant\n%s", got, said)
				}
			}
			for _, f := range []string{"operations.json", "known.json"} {
				wantFile, wantOK := readIf(t, filepath.Join(dir, "want."+f))
				gotFile, gotOK := readIf(t, filepath.Join(app, f))
				if wantOK != gotOK {
					t.Fatalf("%s written: %v, want %v", f, gotOK, wantOK)
				}
				if gotFile != wantFile {
					t.Fatalf("%s:\n%s\nwant\n%s", f, gotFile, wantFile)
				}
			}
		})
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func readIf(t *testing.T, path string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data), true
}
