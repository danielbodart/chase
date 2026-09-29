package generate

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
)

// RunOperations is `chase-generate operations [-apps DIR] APP [path/to/spec]`:
// what `scripts/operations.sh APP [path/to/spec]` was. The script found the
// apps beside itself, at ../apps; a binary has no such place, so -apps names
// the directory, and without it the apps are those of the checkout it is run
// in -- the nearest directory, from the working one up, that holds both
// go.mod and apps.
func RunOperations(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("operations", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apps := fs.String("apps", "", "the directory of each app's source.json and the rest (default: the checkout's apps)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return &ExitError{Code: 2, Err: err}
		}
		return exitf(2, "usage: chase-generate operations [-apps DIR] APP [path/to/spec]")
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return exitf(2, "usage: chase-generate operations [-apps DIR] APP [path/to/spec]")
	}
	dir := *apps
	if dir == "" {
		found, err := checkoutApps()
		if err != nil {
			return err
		}
		dir = found
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return exitf(2, "operations: %v", err)
	}
	return Operations(ctx, OperationsOptions{
		Apps: abs, Name: fs.Arg(0), Spec: fs.Arg(1), Stderr: stderr,
	})
}

// checkoutApps is the apps directory of the checkout the working directory
// is in.
func checkoutApps() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", exitf(2, "operations: %v", err)
	}
	for {
		if isFile(filepath.Join(dir, "go.mod")) {
			if fi, err := os.Stat(filepath.Join(dir, "apps")); err == nil && fi.IsDir() {
				return filepath.Join(dir, "apps"), nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", exitf(2, "operations: no apps directory beside a go.mod here or above: run it in a checkout, or say -apps DIR")
		}
		dir = parent
	}
}
