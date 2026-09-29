package generate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// The version, DERIVED from the repository rather than stored in it.
//
// Only the MAJOR is committed (in ./VERSION) -- it is the one part that is a
// deliberate decision, and 0 says the option interface is still moving.
// MINOR is the commit count, so it only ever rises and names exactly one
// commit. PATCH is the CI run number, or a local timestamp, separating two
// builds of the same commit -- a re-run or a manual build -- and making a
// developer build sort after CI's and obviously not one of CI's.
//
// (Scheme from mogwai-db and dragoman, which lifted it from tidewaiter. It
// was shell, as nothing else here needed a runtime; now chase is Go, it is
// Go, and the git binary is still what counts.)

// VersionOptions is where, and when, a version is derived.
type VersionOptions struct {
	// Dir is inside the repository; "" is the working directory.
	Dir string
	// Getenv reads GITHUB_RUN_NUMBER; nil is os.Getenv.
	Getenv func(string) string
	// Now is the local build's time; nil is time.Now.
	Now func() time.Time
}

// Version is MAJOR.MINOR.PATCH, with its newline, for the repository at
// o.Dir; or it refuses a shallow clone, whose commit count is wrong.
func Version(o VersionOptions) (string, error) {
	getenv, now := o.Getenv, o.Now
	if getenv == nil {
		getenv = os.Getenv
	}
	if now == nil {
		now = time.Now
	}
	// The script read "$(git rev-parse --show-toplevel)/VERSION": where
	// git failed, outside a repository, that is /VERSION, which the
	// redirect failed to open, and so the script's status was 1 rather
	// than git's.
	top, gitErr := gitOutput(o.Dir, "rev-parse", "--show-toplevel")
	data, err := os.ReadFile(top + "/VERSION")
	if err != nil {
		if gitErr != nil {
			return "", &ExitError{Code: 1, Err: gitErr}
		}
		return "", &ExitError{Code: 1, Err: fmt.Errorf("version: %w", err)}
	}
	major := strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \t\n\v\f\r", r) {
			return -1
		}
		return r
	}, string(data))

	// Counted from HEAD, not a branch name: on Actions the checkout is
	// detached, and a pull request ref is not a rev at all.
	// A failure here was only a comparison with "true" that did not hold,
	// as it was in the script's test.
	shallow, _ := gitOutput(o.Dir, "rev-parse", "--is-shallow-repository")
	if shallow == "true" {
		return "", exitf(1, "version: shallow clone, so the commit count and the version are wrong.\n         In Actions, check out with `fetch-depth: 0`.")
	}
	minor, err := gitOutput(o.Dir, "rev-list", "--count", "HEAD")
	if err != nil {
		return "", err
	}
	patch := getenv("GITHUB_RUN_NUMBER")
	if patch == "" {
		patch = now().UTC().Format("20060102150405")
	}
	return fmt.Sprintf("%s.%s.%s\n", major, minor, patch), nil
}

// gitOutput is what git prints, less its trailing newlines, as $(...) took
// it; a failure carries what git said and git's own status.
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		code := 1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		msg := strings.TrimRight(stderr.String(), "\n")
		if msg == "" {
			msg = err.Error()
		}
		return "", &ExitError{Code: code, Err: fmt.Errorf("version: git %s: %s", strings.Join(args, " "), msg)}
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// RunVersion is `chase-generate version`: what scripts/version.sh printed.
// Like the script, it takes no arguments and ignores any it is given.
func RunVersion(args []string, stdout io.Writer) error {
	v, err := Version(VersionOptions{})
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, v)
	return err
}
