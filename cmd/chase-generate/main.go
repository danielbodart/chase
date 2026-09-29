// Command chase-generate regenerates what chase reads but does not derive at
// run time, from what its providers publish, and derives the version CI
// publishes. It is for a person in `nix develop` and for CI, never for the
// NixOS module: it alone reads YAML and GraphQL, and nothing in cmd/chase
// imports what it does.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/danielbodart/chase/internal/generate"
	"github.com/danielbodart/chase/internal/term"
)

const usage = `chase-generate -- what chase reads, generated from what its providers publish

  chase-generate operations [-apps DIR] APP [path/to/spec]
        An app's classification, apps/APP/operations.json -- and for an
        admitted app, known.json -- generated from the spec its source.json
        pins by hash: the one given, else the app's vendored one, else the
        pinned URL. Refuses a spec that does not hash as pinned, and every
        exception, rule or admission that does not fit it. DIR is where the
        apps are; without it, the checkout's apps.

  chase-generate version
        The version: MAJOR from ./VERSION, MINOR the commit count, PATCH the
        CI run number or a local timestamp. Refuses a shallow clone.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "operations":
		err = generate.RunOperations(ctx, args, os.Stderr)
	case "version":
		err = generate.RunVersion(args, os.Stdout)
	// INTEGRATION: the `gcloud` subcommand (scripts/gcloud.sh and
	// scripts/gcloud.py, ported to internal/generate/gcloud) is wired here,
	// and described in usage above.
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "chase-generate: unknown command %q\n\n%s", term.Clean(os.Args[1]), usage)
		os.Exit(2)
	}
	if err != nil {
		stop()
		code := 1
		var ee *generate.ExitError
		if errors.As(err, &ee) {
			code = ee.Code
			if errors.Is(ee.Err, flag.ErrHelp) {
				os.Exit(code)
			}
		}
		fmt.Fprint(os.Stderr, term.Clean(err.Error())+"\n")
		os.Exit(code)
	}
}
