// Command chase decides which sandbox a checkout gets and what each app in it
// is given, and does, at launch, what the NixOS module cannot do by
// evaluating: read the checkout, ask about what it says, and compose the
// session's policy. The module decides what exists and wires it together;
// every hook it gives flong, and every unit it gives systemd, runs this.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/danielbodart/chase/internal/dockerproject"
)

// version is stamped at build time. A build without it says so rather than
// claiming a number.
var version = "dev"

const usage = `chase -- which sandbox a checkout gets, and which credential each app is given

  chase docker-address OWNER/REPO
        A project's Docker identity, as one line of JSON: its owner/repo
        lower-cased, the loopback address everything it publishes is bound
        to, and the .internal names that address is known by. Refuses a slug
        frisket would refuse as a route's project.

  chase version
        The version this binary was built as.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "docker-address":
		err = runDockerAddress(args, os.Stdout)
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "chase: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "chase %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func runDockerAddress(argv []string, out io.Writer) error {
	fs := flag.NewFlagSet("docker-address", flag.ContinueOnError)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: chase docker-address OWNER/REPO")
	}
	p, err := dockerproject.Of(fs.Arg(0))
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(p)
}
