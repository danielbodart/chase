package ssh

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/policy"
)

// Operation is one of the catalogue's, apps/ssh/operations.json: what a
// command is, in words a person is shown, and how a tier answers it by its
// class (lib/operations.nix). Hand-written and reviewed, as docker's
// admit.json is: no machine publishes a description of its commands.
//
// An operation is either its Commands, each a frisket command pattern, or
// Args, globs that make those of its Commands with an argument one matches
// -- or, with no Commands, every command -- stricter. An arg operation only
// ever tightens: it is a rule only where it is answered "ask" or "refuse",
// and never a read.
type Operation struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Class    string `json:"class"`
	Category string `json:"category"`
	// Commands are frisket patterns: literal words, `*` for one word,
	// and `**` last for any number of them.
	Commands []string `json:"commands,omitempty"`
	// Args are frisket arg globs, whose `*` never crosses a `/`. Several,
	// because one flag has several spellings -- clustered, abbreviated,
	// after an `=` -- and is one operation all the same, which a grant
	// names once.
	Args []string `json:"args,omitempty"`
	// Description says why an operation is drawn where it is, for the
	// person reading the catalogue and the one asked about it.
	Description string `json:"description,omitempty"`
}

// The catalogue's classes, as every app's (lib/operations.nix), and its
// categories, a closed list so that a grant's category:<name> is a name
// the catalogue has rather than one misspelt.
var (
	classes    = []string{"read", "write", "guarded"}
	categories = []string{"navigate", "read", "search", "status", "processes", "logs", "services", "network", "packages", "containers", "files", "admin", "secrets"}
)

// idPattern is an operation's id: kebab-case, so that it is never a
// command pattern, which a grant tells apart by a space or a `*`.
var idPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// LoadCatalogue reads the catalogue strictly and checks it whole: a
// misspelt key is an operation that silently does nothing, and a pattern
// or glob frisket would refuse is a session that does not start.
func LoadCatalogue(path string) ([]Operation, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ops []Operation
	if err := policy.Decode(b, &ops); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := CheckCatalogue(ops); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ops, nil
}

// CheckCatalogue is what the catalogue must be for every rule made of it to
// be one frisket loads, and for a grant's names to mean one thing each:
// each id once, each command pattern in one operation, each arg glob once
// for each command it tightens.
func CheckCatalogue(ops []Operation) error {
	ids := map[string]bool{}
	commands := map[string]string{}
	args := map[string]string{}
	for i, o := range ops {
		at := fmt.Sprintf("operation %d (%s)", i, o.ID)
		switch {
		case !idPattern.MatchString(o.ID):
			return fmt.Errorf("%s: id %q is not kebab-case", at, o.ID)
		case ids[o.ID]:
			return fmt.Errorf("%s: id %q is another operation's", at, o.ID)
		case o.Summary == "":
			return fmt.Errorf("%s: no summary", at)
		case !slices.Contains(classes, o.Class):
			return fmt.Errorf("%s: class %q is not one of %s", at, o.Class, strings.Join(classes, ", "))
		case !slices.Contains(categories, o.Category):
			return fmt.Errorf("%s: category %q is not one of %s", at, o.Category, strings.Join(categories, ", "))
		case len(o.Commands) == 0 && len(o.Args) == 0:
			return fmt.Errorf("%s: no commands and no args", at)
		case len(o.Args) > 0 && o.Class == "read":
			// A read is allowed, and an arg rule that allowed would
			// admit whatever else the command said.
			return fmt.Errorf("%s: an arg operation only tightens, so it is never a read", at)
		}
		ids[o.ID] = true
		for _, p := range o.Commands {
			if err := CheckPattern(p); err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
		}
		if len(o.Args) == 0 {
			for _, p := range o.Commands {
				if other, ok := commands[p]; ok {
					return fmt.Errorf("%s: %q is %s's too", at, p, other)
				}
				commands[p] = o.ID
			}
			continue
		}
		for _, g := range o.Args {
			if err := CheckGlob(g); err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			for _, name := range argNames(o.Commands, g) {
				if other, ok := args[name]; ok {
					return fmt.Errorf("%s: %s is %s's too", at, name, other)
				}
				args[name] = o.ID
			}
		}
	}
	return nil
}

// argNames are the names frisket gives the arg rules of one glob: `<pattern>
// [arg <glob>]` for each command, or `[arg <glob>]` alone, and two rules of
// one name are refused.
func argNames(commands []string, glob string) []string {
	if len(commands) == 0 {
		return []string{"[arg " + glob + "]"}
	}
	names := make([]string, len(commands))
	for i, c := range commands {
		names[i] = c + " [arg " + glob + "]"
	}
	return names
}

// CheckPattern is whether p is a command pattern frisket loads, by
// frisket's own reading (its execrule), held to it here, before a grant is
// approved, rather than when a session fails to start.
func CheckPattern(p string) error {
	_, err := execrule.Compile(policy.SSHRoute{Exec: []policy.ExecRule{{Command: p}}})
	if err != nil {
		return fmt.Errorf("pattern %q: %w", p, cause(err))
	}
	return nil
}

// CheckGlob is whether g is an arg glob frisket loads, by its own reading.
func CheckGlob(g string) error {
	if g == "" {
		return errors.New("an empty arg glob")
	}
	_, err := execrule.Compile(policy.SSHRoute{Exec: []policy.ExecRule{{Arg: g, Refuse: true}}})
	if err != nil {
		return fmt.Errorf("arg glob %w", cause(err))
	}
	return nil
}

// cause is why frisket refused a rule, less the rule's name it puts first,
// which the caller says as the catalogue or the grant has it.
func cause(err error) error {
	if u := errors.Unwrap(err); u != nil {
		return u
	}
	return err
}
