// Package projectaddr is a checkout's PROJECT ADDRESS as chase hands it on:
// the owner/repo slug its origin names, the loopback address of the
// project's own, and the .internal name that address is known by. Whatever
// serves the project on the host is bound there -- a session's dev-server
// forwards (flong's `forward:ADDRESS`) and the Docker app's published ports
// alike -- so two projects' servers on one port do not meet.
//
// None of it is derived here. It is frisket's feature, its package project:
// frisket answers the name, in a session's DNS and on the host, and refuses
// a Docker route whose address or names differ, so chase calls frisket's
// own public functions rather than keep a copy that could drift.
package projectaddr

import (
	"fmt"
	"strings"

	"github.com/danielbodart/frisket/project"
)

// Project is a project's address, as `chase project-address` prints it and
// the Docker prepare step puts it in a session's environment.
type Project struct {
	Project string   `json:"project"`
	Address string   `json:"address"`
	Names   []string `json:"names"`
}

// Of is the address of owner/repo, lower-cased. A slug frisket would refuse
// as a project is refused here too, so a checkout that would name
// one is refused when it is approved rather than when its session fails to
// start.
func Of(slug string) (Project, error) {
	p := lowerASCII(slug)
	if !project.Valid(p) {
		return Project{}, fmt.Errorf("%q is not owner/repo as frisket accepts it", slug)
	}
	names := project.Names(p)
	if names == nil {
		// A repo with no DNS label has no names, which is an empty list and
		// not a missing one.
		names = []string{}
	}
	return Project{Project: p, Address: project.Address(p).String(), Names: names}, nil
}

// IsName is whether name is a project's, as Of gives it: one frisket
// answers with that project's address, wherever it is asked.
func IsName(name string) bool {
	_, ok := project.FromName(name)
	return ok
}

// Reserved is whether name is, or is under, a name no project may take --
// frisket's own route hosts, the cloud's metadata service -- as frisket
// keeps the list.
func Reserved(name string) bool { return project.Reserved(name) }

// lowerASCII lower-cases ASCII only, as frisket and nix-config do: a slug
// with any other letter in it is not one frisket accepts, and folding it
// would name a different project.
func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}
