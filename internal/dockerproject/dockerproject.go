// Package dockerproject is a project's Docker identity as chase hands it on:
// the owner/repo slug, the loopback address everything it publishes is bound
// to, and the .internal names that address is known by (docs/docker.md,
// decision 14).
//
// None of it is derived here. frisket derives the address and names again
// from a route's project and refuses a route whose values differ, so chase
// calls frisket's own public functions for them rather than keep a copy that
// could drift. Only lib/docker.nix derives them a second time, for what has
// nothing but Nix to evaluate -- nix-config writing /etc/hosts -- and the
// docker-address check holds it to what this package gives.
package dockerproject

import (
	"fmt"
	"strings"

	"github.com/danielbodart/frisket/docker"
)

// Project is a project's identity, as `chase docker-address` prints it and
// the Docker prepare step puts it in a session's environment.
type Project struct {
	Project string   `json:"project"`
	Address string   `json:"address"`
	Names   []string `json:"names"`
}

// Of is the identity of owner/repo, lower-cased. A slug frisket would refuse
// as a route's project is refused here too, so a checkout that would name
// one is refused when it is approved rather than when its session fails to
// start.
func Of(slug string) (Project, error) {
	p := lowerASCII(slug)
	if !docker.ValidProject(p) {
		return Project{}, fmt.Errorf("%q is not owner/repo as frisket accepts it", slug)
	}
	names := docker.Names(p)
	if names == nil {
		// A repo with no DNS label has no names, which is an empty list and
		// not a missing one.
		names = []string{}
	}
	return Project{Project: p, Address: docker.Address(p).String(), Names: names}, nil
}

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
