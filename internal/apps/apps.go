// Package apps is what an app becomes when a project binds it, for the apps
// whose routes are made at launch rather than written by the module: Docker,
// whose route names the project's own address and images, Google Cloud,
// whose route carries a session key minted for the checkout, and SSH, whose
// routes are the machines the project's grant names.
//
// Each such app is Go, called in the launch's own process: it was a program
// of its own only because each app module built a script, and nothing about
// privilege changes between the launch and an app (PLAN.md, decision 2).
// What an app still reaches outside the process -- Google's token endpoint,
// systemd -- it reaches as it always did.
package apps

import (
	"context"
	"encoding/json"

	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/session"
)

// Request is what an app is prepared from: which session, where it may keep
// what it makes, and what the project's approved grant binds it to.
type Request struct {
	// Tier is the session's tier, whose routes and settings apply.
	Tier string
	// Workspace is the checkout the session is of.
	Workspace string
	// Run is the session's own directory, /run/user/<uid>/chase/<machine>,
	// which no session sees: the app's decrypted secret is at
	// Run/secrets/<app>, and anything it makes that holds a secret goes here.
	Run string
	// Dir is the checkout's own directory on the host, bound into no
	// session, where an app keeps what must outlive one launch. What a
	// session needs of it is a file of the Patch's, seeded into its home.
	Dir string
	// Home is the user's home, which a session has at the same path: where
	// a Patch's files are seeded, and what its variables name them by.
	Home string
	// Project is the Docker project approved for the checkout, from its
	// origin and never from anything its grant says; empty if its
	// grant binds no Docker.
	Project string
	// Binding is the app's binding, as the approved grant holds it.
	Binding json.RawMessage
}

// Patch is what an app adds to the session's policy document, its
// environment and its home. Its routes, and its SSH routes, replace any of
// the same name the tier had.
type Patch struct {
	Routes []policy.Route    `json:"routes,omitempty"`
	SSH    []policy.SSHRoute `json:"ssh,omitempty"`
	Allow  []string          `json:"allow,omitempty"`
	Env    map[string]string `json:"env,omitempty"`
	// Files are seeded into the session's home (see session.File).
	Files []session.File `json:"-"`
}

// App is an app whose routes are made at launch. An error from Prepare ends
// the launch: a grant is applied whole or the session does not start.
type App interface {
	Prepare(ctx context.Context, r Request) (Patch, error)
	// Stop releases what Prepare started, when the session ends, before
	// its Run directory is removed.
	Stop(ctx context.Context, machine string) error
}
