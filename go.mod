module github.com/danielbodart/chase

// frisket's floor, for the same reason: both nixpkgs branches in play ship
// 1.26, and a patch release of it satisfies 1.26.0.
go 1.26.0

require (
	github.com/danielbodart/frisket v0.85.49-0.20260929212139-5e0b9d5d07ec
	golang.org/x/sys v0.48.0
	google.golang.org/protobuf v1.36.11
	pgregory.net/rapid v1.3.0
)

require golang.org/x/net v0.59.0 // indirect
