module github.com/danielbodart/chase

// frisket's floor, for the same reason: both nixpkgs branches in play ship
// 1.26, and a patch release of it satisfies 1.26.0.
go 1.26.0

require (
	github.com/danielbodart/frisket v0.103.64-0.20261002142119-fc6ed4d78b51
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f
	github.com/vektah/gqlparser/v2 v2.5.58
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
	google.golang.org/protobuf v1.36.11
	pgregory.net/rapid v1.3.0
)

require golang.org/x/net v0.59.0 // indirect
