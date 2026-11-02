module github.com/danielbodart/chase

// frisket's floor, for the same reason: chase builds with 1.27 (mise.toml,
// and go_1_27 in flake.nix), but nothing here needs more than 1.26, and a
// patch release of it satisfies 1.26.0.
go 1.26.0

require (
	github.com/danielbodart/frisket v0.199.126
	github.com/danielbodart/quoin v0.100.28
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f
	github.com/vektah/gqlparser/v2 v2.5.64
	go.yaml.in/yaml/v3 v3.0.6
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	google.golang.org/protobuf v1.36.12
	pgregory.net/rapid v1.3.0
)
