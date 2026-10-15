module github.com/danielbodart/chase

// frisket's floor, for the same reason: both nixpkgs branches in play ship
// 1.26, and a patch release of it satisfies 1.26.0.
go 1.26.0

require (
	github.com/danielbodart/frisket v0.176.111-0.20261013103438-437ab2c96b8e
	github.com/danielbodart/quoin v0.79.12-0.20261015154323-6328bd89832c
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f
	github.com/vektah/gqlparser/v2 v2.5.58
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sys v0.48.0
	google.golang.org/protobuf v1.36.11
	pgregory.net/rapid v1.3.0
)
