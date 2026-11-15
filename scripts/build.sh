#!/usr/bin/env bash
# The static chase binary for every platform a release ships for, into
# dist/<os>-<arch>/chase, with the version stamped in. CI's build job runs
# it with the Go mise.toml pins; a release carries what it makes, and the
# flake's package is that release binary (flake.nix says why).
#
# usage: scripts/build.sh [os/arch ...]     (default: linux/amd64 linux/arm64)
#
# Linux only: chase is the hooks and units of flong's sandboxes and
# frisket's sessions, neither of which exists elsewhere. chase-generate is
# not built: it regenerates the apps' tables and derives CI's version, run
# as `go run ./cmd/chase-generate`, and is never on a host.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

version=$(go run ./cmd/chase-generate version)
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(linux/amd64 linux/arm64)

for target in "${targets[@]}"; do
    os=${target%/*}
    arch=${target#*/}
    out="dist/$os-$arch"
    mkdir -p "$out"
    # A STATIC BINARY, with no cgo, as frisket's is: cgo would bring glibc's
    # NSS, which resolves names by whatever the host's nsswitch.conf says.
    # -trimpath so the binary names no path on the machine that built it.
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
        -ldflags "-s -w -X main.version=$version" \
        -o "$out/chase" ./cmd/chase
    echo "$out: $version"
done
