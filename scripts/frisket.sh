#!/usr/bin/env bash
# Fetches the frisket binary of the release go.mod requires, checked against
# that release's SHA256SUMS, into DIR/frisket, and prints DIR. Some of
# chase's tests hold what chase writes to `frisket check`, and with
# CHASE_REQUIRE_FRISKET set they fail rather than skip without it on PATH;
# CI's check and race jobs set it and put DIR on PATH.
#
# go.mod's frisket is the release the binary compiles frisket's packages
# from, and the frisket-pin check holds flake.lock's frisket input to the
# same tag, so the tests run the frisket a host gets with this chase. A
# frisket release carries static linux binaries (frisket's
# scripts/release-assets.sh), so this needs no Nix.
#
# usage: scripts/frisket.sh DIR
set -euo pipefail
unset CDPATH

if [ $# -ne 1 ]; then
    echo "usage: scripts/frisket.sh DIR" >&2
    exit 2
fi
dir=$1

cd "$(git rev-parse --show-toplevel)"
tag=$(go mod edit -json | jq -r '.Require[] | select(.Path == "github.com/danielbodart/frisket") | .Version')
if ! [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "frisket: go.mod requires frisket '$tag', which is not a release tag" >&2
    exit 1
fi
case $(uname -m) in
x86_64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) echo "frisket: no frisket release for $(uname -m)" >&2; exit 1 ;;
esac
name="frisket-${tag#v}-linux-$arch"
base="https://github.com/danielbodart/frisket/releases/download/$tag"

mkdir -p "$dir"
curl -fsSL --retry 3 -o "$dir/SHA256SUMS" "$base/SHA256SUMS"
curl -fsSL --retry 3 -o "$dir/$name" "$base/$name"
(cd "$dir" && grep -E "^[0-9a-f]{64} [ *]$name\$" SHA256SUMS | sha256sum -c --quiet -)
install -m 0755 "$dir/$name" "$dir/frisket"
[ "$("$dir/frisket" version)" = "${tag#v}" ] || {
    echo "frisket: $name does not say it is ${tag#v}" >&2
    exit 1
}
echo "$dir"
