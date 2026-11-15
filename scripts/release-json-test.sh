#!/usr/bin/env bash
# Tests scripts/release-json.sh: the file it writes is the one flake.nix
# reads, with each hash in the SRI form `nix hash convert --hash-algo sha256
# --to sri` gives (worked out with it once, and written here, since check
# runs where there may be no nix), and a SHA256SUMS missing a platform, or a
# version that is not one, makes nothing. Run by mise run check (the
# scripts-test task).
set -euo pipefail
unset CDPATH

script=$(cd "$(dirname "$0")" && pwd)/release-json.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

cat >"$work/SHA256SUMS" <<'SUMS'
8f5d7129c4f3f984525cb6b0a073d9538d75d3d95dfe962a8b00d6573f925b18  chase-0.243.150-linux-amd64
e233a0e3f518d0fcd97d6204a0c9b9ae101eca36cfeb7b475b86d50d0fb12872  chase-0.243.150-linux-arm64
SUMS

cat >"$work/want.json" <<'JSON'
{
  "version": "0.243.150",
  "assets": {
    "x86_64-linux": {
      "url": "https://github.com/danielbodart/chase/releases/download/v0.243.150/chase-0.243.150-linux-amd64",
      "hash": "sha256-j11xKcTz+YRSXLawoHPZU41109ld/pYqiwDWVz+SWxg="
    },
    "aarch64-linux": {
      "url": "https://github.com/danielbodart/chase/releases/download/v0.243.150/chase-0.243.150-linux-arm64",
      "hash": "sha256-4jOg4/UY0PzZfWIEoMm5rhAeyjbP63tHW4bVDQ+xKHI="
    }
  }
}
JSON

if ! "$script" 0.243.150 "$work/SHA256SUMS" >"$work/got.json"; then
    fail "a release's SHA256SUMS: refused"
elif ! diff -u "$work/want.json" "$work/got.json"; then
    fail "a release's SHA256SUMS: not the release.json flake.nix wants"
fi

grep -v linux-arm64 "$work/SHA256SUMS" >"$work/short"
if "$script" 0.243.150 "$work/short" >/dev/null 2>&1; then
    fail "a SHA256SUMS without linux-arm64: accepted"
fi

if "$script" 0.243.151 "$work/SHA256SUMS" >/dev/null 2>&1; then
    fail "another version's SHA256SUMS: accepted"
fi

if "$script" v0.243.150 "$work/SHA256SUMS" >/dev/null 2>&1; then
    fail "a version with a v: accepted"
fi

if [ $failures -gt 0 ]; then
    exit 1
fi
echo "release-json: ok"
