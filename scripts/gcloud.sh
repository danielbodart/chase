#!/usr/bin/env bash
# Google Cloud's classification, GENERATED from Google's own descriptions of
# its APIs, as ./operations.sh generates every other app's (docs/gcloud.md,
# decision 8):
#
#   scripts/gcloud.sh                                 from the pinned sources
#   scripts/gcloud.sh DISCOVERY_DIR GOOGLEAPIS_DIR    from checkouts of them
#   scripts/gcloud.sh --bump [DISCOVERY_COMMIT GOOGLEAPIS_COMMIT]
#
# REST from the Discovery documents in googleapis/discovery-artifact-manager,
# gRPC from the google.api.http rules in googleapis/googleapis, each pinned at
# a commit in apps/gcloud/source.json with a sha256 for every file read. A
# checkout is only where the files come from: each must hash as pinned, and
# only the pinned files are read. --bump re-pins, at each repository's head
# unless commits are given, and is a reviewed change like any other: the
# diff of apps/gcloud/apis is what gets read.
#
# Writes apps/gcloud/apis/<api>.json, one rule per line, and
# apps/gcloud/index.json, what each API is: its versions, hosts, gRPC
# services and streaming methods. ./gcloud.py says how each is classed, from
# apps/gcloud/exceptions.json; `nix develop` has what it needs.
set -euo pipefail

usage() {
    echo "usage: scripts/gcloud.sh [DISCOVERY_DIR GOOGLEAPIS_DIR | --bump [DISCOVERY_COMMIT GOOGLEAPIS_COMMIT]]" >&2
    exit 2
}

scripts="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app="$(CDPATH='' cd -- "$scripts/../apps/gcloud" && pwd)"
source="$app/source.json"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A sparse checkout of one commit, fetched by its hash, holding only what the
# patterns name.
checkout() { # REPOSITORY COMMIT DIR PATTERN...
    local repository=$1 commit=$2 dir=$3
    shift 3
    git init -q "$dir"
    git -C "$dir" fetch -q --depth 1 --filter=blob:none "$repository" "$commit"
    printf '%s\n' "$@" | git -C "$dir" sparse-checkout set --no-cone --stdin
    git -C "$dir" checkout -q FETCH_HEAD
}

# The protos, compiled: what Google's own descriptor parser reads, so
# nothing here parses a .proto.
compile() { # GOOGLEAPIS_DIR ENTRIES OUT
    (cd "$1" && xargs protoc -I . --include_imports --include_source_info --descriptor_set_out="$3" < "$2") 2> "$work/protoc.log" || {
        cat "$work/protoc.log" >&2
        exit 1
    }
}

bump=false
case ${1:-} in
--bump)
    bump=true
    shift
    [ $# -eq 0 ] || [ $# -eq 2 ] || usage
    ;;
*)
    [ $# -eq 0 ] || [ $# -eq 2 ] || usage
    ;;
esac

if $bump; then
    discovery_commit=${1:-$(git ls-remote "$(jq -r .discovery.repository "$source")" HEAD | cut -f1)}
    googleapis_commit=${2:-$(git ls-remote "$(jq -r .googleapis.repository "$source")" HEAD | cut -f1)}
    checkout "$(jq -r .discovery.repository "$source")" "$discovery_commit" "$work/discovery" '/discoveries/'
    checkout "$(jq -r .googleapis.repository "$source")" "$googleapis_commit" "$work/googleapis" '/google/' '/grafeas/'
    (cd "$work/googleapis" && grep -rl --include='*.proto' 'google.api.default_host' google grafeas | sort) > "$work/entries"
    compile "$work/googleapis" "$work/entries" "$work/all.pb"
    python3 "$scripts/gcloud.py" pins "$app" "$work/discovery/discoveries" "$work/googleapis" "$work/all.pb" "$work/entries" > "$work/pins.json"
    for repo in discovery googleapis; do
        jq -r --arg r "$repo" '.[$r][]' "$work/pins.json" | (cd "$work/$repo" && xargs sha256sum) \
            | jq -R 'capture("^(?<value>[0-9a-f]{64})  (?<key>.*)$")' | jq -s 'from_entries' > "$work/$repo.json"
    done
    jq --arg d "$discovery_commit" --arg g "$googleapis_commit" --slurpfile df "$work/discovery.json" \
        --slurpfile gf "$work/googleapis.json" --slurpfile pins "$work/pins.json" '
        .discovery.commit = $d | .discovery.files = $df[0]
        | .googleapis.commit = $g | .googleapis.entries = $pins[0].entries | .googleapis.files = $gf[0]' \
        "$source" > "$work/source.json"
    mv "$work/source.json" "$source"
    set -- "$work/discovery" "$work/googleapis"
fi

if [ $# -eq 0 ]; then
    for repo in discovery googleapis; do
        mapfile -t files < <(jq -r --arg r "$repo" '.[$r].files | keys[] | "/" + .' "$source")
        checkout "$(jq -r --arg r "$repo" '.[$r].repository' "$source")" "$(jq -r --arg r "$repo" '.[$r].commit' "$source")" "$work/$repo" "${files[@]}"
    done
    set -- "$work/discovery" "$work/googleapis"
fi

# Only the pinned files, each as pinned: copied out of the checkout, then
# hashed where they will be read.
for repo in discovery googleapis; do
    from=$1
    shift
    mkdir -p "$work/pinned/$repo"
    jq -r --arg r "$repo" '.[$r].files | keys[]' "$source" | tar -C "$from" -cf - -T - | tar -C "$work/pinned/$repo" -xf -
    jq -r --arg r "$repo" '.[$r].files | to_entries[] | "\(.value)  \(.key)"' "$source" \
        | (cd "$work/pinned/$repo" && sha256sum --quiet --strict -c -) || {
        echo "gcloud: the $repo files above are not as pinned in $source" >&2
        exit 1
    }
done

jq -r '.googleapis.entries[]' "$source" > "$work/entries"
compile "$work/pinned/googleapis" "$work/entries" "$work/descriptors.pb"
python3 "$scripts/gcloud.py" generate "$app" "$work/pinned/discovery/discoveries" "$work/pinned/googleapis" "$work/descriptors.pb" "$work/entries"
