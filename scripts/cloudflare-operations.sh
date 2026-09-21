#!/usr/bin/env bash
# The Cloudflare classification, GENERATED from Cloudflare's own description of
# its API rather than guessed or learned from logs (docs/cloudflare.md,
# decision 2).
#
# Every operation in the spec becomes one rule: a method, a path template and
# whether it asks. GET is safe and everything else asks, and exceptions.json
# says, by operation id and with a reason each, where that rule is wrong
# (decision 4). A path the spec does not describe gets no rule at all, and so
# asks too.
#
# The spec is PINNED, by commit and by hash. A newer one is never picked up on
# its own, because that would let an endpoint be allowed without a person
# deciding it (decision 3). Bumping the pin is a reviewed change, and the diff
# of operations.json is what gets read -- which is why it holds one operation
# per line.
#
#   scripts/cloudflare-operations.sh [path/to/openapi.json]
#
# With no argument it fetches the pinned commit. A local copy is accepted only
# if it hashes the same, so the argument saves a download and changes nothing
# else.
set -euo pipefail

commit=8cb19939b77a69c82fe1144faa7aedee8c25abb2
sha256=84e616992a0322f625ead6936c88d5ca0d38b5c576af7f59586729fd15ecfa37
url="https://raw.githubusercontent.com/cloudflare/api-schemas/$commit/openapi.json"

app="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../apps/cloudflare" && pwd)"
exceptions="$app/exceptions.json"
out="$app/operations.json"

work=$(mktemp -d)
trap 'rm -rf "$work" "$out.new"' EXIT

# Twenty-five megabytes, and read once: not worth vendoring when the hash
# already says exactly which file it has to be.
spec=${1:-}
if [ -z "$spec" ]; then
    spec="$work/openapi.json"
    curl -fsSL --retry 3 -o "$spec" "$url"
fi

actual=$(sha256sum "$spec" | cut -d' ' -f1)
if [ "$actual" != "$sha256" ]; then
    echo "cloudflare-operations: $spec is not the pinned spec." >&2
    echo "  expected sha256 $sha256" >&2
    echo "  got             $actual" >&2
    echo "  (pinned: $url)" >&2
    exit 1
fi

# Every failure below is a halt, not a warning: a classification that is
# quietly wrong is worse than none, because the gate would trust it.
jq -r --slurpfile exceptions "$exceptions" '
    def fail($message): "cloudflare-operations: \($message)\n" | halt_error(1);

    $exceptions[0] as $exceptions

    # The servers url is what the templates are prefixed with. A spec that
    # moved it would produce rules for paths nobody sends.
    | if [.servers[].url] != ["https://api.cloudflare.com/client/v4"]
      then fail("servers is \([.servers[].url]), not https://api.cloudflare.com/client/v4") end

    # Only method keys are operations; "parameters" and "x-*" sit beside them.
    | [ .paths | to_entries[] | .key as $path | .value | to_entries[]
        | select(.key | IN("get", "put", "post", "patch", "delete", "head", "options", "trace"))
        | { method: (.key | ascii_upcase), spec: $path, id: .value.operationId,
            summary: .value.summary, description: .value.description } ]

    | if any(.[]; .id == null or .summary == null)
      then fail("an operation has no operationId or summary: \(map(select(.id == null or .summary == null) | "\(.method) \(.spec)"))") end

    # A literal "*" would be indistinguishable from a template, and an empty
    # segment or a trailing slash is a path no client sends.
    | (map(.spec | select(contains("*") or test("^/") == false or test("//|./$"))) | unique) as $odd
    | if $odd != [] then fail("a path frisket could not match as written: \($odd)") end

    # An exception naming an operation the spec no longer has is how a pin
    # bump that removed one gets noticed. One naming the wrong kind of
    # operation -- an ask on a write, an allow on a read -- would do nothing,
    # so it is a mistake too.
    | (map({ key: .id, value: .method }) | from_entries) as $methods
    | ([$exceptions.ask, $exceptions.allow] | map(keys[]) | group_by(.) | map(select(length > 1)[0])) as $both
    | if $both != [] then fail("in both ask and allow: \($both)") end
    | ($exceptions.ask + $exceptions.allow | to_entries | map(select(.value | type != "string" or length == 0) | .key)) as $unreasoned
    | if $unreasoned != [] then fail("an exception needs a reason: \($unreasoned)") end
    | ($exceptions.ask + $exceptions.allow | keys | map(select($methods[.] == null))) as $missing
    | if $missing != [] then fail("not in the pinned spec: \($missing)") end
    | ($exceptions.ask | keys | map(select($methods[.] != "GET"))) as $wrong
    | if $wrong != [] then fail("an ask exception is not a GET, so it would ask anyway: \($wrong)") end
    | ($exceptions.allow | keys | map(select($methods[.] == "GET"))) as $wrong
    | if $wrong != [] then fail("an allow exception is a GET, so it would be allowed anyway: \($wrong)") end

    # A parameter becomes "*" as a whole segment, even where it shares one
    # with literal text ({scan_id}.png, {event_t}.{event_n}): frisket matches
    # segments, and "*" matching a little more than the spec says is the
    # direction that stays inside one operation.
    | map({
        methods: (if .method == "GET" then ["GET", "HEAD"] else [.method] end),
        path: ("/client/v4" + (.spec | split("/") | map(if test("[{}]") then "*" else . end) | join("/"))),
        ask: (if .method == "GET" then $exceptions.ask[.id] != null else $exceptions.allow[.id] == null end),
        operation: ({ id, summary } + (if (.description // "") == "" then {} else { description } end))
      })

    # Two operations on one method and template would make the match, and so
    # the words in the dialog, a coin toss.
    | ([.[] | .path as $path | .operation.id as $id | .methods[] | { key: "\(.) \($path)", id: $id }]
        | group_by(.key) | map(select(length > 1) | "\(.[0].key) (\(map(.id) | join(", ")))")) as $duplicates
    | if $duplicates != [] then fail("the same method and template twice: \($duplicates)") end

    | sort_by(.path, .methods[0])
    | "[\n" + (map(tojson) | join(",\n")) + "\n]"
' "$spec" > "$out.new"

mv "$out.new" "$out"

jq -r 'length as $n | map(select(.ask)) | length as $asked
    | "cloudflare-operations: \($n) operations, \($n - $asked) allowed, \($asked) ask."' "$out" >&2
