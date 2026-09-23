#!/usr/bin/env bash
# An app's classification, GENERATED from the provider's own description of
# its API rather than guessed or learned from logs (docs/cloudflare.md,
# decision 2). Shared by every app whose provider publishes one:
#
#   scripts/operations.sh cloudflare [path/to/openapi.json]
#   scripts/operations.sh huggingface [path/to/openapi.json]
#   scripts/operations.sh github [path/to/openapi.json]
#
# Every operation in the spec becomes one rule: a method, a path template,
# and a class (PLAN.md, decision 18). GET and HEAD are reads, DELETE is
# guarded, and everything else is a write; the app's exceptions.json says, by
# operation id and with a reason each, where that rule is wrong (decision 4)
# -- under `read`, `write` or `guarded`, the class it is instead -- and, under
# `rules`, what the spec does not describe but a client needs, written by
# hand, with a class and a reason each too. A path neither describes gets no
# rule at all, and is decided by the tier's `unmatched`.
#
# What a class is ANSWERED with is not decided here: a tier and an app say
# that, per class. This file says only what each operation is.
#
# The spec is PINNED by hash, in the app's source.json. A newer one is never
# picked up on its own, because that would let an endpoint be allowed without
# a person deciding it (decision 3). Bumping the pin is a reviewed change, and
# the diff of operations.json is what gets read -- which is why it holds one
# operation per line.
#
# Where the spec comes from, first found: the argument; the app's vendored
# openapi.json, for a provider that publishes its spec at a URL that moves
# rather than at a commit; the pinned URL. Whichever it is, it must hash as
# pinned, so the choice saves a download and changes nothing else.
set -euo pipefail

usage() {
    echo "usage: scripts/operations.sh APP [path/to/openapi.json]" >&2
    exit 2
}
[ $# -ge 1 ] && [ $# -le 2 ] || usage
name=$1

app="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../apps" && pwd)/$name"
[ -f "$app/source.json" ] || {
    echo "operations: $app/source.json does not exist" >&2
    exit 2
}
url=$(jq -r .url "$app/source.json")
sha256=$(jq -r .sha256 "$app/source.json")
server=$(jq -r .server "$app/source.json")
exceptions="$app/exceptions.json"
out="$app/operations.json"

work=$(mktemp -d)
trap 'rm -rf "$work" "$out.new"' EXIT

spec=${2:-}
if [ -z "$spec" ] && [ -f "$app/openapi.json" ]; then
    spec="$app/openapi.json"
elif [ -z "$spec" ]; then
    spec="$work/openapi.json"
    curl -fsSL --retry 3 -o "$spec" "$url"
fi

actual=$(sha256sum "$spec" | cut -d' ' -f1)
if [ "$actual" != "$sha256" ]; then
    echo "operations: $spec is not the pinned spec." >&2
    echo "  expected sha256 $sha256" >&2
    echo "  got             $actual" >&2
    echo "  (pinned: $url, in $app/source.json)" >&2
    exit 1
fi

# Every failure below is a halt, not a warning: a classification that is
# quietly wrong is worse than none, because the gate would trust it.
jq -r --slurpfile exceptions "$exceptions" --arg server "$server" --arg name "$name" '
    def fail($message): "operations: \($name): \($message)\n" | halt_error(1);

    def classes: ["read", "write", "guarded"];

    # The class a method has unless an exception says otherwise.
    def natural: if IN("GET", "HEAD") then "read" elif . == "DELETE" then "guarded" else "write" end;

    # What a rule matches on: a whole segment "*" for any segment holding a
    # parameter.
    def template: split("/") | map(if test("[{}]") then "*" else . end) | join("/");

    # Whether two templates can match one path: segment by segment, where
    # both have one, a literal meets itself or a "*"; an exact template is
    # that many segments, a prefix that many or more.
    def overlaps($a; $aexact; $b; $bexact):
        ($a | split("/")[1:]) as $x | ($b | split("/")[1:]) as $y
        | (if $aexact and $bexact then ($x | length) == ($y | length)
           elif $aexact then ($x | length) >= ($y | length)
           elif $bexact then ($y | length) >= ($x | length)
           else true end)
          and all(range([$x, $y] | map(length) | min); $x[.] == "*" or $y[.] == "*" or $x[.] == $y[.]);

    . as $root
    | $exceptions[0] as $exceptions
    | ($exceptions.rules // []) as $rules
    | (classes | map({ key: ., value: ($exceptions[.] // {}) }) | from_entries) as $reclassed

    # A parameter may be written once under components and referred to.
    | def resolve: if has("$ref") then ."$ref" as $r | $root | getpath($r | ltrimstr("#/") | split("/")) else . end;

    # A path parameter that holds slashes: what Hugging Face calls a
    # "Wildcard path parameter", and GitHub marks x-multi-segment -- a file
    # in a repository, a ref, a branch.
    def multisegment: (.["x-multi-segment"] == true) or ((.schema.description // "") | test("^wildcard path parameter$"; "i"));

    # The servers url is what the templates are prefixed with. A spec that
    # moved it would produce rules for paths nobody sends.
    if [.servers[].url] != [$server]
      then fail("servers is \([.servers[].url]), not \($server)") end
    | ($server | sub("^https://[^/]+"; "")) as $prefix

    # Only method keys are operations; "parameters" and "x-*" sit beside them.
    # A parameter that holds slashes, as the last segment, is the rest of the
    # path, which is a prefix to frisket; anywhere else it is one segment, and
    # a value with a slash matches nothing and is left to `unmatched`.
    | [ .paths | to_entries[] | .key as $path | .value
        | (.parameters // []) as $shared
        | to_entries[]
        | select(.key | IN("get", "put", "post", "patch", "delete", "head", "options", "trace"))
        | ([$shared[], (.value.parameters // [])[]] | map(resolve | select(.in == "path" and multisegment) | .name)) as $slashed
        | ([$slashed[] | select(. as $r | $path | endswith("/{\($r)}"))]) as $rest
        | (.value["x-github"].category // .value.tags[0]? // null) as $category
        | { method: (.key | ascii_upcase), spec: $path, rest: $rest, id: .value.operationId,
            summary: .value.summary, description: .value.description, category: $category } ]

    | if any(.[]; .summary == null)
      then fail("an operation has no summary: \(map(select(.summary == null) | "\(.method) \(.spec)"))") end

    # A literal "*" would be indistinguishable from a template, and an empty
    # segment or a trailing slash is a path no client sends.
    | (map(.spec | select(contains("*") or test("^/") == false or test("//|./$"))) | unique) as $odd
    | if $odd != [] then fail("a path frisket could not match as written: \($odd)") end

    # Only one rest of the path.
    | (map(select((.rest | length) > 1)) | map("\(.method) \(.spec)")) as $odd
    | if $odd != [] then fail("two parameters that are both the rest of the path: \($odd)") end

    # A spec with no operation ids gets them from the method and the path,
    # in the characters an envelope may name one by: what a person writes in
    # exceptions.json, and in a project allow-list.
    | map(.id //= ("\(.method | ascii_downcase)\(.spec)" | gsub("[{}]"; "") | gsub("[^A-Za-z0-9_.:]+"; "-") | sub("-$"; "")))

    | ([.[].id, $rules[].operation.id] | group_by(.) | map(select(length > 1)[0])) as $twice
    | if $twice != [] then fail("the same operation id twice: \($twice)") end

    # An exception naming an operation the spec no longer has is how a pin
    # bump that removed one gets noticed. One giving an operation the class
    # it has anyway would do nothing, so it is a mistake too.
    | (map({ key: .id, value: .method }) | from_entries) as $methods
    | (classes | map($reclassed[.] | keys[]) | group_by(.) | map(select(length > 1)[0])) as $both
    | if $both != [] then fail("in more than one class: \($both)") end
    | ([classes[] as $c | $reclassed[$c] | to_entries[] | select(.value | type != "string" or length == 0) | .key]) as $unreasoned
    | if $unreasoned != [] then fail("an exception needs a reason: \($unreasoned)") end
    | ([classes[] as $c | $reclassed[$c] | keys[] | select($methods[.] == null)]) as $missing
    | if $missing != [] then fail("not in the pinned spec: \($missing)") end
    | ([classes[] as $c | $reclassed[$c] | keys[] | select($methods[.] | natural == $c)]) as $same
    | if $same != [] then fail("an exception gives an operation the class it has anyway: \($same)") end
    | ([classes[] as $c | $reclassed[$c] | keys[] | { key: ., value: $c }] | from_entries) as $exception

    # A hand-written rule says why it exists, what it is, what class, and
    # exactly one of the two ways a rule matches.
    | ($rules | map(select((.reason | type) != "string" or .reason == ""
        or (.operation.id | type) != "string" or (.operation.summary | type) != "string"
        or (.class | IN(classes[]) | not)
        or ((.path != null) == (.prefix != null)) or (.methods | length) == 0) | .operation.id // "?")) as $odd
    | if $odd != [] then fail("a hand-written rule needs a reason, an operation id and summary, a class, methods, and one of path or prefix: \($odd)") end

    # A parameter becomes "*" as a whole segment, even where it shares one
    # with literal text ({scan_id}.png, {event_t}.{event_n}): frisket matches
    # segments, and "*" matching a little more than the spec says is the
    # direction that stays inside one operation.
    | map(
        { methods: (if .method == "GET" then ["GET", "HEAD"] else [.method] end) }
        + (if .rest == [] then { path: ($prefix + (.spec | template)) }
           else { prefix: ($prefix + (.spec | sub("/[{][^/]*[}]$"; "") | template)) } end)
        + { operation: ({ id, summary }
            + (if (.description // "") == "" then {} else { description } end)
            + { class: ($exception[.id] // (.method | natural)) }
            + (if .category == null then {} else { category } end)) })

    # A HAND-WRITTEN RULE MAY NOT DECIDE WHAT THE SPEC ALREADY DOES. frisket
    # takes the most specific rule, segment by segment, so a hand rule with a
    # literal where an operation has a parameter wins wherever the two both
    # match -- /api/models/*/revision/* would admit the jwt of a repository
    # named "revision", which asks. So a rule that can match any path an
    # operation with the same method matches must be of the same class.
    | . as $generated
    | ([ $rules[] as $r | $generated[]
        | select(.operation.class != $r.class and ([.methods[]] - $r.methods) != .methods)
        | select(overlaps((.path // .prefix); .path != null; ($r.path // $r.prefix); $r.path != null))
        | "\($r.operation.id) and \(.operation.id)" ]) as $clash
    | if $clash != [] then fail("a hand-written rule overlaps an operation of another class: \($clash)") end

      + ($rules | map(.operation.class = .class | del(.reason, .class)))

    # Two operations on one method and template would make the match, and so
    # the words in the dialog, a coin toss -- unless they are the same words
    # and the same class, when they are one operation the spec wrote twice
    # ({slug} and {slug}-{id}, say), and the first id speaks for both.
    | group_by([.methods, .path, .prefix])
    | map(if length == 1 then .[0]
          elif (map([.operation.class, .operation.summary]) | unique | length) == 1 then sort_by(.operation.id)[0]
          else fail("the same method and template twice: \(.[0].methods) \(.[0].path // .[0].prefix) (\(map(.operation.id) | join(", ")))") end)

    | sort_by(.path // .prefix, .methods[0])
    | "[\n" + (map(tojson) | join(",\n")) + "\n]"
' "$spec" > "$out.new"

mv "$out.new" "$out"

jq -r --arg name "$name" 'length as $n | group_by(.operation.class) | map("\(length) \(.[0].operation.class)") | join(", ")
    | "operations: \($name): \($n) operations: \(.)."' "$out" >&2
