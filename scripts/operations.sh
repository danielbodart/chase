#!/usr/bin/env bash
# An app's classification, GENERATED from the provider's own description of
# its API rather than guessed or learned from logs (docs/cloudflare.md,
# decision 2). Shared by every app whose provider publishes one:
#
#   scripts/operations.sh cloudflare [path/to/openapi.json]
#   scripts/operations.sh huggingface [path/to/openapi.json]
#   scripts/operations.sh github [path/to/openapi.json]
#   scripts/operations.sh docker [path/to/swagger.yaml]
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
# GraphQL is an endpoint the app's exceptions.json declares, under
# `graphql`: its path, what a query there is, and why it is there. A query is
# a read, whatever it reads. Where source.json pins the provider's GraphQL
# schema too, under `graphql`, each field of its mutation and subscription
# types is an operation of its own, named by the field, in the schema's own
# words and category: a write, or guarded where its name says it deletes, and
# otherwise as exceptions.json says, by the same names as any other
# operation. Without a schema an endpoint's mutations are unmatched. An
# endpoint decides every request at its path, so the operations the spec has
# there are replaced, and it names them.
#
# The spec is PINNED by hash, in the app's source.json. A newer one is never
# picked up on its own, because that would let an endpoint be allowed without
# a person deciding it (decision 3). Bumping the pin is a reviewed change, and
# the diff of operations.json is what gets read -- which is why it holds one
# operation per line.
#
# A spec is OpenAPI 3, whose servers url prefixes every template, or Swagger
# 2.0, whose templates are already relative to its basePath: source.json says
# which, by its `server` or its `basePath`, and says JSON or YAML by its
# `format` or else by its url's extension. A basePath is the API's version as
# well (Docker's /v1.56), so a Swagger spec's info.version must be the top of
# source.json's apiVersions: a pin bumped without the range fails. YAML is
# hashed as it was fetched and only then read, by PyYAML.
#
# Where the spec comes from, first found: the argument; the app's vendored
# spec.json or spec.yaml (or openapi.json, as the apps before YAML still have
# it), for a provider that publishes its spec at a URL that moves rather than
# at a commit; the pinned URL. Whichever it is, it must hash as pinned, so
# the choice saves a download and changes nothing else. A GraphQL schema is
# the app's vendored schema.graphql, or its pinned URL, and is read by
# ./schema.py, which needs graphql-core: `nix develop` has it, and PyYAML.
#
# An app with an admit.json is ADMITTED, not classed (Docker, docs/docker.md):
# its route answers no class, and a request passes only where admit.json
# names the operation, with the methods it lists and the `docker` block
# frisket checks the request by, and nothing else admits: an exceptions.json
# with rules, GraphQL or classes fails. Every other operation is still a rule, a
# refusal that carries its operation, so that what was refused is named. Its
# class is kept, because frisket refuses a rule of no known class, though
# nothing answers it. And for each operation admitted with a `body` table,
# known.json lists every field the spec gives that body -- object properties
# through $ref and allOf, not into an array's items or a map's values -- so
# that a pin bump shows new fields in its diff, and the check that compares
# the tables to it fails until each is decided.
set -euo pipefail

usage() {
    echo "usage: scripts/operations.sh APP [path/to/spec]" >&2
    exit 2
}
[ $# -ge 1 ] && [ $# -le 2 ] || usage
name=$1

app="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../apps" && pwd)/$name"
[ -f "$app/source.json" ] || {
    echo "operations: $app/source.json does not exist" >&2
    exit 2
}
source="$app/source.json"
url=$(jq -r .url "$source")
sha256=$(jq -r .sha256 "$source")
server=$(jq -r '.server // empty' "$source")
basePath=$(jq -r '.basePath // empty' "$source")
version=$(jq -r '.apiVersions.max // empty' "$source")
exceptions="$app/exceptions.json"
admit="$app/admit.json"
out="$app/operations.json"
known="$app/known.json"
scripts="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

work=$(mktemp -d)
trap 'rm -rf "$work" "$out.new" "$known.new"' EXIT

# Which kind of spec, and in what: exactly one of server and basePath, and a
# format that agrees with it where one is given.
format=$(jq -r '.format // empty' "$source")
case "$format" in
    '') ;;
    swagger2-json | swagger2-yaml | openapi3-json | openapi3-yaml) ;;
    *)
        echo "operations: $source: format $format is not swagger2-json, swagger2-yaml, openapi3-json or openapi3-yaml" >&2
        exit 1
        ;;
esac
if [ -n "$basePath" ] && [ -z "$server" ]; then
    flavor=swagger2
elif [ -n "$server" ] && [ -z "$basePath" ]; then
    flavor=openapi3
else
    echo "operations: $source needs exactly one of server (OpenAPI 3) and basePath (Swagger 2.0)" >&2
    exit 1
fi
if [ -n "$format" ] && [ "${format%-*}" != "$flavor" ]; then
    echo "operations: $source: format $format, but a $flavor spec by its ${basePath:+basePath}${server:+server}" >&2
    exit 1
fi
if [ "$flavor" = swagger2 ] && [ -z "$version" ]; then
    echo "operations: $source: a Swagger spec is its basePath's version, which apiVersions.max must say" >&2
    exit 1
fi
if [ -n "$format" ]; then
    ext=${format#*-}
else
    case "$url" in
        *.json) ext=json ;;
        *.yaml | *.yml) ext=yaml ;;
        *)
            echo "operations: $source: $url is neither .json nor .yaml, so format must say which" >&2
            exit 1
            ;;
    esac
fi

spec=${2:-}
if [ -z "$spec" ] && [ -f "$app/spec.$ext" ]; then
    spec="$app/spec.$ext"
elif [ -z "$spec" ] && [ "$ext" = json ] && [ -f "$app/openapi.json" ]; then
    spec="$app/openapi.json"
elif [ -z "$spec" ]; then
    spec="$work/spec.$ext"
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

# The bytes that were hashed are what is read: YAML only after it is pinned.
if [ "$ext" = yaml ]; then
    python3 -c 'import sys,yaml,json; json.dump(yaml.safe_load(sys.stdin), sys.stdout)' < "$spec" > "$work/spec.json" || {
        echo "operations: could not read $spec as YAML (PyYAML is in \`nix develop\`)" >&2
        exit 1
    }
    spec="$work/spec.json"
fi

# No exceptions is none; no admit.json is an app whose classes are answered.
[ -f "$exceptions" ] || {
    exceptions="$work/exceptions.json"
    echo '{}' > "$exceptions"
}
admitted="$admit"
[ -f "$admitted" ] || {
    admitted="$work/admit.json"
    echo 'null' > "$admitted"
}

# The GraphQL schema, pinned the same way, read into its operations.
graphql_path=$(jq -r '.graphql.path // empty' "$app/source.json")
schema="$work/schema.json"
echo '{}' > "$schema"
if [ -n "$graphql_path" ]; then
    graphql_url=$(jq -r .graphql.url "$app/source.json")
    graphql_sha256=$(jq -r .graphql.sha256 "$app/source.json")
    sdl="$app/schema.graphql"
    if [ ! -f "$sdl" ]; then
        sdl="$work/schema.graphql"
        curl -fsSL --retry 3 -o "$sdl" "$graphql_url"
    fi
    actual=$(sha256sum "$sdl" | cut -d' ' -f1)
    if [ "$actual" != "$graphql_sha256" ]; then
        echo "operations: $sdl is not the pinned GraphQL schema." >&2
        echo "  expected sha256 $graphql_sha256" >&2
        echo "  got             $actual" >&2
        echo "  (pinned: $graphql_url, in $app/source.json)" >&2
        exit 1
    fi
    python3 "$scripts/schema.py" "$sdl" > "$schema" || {
        echo "operations: could not read $sdl (graphql-core is in \`nix develop\`)" >&2
        exit 1
    }
fi

# Every failure below is a halt, not a warning: a classification that is
# quietly wrong is worse than none, because the gate would trust it.
jq -r --slurpfile exceptions "$exceptions" --slurpfile admit "$admitted" --slurpfile schema "$schema" --arg graphqlPath "$graphql_path" \
    --arg flavor "$flavor" --arg server "$server" --arg basePath "$basePath" --arg version "$version" --arg name "$name" '
    def fail($message): "operations: \($name): \($message)\n" | halt_error(1);

    def classes: ["read", "write", "guarded"];

    # The class a method has unless an exception says otherwise.
    def natural: if IN("GET", "HEAD") then "read" elif . == "DELETE" then "guarded" else "write" end;

    # The class a GraphQL field has unless an exception says otherwise: as a
    # DELETE is guarded, so is a mutation that says it deletes.
    def fieldNatural: if startswith("delete") then "guarded" else "write" end;

    # An operation'"'"'s summary is the first sentence of its description.
    def sentence: (capture("^(?<s>[^\n]*?[.!?])(\\s|$)").s // split("\n")[0]);

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
    | $admit[0] as $admit
    | ($exceptions.rules // []) as $rules
    | (classes | map({ key: ., value: ($exceptions[.] // {}) }) | from_entries) as $reclassed

    # A parameter may be written once under components and referred to.
    | def resolve: if has("$ref") then ."$ref" as $r | $root | getpath($r | ltrimstr("#/") | split("/")) else . end;

    # A path parameter that holds slashes: what Hugging Face calls a
    # "Wildcard path parameter", and GitHub marks x-multi-segment -- a file
    # in a repository, a ref, a branch.
    def multisegment: (.["x-multi-segment"] == true) or ((.schema.description // "") | test("^wildcard path parameter$"; "i"));

    # The servers url is what the templates are prefixed with. A spec that
    # moved it would produce rules for paths nobody sends. A Swagger spec'"'"'s
    # templates are what follows its basePath, which is the API'"'"'s version:
    # frisket strips a version it admits before it matches.
    (if $flavor == "swagger2" then
       if .swagger != "2.0" then fail("swagger is \(.swagger), not 2.0") end
       | if .basePath != $basePath then fail("basePath is \(.basePath), not \($basePath)") end
       | if .info.version != $version
         then fail("info.version is \(.info.version), not \($version), the top of apiVersions: bump the range with the pin") end
       | ""
     else
       if [.servers[].url] != [$server]
         then fail("servers is \([.servers[].url]), not \($server)") end
       | $server | sub("^[a-z]+://[^/]+"; "")
     end) as $prefix

    # Only method keys are operations; "parameters" and "x-*" sit beside them.
    # A parameter that holds slashes, as the last segment, is the rest of the
    # path, which is a prefix to frisket; anywhere else it is one segment, and
    # a value with a slash matches nothing and is left to `unmatched`. A
    # Swagger body is a parameter too, and is never one of these.
    | [ .paths | to_entries[] | .key as $path | .value
        | (.parameters // []) as $shared
        | to_entries[]
        | select(.key | IN("get", "put", "post", "patch", "delete", "head", "options", "trace"))
        | ([$shared[], (.value.parameters // [])[]] | map(resolve | select(.in == "path") | select(multisegment) | .name)) as $slashed
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

    # GraphQL endpoints, and the fields of the one whose schema is pinned.
    | ($exceptions.graphql // []) as $endpoints
    | ($endpoints | map(select((.reason | type) != "string" or .reason == "" or ((.path // "") | test("^/") | not)
        or (.operation.id | type) != "string" or (.operation.summary | type) != "string") | .path // "?")) as $odd
    | if $odd != [] then fail("a GraphQL endpoint needs a path, a reason, and its query'"'"'s operation id and summary: \($odd)") end
    | if $graphqlPath != "" and ([$endpoints[].path] | index($graphqlPath)) == null
      then fail("source.json pins a GraphQL schema for \($graphqlPath), which exceptions.json does not declare") end
    | ([$schema[0] | to_entries[] | .key as $kind | .value[] | . + { kind: $kind }]) as $fields
    | ($fields | map(select(.description == null) | .name)) as $odd
    | if $odd != [] then fail("a GraphQL field has no description: \($odd)") end

    # An endpoint replacing an operation may keep its id: it is that
    # operation, seen into.
    | ([$endpoints[].replaces[]?]) as $replaced
    | ([(.[].id | select(. as $i | $replaced | index($i) | not)), $rules[].operation.id, $endpoints[].operation.id, $fields[].name]
        | group_by(.) | map(select(length > 1)[0])) as $twice
    | if $twice != [] then fail("the same operation id twice: \($twice)") end

    # An exception naming an operation the spec no longer has is how a pin
    # bump that removed one gets noticed. One giving an operation the class
    # it has anyway would do nothing, so it is a mistake too.
    | ((map({ key: .id, value: (.method | natural) }) + ($fields | map({ key: .name, value: (.name | fieldNatural) }))) | from_entries) as $natural
    | (classes | map($reclassed[.] | keys[]) | group_by(.) | map(select(length > 1)[0])) as $both
    | if $both != [] then fail("in more than one class: \($both)") end
    | ([classes[] as $c | $reclassed[$c] | to_entries[] | select(.value | type != "string" or length == 0) | .key]) as $unreasoned
    | if $unreasoned != [] then fail("an exception needs a reason: \($unreasoned)") end
    | ([classes[] as $c | $reclassed[$c] | keys[] | select($natural[.] == null)]) as $missing
    | if $missing != [] then fail("not in the pinned spec: \($missing)") end
    | ([classes[] as $c | $reclassed[$c] | keys[] | select($natural[.] == $c)]) as $same
    | if $same != [] then fail("an exception gives an operation the class it has anyway: \($same)") end
    | ([classes[] as $c | $reclassed[$c] | keys[] | { key: ., value: $c }] | from_entries) as $exception

    # What admit.json names is an operation, admitted by its methods and a
    # docker block, and nothing else.
    | if $admit != null then
        (map(.id)) as $ids
        | ([$admit | keys[] | select(. as $k | $ids | index($k) | not)]) as $missing
        | if $missing != [] then fail("admit.json names what is not in the pinned spec: \($missing)") end
        | ([$admit | to_entries[] | select((.value | type) != "object" or (.value | keys) != ["docker", "methods"]
            or (.value.docker | type) != "object" or (.value.methods | type) != "array" or (.value.methods | length) == 0) | .key]) as $odd
        | if $odd != [] then fail("an admitted operation needs its methods and a docker block, and nothing else: \($odd)") end
        # Nothing else admits: a hand-written rule, a GraphQL endpoint or a
        # reclassification would be a rule with no docker block, which
        # frisket would pass unfiltered.
        | if ($rules | length) > 0 or ($endpoints | length) > 0 or $graphqlPath != "" or ($exception | length) > 0
          then fail("an admitted app takes no hand-written rules, GraphQL or classes: admit.json is all it admits") end
      end

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
    | map(.where = (if .rest == [] then { path: ($prefix + (.spec | template)) }
                    else { prefix: ($prefix + (.spec | sub("/[{][^/]*[}]$"; "") | template)) } end))

    # A GET answers HEAD too, unless the spec says what a HEAD there is:
    # Docker'"'"'s /_ping has one of each. Where an app is admitted, its
    # admit.json says which of them are.
    | [.[] | select(.method == "HEAD") | .where] as $heads
    | map(
        (if .method == "GET" and (.where as $w | any($heads[]; . == $w) | not) then ["GET", "HEAD"] else [.method] end) as $methods
        | (if $admit == null then null else $admit[.id] end) as $admitted
        | if $admitted != null and ($admitted.methods - $methods) != []
          then fail("admit.json gives \(.id) \($admitted.methods), and the spec has it for \($methods)") end
        | { methods: ($admitted.methods // $methods) }
        + .where
        + (if $admit == null or $admitted != null then {} else { refuse: true } end)
        + { operation: ({ id, summary }
            + (if (.description // "") == "" then {} else { description } end)
            + { class: ($exception[.id] // (.method | natural)) }
            + (if .category == null then {} else { category } end)) }
        + (if $admitted == null then {} else { docker: $admitted.docker } end))

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
          elif (map([.operation.class, .operation.summary, .refuse, .docker]) | unique | length) == 1 then sort_by(.operation.id)[0]
          else fail("the same method and template twice: \(.[0].methods) \(.[0].path // .[0].prefix) (\(map(.operation.id) | join(", ")))") end)

    # A GraphQL endpoint decides every request at its path, so what the spec
    # has there is replaced -- and named, so that it is not replaced unseen.
    | . as $rest
    | ([$endpoints[] | .path as $p | ((.replaces // []) | sort) as $said
        | ([$rest[] | select(.path == $p) | .operation.id] | sort) as $there
        | select($said != $there) | "\($p) has \($there), and replaces \($said)"]) as $odd
    | if $odd != [] then fail("a GraphQL endpoint names what the spec has at its path, in `replaces`: \($odd)") end
    | [$rest[] | select(.path as $p | [$endpoints[].path] | index($p) | not)]

    | sort_by(.path // .prefix, .methods[0])
    | if $admit != null and any(.[]; (.refuse == true) == (.docker != null))
      then fail("a rule of an admitted app is neither refused nor admitted by admit.json: \(map(select((.refuse == true) == (.docker != null)) | .operation.id))") end
    | . + [$endpoints[] | { graphql: .path, query: true, operation: (.operation + { class: "read" }) }]
    + [$fields | sort_by(.kind, .name)[]
        | (.description | sentence) as $summary
        | ([.description] + (if .deprecated then ["Deprecated: \(.deprecated)"] else [] end) | join("\n\n")) as $description
        | { graphql: $graphqlPath, (.kind): .name,
            operation: ({ id: .name, summary: $summary }
              + (if $description == $summary then {} else { description: $description } end)
              + { class: ($exception[.name] // (.name | fieldNatural)) }
              + (if .category == null then {} else { category } end)) }]
    | "[\n" + (map(tojson) | join(",\n")) + "\n]"
' "$spec" > "$out.new"

mv "$out.new" "$out"

# The fields of each admitted body, as the spec gives them. Where one table
# is named by two operations, their bodies must be the same.
if [ -f "$admit" ]; then
    jq -r --slurpfile admit "$admit" --arg name "$name" '
        def fail($message): "operations: \($name): \($message)\n" | halt_error(1);

        . as $root
        | def resolve: if has("$ref") then ."$ref" as $r | $root | getpath($r | ltrimstr("#/") | split("/"))
            // fail("\($r) is not in the spec") else . end;

        # Every path below a schema: each of its properties, and what is below
        # that, through a $ref and each part of an allOf -- so an allOf of
        # objects is their fields together, and one of scalars is a scalar,
        # with nothing below. An array is a field, and so is a map
        # (additionalProperties): their elements are not fields but values,
        # judged by the leaf that names the field.
        def fields($prefix; $seen):
            if has("$ref") then
              ."$ref" as $r
              | if any($seen[]; . == $r) then fail("\($r) contains itself, at \($prefix)") end
              | resolve | fields($prefix; $seen + [$r])
            else
              ((.properties // {}) | to_entries[] | ($prefix + .key) as $p | $p, (.value | fields($p + "."; $seen))),
              ((.allOf // [])[] | fields($prefix; $seen))
            end;

        [ .paths[] | (.parameters // []) as $shared | to_entries[]
          | select(.key | IN("get", "put", "post", "patch", "delete", "head", "options", "trace"))
          | .value as $op | $admit[0][$op.operationId // ""].docker.body // empty
          | . as $table
          | [$shared[], ($op.parameters // [])[] | resolve | select(.in == "body")] as $bodies
          | if ($bodies | length) != 1
            then fail("admit.json gives \($op.operationId) the body table \($table), and the spec gives it \($bodies | length) bodies") end
          | { table: $table, id: $op.operationId,
              fields: (reduce ($bodies[0].schema | fields(""; [])) as $f ([]; if index([$f]) then . else . + [$f] end)) } ]
        | group_by(.table)
        | map(if (map(.fields) | unique | length) > 1
              then fail("the body table \(.[0].table) is named by \(map(.id)), whose bodies differ") end
              | "\(.[0].table | tojson): [\n" + (.[0].fields | map(tojson) | join(",\n")) + "\n]")
        | "{\n" + join(",\n") + "\n}"
    ' "$spec" > "$known.new"
    mv "$known.new" "$known"
fi

jq -r --arg name "$name" 'length as $n | group_by(.operation.class) | map("\(length) \(.[0].operation.class)") | join(", ")
    | "operations: \($name): \($n) operations: \(.)."' "$out" >&2
jq -r --arg name "$name" '[.[] | select(.docker)] | select(length > 0)
    | "operations: \($name): of which admitted: \(length); the rest are refused."' "$out" >&2
jq -r --arg name "$name" '[.[] | select(.graphql)] | select(length > 0)
    | "operations: \($name): of which GraphQL: \(map(select(.query)) | length) queries, \(map(select(.mutation)) | length) mutations, \(map(select(.subscription)) | length) subscriptions."' "$out" >&2
