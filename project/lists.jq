# A project's lists for one app, applied to its route in the session's policy
# document (PLAN.md, decision 18): `allow`, `ask` and `refuse`, each naming
# operations by id, whole categories as "category:<name>", or methods and an
# exact path for an endpoint the description does not name.
#
#   jq --arg app github --argjson lists '{"allow": [...], ...}' -f lists.jq
#
# A name decides before a category, and a category before what the tier and
# the app said. A name or category the route does not have is an error: a
# typo would otherwise be a rule that silently decides nothing. So is a path
# that one of the route's operations already describes: a literal beats a
# "*", so {DELETE, /repos/me/app} would decide repos/delete without naming
# it. An operation the description has is loosened by its name, which is
# what the person approving it reads. And so is an entry in two lists, which
# ../project/default.nix refuses before approval.
# git's push is the operation `git-receive-pack`, in frisket's git rule.

def answer($verb):
  if $verb == "allow" then del(.ask, .refuse)
  elif $verb == "ask" then del(.refuse) | .ask = true
  else del(.ask) | .refuse = true end;

# Whether an exact path and a rule can match one request: segment by
# segment a literal meets itself or a "*", and a prefix matches that many
# segments or more.
def overlaps($path; $rule):
  ($path | split("/")[1:]) as $x | (($rule.path // $rule.prefix) | split("/")[1:] | map(select(. != ""))) as $y
  | (if $rule.path then ($x | length) == ($y | length) else ($x | length) >= ($y | length) end)
    and all(range($y | length); $x[.] == "*" or $y[.] == "*" or $x[.] == $y[.]);

def push($verb): { allow: "allow", ask: "ask", refuse: "refuse" }[$verb];

($lists | to_entries | map(.key as $verb | .value[] | { verb: $verb, entry: . })) as $entries
| ($entries | map(select(.entry | type == "string" and (startswith("category:") | not))) | map({ key: .entry, value: .verb }) | from_entries) as $byId
| ($entries | map(select(.entry | type == "string" and startswith("category:"))) | map({ key: (.entry | ltrimstr("category:")), value: .verb }) | from_entries) as $byCategory
| ($entries | map(select(.entry | type == "object"))) as $endpoints
| (.routes | map(.name) | index($app)) as $i
| if $i == null then error("\($app) is not in this tier") else . end
| .routes[$i] as $route
| ([$route.paths[]?.operation.id? // empty] + (if $route.git then ["git-receive-pack"] else [] end)) as $ids
| ([$route.paths[]?.operation.category? // empty] | unique) as $categories
| ([$byId | keys[] | select(. as $x | $ids | index($x) | not)]
   + [$byCategory | keys[] | select(. as $x | $categories | index($x) | not) | "category:\(.)"]) as $unknown
| if $unknown != [] then error("\($app) has no \($unknown | join(", "))") else . end
| ([$endpoints[].entry as $e | $route.paths[]? | select(.operation.id? and ([.methods[]] - $e.methods) != .methods and overlaps($e.path; .))
    | "\($e.methods | join(",")) \($e.path) is \(.operation.id)"] | unique) as $described
| if $described != [] then error("\($app) describes these, so name them: \($described | join("; "))") else . end
| .routes[$i] |= (
    .paths = ([.paths[]? | (.operation.id? // null) as $id | (.operation.category? // null) as $c
        | if $id != null and $byId[$id] then answer($byId[$id])
          elif $c != null and $byCategory[$c] then answer($byCategory[$c])
          else . end]
      + [$endpoints[] | .verb as $v | { methods: .entry.methods, path: .entry.path } | answer($v)])
    | if .git and $byId["git-receive-pack"] then .git.push = push($byId["git-receive-pack"]) else . end)
