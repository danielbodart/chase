# An app a project binds, merged into the session's policy document: its
# routes in place of any the tier had by the same names, and the names it
# needs added to `allow`, unless the tier allows every name.
#
#   jq --slurpfile patch <(echo '{"routes": [...], "allow": [...]}') -f merge.jq

($patch[0].routes // []) as $routes
| ($routes | map(.name)) as $names
| .routes = ([.routes[]? | select(.name as $n | $names | index($n) | not)] + $routes)
| if (.allow | index("*")) then . else .allow = (.allow + ($patch[0].allow // []) | unique) end
