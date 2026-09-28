# An envelope as it is approved: a project that loosens nothing has no
# seccomp section, and says nothing of an app it does not bind, so an
# envelope approved before there were any still is. One approved before is
# read through this too, so it is compared as it would be written now.
#
#   jq -c -f normal.jq

def pruned: if type == "object" then map_values(pruned) | with_entries(select(.value | IN(null, [], {}) | not)) else . end;

if .seccomp == {allow: [], deny: []} then del(.seccomp) else . end
| if .bindings then .bindings |= pruned else . end
