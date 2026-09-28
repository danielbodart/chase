#!/usr/bin/env bash
# The sandbox's leader: hides the host's credentials, then waits.
set -e
for d in /home/dan /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/e2e/host /run/user/1000 /run/frisket /run/nscd; do
  [ -d $d ] && mount -t tmpfs -o size=1m,mode=755 none $d
done
ip link set lo up
exec sleep infinity
