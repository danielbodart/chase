#!/usr/bin/env bash
E=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey
$E/frisket close -control /run/user/1000/ffk.sock -name fk
L=$(cat $E/leader.pid); kill $(ps -o ppid= -p $L) $L 2>/dev/null
[ "$1" = all ] && kill $(cat $E/daemon.pid) && rm -f /run/user/1000/ffk.sock
true
