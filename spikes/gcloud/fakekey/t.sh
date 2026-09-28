#!/usr/bin/env bash
# t.sh NAME CMD...: run CMD in the sandbox, keep its output and frisket's lines for it.
F=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey
n=$1; shift; s=$(wc -l < $F/logs/frisket.log)
timeout ${TMO:-300} $F/in.sh "$@" > $F/out/$n.out 2>&1; rc=$?; echo "rc=$rc" >> $F/out/$n.out
sleep 0.3; tail -n +$((s+1)) $F/logs/frisket.log > $F/logs/$n.log
printf '%-14s rc=%s\n' $n $rc; python3 $F/sum.py $F/logs/$n.log
