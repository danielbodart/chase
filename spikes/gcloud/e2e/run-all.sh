#!/usr/bin/env bash
E=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/e2e
rm -rf $E/sbx/gcloud; mkdir -p $E/sbx/gcloud
t(){ n=$1; shift; s=$(wc -l < $E/logs/frisket.log); $E/in.sh "$@" > $E/out/$n.out 2>&1; rc=$?; echo "rc=$rc" >> $E/out/$n.out
     tail -n +$((s+1)) $E/logs/frisket.log > $E/logs/$n.log; printf '%-8s rc=%s\n' $n $rc; }
t gcloud bash $E/t-gcloud.sh
t python python3 $E/t.py
t go bash -c "cd $E/goclient && exec ./goclient"
t node bash -c "cd $E/node && exec node t.js"
