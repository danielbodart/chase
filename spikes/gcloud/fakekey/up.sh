#!/usr/bin/env bash
# Host side: daemon, sandbox leader, steer, connect.
set -e
E=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey
NFT=/nix/store/h7nlr7jajsrzzhxg3mmxsfh4l1jz3zb1-nftables-1.1.6/bin/nft
NSENTER=$(readlink -f $(command -v nsenter))
CTL=/run/user/1000/ffk.sock
if ! [ -S $CTL ] || ! kill -0 $(cat $E/daemon.pid 2>/dev/null) 2>/dev/null; then
  rm -f $CTL
  setsid $E/frisket serve -control $CTL -config $E/serve.json -log-level debug >>$E/logs/frisket.log 2>&1 < /dev/null &
  echo $! > $E/daemon.pid
  for i in $(seq 50); do [ -S $CTL ] && break; sleep 0.1; done
fi
setsid unshare -Urnm --map-auto -pf --mount-proc --kill-child bash $E/leader.sh </dev/null >$E/logs/leader.log 2>&1 &
U=$!
for i in $(seq 50); do L=$(pgrep -P $U sleep || true); [ -n "$L" ] && break; sleep 0.1; done
echo $L > $E/leader.pid
$E/frisket steer -control $CTL -nft $NFT -userns /proc/$L/ns/user -nsenter $NSENTER \
  -netns /proc/$L/ns/net -mntns /proc/$L/ns/mnt -roots /etc/ssl/certs/ca-certificates.crt \
  -steering $E/steering.json -name fk -policy $E/policy/gcp.json
$E/frisket connect -control $CTL -nft $NFT -userns /proc/$L/ns/user -nsenter $NSENTER \
  -netns /proc/$L/ns/net -steering $E/steering.json -name fk
echo "leader $L steered"
