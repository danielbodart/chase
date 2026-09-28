#!/usr/bin/env bash
# usage: ns.sh <logname> cmd...   runs cmd in a fresh user+net+mount namespace with the fakes up
set -e
S=$(cd "$(dirname "$0")" && pwd)
. "$S/env.sh"
name=$1; shift
export LOG=$S/logs/$name.log
: > "$LOG"
exec unshare -rnm --kill-child bash -c '
set -e
S='"$S"'
ip link set lo up
ip addr add 192.0.2.2/32 dev lo
ip addr add 192.0.2.10/32 dev lo
ip addr add 169.254.169.254/32 dev lo
ip addr add 127.0.0.53/8 dev lo 2>/dev/null || true
mount --bind ${HOSTS:-$S/ns-hosts} /etc/hosts
mount --bind $S/ns-resolv.conf /etc/resolv.conf
mount -t tmpfs tmpfs /run/nscd
(cd $S/fakes && exec ./fakes) 2>$S/logs/fakes.stderr &
FP=$!
for i in $(seq 50); do (exec 3<>/dev/tcp/192.0.2.10/443) 2>/dev/null && break; sleep 0.05; done
set +e
"$@"
rc=$?
kill $FP
exit $rc
' bash "$@"
