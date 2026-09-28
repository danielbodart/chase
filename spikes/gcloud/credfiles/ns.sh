#!/usr/bin/env bash
# usage: ns.sh <case-name> <command...>
# Runs fake Google + the client inside an unprivileged user+net+mount namespace.
# Names are steered by a hosts file bind-mounted over /etc/hosts; 192.0.2.2 is on lo.
S="$(cd "$(dirname "$0")" && pwd)"
CASE="$1"; shift
mkdir -p "$S/out"
export FAKE_LOG="$S/out/$CASE.jsonl"; rm -f "$FAKE_LOG"
export CASEDIR="$S/cases/$CASE"; rm -rf "$CASEDIR"; mkdir -p "$CASEDIR/home"
export HOME="$CASEDIR/home" CLOUDSDK_CONFIG="$CASEDIR/gcloud"
export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="$S/pki/ca.crt" REQUESTS_CA_BUNDLE="$S/pki/ca.crt" \
       SSL_CERT_FILE="$S/pki/ca.crt" NODE_EXTRA_CA_CERTS="$S/pki/ca.crt" \
       CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=true CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true \
       CLOUDSDK_CORE_CHECK_GCE_METADATA=false
export PATH="$S/tools:$PATH" GOPATH="$S/gopath" GOCACHE="$S/gocache" GOFLAGS=-modcacherw
exec unshare -rnm bash -c '
  set -e
  ip link set lo up
  ip addr add 192.0.2.2/32 dev lo
  mount --bind "$0/pki/hosts" /etc/hosts
  mount -t tmpfs none /run/nscd
  python3 "$0/fakegoogle.py" > "$CASEDIR/server.out" 2>&1 &
  for i in $(seq 50); do grep -q ready "$CASEDIR/server.out" 2>/dev/null && break; sleep 0.1; done
  cd "$CASEDIR"
  set +e
  "$@"
  rc=$?
  echo "== exit $rc"
' "$S" "$@"
