#!/usr/bin/env bash
# chase-gcloud-renew mint|loop RUN
#
# Mints RUN/gcloud-token.json from the service-account key at
# RUN/secrets/gcloud. mint exits 0 minted, 1 transient, 2 Google refused the
# grant, 3 the key is not a usable key of $CHASE_GCLOUD_SA.
set -euo pipefail
umask 077

token_url=https://oauth2.googleapis.com/token
aud=https://oauth2.googleapis.com/token
scope=https://www.googleapis.com/auth/cloud-platform

say() { echo "chase-gcloud-renew: $*" >&2; }
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now_ms() { date +%s%3N; }

mint() {
  local run=$1 key email now header claims signature jwt sent out code body expiry tmp
  key=$run/secrets/gcloud
  [ -r "$key" ] || { say "no key at $key"; return 3; }
  email=$(jq -er 'select(.type == "service_account" and (.private_key | type) == "string") | .client_email | strings' "$key" 2>/dev/null) \
    || { say "$key is not a service-account key"; return 3; }
  if [ -n "${CHASE_GCLOUD_SA-}" ] && [ "$email" != "$CHASE_GCLOUD_SA" ]; then
    say "the key is $email's, not $CHASE_GCLOUD_SA's"
    return 3
  fi

  now=$(date +%s)
  header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
  claims=$(jq -nc --arg iss "$email" --arg scope "$scope" --arg aud "$aud" --argjson now "$now" \
    '{iss: $iss, scope: $scope, aud: $aud, iat: $now, exp: ($now + 3600)}' | b64url)
  signature=$(printf '%s' "$header.$claims" \
    | openssl dgst -sha256 -sign <(jq -r .private_key "$key") 2>/dev/null | b64url) \
    && [ -n "$signature" ] || { say "the key's private_key does not sign"; return 3; }
  jwt=$header.$claims.$signature

  sent=$(now_ms)
  if ! out=$(printf '%s' "$jwt" | curl -sS --max-time 60 -w '\n%{http_code}' \
      --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
      --data-urlencode 'assertion@-' "$token_url"); then
    say "$token_url did not answer"
    return 1
  fi
  code=${out##*$'\n'}
  body=${out%$'\n'*}
  case $code in
    200) ;;
    4??)
      say "Google refused $email's grant ($code): $(printf '%s' "$body" | jq -r '"\(.error // "?"): \(.error_description // "")"' 2>/dev/null || echo "?")"
      return 2
      ;;
    *) say "$token_url answered $code"; return 1 ;;
  esac

  expiry=$(printf '%s' "$body" | jq -er --argjson sent "$sent" \
    'select((.access_token | type) == "string" and .access_token != "" and (.expires_in | type) == "number" and .expires_in > 0)
     | $sent + (.expires_in * 1000 | floor)' 2>/dev/null) \
    || { say "$token_url answered 200 without a token"; return 1; }
  tmp=$(mktemp "$run/.gcloud-token.XXXXXX") || return 1
  if ! printf '%s' "$body" | jq -c --argjson expiry "$expiry" '{access_token, expiry: $expiry}' > "$tmp" \
      || ! mv -f -- "$tmp" "$run/gcloud-token.json"; then
    rm -f -- "$tmp"
    return 1
  fi
  say "minted for $email, expiring $(date -d "@$((expiry / 1000))" -Is)"
}

expiry() { jq -er '.expiry | numbers' "$1/gcloud-token.json" 2>/dev/null || echo 0; }

nap() {
  local run=$1 left=$2
  while [ "$left" -gt 0 ] && [ -d "$run" ]; do
    sleep $((left < 10 ? left : 10))
    left=$((left - 10))
  done
}

loop() {
  local run=$1 wait
  while [ -d "$run" ]; do
    wait=$(( ($(expiry "$run") - $(now_ms)) / 1000 - 600 ))
    if [ "$wait" -gt 0 ]; then
      nap "$run" $((wait < 300 ? wait : 300))
      continue
    fi
    if ! mint "$run"; then
      [ -d "$run" ] || break
      say "trying again in a minute"
      nap "$run" 60
    fi
  done
}

case ${1-} in
  mint) [ $# -eq 2 ] || { say "usage: mint RUN"; exit 64; }; mint "$2" ;;
  loop) [ $# -eq 2 ] || { say "usage: loop RUN"; exit 64; }; loop "$2" ;;
  *) say "usage: chase-gcloud-renew mint|loop RUN"; exit 64 ;;
esac
