#!/usr/bin/env bash
# renew.sh KEY.pem KID ISS PROVIDER_RESOURCE SA LIFETIME OUT  -- needs openssl, curl, jq
set -euo pipefail; umask 077
key=$1 kid=$2 iss=$3 prov=$4 sa=$5 life=$6 out=$7
b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now=$(date +%s)
h=$(printf '{"alg":"RS256","typ":"JWT","kid":"%s"}' "$kid" | b64)
c=$(jq -nc --arg i "$iss" --arg a frisket-spike --argjson n "$now" '{iss:$i,sub:"project:danbodart-sandbox-test",aud:$a,iat:$n,exp:($n+120)}' | b64)
jwt="$h.$c.$(printf '%s' "$h.$c" | openssl dgst -sha256 -sign "$key" | b64)"
fed=$(curl -fsS https://sts.googleapis.com/v1/token -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d audience="$prov" -d scope=https://www.googleapis.com/auth/cloud-platform \
  -d requested_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt --data-urlencode subject_token@<(printf %s "$jwt") | jq -r .access_token)
curl -fsS -H @<(printf 'Authorization: Bearer %s' "$fed") -H 'Content-Type: application/json' \
  -d "{\"lifetime\":\"$life\",\"scope\":[\"https://www.googleapis.com/auth/cloud-platform\"]}" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$sa:generateAccessToken" > "$out.json"
jq -r .accessToken "$out.json" > "$out"; jq -r .expireTime "$out.json"; rm "$out.json"
