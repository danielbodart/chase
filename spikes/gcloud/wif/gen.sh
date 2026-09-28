#!/usr/bin/env bash
# usage: gen.sh FEDTOKFILE LIFETIME OUTFILE [SCOPE...]
set -u; umask 077
fed=$1 life=$2 out=$3; shift 3
scopes=$(printf '%s\n' "${@:-https://www.googleapis.com/auth/cloud-platform}" | jq -R . | jq -sc .)
body=$(jq -nc --arg l "$life" --argjson s "$scopes" '{scope:$s, lifetime:$l}')
code=$(curl -sS -o "$out.resp" -w '%{http_code} %{time_total}' -X POST \
  -H @<(printf 'Authorization: Bearer %s' "$(cat "$fed")") -H 'Content-Type: application/json' -d "$body" \
  https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/frisket-spike@danbodart-sandbox-test.iam.gserviceaccount.com:generateAccessToken)
echo -n "http+secs: $code  "
jq -c '{expireTime, secs_left:(if .expireTime then ((.expireTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601) - now|floor) else null end), error:(.error|if .==null then null else {code,status,message} end), tok_len:(.accessToken|if .==null then null else length end), tok_prefix:(.accessToken|if .==null then null else .[0:4] end)}' "$out.resp"
jq -r '.accessToken // empty' "$out.resp" > "$out"; rm -f "$out.resp"
