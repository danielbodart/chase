#!/usr/bin/env bash
# usage: exchange.sh JWTFILE PROVIDER OUTFILE [extra curl -d args]
set -u
umask 077
jwt=$1 prov=$2 out=$3; shift 3
AUD=//iam.googleapis.com/projects/957865594838/locations/global/workloadIdentityPools/frisket-spike/providers/$prov
code=$(curl -sS -o "$out.resp" -w '%{http_code} %{time_total}' https://sts.googleapis.com/v1/token \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode audience=$AUD \
  --data-urlencode scope=https://www.googleapis.com/auth/cloud-platform \
  --data-urlencode requested_token_type=urn:ietf:params:oauth:token-type:access_token \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode subject_token@"$jwt" "$@")
echo "http+secs: $code"
jq -c '{expires_in,token_type,issued_token_type,error,error_description, tok_len:(.access_token|if .==null then null else length end), tok_prefix:(.access_token|if .==null then null else .[0:4] end)}' "$out.resp"
jq -r '.access_token // empty' "$out.resp" > "$out"; rm -f "$out.resp"
