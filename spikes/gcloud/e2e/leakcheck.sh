#!/usr/bin/env bash
# Counts occurrences of the real token's first 20 chars; never prints it.
E=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/e2e
P=$(python3 -c 'import json;print(json.load(open("'$E'/host/gcp-token.json"))["access_token"][:20])')
c(){ printf '%-28s %s\n' "$1" "$(grep -rFac -- "$P" $2 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')"; }
c "sandbox CLOUDSDK_CONFIG" "$E/sbx/gcloud"
c "sandbox HOME" "$E/sbx/home"
c "client outputs" "$E/out"
c "frisket logs" "$E/logs"
printf '%-28s %s\n' "sandbox env" "$($E/in.sh env | grep -Fc -- "$P")"
printf '%-28s %s\n' "placeholder in gcloud db" "$(grep -rac proxy-injected $E/sbx/gcloud/access_tokens.db 2>/dev/null)"
printf '%-28s %s\n' "sandbox reads host file" "$($E/in.sh cat $E/host/gcp-token.json 2>&1 | grep -Fc -- "$P")"
