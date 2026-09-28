#!/usr/bin/env bash
# Counts occurrences of the real token's first 20 chars; never prints it.
F=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey
P=$(python3 -c 'import json;print(json.load(open("'$F'/host/gcp-token.json"))["access_token"][:20])')
c(){ printf '%-28s %s\n' "$1" "$(grep -rFac -- "$P" $2 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')"; }
c "sandbox CLOUDSDK_CONFIG" "$F/sbx/gcloud"
c "sandbox HOME" "$F/sbx/home"
c "terraform dir (state)" "$F/tf"
c "client outputs" "$F/out"
c "frisket logs" "$F/logs"
printf '%-28s %s\n' "sandbox env" "$($F/in.sh env | grep -Fc -- "$P")"
printf '%-28s %s\n' "placeholder in gcloud db" "$(grep -rac proxy-injected $F/sbx/gcloud/access_tokens.db 2>/dev/null)"
printf '%-28s %s\n' "sandbox reads host file" "$($F/in.sh cat $F/host/gcp-token.json 2>&1 | grep -Fc -- "$P")"
