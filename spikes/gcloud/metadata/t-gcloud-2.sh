. /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata/common.sh
export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=$S/pki/ca.crt
[ -z "$KEEP" ] && { rm -rf $CLOUDSDK_CONFIG; mkdir -p $CLOUDSDK_CONFIG; }
ip addr add 192.0.2.3/32 dev lo
for c in "storage ls" "projects describe frisket-spike"; do t0=$(date +%s.%N); timeout 120 gcloud $c 2>&1 | tail -2; echo "--- gcloud $c rc=${PIPESTATUS[0]} secs=$(echo "$(date +%s.%N) - $t0" | bc) gce-cache=$(cat $CLOUDSDK_CONFIG/gce 2>/dev/null)"; done
