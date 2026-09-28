. /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata/common.sh
export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=$S/pki/ca.crt
rm -rf $CLOUDSDK_CONFIG; mkdir -p $CLOUDSDK_CONFIG
for c in "auth list" "storage ls"; do echo "=== gcloud $c"; t0=$(date +%s.%N); timeout 120 gcloud $c 2>&1 | tail -4; echo "--- rc=${PIPESTATUS[0]} secs=$(echo "$(date +%s.%N) - $t0" | bc) gce-cache=$(cat $CLOUDSDK_CONFIG/gce 2>/dev/null)"; done
