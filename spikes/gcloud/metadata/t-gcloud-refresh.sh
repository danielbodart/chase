. /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata/common.sh
export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=$S/pki/ca.crt
rm -rf $CLOUDSDK_CONFIG; mkdir -p $CLOUDSDK_CONFIG
for i in 1 2 3 4; do gcloud storage ls >/dev/null 2>&1; sleep 1; done
