. /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata/common.sh
export SSL_CERT_FILE=$S/pki/bundle.crt
timeout 90 $S/goclient/goclient 2>&1 | tail -${LINES_MAX:-8}
