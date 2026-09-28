. /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata/common.sh
export NODE_EXTRA_CA_CERTS=$S/pki/ca.crt
timeout 120 node $S/node/t.js 2>&1 | tail -${LINES_MAX:-8}
