. /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata/common.sh
export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=$S/pki/bundle.crt REQUESTS_CA_BUNDLE=$S/pki/bundle.crt
timeout 60 python3 $S/t-pubsub.py 2>&1 | tail -6
