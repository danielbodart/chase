. /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata/common.sh
export REQUESTS_CA_BUNDLE=$S/pki/bundle.crt
python3 $S/t-python.py 2>&1 | tail -${LINES_MAX:-12}
