# usage (inside ns): t-gcloud.sh ; env GCE_* set by caller
. /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata/common.sh
export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=$S/pki/ca.crt
rm -rf $CLOUDSDK_CONFIG; mkdir -p $CLOUDSDK_CONFIG
run() { echo "=== $*"; local t0=$(date +%s.%N); "$@" 2>&1 | head -${LINES_MAX:-15}; echo "--- rc=${PIPESTATUS[0]} secs=$(echo "$(date +%s.%N) - $t0" | bc)"; echo "MARK $*" | python3 -c 'import sys,json,time; open(sys.argv[1],"a").write(json.dumps({"srv":"MARK","t":"-","UNKNOWN":sys.stdin.read().strip(),"query":""})+"\n")' $LOG; }
run gcloud auth list
echo "gce cache file:"; cat $CLOUDSDK_CONFIG/gce 2>&1; echo
run gcloud config list
run gcloud auth print-access-token
run gcloud storage ls
run gcloud storage ls gs://spike-bucket
run gcloud projects describe frisket-spike
run gcloud auth print-identity-token --audiences=https://example.run.app
echo "config dir:"; find $CLOUDSDK_CONFIG -maxdepth 2 | sed "s|$CLOUDSDK_CONFIG||"
