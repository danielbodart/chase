B=gs://danbodart-sandbox-test-frisket-spike
run(){ echo "### $*"; "$@" 2>&1 | grep -v '^$' | head -${N:-8}; echo "rc=${PIPESTATUS[0]}"; }
run gcloud auth list
run gcloud config list
run gcloud storage ls $B
run gcloud storage cat $B/hello.txt
echo "### print-identity-token"; gcloud auth print-identity-token --audiences=https://example-run-service.a.run.app 2>&1 | python3 /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey/jwtshow.py 2>&1 | tail -2
run gcloud pubsub topics describe frisket-spike --project danbodart-sandbox-test --format='value(name)'
