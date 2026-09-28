#!/usr/bin/env bash
# Re-runs the main matrix. Each case writes out/<case>.jsonl (every request fake Google saw).
# Needs the tool links in tools/ (see FINDINGS.md "Setup"). Inspect with: tools/python3 show.py out/<case>.jsonl -v -r
# and tools/python3 decodejwt.py out/<case>.jsonl for JWT bearers/assertions.
set -u
S="$(cd "$(dirname "$0")" && pwd)"; cd "$S"; C=$S/creds
run() { local name=$1 cred=$2; shift 2; echo "### $name"; ./ns.sh "$name" env GOOGLE_APPLICATION_CREDENTIALS=$C/$cred.json "$@" 2>&1 | tail -2; }
for f in au-default au-custom-uri sa-default sa-custom-uri ea-url ea-file ea-url-imp ea-url-customsts ea-url-customall eaau-default eaau-custom; do
  run py-$f $f python3 pyclient.py
  run gooauth2-$f $f goclient oauth2
  run goapi-$f $f goclient api
  run node-$f $f node nodeclient/client.js
done
for f in sa-default sa-custom-uri; do
  run pygapic-$f $f python3 pyclient.py gapic-rest
  run gogapic-$f $f goclient api-gapic
  run node-noscope-$f $f node nodeclient/client2.js headers-noscope
  run node-jwtscope-$f $f node nodeclient/client2.js jwtaccess-scope
done
echo "### gcloud"
./ns.sh gc-refresh-token bash -c "gcloud auth activate-refresh-token spike-user@example.com proxy-injected; gcloud projects list; gcloud projects list"
./ns.sh gc-token-file bash -c "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE=$C/access-token.txt gcloud projects list"
./ns.sh gc-override-au bash -c "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=$C/au-custom-uri.json gcloud projects list"
./ns.sh gc-cred-file-au bash -c "gcloud auth login --cred-file=$C/au-default.json"
./ns.sh gc-sa bash -c "gcloud auth activate-service-account --key-file=$C/sa-custom-uri.json; gcloud projects list; gcloud config set auth/service_account_use_self_signed_jwt true; gcloud projects list"
./ns.sh gc-ea bash -c "gcloud auth login --cred-file=$C/ea-url-customsts.json; gcloud projects list"
./ns.sh gc-ea-imp bash -c "gcloud auth login --cred-file=$C/ea-url-customall.json; gcloud projects list"
./ns.sh gc-eaau-override bash -c "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=$C/eaau-custom.json gcloud projects list"
