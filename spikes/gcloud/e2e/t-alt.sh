SA=frisket-spike@danbodart-sandbox-test.iam.gserviceaccount.com
B='{"scope":["https://www.googleapis.com/auth/cloud-platform"]}'
for h in iamcredentials.googleapis.com. IAMCREDENTIALS.googleapis.com iamcredentials.mtls.googleapis.com iamcredentials.us-central1.rep.googleapis.com iamcredentials.europe-west2.rep.googleapis.com; do
  echo "### $h"; curl -sS -m 8 -X POST -H 'Authorization: Bearer proxy-injected' -H 'Content-Type: application/json' -d "$B" "https://$h/v1/projects/-/serviceAccounts/$SA:generateAccessToken" | tr '\n' ' ' | cut -c1-230; echo
done
echo "### sts.mtls token-exchange (placeholder as subject token)"
curl -sS -m 8 -X POST -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token=proxy-injected&options=%7B%7D' https://sts.mtls.googleapis.com/v1/token | cut -c1-230; echo
