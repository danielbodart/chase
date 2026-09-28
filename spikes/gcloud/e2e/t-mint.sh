SA=frisket-spike@danbodart-sandbox-test.iam.gserviceaccount.com
for h in iamcredentials.googleapis.com iamcredentials.mtls.googleapis.com; do
  curl -sS -m 8 -X POST -H 'Authorization: Bearer proxy-injected' -H 'Content-Type: application/json' -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"300s"}' "https://$h/v1/projects/-/serviceAccounts/$SA:generateAccessToken" > $SBXOUT/mint-$h.json
  python3 -c '
import json,sys
raw=open(sys.argv[1]).read()
try: d=json.loads(raw)
except Exception: print(sys.argv[2], "not json:", raw[:60].strip()); sys.exit()
t=d.get("accessToken")
print(sys.argv[2], ("REAL TOKEN RETURNED: %s… (%d chars), expireTime %s" % (t[:4], len(t), d.get("expireTime"))) if t else d.get("error",{}).get("message","")[:120])
' $SBXOUT/mint-$h.json $h
done
