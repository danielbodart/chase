#!/usr/bin/env python3
# Host renewer: mint the SA's access token via iamcredentials and write it
# atomically as {"access_token", "expiry_ms"}. Never prints the token.
import datetime, json, os, subprocess, sys, tempfile, urllib.request
sa, out = sys.argv[1], sys.argv[2]
lifetime = sys.argv[3] if len(sys.argv) > 3 else "3600s"
os.umask(0o077)
user = subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True, check=True).stdout.strip()
req = urllib.request.Request(
    f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:generateAccessToken",
    data=json.dumps({"scope": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime": lifetime}).encode(),
    headers={"Authorization": "Bearer " + user, "Content-Type": "application/json"})
r = json.load(urllib.request.urlopen(req))
exp = datetime.datetime.fromisoformat(r["expireTime"].replace("Z", "+00:00"))
doc = {"access_token": r["accessToken"], "expiry_ms": int(exp.timestamp() * 1000)}
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(out))
with os.fdopen(fd, "w") as f:
    json.dump(doc, f)
os.rename(tmp, out)
print(f"wrote {out}: token {r['accessToken'][:4]}… ({len(r['accessToken'])} chars), expires {r['expireTime']}")
