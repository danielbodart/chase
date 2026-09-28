import os, sys, time, logging
import google.auth, google.auth.transport.requests as gtr
print("google-auth", google.auth.__version__)
t0 = time.time()
creds, project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
print("default():", type(creds).__module__ + "." + type(creds).__name__, "project=", project, f"{time.time()-t0:.2f}s")
s = gtr.AuthorizedSession(creds)
for i in range(int(os.environ.get("LOOPS", "1"))):
    r = s.get("https://storage.googleapis.com/storage/v1/b?project=frisket-spike")
    print(i, r.status_code, r.text[:60], "token=", creds.token, "expiry=", creds.expiry)
    time.sleep(float(os.environ.get("SLEEP", "1")))
if os.environ.get("IDTOK"):
    from google.oauth2 import id_token
    print("fetch_id_token:", id_token.fetch_id_token(gtr.Request(), "https://example.run.app"))
