import os, sys, json, time, logging
import google.auth, google.auth.transport.requests as gtr
from google.auth.transport.requests import AuthorizedSession
scopes = ["https://www.googleapis.com/auth/cloud-platform"]
mode = sys.argv[1] if len(sys.argv) > 1 else "session"
creds, project = google.auth.default(scopes=scopes)
print("type:", type(creds).__module__, type(creds).__name__, "project:", project)
if mode == "session":
    s = AuthorizedSession(creds)
    for i in range(int(os.environ.get("N", "2"))):
        r = s.get("https://storage.googleapis.com/storage/v1/b?project=spike-proj")
        print("api", r.status_code, "token:", creds.token, "expiry:", creds.expiry)
        time.sleep(float(os.environ.get("SLEEP", "0")))
elif mode == "storage":
    from google.cloud import storage
    c = storage.Client(project="spike-proj")
    print([b.name for b in c.list_buckets()])
    print("token:", c._credentials.token)
elif mode == "noscope":
    creds, _ = google.auth.default()
    s = AuthorizedSession(creds)
    r = s.get("https://storage.googleapis.com/storage/v1/b?project=spike-proj")
    print("api", r.status_code, "token:", (creds.token or "")[:40])
elif mode in ("gapic-rest", "gapic-rest-scoped"):
    from google.cloud import resourcemanager_v3
    from google.api_core.client_options import ClientOptions
    kw = {}
    if mode == "gapic-rest-scoped":
        kw["client_options"] = ClientOptions(scopes=scopes)
    c = resourcemanager_v3.ProjectsClient(transport="rest", **kw)
    for i in range(2):
        print([p.project_id for p in c.search_projects(request={})])
