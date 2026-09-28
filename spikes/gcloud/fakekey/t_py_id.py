import base64, json, datetime
import google.auth.transport.requests as gr
from google.oauth2 import id_token
from google.cloud import storage
def claims(t):
    p = t.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(pad(p[0]))), json.loads(base64.urlsafe_b64decode(pad(p[1])))
try:
    t = id_token.fetch_id_token(gr.Request(), "https://example-run-service.a.run.app")
    h, c = claims(t)
    print("fetch_id_token ok; header", h, "claims", {k: c[k] for k in ("iss","aud","email","exp")})
except Exception as e:
    print("fetch_id_token FAIL", type(e).__name__, str(e)[:300])
b = storage.Client().bucket("danbodart-sandbox-test-frisket-spike").blob("hello.txt")
try:
    u = b.generate_signed_url(expiration=datetime.timedelta(minutes=5), version="v4")
    print("signed url generated (host, has X-Goog-Signature):", u.split("?")[0], "X-Goog-Signature=" in u)
    import requests
    r = requests.get(u)
    print("fetch signed url:", r.status_code, r.text[:160].replace("\n"," "))
except Exception as e:
    print("signed url FAIL", type(e).__name__, str(e)[:300])
