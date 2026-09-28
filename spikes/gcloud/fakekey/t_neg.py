import json, time, requests, google.auth.crypt, google.auth.jwt as J
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
k = json.load(open("/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey/sbx/home/fake-key.json"))
fake = google.auth.crypt.RSASigner.from_service_account_info(k)
other_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
other = google.auth.crypt.RSASigner.from_string(other_pem, "x")
E = k["client_email"]; now = int(time.time())
def jwt(s, **c): return J.encode(s, dict({"iss": E, "sub": E, "iat": now, "exp": now + 3600}, **c)).decode()
U = "https://storage.googleapis.com/storage/v1/b/danbodart-sandbox-test-frisket-spike/o/hello.txt"
cases = {
 "fake key, aud=storage": jwt(fake, aud="https://storage.googleapis.com/"),
 "fake key, aud=pubsub (wrong host)": jwt(fake, aud="https://pubsub.googleapis.com/"),
 "fake key, 24h life": jwt(fake, aud="https://storage.googleapis.com/", exp=now + 86400),
 "fake key, expired": jwt(fake, aud="https://storage.googleapis.com/", iat=now - 7200, exp=now - 3600),
 "fake key, other iss": jwt(fake, aud="https://storage.googleapis.com/", iss="evil@x.iam.gserviceaccount.com", sub="evil@x.iam.gserviceaccount.com"),
 "other key, aud=storage": jwt(other, aud="https://storage.googleapis.com/"),
}
for n, t in cases.items():
    r = requests.get(U, headers={"Authorization": "Bearer " + t})
    print(f"bearer {n}: {r.status_code}")
T = "https://oauth2.googleapis.com/token"
for n, a in {"fake key assertion": jwt(fake, aud=T, scope="https://www.googleapis.com/auth/cloud-platform"),
             "other key assertion": jwt(other, aud=T, scope="x"),
             "fake key, aud=storage": jwt(fake, aud="https://storage.googleapis.com/", scope="x")}.items():
    r = requests.post(T, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": a})
    print(f"token {n}: {r.status_code} {sorted(r.json().keys())} {r.json().get('access_token', r.json().get('error_description', ''))}")
r = requests.post(T, data={"grant_type": "refresh_token", "refresh_token": "x", "client_id": "a", "client_secret": "b"})
print("token refresh_token grant:", r.status_code, r.json().get("error_description"))
for u in ["https://oauth2.googleapis.com/tokeninfo?access_token=proxy-injected", "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=proxy-injected"]:
    print("GET", u.split("?")[0], requests.get(u).status_code)
for u in ["https://accounts.google.com/", "http://169.254.169.254/computeMetadata/v1/", "http://metadata.google.internal/computeMetadata/v1/", k["client_x509_cert_url"]]:
    try: print("GET", u, requests.get(u, headers={"Metadata-Flavor": "Google"}, timeout=5).status_code)
    except Exception as e: print("GET", u, type(e).__name__)
