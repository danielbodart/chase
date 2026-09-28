import base64, json, os, ssl, sys, threading, time, urllib.parse, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.environ.get("FAKE_LOG", os.path.join(HERE, "wire.jsonl"))
FLAGS = set(filter(None, os.environ.get("FAKE_FLAGS", "").split(",")))
EXPIRES_IN = int(os.environ.get("FAKE_EXPIRES_IN", "3599"))
EMAIL = "spike-user@example.com"
lock = threading.Lock()
counter = [0]

idkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def id_token(aud):
    now = int(time.time())
    h = {"alg": "RS256", "kid": "fakekid", "typ": "JWT"}
    p = {"iss": "https://accounts.google.com", "aud": aud, "azp": aud, "sub": "1234567890",
         "email": EMAIL, "email_verified": True, "iat": now, "exp": now + 3600}
    si = b64u(json.dumps(h).encode()) + "." + b64u(json.dumps(p).encode())
    sig = idkey.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())
    return si + "." + b64u(sig)


def next_token(kind):
    with lock:
        counter[0] += 1
        if "CONST_TOKEN" in FLAGS:
            return "proxy-injected"
        return f"ya29.PLACEHOLDER-{kind}-{counter[0]}"


def log(entry):
    with lock:
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.entry["status"] = code
        self.entry["resp"] = obj if not isinstance(obj, bytes) else obj.decode(errors="replace")[:500]
        log(self.entry)

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        host = self.headers.get("Host", "")
        u = urllib.parse.urlsplit(self.path)
        self.entry = {"t": round(time.time(), 3), "tls": isinstance(self.connection, ssl.SSLSocket),
                      "local": "%s:%d" % self.connection.getsockname()[:2],
                      "method": self.command, "host": host, "path": self.path,
                      "headers": dict(self.headers.items()), "body": raw.decode(errors="replace")}
        form = {}
        ct = self.headers.get("Content-Type", "")
        if "json" in ct and raw:
            try:
                form = json.loads(raw)
            except Exception:
                pass
        elif raw:
            form = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}
        self.entry["form"] = form
        p = u.path
        gt = form.get("grant_type", "")

        if p.endswith("/subject-token"):
            if "SUBJECT_JSON" in FLAGS:
                return self.reply(200, {"id_token": "PLACEHOLDER-SUBJECT-TOKEN"})
            return self.reply(200, b"PLACEHOLDER-SUBJECT-TOKEN", "text/plain")

        if p.endswith(":generateAccessToken"):
            exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=EXPIRES_IN)
            return self.reply(200, {"accessToken": next_token("impersonated"),
                                    "expireTime": exp.strftime("%Y-%m-%dT%H:%M:%SZ")})

        if gt == "urn:ietf:params:oauth:grant-type:token-exchange":
            r = {"access_token": next_token("sts"), "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                 "token_type": "Bearer"}
            if "NO_EXPIRES" not in FLAGS:
                r["expires_in"] = EXPIRES_IN
            return self.reply(200, r)

        if gt in ("refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"):
            kind = "user" if gt == "refresh_token" else "sa"
            r = {"access_token": next_token(kind), "token_type": "Bearer"}
            if "NO_EXPIRES" not in FLAGS:
                r["expires_in"] = EXPIRES_IN
            if "NO_SCOPE" not in FLAGS and form.get("scope"):
                r["scope"] = form.get("scope")
            elif "NO_SCOPE" not in FLAGS and kind == "user":
                r["scope"] = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform"
            if "NO_ID_TOKEN" not in FLAGS and kind == "user":
                r["id_token"] = id_token(form.get("client_id", "x"))
            if "ID_TOKEN_ONLY" in FLAGS and kind == "sa":
                r = {"id_token": id_token("x")}
            if "FAIL_TOKEN" in FLAGS:
                return self.reply(400, {"error": "invalid_grant", "error_description": "spike says no"})
            return self.reply(200, r)

        if p.endswith("/introspect"):
            return self.reply(200, {"active": True, "username": "spike-principal@example.com", "client_id": "x",
                                    "scope": "https://www.googleapis.com/auth/cloud-platform", "exp": int(time.time()) + 3600})
        if "tokeninfo" in p:
            return self.reply(200, {"email": EMAIL, "scope": "https://www.googleapis.com/auth/cloud-platform",
                                    "expires_in": 3000, "aud": "x"})
        if "userinfo" in p:
            return self.reply(200, {"email": EMAIL, "email_verified": True, "sub": "1234567890"})
        if p.startswith("/oauth2/v1/certs"):
            pem = idkey.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            return self.reply(200, {"fakekid": pem.decode()})
        if p.startswith("/storage/v1/b/") and "/o" in p:
            return self.reply(200, {"kind": "storage#objects", "items": [{"name": "hello.txt", "bucket": "spike-bucket"}]})
        if p.startswith("/storage/v1/b"):
            return self.reply(200, {"kind": "storage#buckets", "items": [{"name": "spike-bucket", "id": "spike-bucket"}]})
        if "cloudresourcemanager" in host or p.startswith("/v1/projects") or p.startswith("/v3/projects"):
            return self.reply(200, {"projects": [{"projectId": "spike-proj", "name": "spike", "lifecycleState": "ACTIVE",
                                                  "projectNumber": "123"}]})
        return self.reply(404, {"error": {"code": 404, "message": "spike: unhandled " + p}})

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = handle_any


def serve(addr, port, tls):
    srv = ThreadingHTTPServer((addr, port), H)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(HERE, "pki/leaf.crt"), os.path.join(HERE, "pki/leaf.key"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


if __name__ == "__main__":
    serve("127.0.0.1", 443, True)
    serve("192.0.2.2", 443, True)
    serve("192.0.2.2", 80, False)
    print("ready", flush=True)
    while True:
        time.sleep(3600)
