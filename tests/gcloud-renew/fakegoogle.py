# fakegoogle.py PORT PUBLIC_KEY EMAIL DIR: Google's token endpoint, verifying
# the JWT-bearer grant against PUBLIC_KEY. Each request takes the first line
# of DIR/codes as its status, if there is one, and is logged to DIR/log.
import base64, json, os, subprocess, sys, tempfile, time, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

port, pub, email, d = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
served = [0]


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify(form):
    if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"]:
        return "grant_type"
    h, c, s = form["assertion"][0].split(".")
    if json.loads(b64d(h)) != {"alg": "RS256", "typ": "JWT"}:
        return "header"
    with tempfile.NamedTemporaryFile() as sig:
        sig.write(b64d(s))
        sig.flush()
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sig.name],
                           input=f"{h}.{c}".encode(), capture_output=True)
    if r.returncode != 0:
        return "signature"
    claims = json.loads(b64d(c))
    now = time.time()
    if set(claims) != {"iss", "scope", "aud", "iat", "exp"}:
        return "claims"
    if claims["iss"] != email:
        return "iss"
    if claims["aud"] != "https://oauth2.googleapis.com/token":
        return "aud"
    if claims["scope"] != "https://www.googleapis.com/auth/cloud-platform":
        return "scope"
    if not (now - 60 <= claims["iat"] <= now + 5) or not (0 < claims["exp"] - claims["iat"] <= 3600):
        return "times"
    return None


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        form = urllib.parse.parse_qs(raw)
        code = 200
        with open(os.path.join(d, "codes"), "a+") as f:
            f.seek(0)
            lines = f.read().split()
            if lines:
                code = int(lines[0])
                f.truncate(0)
                f.write("".join(l + "\n" for l in lines[1:]))
        wrong = None
        if self.path != "/token":
            code, wrong = 404, "path"
        elif code == 200:
            wrong = verify(form)
            if wrong:
                code = 400
        served[0] += 1
        token = f"ya29.fake-{served[0]}-{os.urandom(8).hex()}"
        body = {"access_token": token, "expires_in": 3599, "token_type": "Bearer"} if code == 200 else \
            {"error": "invalid_grant", "error_description": f"fake says no ({wrong or code})"}
        with open(os.path.join(d, "log"), "a") as f:
            f.write(json.dumps({"code": code, "wrong": wrong, "token": body.get("access_token"),
                                "assertion": form.get("assertion", [""])[0], "t": time.time()}) + "\n")
        out = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


HTTPServer(("127.0.0.1", port), H).serve_forever()
