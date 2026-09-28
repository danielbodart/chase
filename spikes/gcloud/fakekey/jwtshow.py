import sys, json, base64
t = sys.stdin.read().strip()
p = t.split(".")
d = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
print("jwt header", d(p[0]), "claims", {k: v for k, v in d(p[1]).items() if k in ("iss","aud","email","exp","iat")}, "sig_len", len(p[2]))
