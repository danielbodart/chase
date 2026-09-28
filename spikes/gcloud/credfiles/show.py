import json,sys
for l in open(sys.argv[1]):
    e=json.loads(l)
    h=e["headers"]
    auth=h.get("Authorization") or h.get("authorization")
    print(f'{e["method"]} {"https" if e["tls"] else "http"}://{e["host"]}{e["path"]} -> {e["status"]}')
    if auth: print("   Authorization:", auth[:120])
    ua=h.get("User-Agent") or h.get("user-agent"); xg=h.get("x-goog-api-client") or h.get("X-Goog-Api-Client")
    if "-v" in sys.argv:
        print("   headers:", {k:v for k,v in h.items() if k.lower() not in ("authorization",)})
    if e["form"]: print("   form:", json.dumps(e["form"])[:600])
    if "-r" in sys.argv: print("   resp:", json.dumps(e["resp"])[:400])
