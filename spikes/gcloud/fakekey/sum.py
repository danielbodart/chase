import json, sys, collections
c = collections.Counter()
for l in open(sys.argv[1]):
    try: d = json.loads(l)
    except Exception: continue
    m = d.get("msg")
    if m in ("request",):
        k = f'{d.get("method")} {d.get("host")}{d.get("path","")[:70]} {d.get("proto","")} -> {d.get("status")} cred={d.get("credential")} {d.get("reason","") or d.get("rule","")}'
    elif m in ("service account jwt", "service account jwt refused", "token endpoint", "token endpoint refused"):
        k = m + " " + " ".join(f"{x}={d[x]}" for x in ("host","cached","kid","aud","scope","target_audience","life","error") if x in d and x!="kid")
    elif m in ("request start","request detail","response start","response detail"):
        continue
    elif m in ("tls",) and d.get("decision") == "allowed":
        continue
    elif m in ("listening","session opened","dns") and d.get("level")=="INFO" and m!="dns":
        continue
    else:
        k = m + " " + " ".join(f"{x}={d[x]}" for x in ("host","name","dst","sni","decision","reason","qname","answer","error") if x in d)
    c[k] += 1
for k, v in c.items(): print(f"  {v:3d}x {k}")
