import json, sys
for line in open(sys.argv[1]):
    m = json.loads(line)
    s = m["srv"]
    if s == "dns":
        print(f'{m["t"]:>8} dns   {m["type"][4:]:5} {m["name"]} -> {m["answer"]}')
    elif s == "api":
        if "UNKNOWN" in m: print(f'{m["t"]:>8} api   UNKNOWN {m["UNKNOWN"]}'); continue
        h = m["headers"]
        extra = {k: v for k, v in h.items() if k.lower() in ("x-goog-user-project", "x-goog-api-client")}
        print(f'{m["t"]:>8} api   {m["proto"]} {m["method"]} {m["host"]}{m["path"]}{"?"+m["query"] if m["query"] else ""}  Authorization={m["authorization"]!r} {extra}')
    elif "UNKNOWN" in m:
        print(f'{m["t"]:>8} {s} UNKNOWN {m["UNKNOWN"]}?{m["query"]}')
    else:
        h = m.get("headers", {})
        print(f'{m["t"]:>8} {s} {m.get("method","")} {m.get("host","")}{m.get("path","")}{"?"+m["query"] if m.get("query") else ""}  flavor={h.get("Metadata-Flavor")} ua={(h.get("User-Agent") or [""])[0][:60]}')
