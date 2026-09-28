"""Spike: classify Google APIs the way chase classifies Cloudflare and Hugging Face.

    python3 gen.py DISCO_DIR PROTOS_JSON EXCEPTIONS_JSON OUT_DIR api:version...

Every Discovery method becomes one rule (plus its media upload/download
paths); every gRPC method of the same service becomes one exact rule at
/package.Service/Method, classed as the REST method its google.api.http
annotation maps to. GET/HEAD read, DELETE guarded, the rest write; the
exceptions say otherwise by versionless Discovery id or gRPC full name, with a
reason; `forbidden` is a fourth class no tier or project may loosen.
"""
import json, re, sys, os, collections, glob
GOOGLEAPIS = os.environ.get("GOOGLEAPIS", "../googleapis")

disco_dir, protos_json, exc_json, out_dir, *apis = sys.argv[1:]
EXC = json.load(open(exc_json))
P = json.load(open(protos_json))
CLASSES = ["read", "write", "guarded", "forbidden"]
by_id = {}
for c in CLASSES:
    for k, why in EXC.get(c, {}).items():
        if k in by_id: sys.exit(f"{k} in two classes")
        by_id[k] = (c, why)
used = set()

def natural(verb):
    return "read" if verb in ("GET", "HEAD") else "guarded" if verb == "DELETE" else "write"

def classify(did, verb):
    if did in by_id:
        used.add(did); return by_id[did]
    leaf = did.split(".")[-1]
    p = EXC.get("patterns", {}).get(leaf)
    if p and p["class"] != natural(verb):
        return p["class"], p["reason"]
    return natural(verb), None

def sentence(d):
    d = (d or "").strip()
    m = re.match(r"^(.*?[.!?])(\s|$)", d.split("\n")[0])
    return (m.group(1) if m else d.split("\n")[0])[:300]

def template(path):
    segs = []
    for s in path.strip("/").split("/"):
        if "{" not in s: segs.append(s); continue
        m = re.fullmatch(r"\{[^}]+\}(:[A-Za-z][A-Za-z0-9]*)?", s)
        segs.append("*" + (m.group(1) or "") if m else "*")
    return "/" + "/".join(segs)

def host(u): return re.sub(r"^https://|/.*$", "", u)

def methods_of(node, trail=()):
    for n, m in (node.get("methods") or {}).items(): yield trail, m
    for rn, r in (node.get("resources") or {}).items(): yield from methods_of(r, trail + (rn,))

def norm_proto(p):
    return "/" + re.sub(r"\{([^}=]+)(?:=([^}]*))?\}", lambda m: m.group(2) or "*", p).lstrip("/")

MIXINS = {
    "google.iam.v1.IAMPolicy.GetIamPolicy": "read", "google.iam.v1.IAMPolicy.TestIamPermissions": "read",
    "google.iam.v1.IAMPolicy.SetIamPolicy": "guarded",
    "google.cloud.location.Locations.ListLocations": "read", "google.cloud.location.Locations.GetLocation": "read",
    "google.longrunning.Operations.GetOperation": "read", "google.longrunning.Operations.ListOperations": "read",
    "google.longrunning.Operations.WaitOperation": "read", "google.longrunning.Operations.CancelOperation": "write",
    "google.longrunning.Operations.DeleteOperation": "guarded",
}

os.makedirs(out_dir, exist_ok=True)
report = []
for spec in apis:
    name, version = spec.split(":")
    d = json.load(open(f"{disco_dir}/{name}_{version}.json"))
    root = host(d["rootUrl"]); sp = d.get("servicePath", "")
    hosts = sorted({root} | {host(e["endpointUrl"]) for e in d.get("endpoints", [])})
    mtls = host(d["mtlsRootUrl"]) if d.get("mtlsRootUrl") else None
    rules = []; rest_index = {}
    def add(verbs, path, did, desc, cls, why, category, extra=None):
        op = {"id": f"{name}.{version}.{did.split('.',1)[1]}" if not did.startswith("grpc:") else did[5:],
              "summary": sentence(desc) or did, "class": cls, "category": category}
        if desc and desc.strip() != op["summary"]: op["description"] = desc.strip()
        if why: op["reason"] = why
        r = {"methods": verbs, "path": path, "operation": op}
        if extra: r.update(extra)
        rules.append(r)
    for trail, m in methods_of(d):
        verb = m["httpMethod"]; did = m["id"]
        rel = m.get("flatPath") or m["path"]
        full = template(rel if rel.startswith(sp) and sp else sp + rel)
        cls, why = classify(did, verb)
        if EXC.get("hosts", {}).get(root): cls, why = "forbidden", EXC["hosts"][root]
        cat = ".".join(trail)
        verbs = ["GET", "HEAD"] if verb == "GET" else [verb]
        add(verbs, full, did, m.get("description"), cls, why, cat)
        rest_index[(verb, full)] = (did, cls)
        for proto, pr in (m.get("mediaUpload", {}).get("protocols") or {}).items():
            add([verb], template(pr["path"]), did, m.get("description"), cls, why, cat, {"media": "upload-" + proto})
        if m.get("useMediaDownloadService"):
            add(verbs, template("/download/" + sp + rel), did, m.get("description"), cls, why, cat, {"media": "download"})
    if d.get("batchPath"):
        add(["POST"], "/" + d["batchPath"], "batch.batch", "A batch: multipart/mixed, each part a whole HTTP request of its own, which frisket cannot see.", "forbidden",
            "Tunnels any operation of this API -- a secret's access included -- under one POST, answered in the same response.", "batch")
    # gRPC: services whose RPCs map into this API's REST methods, and their siblings.
    services = set(); grpc_rules = 0; unclassified = []; streaming = []; mixins = set()
    host_forbidden = EXC.get("hosts", {}).get(root)
    for pm in P["methods"]:
        if pm["host"] != root and not (name == "storage" and pm["service"].startswith("google.storage.v2.")): continue
        for (v, p, _b) in pm["http"]:
            if (v, norm_proto(p)) in rest_index: services.add(pm["service"])
    if name == "storage": services.add("google.storage.v2.Storage")
    def rest_only(file):
        b = os.path.join(GOOGLEAPIS, os.path.dirname(file), "BUILD.bazel")
        t = open(b).read() if os.path.exists(b) else ""
        return 'transport = "rest"' in t and 'transport = "grpc' not in t
    files = {pm["file"] for pm in P["methods"] if pm["service"] in services}
    if files and all(rest_only(f) for f in files): services = set()
    for f in files:
        for y in glob.glob(os.path.join(GOOGLEAPIS, os.path.dirname(f), "*.yaml")):
            mixins |= set(re.findall(r"^- name: (google\.(?:iam\.v1\.IAMPolicy|cloud\.location\.Locations|longrunning\.Operations))\s*$", open(y).read(), re.M))
    for pm in P["methods"]:
        if pm["service"] not in services: continue
        full = pm["grpc"][1:].replace("/", ".")
        g = EXC.get("grpc", {}).get(full)
        mapped = [rest_index[(v, norm_proto(p))] for (v, p, _b) in pm["http"] if (v, norm_proto(p)) in rest_index]
        if g: cls, why = g["class"], g["reason"]; used.add(full)
        elif mapped:
            cls = max((c for _, c in mapped), key=CLASSES.index); why = f"As {mapped[0][0]}, which its google.api.http rule names."
        elif pm["http"]: cls, why = natural(pm["http"][0][0]), "google.api.http names no Discovery method; by its HTTP verb."
        else: cls, why = "write", "UNCLASSIFIED: no google.api.http rule and no exception."; unclassified.append(full)
        st = pm["client_streaming"]
        if st: streaming.append(full)
        if host_forbidden: cls, why = "forbidden", host_forbidden
        add(["POST"], pm["grpc"], "grpc:" + full, f"gRPC {pm['method']}.", cls, why, pm["service"], {"grpc": True, **({"streaming": True} if st else {})})
        grpc_rules += 1
    for full, cls in MIXINS.items():
        svc, meth = full.rsplit(".", 1)
        if svc not in mixins: continue
        add(["POST"], f"/{svc}/{meth}", "grpc:" + full, f"gRPC mixin {meth}.", cls, "A mixin every Cloud API host serves.", svc, {"grpc": True})
    # Two rules, one method and template: must agree, as chase's generator insists.
    seen = {}
    for r in rules:
        for v in r["methods"]:
            k = (v, r["path"])
            if k in seen and seen[k]["operation"]["class"] != r["operation"]["class"]:
                sys.exit(f"{spec}: {v} {r['path']} is {seen[k]['operation']['id']} and {r['operation']['id']}")
            seen[k] = r
    out = {"api": name, "version": version, "revision": d.get("revision"), "hosts": hosts,
           "mtls": mtls, "rules": rules}
    path = f"{out_dir}/{name}_{version}.json"
    with open(path, "w") as f:
        f.write('{"api":%s,"version":%s,"revision":%s,"hosts":%s,"mtls":%s,"rules":[\n' % tuple(json.dumps(x) for x in (name, version, d.get("revision"), hosts, mtls)))
        f.write(",\n".join(json.dumps(r, separators=(",", ":")) for r in rules) + "\n]}\n")
    c = collections.Counter(r["operation"]["class"] for r in rules if not r.get("grpc"))
    cg = collections.Counter(r["operation"]["class"] for r in rules if r.get("grpc"))
    report.append(dict(api=spec, hosts=len(hosts), rest=sum(1 for r in rules if not r.get("grpc")), rest_classes=dict(c),
                       grpc=sum(1 for r in rules if r.get("grpc")), grpc_classes=dict(cg), unclassified=unclassified, streaming=streaming,
                       bytes=os.path.getsize(path)))
stale = set(by_id) - used - {k for k in by_id if not any(k.startswith(a.split(':')[0] + '.') for a in apis)}
stale |= {k for k in EXC.get("grpc", {}) if k not in used}
for r in report: print(json.dumps(r))
if stale: print("exceptions naming nothing generated:", sorted(stale))
