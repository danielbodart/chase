"""Google Cloud's classification, from Google's own descriptions of its APIs.

    python3 gcloud.py generate APP DISCOVERIES GOOGLEAPIS DESCRIPTORS ENTRIES
    python3 gcloud.py pins APP DISCOVERIES GOOGLEAPIS DESCRIPTORS ENTRIES

Run by ./gcloud.sh, which fetches the pinned sources, checks every file
against its hash and compiles the protos; see ../docs/gcloud.md.
"""
import collections
import json
import os
import re
import sys

import yaml
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

CLASSES = ["read", "write", "guarded"]
MIXINS = {"google.iam.v1.IAMPolicy", "google.cloud.location.Locations", "google.longrunning.Operations"}
STABILITY = {"alpha": 0, "beta": 1, "": 2}


class Failed(Exception):
    pass


def natural(verb):
    return "read" if verb in ("GET", "HEAD") else "guarded" if verb == "DELETE" else "write"


def sentence(text):
    line = text.strip().split("\n")[0]
    m = re.match(r"^(.*?[.!?])(\s|$)", line)
    return m.group(1) if m else line


def words(id, text):
    text = (text or "").strip()
    summary = sentence(text) or id
    return {"summary": summary, **({"description": text} if text and text != summary else {})}


def segment(s):
    if "{" not in s:
        return s
    m = re.fullmatch(r"\{[^}]+\}(:[A-Za-z][A-Za-z0-9_]*)?", s)
    return "*" + (m.group(1) or "") if m else "*"


def template(path):
    return "/" + "/".join(segment(s) for s in path.strip("/").split("/"))


def proto_template(path):
    """A google.api.http path as a template, and whether it is a prefix; None
    where "**" is anything but the whole last segment."""
    flat = re.sub(r"\{[^}=]+=([^}]*)\}", r"\1", path)
    flat, _, verb = re.sub(r"\{[^}]+\}", "*", flat).partition(":")
    segs = flat.strip("/").split("/")
    if "**" in segs[:-1] or any("*" in s and s not in ("*", "**") for s in segs):
        return None
    prefix = segs[-1] == "**"
    if prefix and verb:
        return None
    if prefix:
        segs = segs[:-1]
    if verb:
        segs[-1] += ":" + verb
    return "/" + "/".join(segs), prefix


def version_rank(v):
    m = re.fullmatch(r"v(\d+)(?:p\d+)?(alpha|beta)?(\d*)", v)
    if not m:
        return None
    return (STABILITY[m.group(2) or ""], int(m.group(1)), int(m.group(3) or 0))


def package_version(pkg):
    for part in reversed(pkg.split(".")):
        if version_rank(part):
            return part
    return None


def meet(a, b):
    """Whether one segment can match two template segments."""
    if a == b or "*" in (a, b):
        return True
    if a.startswith("*:") and b.startswith("*:"):
        return False
    if a.startswith("*:"):
        return b.endswith(a[1:])
    return b.startswith("*:") and a.endswith(b[1:])


def rank(rpc):
    return version_rank(package_version(rpc["package"]) or "") or (-1,)


def aip_verb(method):
    return "GET" if re.match(r"(Get|List|BatchGet)[A-Z]", method) else "DELETE" if re.match(r"(Delete|BatchDelete)[A-Z]", method) else "POST"


def host_of(url):
    return re.sub(r"^https://|/.*$", "", url)


def load(path):
    with open(path) as f:
        return json.load(f)


class Protos:
    def __init__(self, path, entries):
        fds = descriptor_pb2.FileDescriptorSet()
        with open(path, "rb") as f:
            fds.ParseFromString(f.read())
        self.files = {fd.name: fd for fd in fds.file}
        pool = descriptor_pool.DescriptorPool()
        added = set()

        def add(name):
            if name in added:
                return
            for dep in self.files[name].dependency:
                add(dep)
            pool.Add(self.files[name])
            added.add(name)

        for name in self.files:
            add(name)
        options = lambda t: message_factory.GetMessageClass(pool.FindMessageTypeByName(t))
        method_options, service_options = options("google.protobuf.MethodOptions"), options("google.protobuf.ServiceOptions")
        http, default_host = pool.FindExtensionByName("google.api.http"), pool.FindExtensionByName("google.api.default_host")

        def bindings(rule):
            out = [(k.upper(), getattr(rule, k)) for k in ("get", "put", "post", "delete", "patch") if rule.HasField(k)]
            if rule.HasField("custom"):
                out.append((rule.custom.kind, rule.custom.path))
            for extra in rule.additional_bindings:
                out += bindings(extra)
            return out

        self.rpcs = []
        for name, fd in sorted(self.files.items()):
            if name not in entries and not any(f"{fd.package}.{s.name}" in MIXINS for s in fd.service):
                continue
            comments = {tuple(loc.path): loc.leading_comments for loc in fd.source_code_info.location}
            for si, s in enumerate(fd.service):
                so = service_options()
                so.ParseFromString(s.options.SerializeToString())
                service = f"{fd.package}.{s.name}"
                for mi, m in enumerate(s.method):
                    mo = method_options()
                    mo.ParseFromString(m.options.SerializeToString())
                    self.rpcs.append({
                        "file": name, "package": fd.package, "service": service, "method": m.name,
                        "name": f"{service}.{m.name}", "path": f"/{service}/{m.name}",
                        "host": so.Extensions[default_host], "http": bindings(mo.Extensions[http]) if mo.HasExtension(http) else [],
                        "streaming": m.client_streaming, "comment": re.sub(r"\[([^\]]+)\]\[[^\]]*\]", r"\1", " ".join(comments.get((6, si, 2, mi), "").split())),
                    })

    def closure(self, names):
        out = set()

        def add(name):
            if name in out or name.startswith("google/protobuf/"):
                return
            out.add(name)
            for dep in self.files[name].dependency:
                add(dep)

        for name in names:
            add(name)
        return out


class Generator:
    def __init__(self, app, discoveries, googleapis, descriptors, entries):
        self.app, self.discoveries, self.googleapis = app, discoveries, googleapis
        self.source = load(os.path.join(app, "source.json"))
        self.exceptions = load(os.path.join(app, "exceptions.json"))
        with open(entries) as f:
            self.protos = Protos(descriptors, set(f.read().split()))
        self.problems = []
        self.counts = collections.Counter()

    def fail(self, what, items):
        if items:
            self.problems.append(f"{what}: {sorted(items)[:40]}{' ...' if len(items) > 40 else ''} ({len(items)})")

    def documents(self):
        index = load(os.path.join(self.discoveries, "index.json"))["items"]
        extra = self.source["discovery"].get("versions", {})
        chosen = {i["id"] for i in index if i["preferred"] or not re.search("alpha|beta|preview", i["version"])} | set(extra)
        self.fail("versions not in Discovery's index", set(extra) - {i["id"] for i in index})
        docs = collections.defaultdict(list)
        for i in sorted(index, key=lambda i: i["id"]):
            path = os.path.join(self.discoveries, f"{i['name']}.{i['version']}.json")
            if i["id"] in chosen and os.path.exists(path):
                docs[i["name"]].append(load(path))
        self.fail("versions without a document at the pinned commit", {v for v in extra if not any(d["id"] == v for ds in docs.values() for d in ds)})
        return docs

    def classify(self, id, base, api):
        """An operation's class: its API's, where the whole API is guarded;
        else its own exception's; else what its name or method says."""
        self.natural.setdefault(id, set()).add(base)
        if api in self.whole:
            self.used.add(("api", api))
            return "guarded"
        if id in self.explicit:
            self.used.add(id)
            return self.explicit[id]
        return base

    def base(self, leaf, verb):
        pattern = self.patterns.get(leaf)
        if pattern:
            self.used.add(("pattern", leaf))
            return pattern["class"]
        return natural(verb)

    def generate(self):
        ex = self.exceptions
        self.whole = ex.get("apis", {})
        self.patterns = ex.get("patterns", {})
        slashed = ex.get("encodedSlashes", {})
        self.explicit = {}
        for c in CLASSES:
            for id, reason in ex.get(c, {}).items():
                self.fail("in more than one class", [id] if id in self.explicit else [])
                self.explicit[id] = c
        self.fail("an exception needs a reason", [k for c in CLASSES for k, r in ex.get(c, {}).items() if not isinstance(r, str) or not r]
                  + [k for k, r in self.whole.items() if not isinstance(r, str) or not r]
                  + [f"{a}.{k}" for a, ps in slashed.items() for k, r in ps.items() if not isinstance(r, str) or not r]
                  + [k for k, p in self.patterns.items() if not p.get("reason") or p.get("class") not in CLASSES])
        self.used = set()
        self.natural = {}

        docs = self.docs = self.documents()
        apis = {}
        rest = {}

        for name, ds in docs.items():
            rules, hosts, mtls, versions = [], set(), set(), []
            for d in ds:
                versions.append(d["version"])
                root = host_of(d["rootUrl"])
                hosts |= {root} | {host_of(e["endpointUrl"]) for e in d.get("endpoints", [])}
                if d.get("mtlsRootUrl"):
                    mtls.add(host_of(d["mtlsRootUrl"]))
                sp = d.get("servicePath", "")

                def walk(node):
                    for m in (node.get("methods") or {}).values():
                        yield m
                    for r in (node.get("resources") or {}).values():
                        yield from walk(r)

                for m in walk(d):
                    id, verb = m["id"], m["httpMethod"]
                    rel = m.get("flatPath") or m["path"]
                    cls = self.classify(id, self.base(id.split(".")[-1], verb), name)
                    op = {"id": id, **words(id, m.get("description")), "class": cls, "category": name}
                    enc = [p for p in slashed.get(name, {}) if "{" + p + "}" in m["path"]]
                    self.used |= {("encodedSlashes", name, p) for p in enc}
                    methods = ["GET", "HEAD"] if verb == "GET" else [verb]
                    paths = [(methods, template(sp + rel))]
                    protocols = m.get("mediaUpload", {}).get("protocols") or {}
                    for proto in protocols.values():
                        paths.append(([verb], template(proto["path"])))
                    if "resumable" in protocols and "simple" in protocols and verb != "PUT":
                        paths.append((["PUT"], template(protocols["simple"]["path"])))
                    if m.get("useMediaDownloadService"):
                        paths.append((methods, template("/download/" + sp + rel)))
                    for ms, path in paths:
                        rules.append({"methods": ms, "path": path, **({"encodedSlashes": True} if enc else {}), "operation": op})
                    rest[(name, verb, template(sp + rel).lower())] = (name, id, cls)
                if d.get("batchPath"):
                    self.used.add(("batch",))
                    rules.append({"methods": ["POST"], "path": "/" + d["batchPath"], "operation": {
                        "id": f"{name}.batch", "summary": f"A batch of {d.get('title', name)} requests in one, each a whole request frisket cannot see.",
                        "class": "guarded", "category": name}})
            apis[name] = {"title": ds[0].get("title", name), "versions": versions, "hosts": hosts, "mtls": mtls, "rules": rules, "grpc": set(), "streaming": set()}

        self.grpc(apis, rest)
        self.fail("exceptions that name no operation", set(self.explicit) - self.used)
        self.fail("APIs guarded whole that are not generated", {a for a in self.whole if ("api", a) not in self.used})
        self.fail("patterns that match no operation", {p for p in self.patterns if ("pattern", p) not in self.used})
        self.fail("encodedSlashes that name no parameter", {f"{a}.{p}" for a, ps in slashed.items() for p in ps if ("encodedSlashes", a, p) not in self.used})
        self.fail("batch has no reason, and APIs have batch paths", [] if ("batch",) not in self.used or ex.get("batch") else ["batch"])
        for c in CLASSES:
            self.fail(f"an exception gives the class it has anyway ({c})",
                      [id for id, cls in self.explicit.items() if cls == c and self.natural.get(id) == {c}])
        self.invariants(apis)
        if self.problems:
            raise Failed("\n".join(self.problems))
        return apis

    def grpc(self, apis, rest):
        """Each gRPC method is a rule at POST /package.Service/Method: the
        Discovery operation its google.api.http rule names, or one of its own."""
        by_host = collections.defaultdict(list)
        for r in self.protos.rpcs:
            if r["host"] and r["service"] not in MIXINS:
                by_host[r["host"]].append(r)
        yamls = self.service_yamls()
        api_of_host = {host_of(d["rootUrl"]): name for name, ds in self.docs.items() for d in ds}
        chosen = collections.defaultdict(set)
        for host, rpcs in by_host.items():
            name = api_of_host.get(host) or host.split(".")[0]
            if name in apis:
                services = {r["service"] for r in rpcs for v, p in r["http"] if self.lookup(rest, name, v, p)}
                bare = [r for r in rpcs if not any(x["http"] for x in rpcs if x["service"] == r["service"])]
                best = max((rank(r) for r in bare), default=None)
                services |= {r["service"] for r in bare if rank(r) == best}
            else:
                best = max(rank(r) for r in rpcs)
                services = {r["service"] for r in rpcs if rank(r) == best}
                apis[name] = {"title": host, "versions": sorted({package_version(r["package"]) or "" for r in rpcs if r["service"] in services}),
                              "hosts": {host}, "mtls": {host.replace(".googleapis.com", ".mtls.googleapis.com")} if host.endswith(".googleapis.com") else set(),
                              "rules": [], "grpc": set(), "streaming": set()}
            chosen[name] |= services
            if services:
                apis[name]["hosts"].add(host)

        rpcs_of = collections.defaultdict(list)
        for r in self.protos.rpcs:
            rpcs_of[r["service"]].append(r)
        mixin_rpcs = [r for r in self.protos.rpcs if r["service"] in MIXINS]
        self.used_files = set()
        self.grpc_rules = set()
        rest_ops = {}
        for name, a in apis.items():
            for rule in a["rules"]:
                rest_ops[rule["operation"]["id"]] = rule["operation"]
        for name in sorted(chosen):
            a = apis[name]
            grpc = {s for s in chosen[name] if not self.rest_only(rpcs_of[s][0]["file"])}
            self.used_files |= {rpcs_of[s][0]["file"] for s in chosen[name]}
            proto_only = not a["rules"]
            mixins = set()
            for s in grpc:
                mixins |= yamls.get(os.path.dirname(rpcs_of[s][0]["file"]), set())
            self.used_files |= {r["file"] for r in mixin_rpcs if r["service"] in mixins}
            for r in sorted((r for s in chosen[name] for r in rpcs_of[s]), key=lambda r: r["path"]) + [r for r in mixin_rpcs if r["service"] in mixins]:
                mapped = sorted({hit[1] for v, p in r["http"] for hit in [self.lookup(rest, name, v, p)] if hit})
                leaf = r["method"][0].lower() + r["method"][1:]
                verb = r["http"][0][0] if r["http"] else aip_verb(r["method"])
                if r["service"] in MIXINS:
                    mapped = []
                base = max((rest_ops[m]["class"] for m in mapped), key=CLASSES.index) if mapped else self.base(leaf, verb)
                if not r["http"] and r["service"] not in MIXINS:
                    self.counts["classed by name"] += 1
                op = {"id": r["name"], **words(r["name"], r["comment"]), "class": self.classify(r["name"], base, None if r["service"] in MIXINS else name),
                      "category": r["service"] if r["service"] in MIXINS else name}
                if r["service"] in grpc or r["service"] in MIXINS:
                    a["rules"].append({"methods": ["POST"], "path": r["path"], "operation": op})
                    self.grpc_rules.add(id(a["rules"][-1]))
                    a["grpc"].add(r["service"])
                    if r["streaming"]:
                        a["streaming"].add(op["id"])
                if proto_only and r["service"] not in MIXINS:
                    for v, p in r["http"]:
                        t = proto_template(p)
                        if t is None:
                            self.counts["HTTP rules no template can say"] += 1
                            continue
                        path, prefix = t
                        a["rules"].append({"methods": ["GET", "HEAD"] if v == "GET" else [v], ("prefix" if prefix else "path"): path, "operation": op})

    def lookup(self, rest, api, verb, path):
        t = proto_template(path)
        if t is None or t[1]:
            return None
        return rest.get((api, verb, t[0].lower()))

    def rest_only(self, file):
        path = os.path.join(self.googleapis, os.path.dirname(file), "BUILD.bazel")
        if not os.path.exists(path):
            return False
        with open(path) as f:
            text = f.read()
        return 'transport = "rest"' in text and 'transport = "grpc' not in text

    def service_yamls(self):
        out = {}
        for d in {os.path.dirname(r["file"]) for r in self.protos.rpcs}:
            full = os.path.join(self.googleapis, d)
            if not os.path.isdir(full):
                continue
            for f in sorted(os.listdir(full)):
                if not f.endswith(".yaml"):
                    continue
                with open(os.path.join(full, f)) as fh:
                    doc = yaml.safe_load(fh)
                if isinstance(doc, dict) and doc.get("type") == "google.api.Service":
                    out.setdefault(d, set()).update(a["name"] for a in doc.get("apis") or [] if a.get("name") in MIXINS)
        return out

    def invariants(self, apis):
        """One path table for every host: two operations at one method and
        template are one class, whichever APIs they are in."""
        table = collections.defaultdict(set)
        ids = collections.defaultdict(set)
        for name, a in apis.items():
            for r in a["rules"]:
                for m in r["methods"]:
                    key = (m, "prefix" in r, (r.get("path") or r.get("prefix")).lower())
                    table[key].add((r["operation"]["class"], r["operation"]["id"]))
                ids[r["operation"]["id"]].add(r["operation"]["class"])
        self.fail("one method and template, two classes",
                  [f"{m} {p} ({', '.join(sorted(f'{i} {c}' for c, i in v))})" for (m, _, p), v in table.items() if len({c for c, _ in v}) > 1])
        self.fail("one operation, two classes", [i for i, v in ids.items() if len(v) > 1])
        self.fail("a path frisket could not match as written", {
            p for a in apis.values() for r in a["rules"] for p in [r.get("path") or r.get("prefix")]
            if not re.fullmatch(r"(/([^/*{}?#%\s]+|\*|\*:[A-Za-z][A-Za-z0-9_]*))+", p)})
        self.shared = sum(1 for v in table.values() if len({i for _, i in v}) > 1)
        self.fail("a less strict operation of another API is more specific than a stricter one", self.outranked(apis))

    def outranked(self, apis):
        """frisket takes the most specific rule, so on one path table a
        literal of one API where another has "*" decides that API's requests.
        A "*:verb" is Google's own custom method wherever it is, and is not
        counted."""
        by = collections.defaultdict(list)
        for name, a in apis.items():
            for r in a["rules"]:
                if "path" in r:
                    segs = r["path"].lower().split("/")[1:]
                    for m in r["methods"]:
                        by[(m, len(segs))].append((name, CLASSES.index(r["operation"]["class"]), segs, r["operation"]["id"]))
        out = set()
        for rules in by.values():
            for name, cls, segs, id in rules:
                for name2, cls2, segs2, id2 in rules:
                    if name2 == name or cls2 >= cls or not all(meet(a, b) for a, b in zip(segs, segs2)):
                        continue
                    for a, b in zip(segs, segs2):
                        if a == b:
                            continue
                        if a == "*" and not b.startswith("*"):
                            out.add(f"{id2} over {id}")
                        break
        return out

    def write(self, apis):
        out = os.path.join(self.app, "apis")
        os.makedirs(out, exist_ok=True)
        for f in os.listdir(out):
            if f.endswith(".json") and f[:-5] not in apis:
                os.remove(os.path.join(out, f))
        index = {}
        for name in sorted(apis):
            a = apis[name]
            seen, rules = set(), []
            for r in sorted(a["rules"], key=lambda r: (r.get("path") or r.get("prefix"), r["methods"], r["operation"]["id"])):
                key = (tuple(r["methods"]), r.get("path"), r.get("prefix"))
                if key in seen:
                    self.counts["rules one API has twice"] += 1
                    continue
                seen.add(key)
                rules.append(r)
            a["rules"] = rules
            with open(os.path.join(out, name + ".json"), "w") as f:
                f.write("[\n" + ",\n".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) for r in rules) + "\n]\n")
            index[name] = {
                "title": a["title"], "versions": a["versions"], "hosts": sorted(a["hosts"]), "mtls": sorted(a["mtls"]),
                "grpc": sorted(a["grpc"]), "streaming": sorted(a["streaming"]),
                "classes": {c: n for c in CLASSES if (n := sum(1 for r in rules if r["operation"]["class"] == c))},
            }
        with open(os.path.join(self.app, "index.json"), "w") as f:
            f.write("{\n" + ",\n".join(f"{json.dumps(k)}:{json.dumps(v, separators=(',', ':'))}" for k, v in index.items()) + "\n}\n")
        return index

    def report(self, apis):
        rules = [r for a in apis.values() for r in a["rules"]]
        grpc = [r for r in rules if id(r) in self.grpc_rules]
        count = lambda rs: ", ".join(f"{sum(1 for r in rs if r['operation']['class'] == c)} {c}" for c in CLASSES)
        size = sum(os.path.getsize(os.path.join(self.app, "apis", n + ".json")) for n in apis)
        print(f"gcloud: {len(apis)} APIs, {len(rules)} rules: {count(rules)}.", file=sys.stderr)
        print(f"gcloud: of which gRPC {len(grpc)}: {count(grpc)}; streaming {sum(len(a['streaming']) for a in apis.values())}.", file=sys.stderr)
        print(f"gcloud: {len({r['operation']['id'] for r in rules})} operations; {self.shared} templates shared by more than one; {size} bytes.", file=sys.stderr)
        print(f"gcloud: {'; '.join(f'{n} {what}' for what, n in sorted(self.counts.items()))}.", file=sys.stderr)

    def pins(self):
        disco = sorted({"discoveries/index.json"} | {
            f"discoveries/{n}.{d['version']}.json" for n, ds in self.docs.items() for d in ds})
        files = self.protos.closure(self.used_files)
        dirs = {os.path.dirname(f) for f in self.used_files}
        for d in dirs:
            full = os.path.join(self.googleapis, d)
            for f in os.listdir(full):
                if f == "BUILD.bazel" or f.endswith(".yaml"):
                    files.add(os.path.join(d, f))
        json.dump({"discovery": disco, "googleapis": sorted(files), "entries": sorted(self.used_files)}, sys.stdout)


def main():
    if len(sys.argv) != 7 or sys.argv[1] not in ("generate", "pins"):
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    g = Generator(*sys.argv[2:])
    try:
        apis = g.generate()
    except Failed as e:
        print(f"gcloud: {e}", file=sys.stderr)
        sys.exit(1)
    if sys.argv[1] == "pins":
        g.pins()
    else:
        g.write(apis)
        g.report(apis)


if __name__ == "__main__":
    main()
