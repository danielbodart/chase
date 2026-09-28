import json, sys, os, glob, collections
def methods(doc):
    def walk(node, prefix):
        for name, m in (node.get('methods') or {}).items():
            yield prefix+[name], m
        for rname, r in (node.get('resources') or {}).items():
            yield from walk(r, prefix+[rname])
    yield from walk(doc, [])
rows=[]
for f in sorted(glob.glob('disco/*.json')):
    d=json.load(open(f))
    for path, m in methods(d):
        rows.append(dict(api=d['name'], version=d['version'], rootUrl=d.get('rootUrl'), servicePath=d.get('servicePath'),
          baseUrl=d.get('baseUrl'), mtlsRootUrl=d.get('mtlsRootUrl'), revision=d.get('revision'),
          id=m.get('id'), httpMethod=m.get('httpMethod'), path=m.get('path'), flatPath=m.get('flatPath'),
          response=(m.get('response') or {}).get('$ref'), request=(m.get('request') or {}).get('$ref'),
          description=(m.get('description') or '')[:400], mediaUpload=bool(m.get('supportsMediaUpload')),
          mediaDownload=bool(m.get('supportsMediaDownload')), useMediaDownloadService=bool(m.get('useMediaDownloadService')),
          endpoints=[e.get('endpointUrl') for e in d.get('endpoints',[])] if d.get('endpoints') else []))
json.dump(rows, open('methods.json','w'))
print(len(rows))
