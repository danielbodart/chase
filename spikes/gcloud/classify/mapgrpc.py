import json, re, collections
P=json.load(open('protos.json')); rows=json.load(open('methods.json'))
def norm_proto(path):
    # /v1/{name=projects/*/secrets/*}:access -> v1/projects/*/secrets/*:access
    def rep(m):
        pat=m.group(2)
        return pat if pat else '*'
    p=re.sub(r'\{([^}=]+)(?:=([^}]*))?\}', rep, path)
    return p.lstrip('/')
def norm_disco(r):
    fp=r['flatPath'] or r['path']
    sp=r['servicePath'] or ''
    full=fp if (sp and fp.startswith(sp)) else sp+fp
    return re.sub(r'\{[^}]+\}','*',full)
def host(u): return re.sub(r'^https://|/$','',u or '')
D={}
for r in rows:
    D.setdefault((host(r['rootUrl']), r['httpMethod'], norm_disco(r)), []).append(r)
# also host-free index
DH=collections.defaultdict(list)
for (h,m,p),v in D.items(): DH[(m,p)].extend(v)
matched=0; unmatched=[]; nohttp=[]; hostless=0; out=[]
for m in P['methods']:
    if not m['http']: nohttp.append(m); continue
    hits=[]
    for (verb,path,body) in m['http']:
        k=(m['host'],verb,norm_proto(path))
        if k in D: hits+= [r['id']+'@'+r['version'] for r in D[k]]
        elif (verb,norm_proto(path)) in DH and not m['host']: hits+=[r['id']+'@'+r['version'] for r in DH[(verb,norm_proto(path))]]
    m['disco']=sorted(set(hits))
    if hits: matched+=1
    else: unmatched.append(m)
    out.append(m)
json.dump(out, open('grpc_map.json','w'))
print('rpcs with http rule:', len(out), 'mapped to a discovery method:', matched, 'unmapped:', len(unmatched), 'no http rule:', len(nohttp))
# which hosts/services unmapped
c=collections.Counter(m['host'] or '(no default_host)' for m in unmatched)
print('unmapped by host (top 40):', c.most_common(40))
print('no-http services:', collections.Counter(m['service'] for m in nohttp).most_common(15))
dhosts={host(r['rootUrl']) for r in rows}
phosts={m['host'] for m in P['methods'] if m['host']}
print('proto hosts not in discovery:', len(phosts-dhosts), sorted(phosts-dhosts)[:80])
print('discovery hosts not in protos:', len(dhosts-phosts), sorted(dhosts-phosts)[:80])
stream=[m for m in P['methods'] if m['client_streaming']]
print('client/bidi-streaming rpcs:', len(stream), [m['grpc'] for m in stream][:40])
