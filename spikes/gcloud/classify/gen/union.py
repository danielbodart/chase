import json,glob,collections,sys
rules=[]
for f in glob.glob('outall/*.json'):
    lines=open(f).read().split('\n')
    head=json.loads(lines[0].split(',"rules":[')[0]+'}')
    for l in lines[1:]:
        l=l.rstrip(',')
        if not l.startswith('{'): continue
        r=json.loads(l); r['api']=head['api']+':'+head['version']; r['root']=[h for h in head['hosts'] if '.rep.' not in h and h.count('-')<2] or head['hosts']
        rules.append(r)
print('rules',len(rules))
RANK={'read':0,'write':1,'guarded':2,'forbidden':3}
g=collections.defaultdict(set); gapis=collections.defaultdict(set)
for r in rules:
    for v in r['methods']:
        g[(v,r['path'])].add(r['operation']['class']); gapis[(v,r['path'])].add(r['api'].split(':')[0])
multi=[k for k,v in gapis.items() if len(v)>1]
conf=[k for k,v in g.items() if len(v)>1]
print('distinct (method,path) in the union:',len(g),'; shared by >1 API:',len(multi),'; of which classes disagree:',len(conf))
for k in conf[:15]: print('  ',k, sorted(g[k]), sorted(gapis[k])[:6])
# specificity: segment compat
def seg_ok(a,b):
    if a==b: return True
    if a=='*' or b=='*':
        o=b if a=='*' else a
        return ':' not in o or True
    if a.startswith('*:') : return b.endswith(a[1:])
    if b.startswith('*:') : return a.endswith(b[1:])
    return False
def spec(s): return 2 if not s.startswith('*') else (1 if s.startswith('*:') else 0)
bylen=collections.defaultdict(list)
for r in rules:
    segs=r['path'].split('/')[1:]
    bylen[len(segs)].append((segs,r))
danger=[]
for r in rules:
    if r['operation']['class'] not in ('forbidden',): continue
    segs=r['path'].split('/')[1:]
    for s2,r2 in bylen[len(segs)]:
        if r2['api'].split(':')[0]==r['api'].split(':')[0] or RANK[r2['operation']['class']]>=RANK[r['operation']['class']]: continue
        if not set(r['methods'])&set(r2['methods']): continue
        if not all(seg_ok(a,b) for a,b in zip(segs,s2)): continue
        # frisket: leftmost differing specificity decides
        d=0
        for a,b in zip(segs,s2):
            if spec(a)!=spec(b): d=spec(b)-spec(a); break
        if d>=0: danger.append((r['operation']['id'],r['path'],'<-',r2['operation']['id'],r2['path'],r2['operation']['class'],'EQUAL' if d==0 else 'MORE-SPECIFIC'))
print('forbidden rules that a less strict rule of ANOTHER API would decide in a host-agnostic union:',len(danger))
for x in danger[:12]: print('  ',x)
import re
n=collections.defaultdict(set); nids=collections.defaultdict(set)
for r in rules:
    if r.get('grpc'): continue
    p=re.sub(r'/\*:[A-Za-z0-9]+','/*',r['path'])
    for v in r['methods']:
        n[(r['api'],v,p)].add(r['operation']['class']); nids[(r['api'],v,p)].add(r['operation']['id'])
col=[k for k,v in nids.items() if len(v)>1]
dis=[k for k in col if len(n[k])>1]
print('\nwithout a "*:verb" segment in frisket: templates that merge two or more operations:',len(col),'; merged operations of different classes:',len(dis))
print('  GET templates merging ops:',sum(1 for k in col if k[1]=='GET'))
for k in [k for k in dis if k[1]=='GET'][:6]: print('  ',k,sorted(nids[k])[:4],sorted(n[k]))
verb_rules=sum(1 for r in rules if ':' in r['path'] and not r.get('grpc'))
print('REST rules whose path ends in a :verb:',verb_rules,'of',sum(1 for r in rules if not r.get('grpc')))
