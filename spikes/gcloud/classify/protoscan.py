import json,re,collections
P=json.load(open('protos.json')); F=P['fields']
M={m['grpc']:m for m in json.load(open('grpc_map.json'))}
STRONG=re.compile(r'^(private_key(_data)?|access_token|id_token|refresh_token|signed_jwt|signed_blob|secret|secret_key|shared_secret|password|client_key|client_secret|token|signed_url|signed_uri|key_string|api_key|kubeconfig|auth_code|authorization_code|oauth_token|bearer_token|sas_token|auth_string|security_token|.*_(secret|password|token|signed_url|signed_uri|private_key|auth_string))$')
NOISE=re.compile(r'(page|sync|continuation|resume|routing|change|import|upload|consistency|watch|session|replay|idempotency|progress|batch|commit|stream|next|prev|start|verification|source|read|capacity|request|query|enable|cursor|snapshot|checkpoint|mutation|cancel|seek|offset|ack|etag|lease|lock|retry|position|rotation|claim|reservation|restore|rewrite|run_execution|start_execution|purchase|attribution|widget_context|trace|delivery|recall|subscription|offer|game_player|device|continuation|partner_user|data_source_separator|recaptcha_s|activation|signin_enrollment|google_maps_widget_context)_token$|^secret_version|^encrypted_|_secret_version$|_secret_(name|ref|id|resource|uri|path|key_name)$|^(secret|password)_(manager|version|ref|name|id|policy|config|reference|secret)|_secret_manager|_sm_')
def walk(t, path, depth, seen, hits):
    if t not in F or depth>6 or t in seen: return
    for n,f in F[t].items():
        if 'INPUT_ONLY' in f['behavior']: continue
        if STRONG.match(n) and not NOISE.search(n):
            hits.append(('.'.join(path+[n]), f['type'] or 'scalar'))
        if f['type'] and f['type'] in F: walk(f['type'], path+[n], depth+1, seen|{t}, hits)
out=[]
for m in P['methods']:
    hits=[]
    walk(m['output'], [], 0, frozenset(), hits)
    if m['lro']: walk(m['lro'], ['<lro>'], 0, frozenset(), hits)
    if hits:
        verb=m['http'][0][0] if m['http'] else '(grpc-only)'
        out.append(dict(grpc=m['grpc'], verb=verb, host=m['host'], hits=hits, disco=M.get(m['grpc'],{}).get('disco',[])))
json.dump(out,open('protoscan.json','w'))
print('rpcs whose response (or LRO result) has a non-INPUT_ONLY credential-shaped field:',len(out), collections.Counter(o['verb'] for o in out))
# stable versions, GET only, one per service method name (drop version dup)
seen=set()
for o in sorted(out,key=lambda o:o['grpc']):
    if o['verb'] not in ('GET','(grpc-only)'): continue
    if re.search(r'\.v\d+(alpha|beta|p\d)',o['grpc']): continue
    fs=sorted({h[0] for h in o['hits']})
    print(o['verb'][:4], o['grpc'], '|', ', '.join(fs[:3])[:150])
