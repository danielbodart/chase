import json,collections,re,sys
rows=json.load(open('scan.json'))
NOISE_NAME=re.compile(r'(?i)(page|sync|continuation|resume|routing|change|import|upload|consistency|watch|session|replay|idempotency|progress|batch|commit|stream|next|prev|start|end|verification|attachmentUpload|source|read|capacity|request|query|enable|cursor|snapshot|checkpoint|mutation|cancel|seek|offset|ack|etag|lease|lock|retry|position|rotation|claim|reservation)Token$|^(nextPageToken|syncToken|pageToken)$|^secretVersion|^encrypted|SecretVersion$|SecretName$|SecretRef$|SecretId$|^enable|^use|^has|^is|Secret(s)?(Manager)?(Ref|Reference|Resource|Uri|Path|Name|Id|Key)$')
REF_DESC=re.compile(r'(?i)(resource name|in the format\s*`?projects/|projects/\*/secrets|projects/\{[^}]*\}/secrets|secret manager (secret )?(version|resource)|reference to (a|the) secret|name of the secret|secret version (resource|name)|format: projects/|the id of the secret|the name of a secret|secretmanager\.googleapis|pointer to)')
REDACT=re.compile(r'(?i)(input[ -]only|write[ -]only|never (be )?returned|not (be )?returned|is not returned|will not be returned|won.t be returned|redacted|masked|obfuscated|\*{3,}|hash of|only (be )?(returned|populated|set|available|provided) (on|at|in|during|when|after|upon|for) (the )?(creat|initial|first)|returned only (on|at|in|during|when) creat|only returned (on|at|in|during|when) (the )?creat|input only|\[input-only\])')
res=[]
for r in rows:
    hs=[h for h in r['hits'] if h['strong'] and not NOISE_NAME.search(h['field'].split('.')[-1]) and not REF_DESC.search(h['desc'])]
    live=[h for h in hs if not REDACT.search(h['desc'])]
    red=[h for h in hs if REDACT.search(h['desc'])]
    if live or red:
        res.append(dict(r, live=live, red=red))
json.dump(res,open('refined.json','w'))
live=[r for r in res if r['live']]
print('methods with a credential-shaped response field, not ref, not documented as redacted:',len(live), collections.Counter(r['httpMethod'] for r in live))
print('... only redacted/input-only:',len([r for r in res if not r['live']]))
g=[r for r in live if r['httpMethod']=='GET']
print('GET apis', len({r['api'] for r in g}))
fc=collections.Counter(h['field'].split('.')[-1] for r in g for h in r['live'])
print(fc.most_common(60))
