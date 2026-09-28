import json, glob, re, collections, sys
FIELD = re.compile(r'(?i)^(privateKey(Data)?|private_key|accessToken|access_token|idToken|id_token|refreshToken|signedJwt|signedBlob|signature|secret|.*Secret$|secretKey|sharedSecret|password|.*Password$|passwd|clientKey|clientSecret|client_secret|token|.*Token$|signedUrl|.*SignedUrl$|keyString|apiKey|key|.*Key$|payload|data|kubeconfig|credential|credentials|.*Credentials?$|authCode|authorizationCode|connectionString|.*Uri$|.*Url$|oauthToken|bearerToken|sasToken|pem|certificateAuthority|clientCertificate|sshKey|.*Pem$)$')
STRONG = re.compile(r'(?i)^(privateKey(Data)?|private_key|accessToken|access_token|idToken|id_token|refreshToken|signedJwt|signedBlob|secret|secretKey|sharedSecret|password|clientKey|clientSecret|client_secret|token|signedUrl|keyString|apiKey|kubeconfig|authCode|authorizationCode|oauthToken|bearerToken|sasToken|.*(Secret|Password|Token|SignedUrl|PrivateKey)$)$')
REDACT = re.compile(r'(?i)(input[ -]only|write[ -]only|never (be )?returned|not (be )?returned|is not returned|will not be returned|redacted|masked|\*{3,}|only (set|used|populated|returned) (on|at|in|when|during) (creat|the create)|only returned (on|at|in|during|when) creat|hash of)')
def load(f):
    d=json.load(open(f)); return d
out=[]
for f in sorted(glob.glob('disco/*.json')):
    d=load(f); schemas=d.get('schemas',{})
    def walk_schema(ref, path, depth, seen, hits):
        s=schemas.get(ref)
        if not s or depth>6 or ref in seen: return
        seen=seen|{ref}
        def props(node, path):
            for name,p in (node.get('properties') or {}).items():
                desc=p.get('description','')
                if STRONG.match(name) or (FIELD.match(name) and re.search(r'(?i)(secret|password|private key|token|credential|signed|kubeconfig|api key|access key|hmac|bearer)',desc)):
                    hits.append(dict(field='.'.join(path+[name]), strong=bool(STRONG.match(name)), redacted=bool(REDACT.search(desc)), desc=desc[:220]))
                sub=p
                if p.get('type')=='array': sub=p.get('items',{})
                if p.get('additionalProperties'): sub=p['additionalProperties'] if isinstance(p['additionalProperties'],dict) else {}
                if '$ref' in sub: walk_schema(sub['$ref'], path+[name], depth+1, seen, hits)
                elif sub.get('properties'): props(sub, path+[name])
        props(s, path)
    def walk(node, rp):
        for name,m in (node.get('methods') or {}).items():
            hits=[]
            r=(m.get('response') or {}).get('$ref')
            if r: walk_schema(r, [], 0, frozenset(), hits)
            out.append(dict(api=d['name'],version=d['version'],root=d.get('rootUrl'),id=m['id'],httpMethod=m['httpMethod'],
               flatPath=m.get('flatPath') or m['path'], path=m['path'], servicePath=d.get('servicePath',''),response=r,
               description=m.get('description',''), hits=hits, mediaDownload=bool(m.get('supportsMediaDownload')),
               mediaUpload=m.get('mediaUpload',{}).get('protocols',{})))
        for rn,rr in (node.get('resources') or {}).items(): walk(rr, rp+[rn])
    walk(d, [])
json.dump(out, open('scan.json','w'))
print(len(out))
