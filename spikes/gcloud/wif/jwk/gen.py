import json,subprocess,base64,sys
def b(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
def pub(pem, kind):
    der = subprocess.run(['openssl','pkey','-in',pem,'-pubout','-outform','DER'],capture_output=True,check=True).stdout
    return der
out={}
# ed25519: last 32 bytes of SPKI DER
subprocess.run(['openssl','genpkey','-algorithm','ed25519','-out','ed.pem'],check=True)
out['okp']={"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"ed1","use":"sig","x":b(pub('ed.pem','ed')[-32:])}]}
subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-384','-out','p384.pem'],check=True)
d=pub('p384.pem','ec'); pt=d[-97:]; assert pt[0]==4
out['p384']={"keys":[{"kty":"EC","crv":"P-384","alg":"ES384","kid":"p384","use":"sig","x":b(pt[1:49]),"y":b(pt[49:])}]}
subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-521','-out','p521.pem'],check=True)
d=pub('p521.pem','ec'); pt=d[-133:]; assert pt[0]==4
out['p521']={"keys":[{"kty":"EC","crv":"P-521","alg":"ES512","kid":"p521","use":"sig","x":b(pt[1:67]),"y":b(pt[67:])}]}
r=json.load(open('../rsa.jwks.json'))['keys'][0]; e=json.load(open('../ec.jwks.json'))['keys'][0]; o=json.load(open('../other.jwks.json'))['keys'][0]
out['ps256']={"keys":[dict(r,alg="PS256")]}
out['noalg']={"keys":[{k:v for k,v in r.items() if k!='alg'}]}
out['two']={"keys":[r,e]}
o2=dict(o,kid="rsa2"); out['rotate']={"keys":[r,o2]}
out['x5c']={"keys":[dict(r,x5c=["MIIB"])]}
for k,v in out.items(): json.dump(v,open(k+'.json','w'))
