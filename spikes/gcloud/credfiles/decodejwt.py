import json,sys,base64
def d(s): return json.loads(base64.urlsafe_b64decode(s+"="*(-len(s)%4)))
for l in open(sys.argv[1]):
    e=json.loads(l)
    for src,val in [("bearer",(e["headers"].get("Authorization") or e["headers"].get("authorization") or "").removeprefix("Bearer ")),("assertion",e["form"].get("assertion","") if isinstance(e["form"],dict) else "")]:
        if val.count(".")==2 and val.startswith("ey"):
            h,p,_=val.split(".")
            print(f'{e["method"]} {e["host"]}{e["path"][:60]} {src}: header={d(h)} payload={d(p)}')
