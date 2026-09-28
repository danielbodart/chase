# usage: refresh.sh ; runs each client LOOPS=6 SLEEP=1 at several TOKEN_TTLs and counts token fetches vs API calls
S=$(cd "$(dirname "$0")" && pwd)
export GCE_METADATA_HOST=192.0.2.2 GCE_METADATA_IP=192.0.2.2 GCE_METADATA_ROOT=192.0.2.2 LOOPS=6 SLEEP=1 GOOGLE_CLOUD_PROJECT=frisket-spike
count() { python3 -c '
import json,sys
tok=api=0
for l in open(sys.argv[1]):
    m=json.loads(l)
    if m["srv"]=="metadata" and m.get("path","").endswith("/token"): tok+=1
    if m["srv"]=="api" and "UNKNOWN" not in m and "allowedLocations" not in m.get("path",""): api+=1
print(f"token fetches={tok} api calls={api}")' $1; }
for c in python go node; do for ttl in 3599 301 299 226 224 61 59 11 9; do
  TOKEN_TTL=$ttl $S/ns.sh refresh-$c-$ttl bash $S/t-$c.sh >/dev/null 2>&1
  echo "$c ttl=$ttl $(count $S/logs/refresh-$c-$ttl.log)"
done; done
