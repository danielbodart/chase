S=$(cd "$(dirname "$0")" && pwd)
export GCE_METADATA_HOST=192.0.2.2 GCE_METADATA_IP=192.0.2.2 GCE_METADATA_ROOT=192.0.2.2 GOOGLE_CLOUD_PROJECT=frisket-spike LOOPS=1 SLEEP=0
ok() { case $1 in
  gcloud-min) grep -q "gs://spike-bucket" ;;
  python|node) grep -q "^0 200" ;;
  go) grep -q "GET 200" ;;
  pubsub) grep -q "^0 list_topics ok" ;;
  tf) grep -q "Apply complete" ;;
esac; }
for d in '^/$' '^/computeMetadata/v1/instance$' 'service-accounts/$' 'recursive=true' '/email$' 'project-id$' 'numeric-project-id' 'universe' '/identity'; do
  line="deny ${d}:"
  for c in gcloud-min python go node pubsub tf; do
    if MD_DENY="$d" $S/ns.sh deny-$c bash $S/t-$c.sh 2>&1 | ok $c; then line="$line $c=ok"; else line="$line $c=FAIL"; fi
  done
  echo "$line"
done
