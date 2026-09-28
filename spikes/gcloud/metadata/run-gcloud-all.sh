S=$(cd "$(dirname "$0")" && pwd)
GCE_METADATA_HOST=192.0.2.2 GCE_METADATA_IP=192.0.2.2 GCE_METADATA_ROOT=192.0.2.2 $S/ns.sh gcloud-all bash $S/t-gcloud.sh
