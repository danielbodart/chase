S=$(cd "$(dirname "$0")" && pwd)
ALL="GCE_METADATA_HOST=192.0.2.2 GCE_METADATA_IP=192.0.2.2 GCE_METADATA_ROOT=192.0.2.2"
r() { name=$1; shift; echo ">>> $name" >&2; ( env "$@" ) > $S/out/$name.out 2>&1; }
case "$1" in
gcloud) r gcloud-all $ALL LINES_MAX=30 $S/ns.sh gcloud-all bash $S/t-gcloud.sh ;;
id) for m in plain jwt; do
      r py-id-$m $ALL IDTOKEN_MODE=$m IDTOK=1 GOOGLE_CLOUD_PROJECT=frisket-spike $S/ns.sh py-id-$m bash $S/t-python.sh
      r node-id2-$m $ALL IDTOKEN_MODE=$m IDTOK=1 GOOGLE_CLOUD_PROJECT=frisket-spike $S/ns.sh node-id2-$m bash $S/t-node.sh
      r gcloud-id-$m $ALL IDTOKEN_MODE=$m $S/ns.sh gcloud-id-$m bash -c ". $S/common.sh; export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=$S/pki/ca.crt; rm -rf \$CLOUDSDK_CONFIG; gcloud auth print-identity-token --audiences=https://example.run.app; echo rc=\$?"
    done ;;
go) for v in ALL HOST; do e=$ALL; [ $v = HOST ] && e="GCE_METADATA_HOST=192.0.2.2"; r go2-$v $e $S/ns.sh go2-$v bash $S/t-go.sh; done ;;
tf) r tf $ALL $S/ns.sh tf2 bash $S/t-tf.sh ;;
noflavor) for c in python node go gcloud-min; do r noflavor2-$c $ALL NO_FLAVOR=1 GOOGLE_CLOUD_PROJECT=frisket-spike $S/ns.sh noflavor2-$c bash $S/t-$c.sh; done ;;
refused) for c in python node go gcloud-min; do r refused2-$c $ALL MD_ADDR=192.0.2.2:81 GOOGLE_CLOUD_PROJECT=frisket-spike $S/ns.sh refused2-$c bash -c "t0=\$(date +%s.%N); bash $S/t-$c.sh; echo total-secs=\$(echo \"\$(date +%s.%N) - \$t0\" | bc)"; done ;;
unreach) for c in python node go gcloud-min; do r unreach-$c GCE_METADATA_HOST=192.0.2.99 GCE_METADATA_IP=192.0.2.99 GCE_METADATA_ROOT=192.0.2.99 GOOGLE_CLOUD_PROJECT=frisket-spike $S/ns.sh unreach-$c bash -c "t0=\$(date +%s.%N); bash $S/t-$c.sh; echo total-secs=\$(echo \"\$(date +%s.%N) - \$t0\" | bc)"; done ;;
knobs) r py-nogcecheck $ALL NO_GCE_CHECK=true GOOGLE_CLOUD_PROJECT=frisket-spike $S/ns.sh py-nogcecheck bash $S/t-python.sh
       r node-assume $ALL METADATA_SERVER_DETECTION=assume-present GOOGLE_CLOUD_PROJECT=frisket-spike $S/ns.sh node-assume bash $S/t-node.sh
       r py-noip-assume GCE_METADATA_HOST=192.0.2.2 GOOGLE_CLOUD_PROJECT=frisket-spike $S/ns.sh py-noip bash $S/t-python.sh ;;
gcecache) r gcloud-cachefalse $ALL $S/ns.sh gcloud-cachefalse bash -c ". $S/common.sh; export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=$S/pki/ca.crt; rm -rf \$CLOUDSDK_CONFIG; mkdir -p \$CLOUDSDK_CONFIG; echo -n False > \$CLOUDSDK_CONFIG/gce; t0=\$(date +%s.%N); gcloud auth list 2>&1; gcloud storage ls 2>&1 | tail -3; echo secs=\$(echo \"\$(date +%s.%N) - \$t0\" | bc); cat \$CLOUDSDK_CONFIG/gce" ;;
esac
