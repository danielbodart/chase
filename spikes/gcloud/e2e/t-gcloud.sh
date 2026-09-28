B=gs://danbodart-sandbox-test-frisket-spike
run(){ echo "### $*"; "$@"; echo "rc=$?"; }
run gcloud auth list
run gcloud config list
run gcloud storage ls $B
run gcloud storage cat $B/hello.txt
run gcloud projects describe danbodart-sandbox-test --format='value(projectId,projectNumber,lifecycleState)'
