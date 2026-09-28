# env every client test uses
S=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata
export CLOUDSDK_CONFIG=$S/gcloud-config
export HOME=$S/home
mkdir -p $HOME $CLOUDSDK_CONFIG
unset GOOGLE_APPLICATION_CREDENTIALS GOOGLE_CLOUD_PROJECT CLOUDSDK_CORE_PROJECT
