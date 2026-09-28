gcloud auth activate-service-account --key-file=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey/sbx/home/fake-key.json >/dev/null 2>&1
gcloud config set auth/service_account_use_self_signed_jwt true 2>&1
bash /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey/t_gcloud.sh
