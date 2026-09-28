. /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/metadata/common.sh
export SSL_CERT_FILE=$S/pki/bundle.crt CHECKPOINT_DISABLE=1 TF_PLUGIN_CACHE_DIR=$S/tf/.plugins
cd $S/tf && rm -f terraform.tfstate* && timeout 180 terraform apply -auto-approve -input=false -no-color 2>&1 | tail -${LINES_MAX:-12}
timeout 30 terraform output -raw token_seen_by_terraform; echo
