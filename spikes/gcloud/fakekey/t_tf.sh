cd /tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey/tf && rm -f terraform.tfstate*
export CHECKPOINT_DISABLE=1
terraform apply -auto-approve -input=false -no-color 2>&1 | tail -8
echo "token_seen_by_terraform: $(terraform output -raw token_seen_by_terraform)"
