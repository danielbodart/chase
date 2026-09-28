#!/usr/bin/env bash
# Run a command in the sandbox: only the fake key file, CA vars and a scratch HOME/CLOUDSDK_CONFIG.
F=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/fakekey
L=$(cat $F/leader.pid)
exec nsenter -t $L -U -n -m -p --preserve-credentials -- env -i \
  PATH=/nix/store/frlyjd2wya3rk8xmdc98yq3x0rhpkh9n-nodejs-24.21.0/bin:$F/pyenv/bin:/nix/store/30h4aphk3m9gkx3lhd3czbww821xsrfw-terraform-1.15.3/bin:/etc/profiles/per-user/dan/bin:/run/current-system/sw/bin \
  HOME=$F/sbx/home CLOUDSDK_CONFIG=$F/sbx/gcloud \
  GOOGLE_APPLICATION_CREDENTIALS=$F/sbx/home/fake-key.json \
  SSL_CERT_FILE=/etc/frisket/ca-bundle.crt REQUESTS_CA_BUNDLE=/etc/frisket/ca-bundle.crt \
  CURL_CA_BUNDLE=/etc/frisket/ca-bundle.crt NODE_EXTRA_CA_CERTS=/etc/frisket/ca.crt \
  CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=/etc/frisket/ca-bundle.crt \
  GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/etc/frisket/ca-bundle.crt \
  "$@"
