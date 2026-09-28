#!/usr/bin/env bash
# Run a command in the sandbox with a clean env: only placeholders, no host config.
E=/tmp/claude-1000/-home-dan-Projects-frisket/d148bf0d-8069-4d10-b051-b5be28488830/scratchpad/spikes/e2e
L=$(cat $E/leader.pid)
exec nsenter -t $L -U -n -m -p --preserve-credentials -- env -i \
  PATH=/nix/store/frlyjd2wya3rk8xmdc98yq3x0rhpkh9n-nodejs-24.21.0/bin:/nix/store/i6kib5fs8ndpk0s0zybdh5kdhy5vkmmv-go-1.26.7/bin:/nix/store/pfy9lf8v6y0387vd1n78cni3vxc50gw9-python3-3.13.15-env/bin:/etc/profiles/per-user/dan/bin:/run/current-system/sw/bin \
  HOME=$E/sbx/home CLOUDSDK_CONFIG=$E/sbx/gcloud \
  GCE_METADATA_HOST=192.0.2.2 GCE_METADATA_IP=192.0.2.2 GCE_METADATA_ROOT=192.0.2.2 \
  GOOGLE_CLOUD_PROJECT=danbodart-sandbox-test \
  SSL_CERT_FILE=/etc/frisket/ca-bundle.crt REQUESTS_CA_BUNDLE=/etc/frisket/ca-bundle.crt \
  CURL_CA_BUNDLE=/etc/frisket/ca-bundle.crt NODE_EXTRA_CA_CERTS=/etc/frisket/ca.crt \
  CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=/etc/frisket/ca-bundle.crt \
  GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/etc/frisket/ca-bundle.crt \
  GOCACHE=$E/sbx/gocache GOPATH=$E/sbx/gopath GOFLAGS=-mod=mod GOTOOLCHAIN=local \
  "$@"
