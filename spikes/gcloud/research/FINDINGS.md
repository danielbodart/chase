# GCP credential injection — research findings (2026-09-28, web research agent)

Condensed from the agent's report; claims marked UNCONFIRMED were not found in a primary source.

## Metadata server
- Standard, free part of GCE/GKE/Cloud Run at metadata.google.internal / 169.254.169.254 (IPv6 fd20:ce::254). Not a paid feature. https://docs.cloud.google.com/compute/docs/metadata/overview
- Emulators exist (salrashid123/gce_metadata_server, matheuscscp/gke-metadata-server); not Google products.
- google-auth-python env vars: GCE_METADATA_HOST (first), GCE_METADATA_ROOT (legacy fallback), GCE_METADATA_IP (ping), GCE_METADATA_TIMEOUT, GCE_METADATA_DETECT_RETRIES, NO_GCE_CHECK, GCE_METADATA_MTLS_MODE. https://github.com/googleapis/google-auth-library-python/blob/main/google/auth/environment_vars.py
- DMI product_name check exists in google-auth-python (precedence UNCONFIRMED).

## Tokens
- generateAccessToken: default/max 1h, min 600s, up to 12h with iam.allowServiceAccountCredentialLifetimeExtension. https://docs.cloud.google.com/iam/docs/create-short-lived-credentials-direct
- SA access tokens cannot be revoked early. https://docs.cloud.google.com/docs/security/compromised-credentials
- Credential Access Boundaries: Cloud Storage documented; broader coverage UNCONFIRMED.

## SA keys
- Orgs created on/after 2024-05-03 enforce iam.managed.disableServiceAccountKeyCreation (plus key upload ban, no auto-Editor for default SAs, domain-restricted sharing, uniform bucket access). Older orgs not retroactively affected. https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations
- iam.serviceAccountKeyExpiryHours is opt-in.
- No-org personal project: no constraints by default (inferred).

## Workload Identity Federation
- JWKS can be uploaded directly to a provider (--jwk-json-path), max 8 keys, no x5c/x5t. https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers
- Attribute conditions (CEL) gate exchange; direct resource access to federated principals preferred over SA impersonation.
- Org requirement: none found (UNCONFIRMED).

## User credentials
- gcloud auth login (credentials.db) and ADC are separate stores; gcloud doesn't read ADC.
- Refresh token reuse vs rotation: assumed reusable (UNCONFIRMED GCP-specifically).
- Workspace session control: reauth every 1–24h, invalid_rapt errors. https://docs.cloud.google.com/access-context-manager/docs/session-controls-for-reauthentication
- OAuth scopes are per-API, never per-project.

## Scoping to one project
- IAM Conditions incl. request.time expiry.
- Deny policies attach at org/folder/project — no org needed. https://docs.cloud.google.com/iam/docs/deny-overview
- Principal Access Boundary: org required. VPC-SC: org-level access policy required.
- Escalation: iam.serviceAccounts.actAs; default compute SA gets Editor unless org baseline prevents it.

## Hosts
- *.googleapis.com; regional {region}-aiplatform.googleapis.com; *.rep.googleapis.com; *.mtls.googleapis.com (GOOGLE_API_USE_CLIENT_CERTIFICATE; Certificate-Based Access would defeat interception — inference).
- Artifact Registry: Basic, user oauth2accesstoken. Cloud Run: ID tokens (or X-Serverless-Authorization). IAP: tunnel.cloudproxy.app. GKE DNS endpoint *.gke.goog presents a public cert; IP endpoint the cluster CA.
- No evidence of certificate pinning (UNCONFIRMED).

## Discovery documents
- https://www.googleapis.com/discovery/v1/apis; each method has id, httpMethod, path template. gRPC-first APIs may lack one.

## Prior art
- NVIDIA OpenShell #1706: metadata emulation in the sandbox netns serving a placeholder token; proxy swaps it on *.googleapis.com. https://github.com/NVIDIA/OpenShell/issues/1706
- iron.sh: MITM of both the OAuth token endpoint and metadata token paths with a stub token, swapped on API calls. https://docs.iron.sh/credential-proxying/gcp-auth
- Google gcp-token-broker (Kerberos, GCS); Codespaces pattern is WIF minting real tokens into the container; Vault GCP.
