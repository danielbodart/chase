# WIF with a self-held OIDC key — real-GCP measurements (2026-09-28)

Project danbodart-sandbox-test (957865594838). SA frisket-spike@…, bucket
gs://danbodart-sandbox-test-frisket-spike/hello.txt. Tokens never printed; only
lengths / `ya29` prefix. All WIF resources deleted at the end (see Cleanup).

Tools here: `jwtool/` (stdlib Go: genkey RSA-2048/P-256 + JWKS, sign RS256/ES256),
`exchange.sh` (STS), `gen.sh` (generateAccessToken), `renew.sh` (whole flow,
openssl+curl+jq, 15 lines), `jwk/*.json` (JWKS variants tried).

## 1. Pool + provider with uploaded JWKS

```
gcloud iam workload-identity-pools create frisket-spike --project=danbodart-sandbox-test --location=global
gcloud iam workload-identity-pools providers create-oidc frisket-rsa --project=danbodart-sandbox-test \
  --location=global --workload-identity-pool=frisket-spike \
  --issuer-uri=https://frisket.invalid/host-rsa --allowed-audiences=frisket-spike \
  --attribute-mapping=google.subject=assertion.sub \
  --attribute-condition="assertion.sub == 'project:danbodart-sandbox-test'" \
  --jwk-json-path=rsa.jwks.json
```

- Issuer: any `https://` URI accepted, including the unresolvable `https://frisket.invalid/...`.
  `http://…` → `Invalid OIDC issuer URI. The scheme must be https.`; `frisket-host` → `Invalid OIDC issuer URI.`
- JWKS accepted: RSA-2048 RS256, RSA-4096, EC P-256 ES256, RSA with `alg: PS256`, RSA with no `alg`,
  two keys (RSA+EC), two RSA keys (rotation), and an RSA key with a garbage `x5c` (not validated).
- JWKS rejected: EC P-384 and P-521 → `Invalid JWKs … Only RSA, EC key types are supported.`;
  Ed25519 OKP → `Input jwks contains corrupted key material.` So: RSA or EC P-256 only.
- JWKS update (update-oidc --jwk-json-path) took effect within ~5 s (new kid exchanged OK on first try).
- Allowed audiences: explicit list; with it set, the default audience
  (`https://iam.googleapis.com/projects/…/providers/…`) is rejected.

## 2. JWT + STS exchange

Header `{"alg":"RS256"|"ES256","kid":…}`; claims iss, sub, aud, iat, exp. POST
`https://sts.googleapis.com/v1/token` form: grant_type=urn:ietf:params:oauth:grant-type:token-exchange,
audience=//iam.googleapis.com/projects/957865594838/locations/global/workloadIdentityPools/frisket-spike/providers/frisket-rsa,
scope=https://www.googleapis.com/auth/cloud-platform, requested_token_type=…:access_token,
subject_token_type=urn:ietf:params:oauth:token-type:jwt, subject_token=<jwt>.
Result: 200, `token_type Bearer`, `issued_token_type …:access_token`, `ya29…` ~1000 chars. RS256 and ES256 both work.

Required claims (omit each):
| omitted | error |
|---|---|
| iss | invalid_grant: The issuer in ID Token null does not match the expected one |
| sub | unauthorized_client: rejected by the attribute condition (would be required anyway for google.subject) |
| aud | invalid_grant: The audience in ID Token [] does not match the expected audience. |
| iat | invalid_grant: ID Token issued at null is stale to sign-in. |
| exp | invalid_grant: ID Token issued at … is stale to sign-in. |

Lifetime: federated `expires_in` = min(exp − now, 3600) (minus ~2 s).
JWT ttl 30s→28, 10m→598, 1h→3598, 2h/23h/25h/1y/11y→3599. **No max on exp − iat**: an 11-year JWT was accepted.
iat 2 h in the past accepted if exp is in future. Clock skew ~60 s both ways: iat +60 s OK, +119 s rejected;
exp −59 s OK (gets expires_in 59!), −61 s rejected. ttl 2 s → 200 with no expires_in; ttl 1 s → **HTTP 500 INTERNAL** (repeatable).
The only way to shorten the federated token is a short JWT exp (STS has no lifetime parameter).

## 3. Path A — direct resource access

```
gcloud storage buckets add-iam-policy-binding gs://danbodart-sandbox-test-frisket-spike \
  --member=principal://iam.googleapis.com/projects/957865594838/locations/global/workloadIdentityPools/frisket-spike/subject/project:danbodart-sandbox-test \
  --role=roles/storage.objectViewer
```
Federated token: JSON API `…/o/hello.txt?alt=media` → 200 `hello`; XML API → 200 `hello`; list → `["hello.txt"]`;
`CLOUDSDK_AUTH_ACCESS_TOKEN_FILE=fed.tok gcloud storage cat …` → `hello`.
CRM getProject (no grant) → 403 PERMISSION_DENIED (i.e. authenticated; bogus token gives 401).
`oauth2.googleapis.com/tokeninfo` does NOT understand federated tokens (`invalid_token`).

## 4. Path B — SA impersonation

```
gcloud iam service-accounts add-iam-policy-binding frisket-spike@danbodart-sandbox-test.iam.gserviceaccount.com \
  --member=principal://…/workloadIdentityPools/frisket-spike/subject/project:danbodart-sandbox-test \
  --role=roles/iam.workloadIdentityUser
POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<SA>:generateAccessToken
  {"lifetime":"600s","scope":["https://www.googleapis.com/auth/cloud-platform"]}   (Bearer = federated token)
```
Binding propagation: first 200 ~70 s after SetIAMPolicy (403 `iam.serviceAccounts.getAccessToken denied` until then).

| lifetime | result |
|---|---|
| 0s | 400 Lifetime of access token must be larger then zero. |
| 1s | 200 (token already dead: read → 401) |
| 59s, 60s, 300s, 599s, 600s, 3600s | 200, expireTime = now + lifetime |
| 3601s, 43200s | 400 can not have lifetimes of more than 1 hour. Use the Org Policy Constraint constraints/iam.allowServiceAccountCredentialLifetimeExtension to allow up to 12 hours. |

Scopes: `devstorage.read_only` → token with only that scope (reads OK, CRM → 403 ACCESS_TOKEN_SCOPE_INSUFFICIENT);
`[""]` → defaults to cloud-platform; bogus scope → 400 INVALID_ARGUMENT. SA token read hello.txt → 200 `hello`.
tokeninfo shows no email (no userinfo.email scope requested).

## 5. Negative checks and revocation

| case | error |
|---|---|
| wrong sub | 400 unauthorized_client: The given credential is rejected by the attribute condition. |
| wrong aud | 400 invalid_grant: The audience in ID Token [other] does not match the expected audience. |
| wrong iss | 400 invalid_grant: The issuer in ID Token … does not match the expected one in config |
| expired (>60 s) | 400 invalid_grant: ID Token issued at … is stale to sign-in. |
| different key, same kid | 400 invalid_grant: Unable to verify the ID Token signature. |
| unknown kid / EC token vs RSA-only JWKS | 400 invalid_grant: Error connecting to the given credential's issuer. |

Disable provider (update-oidc --disabled, 12:01:0x): new exchange failed on the first try +1 s:
`The target service indicated by the "audience" parameters is invalid … disabled or deleted …`.
Then delete provider (12:04:26). For the whole 7 minutes observed afterwards:
- previously issued SA token: still 200 (expected).
- previously issued **federated** token: still 200 on the bucket (path A) **and still minted fresh SA tokens** (path B, 200, and those tokens read 200).
Removing the principal's workloadIdentityUser binding on the SA (12:08:29) stopped the old federated token
minting at 12:10:00 (~90 s); it still read the bucket via its own direct grant (path A).
So disabling/deleting the provider stops new exchanges only; an outstanding federated token (≤1 h) stays live
for everything its principal is granted, including minting ≤1 h SA tokens: worst-case leak window ≈ 2 h.
Real kill levers: remove the principal's IAM bindings (~90 s) or disable the SA.

## 6. Audit

Data Access logs were not enabled (project auditConfigs null); enabled DATA_READ/WRITE for storage, iam
(covers iamcredentials; `iamcredentials.googleapis.com` is rejected as an auditConfig service) and sts, then reverted.
- sts ExchangeToken: `principalSubject = "project:danbodart-sandbox-test"` (raw sub), resource = provider.
- iamcredentials GenerateAccessToken: `principalSubject = principal://…/subject/project:danbodart-sandbox-test`,
  `identityDelegationChain = [SA]`.
- storage.objects.get, path A: `principalSubject = principal://…/subject/project:danbodart-sandbox-test`, no email.
- storage.objects.get, path B: `principalEmail = frisket-spike@…`, `serviceAccountDelegationInfo[0].principalSubject = principal://…/subject/…`.
- path C: `principalEmail = SA`, delegation `firstPartyPrincipal.principalEmail = dan.bodart@triptease.com`.
- Admin Activity: Create/Update/Delete WorkloadIdentityPoolProvider logged under the user.
So the sub is visible in every hop; path B attributes the call to the SA with the federated subject as delegator.

Also seen: storage/CRM/artifactregistry calls in this project at the same time that were not from this spike
(SA impersonated by dan, 12:00:18–29) — another agent was using the fixtures concurrently.

## 7. Path C — gcloud user-credential impersonation

`gcloud auth print-access-token --impersonate-service-account=SA --lifetime=N > file` (dan has TokenCreator):
N=1,59,60,300,600,3600 all rc 0, distinct tokens each time (no caching), tokeninfo expires_in ≈ N
(1 s token already invalid). N=3601, 43200 → same 1-hour org-policy error. ~520–600 ms per call (Python startup).
Minimum accepted lifetime: 1 s (0 rejected by the API, as in path B).

## 8. Latency and renewer

10 runs, each a fresh curl (TLS handshake included): sign 4–5 ms (Go), STS 66–102 ms, generateAccessToken
74–99 ms; ES256 sign+STS 69–103 ms. Whole renew.sh (openssl sign + 2 curls) 225 ms incl. `nix shell`.
gcloud path C: ~550 ms. No billing for STS/iamcredentials calls.

`renew.sh` = 15 non-comment lines, needs openssl, curl, jq, date. In Go it is crypto/rsa or crypto/ecdsa +
net/http + encoding/json: no dependency.

## Cleanup

Deleted providers frisket-rsa, frisket-ec, frisket-jwk and pool frisket-spike (soft-deleted, state DELETED,
undeletable for 30 days; the id `frisket-spike` is unavailable until purge). Removed the principal's bucket and
SA bindings. Data Access auditConfigs reverted to none (note: `set-iam-policy` without `auditConfigs` keeps
them; needed `"auditConfigs": []`). Token/JWT files and private keys deleted. Fixtures (SA, bucket,
dan's TokenCreator) untouched.
