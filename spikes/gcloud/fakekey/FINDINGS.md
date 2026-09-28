# Fake service-account key, no metadata server, real Google (2026-09-28)

Project `danbodart-sandbox-test` only. SA `frisket-spike@…`, bucket
`gs://danbodart-sandbox-test-frisket-spike/hello.txt`, topic `frisket-spike`.
Harness = the e2e one (`up.sh`/`in.sh`/`down.sh`/`leader.sh`/`renew.py`), rootless
steer/connect, set `all`, control socket `/run/user/1000/ffk.sock`. Prototype = the
e2e worktree plus `fakekey.patch` (my changes only; `worktree-full.patch` is the
whole uncommitted worktree). Evidence: `out/<test>.out` (client), `logs/<test>.log`
(frisket's lines for it), `logs/frisket.log`; `python3 sum.py logs/<test>.log`
condenses one.

Versions: gcloud 583.0.0; google-auth 2.50.0, google-cloud-storage 3.10.1, pubsub
2.34.0, resource-manager 1.17.0 (Python 3.13); Go storage 1.68.0, pubsub 1.51.1
(apiv1 GAPIC), google.golang.org/api 0.299.0, cloud.google.com/go/auth 0.23.3;
Node 24, @google-cloud/storage 8.2.0 (nested google-auth-library 9.15.1),
@google-cloud/pubsub 6.1.0 (google-gax 6.7.0, google-auth-library 11.1.0);
Terraform 1.15.3 + hashicorp/google 8.4.0.

## Answer

Yes. The sandbox held a `service_account` JSON whose private key was generated for
the session (`genkey.py`; public half to frisket via the policy), with no metadata
server and no `GCE_METADATA_*`, and every client read real data through frisket as
the SA. The real token (ya29…, 1024 chars) lived only in `host/gcp-token.json`
(deleted). Its first 20 chars: 0 in the sandbox's CLOUDSDK_CONFIG, HOME, env,
terraform state, client outputs and frisket's logs (`out/leakcheck.out`); the
sandbox could not read the host file.

Sandbox env: `GOOGLE_APPLICATION_CREDENTIALS=<fake key>`, the CA variables
(`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`,
`CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`, `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`), `HOME`,
`CLOUDSDK_CONFIG`. No `GOOGLE_CLOUD_PROJECT`: every library took the project from
the key's `project_id`. gcloud additionally needs one of the two options below.

## Matrix

**X** = assertion exchanged at a token endpoint frisket answers (`credential:
answered`, placeholder back), then the placeholder on the API call. **S** =
self-signed JWT as the bearer, recognised by frisket (RS256 against the fake
public key) and replaced. Every API call logged `credential: injected`.

| client | path | result |
|---|---|---|
| gcloud, env var only | – | FAIL "No credentialed accounts": gcloud ignores `GOOGLE_APPLICATION_CREDENTIALS` |
| gcloud, `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=<key>` | X | PASS storage ls/cat, pubsub describe, print-identity-token; `auth list` says "No credentialed accounts" (cosmetic) |
| gcloud, `auth activate-service-account --key-file` | X | PASS all; `auth list`/`config list` name the SA. Copies the fake key into CLOUDSDK_CONFIG (credentials.db, legacy_credentials/…/adc.json, .boto). No network at activation |
| gcloud + `auth/service_account_use_self_signed_jwt=true` | S for API calls, X for gcloud's own credential load/ID token | PASS all |
| gcloud storage sign-url (with and without `--private-key-file`) | local signing | URL produced but useless: signed with the fake key; gcloud's own HEAD check → 403 and it warns. No signBlob. Needs `--region` (SA lacks buckets.get) |
| Python google-cloud-storage download | X | PASS |
| Python pubsub `get_topic`, gRPC | S (aud) | PASS |
| Python pubsub `get_topic`, REST | S (aud) | PASS |
| Python resource-manager v3 `get_project`, gRPC + REST | S (aud) | Google 403 IAM for the SA = authenticated |
| Python `id_token.fetch_id_token` | X + `target_audience` | PASS; JWT-shaped placeholder parsed |
| Python `blob.generate_signed_url` v4 | local signing | fetch → 403 `SignatureDoesNotMatch`. No signBlob |
| Go storage JSON | X | PASS (HTTP/2) |
| Go storage gRPC | S (scope) | PASS (`Storage/ReadObject`) |
| Go pubsub apiv1 GAPIC gRPC `GetTopic` ×2 | S (scope) | PASS, one JWT for both |
| Go pubsub apiv1 GAPIC REST `GetTopic` ×2 | X | PASS |
| Go `idtoken.NewTokenSource` | X + `target_audience` | PASS, expiry read from placeholder |
| Node @google-cloud/storage download | X at **`www.googleapis.com/oauth2/v4/token`** | FAIL at first (reached Google via the wildcard: "invalid_grant: Invalid JWT Signature"); PASS once frisket answers that URL too |
| Node @google-cloud/pubsub `getMetadata`, gRPC ×2 | S (scope) | PASS |
| Node @google-cloud/pubsub `fallback: 'rest'` ×2 | S (scope) | PASS |
| Node `getIdTokenClient` | X + `target_audience` (oauth2.googleapis.com) | PASS |
| Node `file.getSignedUrl` v4 | local signing | 403 `SignatureDoesNotMatch` |
| Terraform google 8.4.0 (object content, pubsub topic) | X (3 exchanges) | PASS; `google_client_config.access_token` = `proxy-injected`. `openidconnect…/v1/userinfo` 401 (real token is cloud-platform only), tolerated |

Negative (`out/neg.out`, Python in the sandbox): a bearer JWT from the fake key with
another host's aud, a 24 h life, expired, or another iss, or signed by another key
→ not the placeholder, so forwarded as the client's own (`credential: passed`),
Google 401. An assertion signed by another key, with an API aud, or a
`refresh_token` grant → 400 from frisket, nothing sent. `oauth2…/tokeninfo` → 403
(route scope). `accounts.google.com`, `metadata.google.internal` → NXDOMAIN;
`169.254.169.254:80` → refused (structural: link-local).

## Self-signed JWTs (on the wire)

| client | when | claims | aud | reuse seen |
|---|---|---|---|---|
| Python GAPIC (pubsub, resource-manager) | default, gRPC **and** REST | iss=sub=SA, iat, exp=iat+3600, no scope | `https://<host>/` | one per client per host; 2nd call cached |
| gcloud with `service_account_use_self_signed_jwt` | API calls only | iss=sub=SA, `scope`=gcloud's 6 scopes | none | one per process per host |
| Go GAPIC gRPC (pubsub apiv1, storage gRPC) | default | iss=sub=SA, `scope`=client defaults | none | one per client |
| Go GAPIC REST | never: exchanges | | | |
| Node google-gax (gRPC and REST fallback) | default | iss=sub=SA, `scope` (cloud-platform + pubsub) | none | one per PubSub instance (two instances in the same second made a byte-identical JWT: PKCS#1 v1.5 is deterministic) |

Lifetime (source): 3600 s everywhere; re-minted early by 225 s (Python
`REFRESH_THRESHOLD`, Go `defaultExpiryDelta`) or 5 min (Node `JWTAccess`, LRU 500).
So a long-lived process makes ~1 new JWT per ~56 min per audience/scope set, and
frisket verifies each once.

Cost (i9-12900K): verify 21.7 µs/op (2.7 KB, 28 allocs); cached 0.45 µs/op.

Claims frisket requires: RS256; signature by the session key; iss = SA; sub absent
or = SA; exp in the future; iat ≤ now+5 min; exp−iat ≤ 65 min; and aud =
`https://<SNI>/`, or no aud with a non-empty scope. Token-endpoint assertions: aud =
the key's `token_uri` or `https://www.googleapis.com/oauth2/v4/token`.

## Other endpoints (counted over every client log, negative test excluded)

- `accounts.google.com` 0; `tokeninfo` (either host) 0.
- `www.googleapis.com/oauth2/v4/token`: Node storage only (gtoken in
  google-auth-library 9.x ignores `token_uri`). Now answered.
- iamcredentials: only gcloud's `…/allowedLocations` GET (5 per suite), refused by
  the exact route, tolerated. No signBlob/signJwt/generateAccessToken: signed URLs
  are signed locally with the fake key.
- `client_x509_cert_url`: fetched by nothing. A manual GET returns the SA's real
  certs (the fake key is not among them).
- Metadata, with none served: Python, Node, Terraform make no probe. gcloud looks
  up `metadata.google.internal` (+ `.lan`) once per fresh CLOUDSDK_CONFIG (NXDOMAIN,
  cached in `$CLOUDSDK_CONFIG/gce`). Go storage gRPC's DirectPath check dials
  `169.254.169.254:80` (refused) and resolves `metadata.google.internal` (NXDOMAIN);
  whole Go run 0.6–0.8 s. Nothing probed successfully.

## frisket code (`fakekey.patch`)

- `internal/fakekey/fakekey.go` 264 lines (230 code): load public key (PEM PUBLIC
  KEY or CERTIFICATE); `verify` (RS256 via stdlib `crypto/rsa`, then claims);
  `Bearer(tok, host)` with a per-JWT cache (`map[jwt]exp`, pruned past 4096);
  `TokenEndpoint()` (jwt-bearer only; access token = placeholder, expires_in 3599;
  `target_audience` → JWT-shaped placeholder ID token, `kid: frisket-placeholder`);
  `LegacyTokenEndpoint(host, path)`. Test + benchmarks 130 lines.
- `intercept/route.go` +11: `Route.PlaceholderJWT func(token, host) bool`, asked by
  `carries` for a Bearer that isn't the exact placeholder; `Route.AnswerFor
  func(host, path) http.Handler`.
- `intercept/intercept.go` +7/−3: `carries(h, sni)`; answer by host+path.
- `policy/policy.go` +34: `serviceAccountKey {publicKey, email, tokenURI,
  tokenRoute, route}`.
Policy: `policy/gcp.json` (e2e's, metadata block removed, oauth2 route scoped to
`POST /token` instead of refuse-all).

## Compared with the metadata design

| | metadata server | fake key |
|---|---|---|
| frisket code | metadata.go 251 + dispatch +8 + policy ~24 | fakekey.go 264 + route/intercept +18 + policy +34 |
| new listener | HTTP on service address :80 | none; answers on routes that exist |
| sandbox env | `GCE_METADATA_HOST`+`IP`+`ROOT`, `GOOGLE_CLOUD_PROJECT`, `CLOUDSDK_CORE_PROJECT`, CA vars, fresh CLOUDSDK_CONFIG | `GOOGLE_APPLICATION_CREDENTIALS`, CA vars; gcloud: `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE` or an activate step; `CLOUDSDK_CORE_PROJECT` still handy for gcloud |
| file in sandbox | none | key JSON with a private key Google doesn't know |
| placeholder rule | exact (decision 13) | exact, or a JWT the session key signed |
| removes | – | the 3-variable matrix; Node's `instance` probe and anonymous fallback; Metadata-Flavor/XFF rules; metadata log lines without session; expires_in tracking and refetch-per-request near expiry |
| adds | – | RS256 verify + cache; legacy token URL; gcloud activation/override; signed URLs fail at use not at signing; JWTs that fail verification go upstream as the client's own |
| ID tokens | `identity` placeholder | `target_audience` placeholder; real per-audience ID tokens built in neither |
| SA-key-forbidding orgs | works | works: nothing registered with Google |

## Rough edges

1. Legacy token URL: Node storage posts to `www.googleapis.com/oauth2/v4/token`
   regardless of `token_uri`; must be answered (done) or refused, else it reaches Google.
2. gcloud ignores ADC: needs the override (then `auth list` is empty) or
   `activate-service-account` (copies the fake key into CLOUDSDK_CONFIG).
3. Decision 13's exact match gains a second shape. The spike's JWS parsing is
   hand-written on stdlib; the dependency policy wants a vetted JOSE library
   (go-jose v4 is what Google's Go libs already use).
4. Key upload: an SA allowed `iam.serviceAccountKeys.create` lets the sandbox
   `keys:upload` a public key through the wildcard route, making the key real with no
   expiry. The same holds for any key the sandbox generates, so the metadata design
   has the same exposure, but here the sandbox already holds a correctly formatted
   key. Refuse `serviceAccounts/*/keys*` POST by path, alongside e2e's minting paths.
5. Signed URLs are produced and fail late (SignatureDoesNotMatch).
6. Scopes are the renewer's: Terraform's userinfo 401 (as with metadata).
7. JWTs that are not the session's are forwarded upstream as the client's own (401).
   A JWT the session key signed with bad claims could be refused locally.

## Recommendation

Fake key. It covered every client measured, including the self-signed GAPIC paths
(frisket must verify them anyway once a key file is present), with one sandbox
variable instead of five, no port-80 server and no GCE emulation that has to keep
up with each library's probe order. Its cost sits in one small package (use a
vetted JOSE library there), two token URLs to answer, and a path refusal for key
upload/create. The metadata design's remaining advantages: the session looks like
GCE, and it holds no key-shaped file.

## Left behind

Nothing new in GCP. Real token file deleted (grep for `ya29.` over this dir: 0).
Harness torn down. The fake key and its public half remain in `sbx/home/` and
`host/`; they are not secrets.
