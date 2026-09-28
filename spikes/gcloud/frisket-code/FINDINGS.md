# frisket code spike: Google Cloud through the intercept path (2026-09-28)

Worktree `.claude/worktrees/agent-a075a3bc82f672172`, uncommitted. Diff: `gcp-spike.patch` (16 files, +1724/-16, of which ~1400 are spike tests).
Production-side change is ~210 lines: ca.go +28, intercept.go +78, route.go +20, policy.go +24, dispatch.go +8, metadata/metadata.go 248 (design a), metadata/token.go 34 (design b).
Everything below is from `go test ... -run Spike -v` or `openssl verify`. The only failures in `go test ./internal/...` are the two tests that assert wildcards are refused (TestTheCARefusesAHostThatIsNotAName, TestARouteIsForOneHost).

## 1. Many hosts: a `*.googleapis.com` route
Change: route Host `*.suffix`, upstream `https://*.suffix[:port]`; route map keyed `.suffix`; `lookup` is exact name first, then the closest `*.` ancestor; upstream is the client's SNI (rewrite sets URL.Host = SNI, TLS ServerName "" so Transport verifies the SNI); host checks/logs/ask use the SNI; policy allows `*.x` routes only when the allowlist has `*` or a wildcard at or above the suffix (exact names cannot cover it); `pat.Any` still refused.
- DNS: no DNS change needed. TestSpikeAWildcardRouteBuilds: storage., us-central1-aiplatform., a.b.googleapis.com resolve to 192.0.2.2; the bare `googleapis.com` is resolved upstream (allowed, not intercepted).
- CA constraint, two encodings, Go 1.26 and OpenSSL 3.6.4 (`openssl verify -x509_strict -verify_hostname`) agree exactly:
  - bare `googleapis.test` (RFC 5280 subtree): permits apex + every depth below; refuses `evilgoogleapis.test`, `example.test`.
  - leading dot `.googleapis.test`: same, but apex refused.
  - Wildcard leaf `*.googleapis.test` passes both; its hostname match is one label only (Go), so minting per SNI is what covers `a.b.` names.
  - Note: today's exact-host constraints (`api.github.com`) already permit every subdomain of that name per RFC 5280; getCertificate is what stops minting for them.
- Leaf issuance: per-SNI, as today. BenchmarkSpikeMint: 110 µs/leaf (i9-12900K). Names under the suffix are the workload's to invent, so cache churn is possible but cheap.
- End to end (TestSpikeWildcardRoute, h1 and h2): 3 names each got own leaf (CN = SNI); upstream saw SNI = Host = requested name and `Bearer <real>`; frisket dialled exactly `<sni>:port`. Apex, `evilgoogleapis.test`, `example.test` refused at handshake ("not a route"), nothing dialled. Cross-host request on one conn → 421 (TestSpikeWildcardCrossHostOnOneConnIsMisdirected).
- Shadowing (TestSpikeWildcardShadowedByExactRoute): an exact credential-less route with a Refuse rule for `iamcredentials.<suffix>` wins over the wildcard: generateAccessToken → 403, nothing upstream; storage still 200 with real token.
Security:
- The token then goes to every Google API; IAM on the token is the only per-service limit. Scope is path-only, with no host dimension, so a wildcard route cannot say "GET on storage only". Needs a host (or host-pattern) key in PathRule, or exact routes per service.
- Token-minting endpoints under the suffix hand real credentials back into the sandbox in the response body: iamcredentials generateAccessToken/generateIdToken/signJwt/signBlob, sts.googleapis.com token exchange. These must be shadowed (proven possible above) or refused by path. This breaks the LOCKED "no real token in the sandbox" rule if missed.
- Virtual-hosted GCS (`<bucket>.storage.googleapis.com`) puts attacker-chosen labels under the suffix; the token still only goes to Google's frontend.
- `*.mtls.googleapis.com` / certificate-based access cannot work through interception (frisket presents no client cert).
- The explicit-list alternative needs no code but breaks on regional/rep hosts (`{region}-aiplatform`, `*.rep.googleapis.com`), which are open-ended.

## 2. gRPC: works
TestSpikeGRPCUnary/BidiStream/Cancel/Refusals/StaleCredential, against both a native grpc-go server and grpc.Server.ServeHTTP behind net/http:
- Unary: `authorization: Bearer proxy-injected` arrives upstream as `Bearer <real>`; response trailer `x-upstream-trailer` kept; trailers-only error (PermissionDenied + message) kept; 8 MiB each way ok (past both hops' 64 KiB windows). Upstream sees `TE: trailers`.
- Bidi ping-pong x6, with 1.5 s idle mid-stream past a shrunk 500 ms idle timeout: each reply before next send (no buffering); final status FailedPrecondition "done after 6" and trailer "6" intact.
- Client cancel reaches upstream as Canceled.
- frisket refusals are plain text, not grpc-status: out of scope 403 → client sees PermissionDenied; stale credential 503 → Unavailable (retryable). Adequate; a `application/grpc` refusal shape would give readable messages.
No production change was needed for gRPC.

## 3. Metadata endpoint (design a)
- There is no HTTP listener on the service address today: steering marks every TCP port to 192.0.2.2/2001:db8::2 (nix/steering.nix, `ip daddr svc tcp`), all reaching one TPROXY listener; Dispatch sends all service-address TCP to Intercept (TLS). So port 80 needs no ruleset change, only a Dispatch case: `Orig.Port()==80 && IsService → Metadata` (+8 lines, serve/dispatch.go).
- Handler (internal/metadata/metadata.go, 248 lines): plain http.Server over a channel listener fed by steer.Conn. Sets `Metadata-Flavor: Google` on every response; `/` ping answers without requiring the header; everything else 403 without `Metadata-Flavor: Google`; refuses X-Forwarded-For (GCE's SSRF rule); GET only. Serves project-id, numeric-project-id, universe-domain, service-accounts (list, recursive), email/aliases/scopes, and `token` → `{"access_token":"proxy-injected","expires_in":N,"token_type":"Bearer"}` with N tracking the real token's expiry (capped 3599). `identity` is 404: an ID token cannot be a placeholder.
- TestSpikeMetadataThenAPI: cloud.google.com/go/compute/metadata with GCE_METADATA_HOST=192.0.2.2 → OnGCE true, project, email, universe; token = placeholder, expires_in 2399 for a 40 min real token; no-flavor → 403; then storage/bigquery with the placeholder reach upstream as the real token; real token absent from logs.
- Per PLAN: clients also need GCE_METADATA_IP / GCE_METADATA_ROOT; real-client measurements for gcloud/python/node are in `spikes/metadata/`.

## 4. Token endpoint answered locally (design b)
- Shape: `Route.Answer http.Handler` (route.go +4, intercept.go +6): after steering checks and the scope decision, an admitted request goes to the handler; no credential looked at, nothing dialled, logged `credential: "answered"`. Route: `oauth2.googleapis.com`, scope `POST /token`, Answer = `metadata.TokenEndpoint(placeholder, expiresIn)` (34 lines): form `grant_type=refresh_token` and `refresh_token=<placeholder>` → `{"access_token":"proxy-injected","expires_in":N,"token_type":"Bearer","scope":...}`, anything else 400 invalid_grant, body capped at 64 KiB.
- The exact route coexists with `*.googleapis.com` (exact wins); the CA gets `googleapis.com` + `oauth2.googleapis.com`.
- TestSpikeTokenEndpointThenAPI, golang.org/x/oauth2 v0.37 `google.CredentialsFromJSON` with a placeholder authorized_user file and the default token URL: token = placeholder; storage and bigquery calls reach upstream with the real token; a non-placeholder refresh token → 400; `GET /tokeninfo` → 403 out of scope; frisket never dialled oauth2.*; real token not in the log.
- Unlike (a), no new listener, port or env vars; it's just a route kind. It does require intercepting oauth2.googleapis.com, so a real refresh token used in the sandbox fails closed (400), never forwarded.

## 5. Token file → credential: yes, with one gap
Existing `credential.WatchFile` + `JSON{Token, ExpiresMillis}` feeds the GCP route unchanged (used in the metadata test; a stale Secret gives 503/Unavailable, shown for gRPC). TestSpikeTokenFileShapes:
- bare token (`gcloud auth print-access-token > f`): ok, no expiry (stale → upstream 401, not 503).
- `{"access_token", "expiry_ms": <ms>}`: ok.
- RFC 3339 `expiry` (the JSON form of x/oauth2's `Token`): refused, "no number at expiry".
- `expires_in` seconds misnamed as ExpiresMillis: silently parsed as 3.599 s after epoch → always expired → every request 503. A config footgun.
- ya29 tokens are opaque, so ExpiresJWT does not apply.
So the refresher must write epoch millis, or add an `expiresRFC3339` extractor (~15 lines + policy field).

## 6. Artifact Registry Basic: works as is
`basicUser: "oauth2accesstoken"` already exists (policy.go, intercept.BasicUser), and `carries` accepts Basic with the placeholder as password under any user. TestSpikeArtifactRegistryBasic (`*.pkg.test` wildcard route): docker token flow with user `oauth2accesstoken` and `_dcgcloud_token` (docker-credential-gcloud) → upstream saw `Basic oauth2accesstoken:<real>` at the realm; subsequent `Bearer <registry-issued token>` passed through untouched (`credential: passed`); direct per-request Basic also injected.
Risk, unmeasured: the registry-issued bearer token returned by the realm is visible in the sandbox. If Artifact Registry returns an opaque repo-scoped token that is fine; if it echoes a usable OAuth token it breaks the LOCKED rule. Needs one real `/v2/token` call to settle. AR hosts are `*-docker.pkg.dev`, so it's a second wildcard route (`*.pkg.dev`) with its own inject shape.

## Spike code risks / nits
- `CA.Permits` spike loop: `HasPrefix(c,".") && HasSuffix(h,c) || HasSuffix(h,"."+c)` accepts subdomains of *exact* constraints too (true to RFC 5280, but looser than today's contains-check). getCertificate still refuses by route first.
- Upstream on a wildcard route uses the upstream URL's port for every SNI; a path base on the upstream is refused.
- Policy tests asserting "a route is for one host" would need rewriting; allowCovers is a new rule that only a wildcard allow at or above the suffix covers a wildcard route.
