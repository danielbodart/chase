# Real-GCP end to end through prototype frisket (2026-09-28)

Project `danbodart-sandbox-test` only. SA `frisket-spike@…`, bucket
`gs://danbodart-sandbox-test-frisket-spike/hello.txt`. Prototype = worktree
`.claude/worktrees/agent-a075a3bc82f672172` plus two changes made here (below).
Token files are deleted. Evidence: `out/*.out` (client stdout), `logs/<client>.log`
(frisket's lines for that client), `logs/frisket.log` (all).

## Result

A sandbox holding only `proxy-injected` read real GCS data and called Pub/Sub,
through gcloud, Python, Go and Node, over HTTP/1.1, HTTP/2 and gRPC. frisket
logged `credential: injected` and Google answered as the SA. The real token's
first 20 chars appear 0 times in the sandbox's CLOUDSDK_CONFIG, HOME, env,
client outputs and frisket's logs (`leakcheck.sh`). gcloud's `access_tokens.db`
holds the placeholder.

**But the sandbox did get a real token**: `iamcredentials.mtls.googleapis.com`
is a second name for iamcredentials, and it falls under `*.googleapis.com`
instead of the exact refuse-everything route. See "Security" below.

| test | result | on the wire (frisket log) |
|---|---|---|
| `gcloud auth list` | PASS: SA listed, active | metadata only |
| `gcloud config list` | PASS | CRM `v1/projects/P` injected → 403 (tolerated) |
| `gcloud storage ls gs://…` | PASS | storage 200, injected |
| `gcloud storage cat …/hello.txt` | PASS (`hello`) | storage 200/206, injected |
| `gcloud projects describe` | FAIL, IAM: SA has no `resourcemanager.projects.get`. Google named the SA as the caller, so authentication worked | CRM 403, injected |
| Python google-cloud-storage 3.10.1 download | PASS | storage 200 HTTP/1.1 |
| Python pubsub 2.34 / grpcio 1.80 `get_topic` (gRPC) | PASS | pubsub `GetTopic` HTTP/2 200 |
| Python pubsub `list_topics` (gRPC) | PermissionDenied from Google (IAM, as expected). frisket logs `status: 200`: the gRPC status is in the trailer | |
| Go cloud.google.com/go/storage 1.68 JSON | PASS | storage 200 HTTP/2 |
| Go storage `NewGRPCClient` (grpc-go 1.82.1) | PASS | `google.storage.v2.Storage/ReadObject` 200, injected |
| Node @google-cloud/storage 8.2.0 (Node 24) | FAIL at first, PASS after a fix: the prototype metadata server 404'd `computeMetadata/v1/instance`. Node then decided it was not on GCE and **sent the request anonymously**: `credential: none`, Google 401 "Anonymous caller". After adding `instance`: PASS | storage 200 |

gcloud's allowedLocations call to `iamcredentials…/allowedLocations` was refused
(6×, 403), and gcloud tolerated it. Go asked for `instance/machine-type` (404),
which it tolerated, and it did not take DirectPath.

## Refusals and bypass (sandbox, `out/refuse.out`, `out/alt.out`)

- The exact routes refuse at frisket (403 `refused by rule`, nothing sent upstream):
  `iamcredentials.googleapis.com` generateAccessToken and signJwt, `sts…/v1/token`,
  `oauth2…/token` and `/tokeninfo`. They also refuse `iamcredentials.googleapis.com.`
  and `IAMCREDENTIALS.googleapis.com`.
- Nothing usable outside frisket: storage's real IP with `--resolve` gives a reset or
  broken pipe; `169.254.169.254:80` is reset; `metadata.google.internal`,
  `accounts.google.com` and the `googleapis.com` apex are NXDOMAIN; UDP to 8.8.8.8:443
  is EPERM; the system CA fails verification against frisket's leaf.
- Metadata: no Metadata-Flavor → 403; `X-Forwarded-For` → 403; `identity` → 404.

## Security: the exact-route shadow does not hold (measured)

These names all went to the `google` wildcard route with the real token injected:

- `iamcredentials.mtls.googleapis.com` generateAccessToken: Google answered
  403 `iam.serviceAccounts.getAccessToken denied`, so authentication passed. I then
  granted the SA Token Creator on itself (temporarily; removed right after, and the
  bindings were checked). The sandbox received **a real ya29… token (1024 chars)**,
  and using it from the sandbox was `credential: passed`, storage 200. frisket
  forwards any non-placeholder credential untouched. The minted-token file is deleted.
- `iamcredentials.us-central1.rep.googleapis.com` and `europe-west2.rep`: reached
  iamcredentials (400 FAILED_PRECONDITION, a regional-endpoint condition, not frisket).
- `sts.mtls.googleapis.com`: reached STS (400 invalid args). The body is not
  injected, so a placeholder subject token is useless there. A real subject token
  would still go through.
- `www.googleapis.com/oauth2/v4/token` (the legacy token endpoint): reached Google.
  It is harmless only while the sandbox has no refresh token or signed JWT, and
  signJwt is reachable through the mtls alias above.
- `www.googleapis.com/oauth2/v{1,3}/tokeninfo` with the placeholder header: 200,
  which reveals the token's scope and expiry but not the token.
- `iam.googleapis.com` `keys.create` and v1 `signJwt`: reached Google, and only IAM
  refused them. An SA allowed to create keys would hand the sandbox a long-lived key.

So "no real token in the sandbox" currently depends on the SA's IAM. It needs
refusal by **path** on the wildcard route (`:generateAccessToken`,
`:generateIdToken`, `:signJwt`, `:signBlob`, `/v1/token`, `/oauth2/*/token`,
`serviceAccounts/*/keys` POST, …), or host patterns such as `iamcredentials.*`,
`sts.*` and `*.mtls.*`, not exact names. Better still, invert it to an allowlist of
services.

## Expiry and rotation (`out/rotate.out`)

- Stale file (same token, `expiry_ms` 60 s in the past): storage → **503
  `credential expired`**, nothing sent upstream. Metadata `expires_in` → 0.
  Python storage treats 503 as retryable and spun for **120 s**, then failed with
  RetryError (14 × 503 logged).
- Renewer rewrote the file: frisket logged `credential loaded` within ~1 s and the
  next request was 200 (token hash changed `f05f…` → `20dd…`; `expires_in` 3598).
- Rotation during a retrying client: the file was made stale, a Python download was
  started, and the renewer ran 10 s later. The download succeeded at 13.9 s. No client
  restart was needed.

## Harness vs production

- **Same as production**: `frisket serve` as the daemon's user (dan, no caps), and
  `frisket steer -userns … -nsenter …` / `frisket connect` exactly as flong's hooks
  run them, rootless, set `all`, with the steering JSON from `nix/steering.nix`.
  TPROXY listeners, nftables, the dummy interface, per-session CA at `/etc/frisket`,
  DNS from frisket, IPv6 (clients connected to `[2001:db8::2]:443`).
- **Different**:
  - The prototype binary ran outside systemd: no unit hardening, no fd store, a
    control socket at `/run/user/1000/fe2e.sock`.
  - The sandbox is `unshare -Urnm --map-auto -pf --mount-proc` (newuidmap, so
    setgroups is allowed, as flong's is), not flong. `unshare -r` alone fails
    steer: `nsenter: setgroups failed`. lo had to be brought up by the leader, or
    steer fails with "lo is still down".
  - The sandbox sees the host filesystem, masked with tmpfs over `/home/dan`, the token
    dir, `/run/user/1000`, `/run/frisket` and `/run/nscd`. The sandbox **can
    `umount` those masks** (it owns the mount ns) and then read the host token file.
    Measured, so this harness is not a security boundary. flong's is.
  - It shares host `/tmp` and runs as uid 0 in its userns.
  - The env (`GCE_METADATA_{HOST,IP,ROOT}=192.0.2.2`, `GOOGLE_CLOUD_PROJECT`, CA
    variables incl. `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`,
    `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`) was set by `in.sh`. Who sets it (chase?) is open.
- Host renewer `renew.py`: calls iamcredentials generateAccessToken with the user's
  gcloud token and writes `{"access_token","expiry_ms"}` atomically (mkstemp +
  rename, umask 077). It never prints the token.

## Code added here (worktree, uncommitted)

- `internal/policy/policy.go`: a policy `metadata` block `{projectId,
  numericProjectId, email, route}` builds `metadata.Server` from the named route's
  placeholder and credential, set as `Handlers.Metadata`. Without it, the prototype's
  metadata server was reachable only from tests.
- `internal/metadata/metadata.go`: serves `instance`/`instance/` (Node's probe) and
  `universe/universe_domain` (Terraform's spelling).

## Rough edges production frisket/chase must fix

1. **Token-minting aliases under the wildcard** (above). This is the blocker.
2. The metadata server must serve `instance` (Node). Otherwise the client silently goes
   anonymous, and frisket forwards the anonymous request, so the failure looks like
   an IAM problem.
3. Metadata log lines have no `session`/`policy`, unlike every other line.
4. gRPC outcomes are logged as HTTP 200. Log `grpc-status` from the trailer.
5. A stale credential gives a 503, which Google clients retry for up to 2 min. That is
   good if the renewer is late by seconds and bad if it is dead. Consider a distinct
   refusal, or log/alert when a file stays stale. While stale, metadata `expires_in` 0
   makes clients refetch on every call.
6. `expires_in` follows the real token down to 0, so near expiry Node and gcloud
   refetch per request (≤300 s). That is harmless locally but noisy. The renewer should
   renew well before 5 min remain.
7. The policy JSON needs `"name"` inside the document (`frisket check` fails with
   `policy name ""` otherwise), and `frisket serve -control` must be ≤108 bytes (a
   scratch path failed with `bind: invalid argument`). The error could say so.
8. `/run/nscd`: with the host's nscd socket visible, the sandbox resolved
   `accounts.google.com` (not allowed) to a real IP through the host resolver. The
   connection is still refused, but it is a DNS side channel and bypasses the
   allowlist's NXDOMAIN. I did not check whether flong sandboxes see `/run/nscd`.
9. The wildcard route's scope is path-only, so it cannot say "storage GET only".
   Per-service limits come only from IAM (per the frisket-code spike, now confirmed live).
10. gcloud calls `iamcredentials …/allowedLocations` on every command, and a refuse-all
    exact route logs a WARN each time (6 per run here). Admit that GET, or quiet it.
11. The renewer needs the user's (or a federated) credential on the host. gcloud's own
    impersonated token is cached, so `print-access-token --impersonate` plus "now + 1h"
    would overstate the expiry. Use the API's `expireTime`.

## Left behind in the project

Pub/Sub API enabled, topic `frisket-spike` with `roles/pubsub.viewer` for the SA on
that topic only. The SA self-Token-Creator grant was removed. The SA's remaining
bindings: the user's Token Creator, plus a `workloadIdentityUser` principal from the
other (federation) agent.
