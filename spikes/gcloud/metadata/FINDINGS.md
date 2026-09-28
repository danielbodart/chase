# GCE metadata emulation on frisket's service address: findings

Offline, no sudo, in `unshare -rnm` with `/run/nscd` masked by tmpfs. `fakes/fakes`
serves a GCE metadata server on 192.0.2.2:80 (token `proxy-injected`), a TLS
"googleapis" on 192.0.2.10:443 (hosts file and a fake DNS on 127.0.0.53), and a
trap that logs anything reaching 169.254.169.254:80/443 or `metadata.google.internal`
(DNS points it at the trap). Logs: `logs/*.log` (server side, JSON; `summarize.py`),
`out/*.out` (client stdout).

Versions: gcloud 583.0.0; google-auth 2.50.0 (Python 3.13); google-cloud-pubsub
2.34.0 / grpcio 1.80.0; cloud.google.com/go/compute/metadata v0.10.0 +
golang.org/x/oauth2 v0.37.0; google-auth-library 11.1.0 + gcp-metadata 9.0.4
(Node 24); Terraform 1.15.3 + hashicorp/google 8.4.0.

## Result

With all three of `GCE_METADATA_HOST`, `GCE_METADATA_IP`, `GCE_METADATA_ROOT`
set to `192.0.2.2`, every client works and every API call carries
`Authorization: Bearer proxy-injected`; nothing reaches 169.254.169.254 or
resolves `metadata.google.internal` (checked across all such logs).
gcloud auth list / config list / print-access-token / print-identity-token /
storage ls / storage ls gs://b / projects describe all rc=0 (`out/gcloud-all.out`).
Terraform apply rc=0, `google_client_config.access_token` = `proxy-injected`.
Python pubsub over gRPC (HTTP/2 POST `/google.pubsub.v1.Publisher/ListTopics`)
carries the placeholder.

## Which variable each client honours (one alone is never enough for all)

| client | data calls | detection | alone enough |
|---|---|---|---|
| gcloud | `GCE_METADATA_ROOT` only | `numeric-project-id` on ROOT | ROOT. HOST alone or IP alone -> `metadata.google.internal` |
| Python google-auth | `GCE_METADATA_HOST`, else `GCE_METADATA_ROOT` | `GET /` on `GCE_METADATA_IP` | none: needs IP + (HOST or ROOT). HOST only / ROOT only -> ping to 169.254.169.254, no creds; IP only -> data to `metadata.google.internal` |
| Go compute/metadata, x/oauth2 | `GCE_METADATA_HOST` only | none when HOST set: `OnGCE()` true in <2us without a request | HOST. IP/ROOT ignored -> `GET /` (no Metadata-Flavor) to 169.254.169.254 + `metadata.google.internal`, retries ~3-6s |
| Node gcp-metadata | `GCE_METADATA_IP` or `GCE_METADATA_HOST` | `GET /computeMetadata/v1/instance` | HOST or IP. ROOT only / none -> probes 169.254.169.254 and `metadata.google.internal.` in parallel |
| Terraform google | Go libraries: HOST (only ran with all three) | | |

So frisket must set all three: Go needs HOST, gcloud needs ROOT, Python needs IP.

Knobs that must NOT be set: `NO_GCE_CHECK=true` makes Python skip the metadata
server entirely (DefaultCredentialsError, `out/py-nogcecheck.out`).
Node `METADATA_SERVER_DETECTION=assume-present` skips the `/instance` probe and
works (`logs/node-assume.log`) — optional. gcloud's
`compute/gce_metadata_check_timeout_sec` property exists (not tested).
Python `GCE_METADATA_MTLS_MODE=strict` would refuse a non-default host (source read, not run).

## Paths hit, in order (first run, fresh config)

gcloud `storage ls` (cold): `project/numeric-project-id` (GCE probe; must be
digits) -> `universe/universe-domain` -> `instance/service-accounts/default/email`
-> `project/project-id` (x2) -> `default/email` -> `instance/service-accounts/`
-> `default/identity?audience=32555940559.apps.googleusercontent.com&format=standard&licenses=FALSE`
(gcloud's own client id; on every credential load) ->
`service-accounts/<email>/?recursive=true` -> `default/token?scopes=cloud-platform,userinfo.email`
-> `project/project-id` -> API. Then an unsolicited
`GET iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<email>/allowedLocations`
with the placeholder (404 or NXDOMAIN is tolerated, `logs/gcloud-noiam.log`).
`gcloud config list` calls Cloud Resource Manager (`v1/projects/P` and
`v3/effectiveTags`) for its "[environment: ...]" line. `auth list` hits
numeric-project-id, `service-accounts/` (x2), universe-domain, default/email.

Python (`google.auth.default` + AuthorizedSession): `GET /` on IP (response
must carry `Metadata-Flavor: Google`) -> `project/project-id` ->
`service-accounts/default/?recursive=true` -> `default/token?scopes=...`. Every
later refresh: `service-accounts/<email>/?recursive=true` then `default/token`.
`fetch_id_token`: `/`, `default/?recursive=true`, `default/identity?audience=A&format=full`.

Go: `project/project-id`, `default/token?scopes=...`. Nothing else.

Node: `instance` (probe; Metadata-Flavor response required) -> `default/token`.
If neither `GOOGLE_CLOUD_PROJECT` nor `GCLOUD_PROJECT` is set, it first runs
`gcloud config config-helper --format json` (child process) for the project,
which costs ~250 ms and all of gcloud's own metadata calls (email,
universe-domain, project-id), and goes to `metadata.google.internal` unless
`GCE_METADATA_ROOT` is set (`logs/node-HOST.log`). With the project set:
3 requests total (`logs/node-gcp2.log`). ID token: `default/identity?format=full&audience=A`.

Terraform: `project/project-id`, `universe/universe_domain` (underscore, x2),
`default/token?scopes=cloud-platform,userinfo.email` (twice per run, per
provider instance), plus API calls to `openidconnect.googleapis.com/v1/userinfo`
and `compute.googleapis.com/compute/v1/projects/<number>` (404s tolerated).

pubsub (gRPC): as Python, scopes `cloud-platform,userinfo.email`.

## Endpoint list frisket must serve (all under /computeMetadata/v1/, Metadata-Flavor: Google on the response)

Required (a 404 on it broke a client, `out/deny-matrix.out`):

- `GET /` (Python and pubsub detection) — 200 with `Metadata-Flavor: Google`.
- `instance` and/or `instance/` (Node detection).
- `project/numeric-project-id` (gcloud detection; digits).
- `project/project-id` (gcloud, unless `CLOUDSDK_CORE_PROJECT` is set — then not needed, measured).
- `instance/service-accounts/` (gcloud: account list, text `default/\n<email>/\n`).
- `instance/service-accounts/default/email` (gcloud).
- `instance/service-accounts/default/?recursive=true` and
  `instance/service-accounts/<email>/?recursive=true` (JSON `{aliases,email,scopes}`;
  Python, pubsub, gcloud).
- `instance/service-accounts/default/token` with any `?scopes=` (JSON
  `{"access_token":"proxy-injected","expires_in":N,"token_type":"Bearer"}`).

Tolerated if 404: `universe/universe-domain`, `universe/universe_domain`,
`instance/service-accounts/default/identity`. Serve them anyway: universe must be
`googleapis.com`; identity for ID tokens (below).

Not seen from any client: `service-accounts/?recursive=true` (listed in PLAN.md),
`instance/zone`, `instance/id`, `instance/hostname`.

## Response headers

Python and Node reject a response without `Metadata-Flavor: Google`
(Node: "incorrect Metadata-Flavor header"); gcloud and Go do not check
(`out/noflavor2-*.out`). Every client sends `Metadata-Flavor: Google` on every
`/computeMetadata/` request, so frisket can require it (403 otherwise, like GCE);
only Go's un-overridden `GET /` probe omits it, and that never happens with HOST set.

## Refresh cadence vs expires_in (6 calls, 1 s apart; `logs/refresh-*.log`)

| client | refetches when remaining lifetime is below | expires_in 3599 |
|---|---|---|
| Go | 10 s (ttl 11: every call; 59+: once) | once |
| Python | ~225 s (ttl 226: every call; 299: once) | once |
| Node | 300 s (ttl 301: every call) | once |
| gcloud | per invocation; the token is cached on disk in `access_tokens.db` and reused across invocations only if >~300 s remain (ttl 400/3599: 1 fetch for 4 invocations; 299: 1 per invocation; 200/30: 2 per invocation) | once |

So `expires_in` must exceed 300 s or Node and gcloud fetch per request; 3599 is
what GCE hands out. gcloud writes the placeholder to `$CLOUDSDK_CONFIG/access_tokens.db`.

## ID tokens

The placeholder `proxy-injected` as the identity response: gcloud
print-identity-token and Node `getIdTokenClient` accept it; Python
`fetch_id_token` fails (`MalformedError: Wrong number of segments`, it decodes
`exp`). A JWT-shaped placeholder (header `kid: proxy-injected`, real claims,
signature `proxy-injected`) works for all three (`out/*-id-*.out`). Note an ID
token is sent to the caller's own audience (e.g. `*.run.app`), not a Google API
host, so injecting a real one on the wire is a separate route. Go idtoken untested.

## gcloud GCE detection and its cache

- Probe: `project/numeric-project-id` via `ReadNoProxy` (bypasses HTTP proxies),
  up to 4 attempts, result written to `$CLOUDSDK_CONFIG/gce` (`True`/`False`)
  and trusted for 10 min from the file's mtime.
- Refused or unreachable metadata: gcloud writes `False` in ~0.4 s and reports
  "No credentialed accounts" (`out/refused2-gcloud-min.out`, `out/unreach-gcloud-min.out`).
- A `False` file makes gcloud send zero metadata requests for 10 minutes even
  when the server is up (`out/gcloud-cachefalse.out`, empty log). So metadata
  must be up before the first gcloud run, and the sandbox must not inherit a
  host `CLOUDSDK_CONFIG` whose `gce` says `False`.
- A fresh `True` file skips the probe (`logs/gcloud-seedtrue.log`); an aged one
  reprobes (`logs/gcloud-cacheaged.log`). frisket could seed `True`.

## Failure behaviour when metadata is down (all three variables set)

Refused (port closed): Node fails in 22 ms, Python in 3.0 s (detection retries),
gcloud 0.4 s and caches False, Go reports OnGCE true then fails after ~5 s of
token retries. Unreachable (no route): same except Go fails immediately.
A silently dropping address (timeouts) was not tested.

## deny-* logs

`deny-matrix.sh` 404s one path pattern at a time (re-run: `out/deny-matrix.out`;
`logs/deny-*.log` only hold the last pattern, `/identity`):

```
deny ^/$:                gcloud=ok   python=FAIL go=ok node=ok   pubsub=FAIL tf=ok
deny instance$:          gcloud=ok   python=ok   go=ok node=FAIL pubsub=ok   tf=ok
deny service-accounts/$: gcloud=FAIL python=ok   go=ok node=ok   pubsub=ok   tf=ok
deny recursive=true:     gcloud=FAIL python=FAIL go=ok node=ok   pubsub=FAIL tf=ok
deny /email$:            gcloud=FAIL python=ok   go=ok node=ok   pubsub=ok   tf=ok
deny project-id$:        gcloud=FAIL python=ok   go=ok node=ok   pubsub=ok   tf=ok
deny numeric-project-id: gcloud=FAIL python=ok   go=ok node=ok   pubsub=ok   tf=ok
deny universe:           all ok
deny /identity:          all ok
```

`project-id$` also matched `numeric-project-id`; denying only `/project/project-id`
still fails gcloud storage ls, and passes once `CLOUDSDK_CORE_PROJECT` is set.
Caveat: `common.sh` unsets `GOOGLE_CLOUD_PROJECT`, so the matrix ran without a
project variable.

## Surprises

- No single variable works for everyone; gcloud reads only the legacy `GCE_METADATA_ROOT`.
- Node shells out to gcloud for the project id unless a project variable is set.
- gcloud caches "not on GCE" on disk for 10 minutes.
- gcloud calls `iamcredentials .../allowedLocations` and `config list` calls
  Resource Manager; Terraform calls `openidconnect.googleapis.com/v1/userinfo`
  and `compute.googleapis.com` — all with the placeholder, so each needs a route
  (or is tolerated as 404: all were).
- Terraform uses `universe/universe_domain`, gcloud and Python `universe-domain`.
- Python needs a JWT-shaped ID token.

## Not tested

Real Google; `GCE_METADATA_HOST` with a port; IPv6 (`2001:db8::2`); a
timing-out (dropping) metadata address; Go `idtoken`; Java/.NET/Ruby libraries;
`bq`/`gsutil` (bq bundles oauth2client, which reads `GCE_METADATA_IP` for
detection and `GCE_METADATA_ROOT` for data — source only); Terraform with HOST alone;
`X-Forwarded-For` rejection; scopes other than the defaults.
