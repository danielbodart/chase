# Classifying Google APIs for one `*.googleapis.com` route — spike findings

Everything below was measured on 2026-09-28 against public, unauthenticated
endpoints and public repos. No Google credential was used. Files are in this
directory; `gen/` is the prototype.

## 1. Source: Discovery

- Directory: 535 API-versions (315 `preferred`); 530 docs fetched (5 dead:
  area120tables, datalabeling, integrations, mybusinessqanda, poly).
  28,629 methods; 15,914 distinct method ids (ids are version-free:
  `secretmanager.projects.secrets.versions.access` is the same id in v1,
  v1beta1, v1beta2).
- Every method has `httpMethod` and `path`. `flatPath` is missing on 165
  (storage 87, calendar 38, identitytoolkit 20, …): exactly the ones whose
  `path` has no `{+var}`, so `path` is already flat there. Methods:
  GET 11,676 · POST 11,035 · DELETE 3,166 · PATCH 2,353 · PUT 399.
- Hosts: `rootUrl` is always `https://<x>.googleapis.com/` (305 distinct);
  16 differ from the API name (`www.googleapis.com` for calendar, drive,
  oauth2, identitytoolkit v3, groupssettings, siteVerification;
  `translation.` for translate; …). `servicePath` + `flatPath` is the request
  path. 128 API-versions list regional `endpoints` in two shapes,
  `{svc}.{region}.rep.googleapis.com` and `{region}-{svc}.googleapis.com`:
  2,606 distinct hosts in total, 2,208 of them `.rep.`. `mtlsRootUrl` is
  `{svc}.mtls.googleapis.com` (missing on 7) — a client-certificate endpoint
  frisket cannot terminate.
- Versions: v1 240, v1beta1 53, v2 46, v1beta 35, v1alpha 27, … and now dated
  ones (`compute:2026-09-01`, `compute:2026-10-01-preview`, `compute:stable`).
- Undescribed but real: GCS's XML API (`storage.googleapis.com/{bucket}/{obj}`
  and `{bucket}.storage.googleapis.com/{obj}`, both 206 on a public object);
  the JSON API is also served at `www.googleapis.com/storage/v1/...` (200).
- **Pinning.** The live docs are not pinnable: six fetches of secretmanager v1
  returned revision 20260731 eight times and 20260922 four times.
  `googleapis/discovery-artifact-manager` (`discoveries/<api>.<ver>.json`,
  528 docs, automated commit daily, e.g. `3d84c9e7aa` 2026-09-28) is the
  git-pinnable source: pin the commit, sha256 each file in source.json, fetch
  from `raw.githubusercontent.com/.../<commit>/discoveries/...` — the
  Cloudflare pattern. (`google-api-go-client` carries the same docs as
  `<api>/<ver>/<api>-api.json`.) Its revisions differ from live in both
  directions, so a pin is a snapshot of Google's own snapshot, not of prod.

## 2. gRPC

- `googleapis/googleapis` (depth-1 clone 116 MB), 1,587 protos with services,
  compiled with nixpkgs `protobuf` 34.1: 13,659 RPCs in 1,884 services on 268
  default hosts; 13,507 carry `google.api.http`.
- Mapping RPC → Discovery method by (host, verb, normalised template) matches
  9,935; 3,572 do not (mostly APIs with no Discovery doc — googleads 670,
  admanager 321, visionai 155, generativelanguage 144 — or versions Discovery
  lacks). 152 RPCs have no http rule, notably **all 24 of
  `google.storage.v2.Storage`** and Pub/Sub's `StreamingPull`.
- Coverage: 88 proto hosts have no Discovery doc (memorystore, bigquerystorage,
  bigtable, chronicle, generativelanguage, iamconnectorcredentials, …); 126
  Discovery hosts have no protos (Workspace, Firebase, Android, Ads, dns,
  healthcare, apigee, deploymentmanager, …). Neither source is complete: use
  Discovery for REST, protos for gRPC, and protos' http rules for REST of the
  88 proto-only hosts.
- **What actually serves gRPC** (empty gRPC frame, unauthenticated): pubsub,
  secretmanager, storage (v2), iamcredentials, run, and regional
  `secretmanager.us-central1.rep.` / `us-central1-run.` answer `grpc-status`
  (16/7/3); `compute.googleapis.com/google.cloud.compute.v1.Instances/Get` is
  HTTP 404. `BUILD.bazel` says so mechanically: `transport = "rest"` with no
  grpc transport (compute, bigquery v2, gkeconnect gateway, memorystore,
  apihub, oracledatabase, admanager, admob, ftp). A gRPC path sent to the
  wrong host is HTTP 404 (secretmanager's RPC at pubsub), and a mixin a host
  does not register is `grpc-status 12` (`/google.iam.v1.IAMPolicy/GetIamPolicy`
  at secretmanager). gRPC paths are host-bound in practice.
- **One classification covers both**: a gRPC rule is an exact `POST
  /pkg.Service/Method`, classed as the Discovery method its http rule maps to
  (`AccessSecretVersion` → forbidden because `…versions.access` is). Only
  unmapped RPCs need their own entry. Mixins (IAMPolicy, Locations,
  Operations) come from the service yaml's `apis:` list.
- **Streaming**: 79 client/bidi-streaming RPCs in the protos (39 in the
  generated set). frisket reads an asked body whole (≤16 MiB) before asking,
  so a bidi RPC can never be asked — it must be allow or refuse
  (`StreamingPull`, `BidiWriteObject`, `BidiReadObject`).

## 3. Classes and exceptions

Default: GET/HEAD read, DELETE guarded, else write, exactly as chase. Whole
catalogue under the default plus the spike's exceptions: REST 29,280 rules
(read 12,608 · write 12,312 · guarded 3,804 · forbidden 556, which is mostly
one batch rule per API-version); preferred versions only: 13,551 REST +
5,488 gRPC.

Pattern exceptions (by method-name leaf, expanded to ids so the diff is read):
`setIamPolicy` → guarded (594 POST + 3 PUT); `testIamPermissions` POST → read
(812); `getIamPolicy` POST → read (110). ~790 more POSTs are named like reads
(search/lookup/query/validate/…) and were not reviewed.

**The LOCK does not fit chase's three classes**: `guarded` and `write` are
tier-switchable (`allow`/`ask`/`refuse`) and nameable in a project's `allow`
list. A fourth class, `forbidden` — refused whatever the tier or project says,
never asked — is what the spike emits.

Found mechanically by: method-name scan (313 hits), Discovery response-schema
walk (credential-shaped field names, minus pagination/refs/documented
redaction: 1,110 methods, 487 GETs in 75 APIs), and a proto walk honouring
`google.api.field_behavior = INPUT_ONLY` and LRO `operation_info` results (746
RPCs). All three are candidate generators: Google reuses one message for
request and response, so `password` in `sql.users.get` and the
`importContext` echo in every `sql.*` Operation are not proof of a leak. Raw
lists: `name_candidates.txt`, `get_candidates.txt`, `refined.json`,
`protoscan.json`.

### Candidate list (ids version-free; applies to every version carrying it)

**forbidden — returns or mints a usable credential**

| What | Why |
|---|---|
| host `iamcredentials.googleapis.com` | generateAccessToken, generateIdToken, signJwt, signBlob |
| host `sts.googleapis.com` | token exchange |
| host `oauth2.googleapis.com` | `/token`; frisket answers it itself |
| host `securetoken.googleapis.com` | Firebase refresh → ID token |
| every API's `batchPath` (`POST /batch`, `/batch/<api>/<ver>`) | **measured**: `POST secretmanager.googleapis.com/batch` routes an inner `GET …/versions/latest:access` (inner 401); storage batch runs an inner list (200). A tunnel for any operation |
| GET `secretmanager.projects[.locations].secrets.versions.access` | the payload |
| GET `parametermanager.projects.locations.{parameters,templates}.versions.render` | renders secret references |
| GET `apikeys.projects.locations.keys.getKeyString` | the key |
| GET `redis.projects.locations.instances.getAuthString`; memorystore `GetAuthToken`/`ListAuthTokens` (proto-only) | AUTH string / token |
| GET `vmwareengine.….privateClouds.showNsxCredentials`, `showVcenterCredentials` | admin passwords |
| GET `threatintelligence.projects.alerts.getPassword` | "decrypted password" |
| GET `recaptchaenterprise.projects.keys.retrieveLegacySecretKey` | secret key |
| GET `domains.….registrations.retrieveAuthorizationCode`; POST `resetAuthorizationCode` | domain transfer code |
| GET `cloudshell.users.environments.generateAccessToken` | access token by GET |
| GET `networkmanagement.….generateProviderAccessToken` | access token by GET |
| GET `discoveryengine.….dataConnector.getConnectorSecret`; POST `acquireAccessToken` | connector secret / token |
| GET `edgecontainer.….clusters.generateAccessToken`, `generateOfflineCredential` | token / client key |
| GET `gkemulticloud.….generateAwsAccessToken`, `generateAzureAccessToken`; POST `generate*ClusterAgentToken` | tokens |
| GET/list `iap.projects.brands.identityAwareProxyClients.*`; POST `create`, `resetSecret` | `secret`, "Output only" |
| `iam.projects.locations.oauthClients.credentials.{create,get,list,patch}` | `clientSecret`, "Output only" |
| GET `apigee.organizations.{developers,appgroups}.apps.keys.get` ("including the key and secret value"); POST `keys.create`, `generateKeyPairOrUpdateDeveloperAppStatus` | consumer secret |
| POST `iam.projects.serviceAccounts.keys.create` | `privateKeyData` |
| POST `iam.projects.serviceAccounts.signBlob`, `signJwt` (deprecated v1) | signatures as the SA |
| POST `storage.projects.hmacKeys.create` | HMAC secret |
| POST `sql.sslCerts.insert` | `certPrivateKey` |
| POST `firestore.projects.databases.userCreds.create`, `resetPassword` | `securePassword` (get/list say they omit it) |
| POST `managedidentities.….domains.resetAdminPassword` | password |
| POST `iam.locations.workforcePools.providers.scimTenants.tokens.create` | SCIM token (only on create) |
| POST `oslogin.….signSshPublicKey` (3 ids) | SSH certificate |
| POST `cloudbuild.….repositories.accessReadToken`, `accessReadWriteToken` | Git provider tokens |
| POST `developerconnect.….fetchReadToken`, `fetchReadWriteToken`, `users.fetchAccessToken` | Git provider tokens |
| POST `connectors.….connections.refreshAccessToken`, `exchangeAuthCode` | OAuth tokens |
| POST `backupdr.….dataSources.fetchAccessToken`; `workstations.….generateAccessToken`; `notebooks.….generateAccessToken`; `aiplatform.….notebookRuntimes.generateAccessToken`, `notebookExecutionJobs.generateAccessToken`, `featureViews.generateFetchAccessToken`; `ces.….sessions.generateChatToken` | tokens |
| POST `firebaseappcheck.*` exchange*/`mintAppCheckToken`/`debugTokens.create`; `identitytoolkit` signIn*/signUp/`verifyPassword`/`verifyCustomToken`/`createSessionCookie`/`mfaSignIn.finalize` | Firebase/Identity Platform tokens |
| POST `publicca.….externalAccountKeys.create` | ACME EAB MAC key |
| POST `config.….deployments.exportState`, `revisions.exportState` | signed URL to Terraform state |

**forbidden or write — the human's call (see open questions)**

- Ephemeral client certs for a key the sandbox holds: `sql.connect.generateEphemeral`,
  `sql.sslCerts.createEphemeral`, `alloydb.….generateClientCertificate`. Cloud SQL /
  AlloyDB connectors need them.
- Signed URLs: GET `gkebackup.….getBackupIndexDownloadUrl`,
  `contactcenterinsights.….generateSignedAudio`, `apigee.….queries.getResulturl`,
  `migrationcenter` import/export job get/list; POST
  `cloudfunctions.….generateUploadUrl` / `generateDownloadUrl` (gcloud's deploy path).

**write (ask) — schema says a secret may come back; unverified without a credential**

`container.projects.{locations,zones}.clusters.get/list` (`masterAuth.clientKey`,
`password`, legacy; also what `get-credentials` reads) · `sql.users.get/list`
(`password`), `sql.instances.get/list` (`onPremisesConfiguration.password`,
replica `clientKey`) · `compute.vpnTunnels.get/list/aggregatedList`
(`sharedSecret`, believed masked) · `iam.locations.workforcePools.providers.get`
(`clientSecret`) · `apigee.organizations.{developers,appgroups}.apps.get/list`
(credentials[]) · `connectgateway.….generateCredentials` (kubeconfig) ·
`cloudkms.….exportTrustedKeyWrappedCryptoKeyVersion` · the long tail of
connection/profile configs (datastream, datamigration, netapp AD,
monitoring uptime checks, websecurityscanner, oracledatabase, dialogflow
webhooks/tools, ces tools, chronicle feeds, apihub plugins, alloydb
`initialUser`). One authenticated call each settles them.

**guarded — widens access**

`*.setIamPolicy`; `iam.projects.serviceAccounts.keys.upload`, `enable`,
`keys.enable`, `undelete`; storage `{bucket,defaultObject,object}AccessControls.
{insert,patch,update}`, `buckets.lockRetentionPolicy`, `folders.deleteRecursive`;
`compute.instances.setMetadata`, `compute.projects.setCommonInstanceMetadata`
(ssh-keys, startup scripts), `compute.instances.setServiceAccount`;
`oslogin.users.importSshPublicKey`; `secretmanager.….versions.destroy`.

**read — writes that are reads**: the patterns above,
`pubsub.projects.schemas.validate`, `validateMessage`.

**Kept read, flagged**: `compute.instances.getSerialPortOutput` (gcloud's
reset-windows-password reads the new password from it after a `setMetadata`,
which asks); `pubsub.….subscriptions.get` (`oidcToken` is config);
`run.*`/`cloudfunctions.*` `secret` fields are Secret Manager references, but
Cloud Run and Functions return plain `env[].value` — user data no method
classification can see, as with any GCS object.

## 4. Scale, and what the wildcard needs from frisket

Measured problems, each a frisket change:

1. **Method override — an allowed GET can run a DELETE.** On ESF-fronted APIs,
   `GET …/schemas/s:deleteRevision` is 404 but with
   `X-HTTP-Method-Override: DELETE` it is 403 (routed as DELETE); the same with
   `HEAD`, with `?$httpMethod=DELETE` and `?%24httpMethod=POST`, and GET→POST at
   `secretmanager …:addVersion` (404 → 401). GCS's JSON API honours the header
   (GET `…/compose` 404 → 400 as POST) but not the parameter. The header value
   is case-sensitive (`delete` → 404). frisket must refuse requests carrying
   these, or decide on the effective method.
2. **`*:verb` segments.** 6,302 REST rules end in a custom verb. With only whole-
   segment `*`, 1,851 templates merge operations and 358 merge different classes
   — e.g. `GET /v1/projects/*/secrets/*/versions/*` is both `versions.get`
   (read) and `versions.access` (forbidden). frisket needs a segment `*:verb`
   (literal suffix, more specific than `*`). Google matches the verb
   case-sensitively and does not take `%3A` as the separator for POSTs
   (`s%3AaddVersion` 404); frisket's lenient reading is already the safe side.
3. **Encoded slashes.** GCS object names are one `%2F`-encoded segment; frisket
   refuses to let `*` match that, so every nested object read would be
   unmatched (asked). Needs an opt-in per rule or route.
4. **A wildcard route.** frisket refuses a wildcard route host today (the
   parallel spike's `wildcard_spike_test.go` is working on it). Per-host rule
   sets mean 2,606 hosts; the alternative, one host-agnostic path table, had
   **no conflicts**: 40,579 distinct method+template pairs, 705 shared by more
   than one API, 0 with disagreeing classes, and 0 forbidden rules that a less
   strict rule of another API would out-specify. The generator should enforce
   that as an invariant (as chase already refuses overlapping hand rules). Host
   conditions are still needed for the forbidden hosts' unmatched paths
   (`oauth2.…/token` is not in any Discovery doc), which an exact-host route
   beside the wildcard would give.
5. **Batch** (above), **streaming** (§2), **mTLS hosts** (refuse).

Sizes: target set (storage, iam, iamcredentials, secretmanager, compute, run
v1+v2, pubsub) is 1,477 REST + 169 gRPC rules, 636 KB with descriptions;
compute alone is 1,019 rules / 393 KB. The preferred catalogue is ~19k rules /
7.9 MB; all versions ~38k / ~16 MB — Cloudflare's operations.json is 3,543 /
1.2 MB. A policy document per session at that size argues for selecting APIs
per tier or project, not shipping the catalogue.

## 5. Prototype

`gen/gen.py DISCO_DIR PROTOS_JSON EXCEPTIONS_JSON OUT_DIR api:ver…` — stdlib
Python; protos are read into `protos.json` by `protos.py`, which needs
`python3.withPackages (p: [p.protobuf])` and nixpkgs `protobuf` for `protoc`.
Emits chase's rule shape (`methods`, `path`, `operation{id, summary,
description, class, category, reason}`) plus `grpc`, `streaming`, `media`, and
per-API `hosts`/`mtls`. Media upload (`/upload/…`, `/resumable/upload/…`) and
download (`/download/…`) paths are emitted with their method's id. It halts on
two classes at one method+template, and reports exceptions that name nothing
(`compute.projects.setDefaultServiceAccount` was caught that way).

| API | hosts | REST (read/write/guarded/forbidden) | gRPC |
|---|---|---|---|
| storage v1 | 46 | 91 (33/33/23/2) | 29, 3 streaming, all by hand |
| iam v1 | 1 | 137 (52/52/25/8) | 31 (3 forbidden) |
| iamcredentials v1 | 1 | 8 (all forbidden) | 4 (all forbidden) |
| secretmanager v1 | 51 | 37 (14/14/6/3) | 19 (AccessSecretVersion forbidden) |
| compute v1 | 44 | 1,019 (446/438/134/1) | 0 (REST only) |
| run v2 / v1 | 97 | 61 / 77 | 48 / 0 |
| pubsub v1 | 47 | 47 (21/16/9/1) | 38 (StreamingPull streaming) |

## Open questions

1. A fourth class, `forbidden`, not switchable by tier nor nameable by a project
   — or is refusing via `guarded` plus a rule that projects cannot name enough?
2. Ephemeral DB client certs (Cloud SQL/AlloyDB connectors) and signed URLs
   (Functions deploy uses `generateUploadUrl`): forbidden per the LOCK, or ask?
3. `container.clusters.get` may carry a legacy client key; `get-credentials` needs
   it. Ask, forbidden, or have frisket strip response fields (a new capability)?
4. frisket: refuse method-override headers/params everywhere, or only on the
   Google route? (Cloudflare and GitHub untested.)
5. frisket: per-host rules, or one host-agnostic table with the generator
   proving no cross-API conflict?
6. Streaming RPCs: allow or refuse (they cannot be asked)?
7. Which APIs a tier carries: the whole catalogue (~16 MB) or a chosen list?
8. Pin: `discovery-artifact-manager` + `googleapis/googleapis` commits, both
   sha256'd per file — agreed?
9. The unverified "write" list needs one authenticated call per API against a
   disposable project to move each item to read or forbidden.
