# Google Cloud — plan

gcloud and the Google client libraries, from inside a session, as a
project's own service account. Read [../PLAN.md](../PLAN.md) first: decisions
4, 5, 6, 9, 14 and 18 are the ones this builds on, and
[cloudflare.md](cloudflare.md) for how an app's rules are generated.

Everything below marked *measured* was measured on 2026-09-28: offline against
fake Google servers for gcloud 583.0.0, google-auth 2.50.0, Go
`golang.org/x/oauth2` 0.37.0 and `cloud.google.com/go/compute/metadata`
0.10.0, Node google-auth-library 11.1.0, Terraform's google provider 8.4.0 and
Python Pub/Sub over gRPC; then against real Google in `danbodart-sandbox-test`
through a prototype frisket, for gcloud, Python, Go, Node and Terraform over
REST and gRPC.

## Goal

A session in a project that binds a Google credential can run `gcloud storage
cat`, a Python, Go or Node client, Terraform, or a gRPC client, and each acts
as that project's service account, with:

- no Google credential of any kind in the session — not a key Google knows,
  not a refresh token, not an access or ID token, however short-lived;
- the service account's own key only on the host, in the project's sops, and
  later a keyless way for organisations that forbid keys;
- every request classified from Google's own API descriptions, the way
  Cloudflare's are.

## Decisions

**1. No Google credential in a session, ever.** frisket's decision 5 with its
exception closed: a real token handed over once, however short its life, is a
last resort and not the plan. Google cannot revoke a service-account access
token before it expires (measured: tokens kept working after the grant that
minted them was gone), so a token that reaches a session is usable from
anywhere until it dies, and nothing logs or gates what is done with it.

**2. The session holds a service-account key, and the key is fake.** A key
file of the ordinary `service_account` shape, naming the project's service
account, whose private key chase made for the session and Google has never
seen. Every Google client finds it through `GOOGLE_APPLICATION_CREDENTIALS`,
and does one of two things with it (measured):

- **signs an assertion and trades it** at `oauth2.googleapis.com/token`
  (Node's storage library at `www.googleapis.com/oauth2/v4/token`, whatever
  the file says). frisket answers that itself with the placeholder, and the
  placeholder is replaced on every API call. gcloud, Python's storage library,
  Go over REST, Node's storage library and Terraform.
- **signs its own JWT and sends it as the bearer**, for an hour, one per API.
  frisket checks it against the session key's public half and replaces it.
  Python's generated clients by default, Go's and Node's over gRPC, gcloud
  with `auth/service_account_use_self_signed_jwt`.

The session is a service account in a project, because that is what it is:
the file names both. A leaked fake key is worth nothing outside frisket: a
JWT it signs, sent to Google, is refused 401 (measured).

Two others were built and measured and not taken. A GCE metadata server on
frisket's service address, answering the token path with the placeholder,
worked for every client, but needs three variables no one client reads alike
(Go reads only `GCE_METADATA_HOST`, gcloud only `GCE_METADATA_ROOT`, Python
detects on `GCE_METADATA_IP`), and has traps: gcloud believes a failed probe
for ten minutes, and Node sends requests with no credential at all if one
probe path is missing. A placeholder `authorized_user` file works too, but
makes the session a person, and it is not one.

Signed URLs are signed by the fake key, locally, so one is made and then
refused when used (`SignatureDoesNotMatch`, measured). Nothing asks Google to
sign.

**3. The environment is the app's, and only when the app is on.** frisket
answers; chase's `gcloud` app says where. With the app enabled for a session
it:

- writes the fake key file, from a key made for the session, and hands frisket
  its public half in the policy;
- sets `GOOGLE_APPLICATION_CREDENTIALS` to it, and
  `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE` too, since gcloud reads only that.
  (`gcloud auth activate-service-account --key-file` at start instead makes
  `gcloud auth list` name the account, which the override does not; measured,
  and cosmetic.)
- sets the CA for the Google runtimes: `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`
  for gcloud's bundled Python, `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` for gRPC,
  beside the ones the tier already sets;
- gives gcloud a `CLOUDSDK_CONFIG` of the session's own.

No project variable is needed: the key file names it.

**4. The real credential is a project's service account and its key.**
Decision 9 holds: there is no machine-wide Google login, and a person's own
login is never the source, not even to impersonate. Each project that binds
Google has:

- a service account in its own Google Cloud project, with the roles it needs
  and no more — the floor (decision 6);
- a key for it, the JSON Google issues, in the project's sops file (decision
  7), and never anywhere a session can read.

That is the first version: one command to set up, one call to renew, and it
works wherever keys are allowed, which includes Triptease's organisation
(checked: key creation is not restricted there). It is what an organisation
created since May 2024 forbids by default
(`iam.managed.disableServiceAccountKeyCreation`, and key upload beside it),
and a key does not expire unless a policy says so; revoking it is deleting the
key.

**Keyless, later, by federation.** For an organisation that forbids keys, the
project holds a signing key of its own instead, and Google trusts it through a
workload identity pool: an OIDC provider whose JWKS is that key's public half,
uploaded (no public issuer URL), an issuer of our choosing under `.invalid`,
an audience of our own, the attribute condition
`assertion.sub == 'project:<id>'`, and `roles/iam.workloadIdentityUser` on the
service account for exactly that subject. Only the renewer changes; nothing in
a session or in frisket does.

*Measured, for when it is built:* any `https://` issuer is accepted, including
an unresolvable one; RSA-2048, RSA-4096 and EC P-256 upload and P-384 and
Ed25519 do not; a JWKS of two keys works, so a key rotates without a gap; a
changed JWKS takes effect in about 5 seconds. A JWT with the wrong `sub`,
audience or issuer, an expired one, or one signed by another key is each
refused with its own error. The audit log names the service account as the
caller and the pool's subject as the delegator. Revoking is removing the
`workloadIdentityUser` binding (about 90 seconds) or disabling the service
account: disabling or deleting the provider stops new exchanges within a
second, but a federated token already issued kept working, and kept minting
service-account tokens, for as long as it was watched. A deleted pool's name
is held for 30 days, so pools are per project and not churned. The whole flow
is STS then `iamcredentials…:generateAccessToken`, about 225 ms, fifteen lines
of openssl, curl and jq (`spikes/gcloud/wif/renew.sh`).

**5. The renewer is chase's, beside claude-refresh and codex-refresh.**
frisket never refreshes (frisket decision 10). A user service per project
binding:

1. signs a JWT as the service account with its key: `iss` the service
   account's email, `scope` `https://www.googleapis.com/auth/cloud-platform`,
   `aud` `https://oauth2.googleapis.com/token`, `iat`, and `exp` at most an
   hour on;
2. posts it to `oauth2.googleapis.com/token` as a JWT-bearer grant
   (`urn:ietf:params:oauth:grant-type:jwt-bearer`), for an access token of an
   hour — the longest the organisation allows, the extension constraint being
   denied;
3. writes `{access_token, expiry}` with `expiry` in epoch milliseconds, from
   the response's `expires_in` counted from when the request was sent;
4. renews with at least ten minutes left, so a slow renewal never leaves a
   gap: past the file's expiry frisket answers 503, and clients retry that
   quietly for about two minutes (measured).

This is the grant every client in the spikes made against frisket; against
Google, with a real key, it is not yet measured here.

**6. One route for every Google API.** `*.googleapis.com`, carrying the
service account's token. A fixed list of hosts cannot keep up: Discovery alone
names 2,606 regional hosts, in two shapes, `{svc}.{region}.rep.googleapis.com`
and `{region}-{svc}.googleapis.com`. Beside it, `*.mtls.googleapis.com` is
refused outright: those hosts want a client certificate frisket does not have,
and they are aliases the path rules must not be the only thing guarding.

**7. Scope is by path, on every Google host alike.** Aliases are the rule,
not the exception: `iamcredentials.mtls.`, the `.rep.` hosts,
`sts.mtls.`, `www.googleapis.com/oauth2/v4/token` all reached Google with the
real token when only `iamcredentials.` and `sts.` were refused by name, and the
session got a real token back through the first (measured, with the grant that
allowed it removed straight after). So a rule is a method and a path, the same
on every host under the route. Across the whole catalogue that is 40,579
distinct method-and-template pairs, 705 of them shared by more than one API,
and not one with disagreeing classes (measured); the generator refuses to
emit a conflict, as chase already refuses overlapping hand rules.

**8. The rules are generated, as Cloudflare's are.** Decision 18 unchanged:
read, write and guarded, a tier's switch per class, a project's lists by name.

- **Sources.** REST from Google's Discovery documents, pinned at a commit of
  `googleapis/discovery-artifact-manager` (`discoveries/<api>.<ver>.json`,
  528 documents) with a sha256 per file — the live documents are not
  pinnable: six fetches of one API returned two revisions. gRPC from the
  `google.api.http` rules in `googleapis/googleapis`, pinned the same way.
  Neither is complete: 88 hosts have protos and no Discovery document, 126 the
  reverse.
- **gRPC** is `POST /<package>.<Service>/<Method>`, classed as the Discovery
  method its http rule maps to, so `AccessSecretVersion` is whatever
  `secretmanager…versions.access` is. 9,935 of 13,659 RPCs map; the rest are
  classed on their own. Some services have no http rule at all
  (`google.storage.v2.Storage`, Pub/Sub's `StreamingPull`) and are listed by
  hand. Mixins (`google.iam.v1.IAMPolicy`, Locations, Operations) come from
  each service's yaml.
- **Exceptions**, by operation id, each with its reason:
  - *guarded*: everything that returns or mints a credential. Tokens
    (`iamcredentials.*`, `sts.*`, `cloudshell…generateAccessToken`, which
    mints one by GET), keys and secrets (`serviceAccounts.keys.create`,
    `storage.projects.hmacKeys.create`, `apikeys…getKeyString`,
    `secretmanager…versions.access`, `redis…getAuthString`, and about sixty
    more the spike found by method name, response schema and proto field),
    signed URLs, ephemeral database client certificates, and every API's
    batch path — `POST /batch` carried a Secret Manager `access` inside it
    (measured). Also `*.setIamPolicy`, key upload, ACLs, and what writes
    instance metadata (ssh keys, startup scripts).
  - *write*: `container…clusters.get` and `list`, which can carry a legacy
    client key and are what `get-credentials` reads; and the configs whose
    schemas say a secret may come back, until one authenticated call each
    says otherwise.
  - *read*: `testIamPermissions` and `getIamPolicy`, which are POSTs.
- **Unmatched** is the tier's, as for every app: trusted asks, strict refuses.

**9. Which APIs a session carries is a tier's default and a project's
override.** The whole catalogue is about 19,000 rules for the preferred
versions, 7.9 MB, against Cloudflare's 3,543. A tier names the APIs it
carries — trusted with BigQuery, say, because that is what gets used — and a
project adds or removes. A project is never forced to declare anything to get
the tier's default; what it must bring is its credential (decision 4 of
PLAN.md: declared but unbound refuses).

## What frisket needs

Each is a capability, knowing nothing of Google but a host name in a policy;
frisket's PLAN.md has the detail.

1. **Wildcard route hosts.** A route for `*.googleapis.com`, the exact route
   winning over the nearest wildcard, the upstream dialled at the name the
   client asked for. *Prototyped.*
2. **A session key.** A JWT-bearer grant the key signed is answered with the
   placeholder, and a bearer JWT the key signed is the placeholder, checked
   with go-jose. Neither is Google's alone: they are OAuth's JWT-bearer flow.
   *Prototyped.*
3. **`*:verb` path segments.** 6,302 REST templates end in a custom verb, and
   without it `GET …/versions/*` is both `versions.get` and `versions.access`.
4. **Encoded slashes, by opt-in.** A Cloud Storage object name is one
   `%2F`-encoded segment.
5. **Method overrides applied.** Google honours `X-HTTP-Method-Override` and
   `$httpMethod` (measured: an allowed `GET` ran as a `DELETE`); frisket takes
   the method they name, rewrites the request with it, and decides on that.
6. **Asked bodies by their first bytes**, so a streaming RPC can be asked
   about like any other request.

gRPC itself needs nothing: unary and bidirectional calls, trailers and 8 MiB
messages passed through the interceptor unchanged (measured).

## Order of work

1. frisket: 1 to 6.
2. chase: the generator and the pinned sources; read the exceptions before
   anything uses them. *Done:* `scripts/gcloud.sh`, pinned to
   `discovery-artifact-manager` 3d84c9e and `googleapis` bf87786 (359 and
   3,677 files, each hashed), writes `apps/gcloud/apis/<api>.json` for 394
   APIs, 79 of them proto-only, and `apps/gcloud/index.json`, each API's
   versions, hosts, gRPC services and streaming methods: 24,726 rules, 10,379
   read, 10,735 write and 3,612 guarded, 7,599 of them gRPC, 9.7 MB.
   - *Versions:* the preferred one and every stable one, since `iam`'s
     preferred is v2 while service accounts are v1, and `compute` has none
     preferred. A beta only where it is preferred, or named in
     `source.json`'s `versions` with a reason.
   - *Names:* Discovery's own ids, the same in every version. A gRPC method is
     its full name, classed as the strictest Discovery method its http rule
     names; one with no http rule by its name as AIP-131 to 135 give a verb
     (Get and List read, Delete guarded). Mixins are their own, whatever API
     carries them. A category is the API.
   - *The table is one:* a method and template with two classes, or a literal
     of one API more specific than a stricter operation's `*` in another,
     fails the build. So container's `clusters.get`, a write, takes AlloyDB's,
     Redis's, Managed Kafka's and three others' reads at that path with it;
     `sql.instances.get` stays a read, or Spanner's would follow.
   - Storage's object and folder names are one `%2F` segment
     (`encodedSlashes`); an upload's resumable chunks are a `PUT` to its
     upload path; Firebase's `securetoken` is undescribed, but its
     `POST /v1/token` is `sts.token`'s, guarded.
   - `nix flake check` runs the generator on a small API of each kind, and
     every way it refuses.
3. chase: the `gcloud` app — the route, a fake key per session and the
   environment that points at it, the credential shape (a JSON token file with
   an expiry), and the renewer.
4. `danbodart-sandbox-test`, the test project: a key for its service account
   `frisket-spike`, which reads one bucket, in a project's sops, bound from
   there.
5. In a trusted session: `gcloud storage cat`, a Python, Go and Node read, a
   gRPC call, and a write that asks. Read frisket's log: every Google request
   matched a named operation, or was asked about.

## Open

- **Keyless, by federation** (decision 4): the renewer's second mode, for
  organisations that forbid keys. Measured and ready to build; built when a
  project needs it.

- **ID tokens.** Cloud Run and Functions want an ID token for their own
  audience, sent to `*.run.app`, not a Google API. frisket answers a grant for
  one with a placeholder shaped like a JWT, which every client parses
  (measured), but injecting a real one is a route per audience.
- **Artifact Registry.** Its token endpoint returns a registry token that
  lasts twelve hours, acts as the service account on every repository it can
  reach, and ignores the scope asked for (measured). frisket must answer
  `/v2/token` itself with a placeholder and put Basic `oauth2accesstoken:<token>`
  on every `*-docker.pkg.dev` request, which the registry accepts (measured).
- **The unverified writes.** Each schema that says a secret may come back
  needs one authenticated call to move it to read or guarded.
- **gcloud's own noise.** Every gcloud command calls
  `iamcredentials…/allowedLocations`, which is guarded; gcloud tolerates the
  refusal (measured), but the log has a line per command.
- **The host's name service.** With `/run/nscd` visible, a session resolved a
  name outside its allowlist; the connection was still refused. Whether flong
  sessions see it is unmeasured.
