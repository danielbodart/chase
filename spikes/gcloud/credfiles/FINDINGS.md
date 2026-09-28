# Placeholder credential files — measured (2026-09-28)

Offline, unshare -rnm with hosts bind-mount (+ tmpfs over /run/nscd), fakegoogle.py on 127.0.0.1:443 / 192.0.2.2:{80,443}.
Clients: gcloud 583.0.0 (bundled google-auth 2.56.2), python google-auth 2.50.0, Go x/oauth2 v0.37.0, google.golang.org/api v0.299.0 (cloud.google.com/go/auth v0.24.0), Node google-auth-library 11.1.0.

## Matrix (✅ = placeholders only)
| Variant | gcloud | Python | Go x/oauth2 | Go api/auth | Node |
|---|---|---|---|---|---|
| A authorized_user | ✅ via CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE / auth/credential_file_override; token_uri ignored; `auth login --cred-file` rejects type | ✅ token_uri ignored | ✅ token_uri honoured (HTTP ok) | ✅ ignored | ✅ ignored |
| B gcloud store | ✅ `auth activate-refresh-token ACCT proxy-injected` (cached in access_tokens.db); ✅ CLOUDSDK_AUTH_ACCESS_TOKEN_FILE (no exchange); CLOUDSDK_AUTH_TOKEN_HOST redirects refresh | – | – | – | – |
| C service_account fake key | ✅ exchange, token_uri honoured; self-signed JWT if auth/service_account_use_self_signed_jwt | exchange ✅; GAPIC REST sends self-signed JWT by default (aud=https://host/) | ✅ | self-signed JWT with scope under EnableJwtWithScope (GAPIC default) | exchange ✅ (uri ignored); self-signed JWT with no scopes / useJWTAccessWithScope |
| D external_account | ✅ (+ sts introspect when no impersonation) | ✅ all URLs honoured | ✅ | ✅ | ✅ |
| D' external_account_authorized_user | ✅ override only; token_url honoured; introspect at default STS | ✅ | ✅ | ✅ | ✅ |

## Wire
- A: POST oauth2.googleapis.com/token, form grant_type=refresh_token, client_id, client_secret, refresh_token; no scope; never accounts.google.com. Response needs only access_token. No tokeninfo/userinfo/certs, no id_token signature check.
- C exchange: RS256 JWT (kid=private_key_id, iss=email, aud=token_uri, scope). gcloud also asks for an ID token, tolerates none.
- D: GET subject token URL, STS exchange, optional generateAccessToken ({accessToken, expireTime}).
- Extra calls to route: iamcredentials .../allowedLocations (gcloud, SA/external); cloudresourcemanager v1 projects/<number> (Python/Node external_account).

## Refresh
Margins: Python 3m45s (never refreshes if no expires_in), Go x/oauth2 10s, go/auth 225s background, Node 5m. gcloud: expires_in=200 → twice per command; none → every command; 3599 or 10y → once, cached. Long expires_in = one exchange per process.

## Conclusions
- frisket should answer the exchange itself (forward-and-rewrite would make frisket a refresher, against decision 10).
- Bypass fails closed: nothing real in the sandbox.
- C's self-signed JWTs break decision 13's exact match; frisket would need RS256 verification against the fake public key. Avoid C.
- A+B strongest: one placeholder authorized_user file covers gcloud/Python/Node with no env vars (gcloud needs credential_file_override; Go needs $HOME/.config/gcloud or GOOGLE_APPLICATION_CREDENTIALS). Costs interception of oauth2.googleapis.com.
- D most steerable (token_url etc. can point at http://192.0.2.2), bigger config.
- All variants need every API host intercepted.

## Not tested
Real Google, reauth, forward-and-rewrite; gRPC; Node google-gax defaults; bq/gsutil; re-exchange after 401; application-default login; mTLS; real Go GAPIC client (default read from source).
