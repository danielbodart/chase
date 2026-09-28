# Artifact Registry docker token: is it a Google credential?

Project danbodart-sandbox-test, SA frisket-spike@, repos in europe-west2 (+ one us-central1), 2026-09-28. All repos deleted afterwards; API left enabled; token files deleted.

## Token dance
- `GET https://europe-west2-docker.pkg.dev/v2/` -> 401, `WWW-Authenticate: Bearer realm="https://europe-west2-docker.pkg.dev/v2/token"` (no service/scope in challenge).
- `GET /v2/token?service=...&scope=repository:P/frisket-spike/x:pull` with Basic `oauth2accesstoken:<ya29 SA token>` -> 200 `{"token", "expires_in": 43200}`.
- Empty scope -> 401 "Unknown Error".

## What the token is
- Not a JWT. One segment, base64url(JSON) ~4.5 KB, prefix `eyJh`.
- Decoded fields: `access_token` (string ~3.27 KB, prefix `AGdT`, opaque), `commands` (`{"P/frisket-spike/x": {"14": true}}`; push,pull with writer gives `{"15": true}`), `product: "artifactregistry"`, `token_id` (number).
- Lifetime: `expires_in` 43200 s = 12 h, vs 1 h for the source ya29 token. (Couldn't test surviving source-token expiry: revoking an impersonated token returns 400.)

## As a Google credential (control: SA ya29 token)
| call | SA token | registry token | inner access_token |
|---|---|---|---|
| oauth2 tokeninfo | 200 | 400 invalid_token | 400 invalid_token |
| GCS list objects (bucket) | 200 | 401 | 401 |
| GCS list buckets (project) | 403 | 401 | 401 |
| iamcredentials generateAccessToken | 403 | 401 | 401 |
| artifactregistry.googleapis.com list repos | 403 | 401 | 401 |

Can't be used against Google APIs. Also can't mint new registry tokens (as Basic password on /v2/token -> 401) and doesn't work as a Basic password on the registry; the inner `access_token` alone as Bearer on the registry -> 401.

## Scope on the registry (SA: writer on frisket-spike, reader on spike2 and spike-us)
Token requested for `frisket-spike/x:pull` only:
| request | status |
|---|---|
| tags/list frisket-spike/x | 200 |
| tags/list frisket-spike/y (other image) | 200 |
| tags/list frisket-spike2/x (other repo) | 200 |
| tags/list us-central1 frisket-spike-us/x (other region host) | 200 |
| POST blobs/uploads on frisket-spike/x (push) | 202 |
| tags/list on repo with no SA grant | 403 downloadArtifacts denied |

The requested scope and the `commands` claim are **not enforced**. The token works as the SA across every image, repo and region, with the SA's full IAM (push included), and IAM is still checked per request.

## Also
- Basic `oauth2accesstoken:<ya29>` sent straight to registry endpoints (no token dance) -> 200. The registry accepts the Google token on every request.
- docker and docker-credential-gcloud are installed but weren't exercised; the curl flow follows the distribution spec that docker uses.

## Implication for frisket
The registry token isn't a Google API credential. It is still a real bearer credential: SA-level Artifact Registry read and write across all regions for 12 h, unbound by scope. frisket must not pass it through to the sandbox. Options: swap the /v2/token response for a placeholder and re-inject the real token on later registry requests, or skip the dance and inject Basic `oauth2accesstoken:<ya29>` on every `*-docker.pkg.dev` request (measured to work).
