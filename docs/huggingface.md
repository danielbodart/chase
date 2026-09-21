# Hugging Face

The second app whose allowlist is generated from the provider's own API
description. Everything in [cloudflare.md](cloudflare.md)'s decisions 1–4 and
7 holds here unchanged: anything not known to be safe asks, the rules come
from the spec and are not guessed, the spec is pinned and bumping it is a
reviewed change, and safe is decided per operation, with a rule and a list of
exceptions. What follows is only where Hugging Face differs.

## The spec

The Hub publishes OpenAPI 3.1 at `https://huggingface.co/.well-known/openapi.json`
— "Hub API Endpoints", 361 operations, each with a summary. Unlike Cloudflare's,
it lives at a URL that moves rather than at a commit: it changed within an hour
of first being fetched. So it is **vendored**, as
`apps/huggingface/openapi.json`, and pinned by hash in `source.json`; the
generator reads the vendored copy, and taking a newer one is replacing that
file, updating the hash, and reading the diff of `operations.json`.

    scripts/operations.sh huggingface

Three things about it that the shared generator handles:

- **No operation ids.** They are derived from the method and the path, in the
  characters an envelope may name one by:
  `GET /api/models/{namespace}/{repo}/xet-write-token/{rev}` is
  `get-api-models-namespace-repo-xet-write-token-rev`.
- **File paths.** A parameter whose schema the spec calls a "Wildcard path
  parameter" is a path in a repository, slashes and all, so its operation is a
  prefix rule, not a template: `/*/*/resolve/*` and everything under it.
- **Operations written twice.** A Collection is addressed by `{slug}` or by
  `{slug}-{id}`, which are one template to frisket. Where the words and the
  answer agree they are one operation, under the first id; where they did
  not, the generator would refuse.

## The exceptions

In `apps/huggingface/exceptions.json`, each with its reason.

**Reads that ask** — the ones that mint a credential rather than describe one:
Xet's write token, five times over (a write reached by a GET: with it, bytes
go into Xet's store with no further request frisket sees), a repository's
JWT, the container registry's token, and webhooks, which carry their jobs'
secrets. What stays allowed was read for: `whoami-v2`'s `accessToken` is
metadata about the token, a Space's secrets are listed without their values,
a service account's token secrets are never returned, and Xet's *read* token
is what every download needs.

**Writes that are harmless** — `paths-info` (a read by POST), `preupload` (says
how a file would be uploaded, and changes nothing: the upload asks at its
commit), `quicksearch` and `oauth/userinfo` by POST.

**What the spec leaves out**, written by hand as `rules`. The spec does not
describe the reads huggingface_hub is built on: repository information
(`/api/models/{namespace}/{repo}`, and at a revision), and listing and search
(`/api/models`) — for models, datasets and Spaces. Without them every
whole-repository download asks. And a repository named without a namespace
(`gpt2`, from before namespaces) is still downloaded at `/gpt2/resolve/...`,
answered directly, and its information at `/api/models/gpt2`, answered with a
redirect. Found by reading huggingface_hub's own URLs against the spec, and
measured.

**A hand-written rule may not decide what the spec already does.** frisket
takes the most specific rule segment by segment, so a rule with a literal
where an operation has a parameter wins wherever both match. The first draft
had `/api/models/*/revision/*`, for a legacy name's revision; it also matched
`/api/models/someone/revision/jwt` — the JWT of a repository named
`revision`, which asks, and which anyone can create (`Nlibert/revision`
exists). The generator now refuses any hand rule that overlaps an operation
with a different answer, and that rule is gone: a whole-repository download by
a legacy name asks, once, for the redirect.

## Strict

Strict has no credential and no asker to speak of: a planted token is the
threat there. So its route is the same rules with every one that would ask
turned into a refusal, and anything unnamed refused — public downloads work,
and nothing that writes or mints a token does. Measured: a planted token asking
for Xet's write token is refused by rule, in the Hub's own error shape, and so
is a POST.

## Hosts

Only `huggingface.co` takes the token. A large file's `resolve/` redirects to
a presigned URL on a CDN under `hf.co`, and Xet's content-addressed store is
under `hf.co` too, with its own short-lived token. So `huggingface.co` and
`*.hf.co` are allowed, and only the first is intercepted.

## Open

- **A revision with a slash** — `refs/pr/1`, which huggingface_hub sends
  encoded as one segment — matches no template, since frisket will not let a
  `*` stand for something that decodes to two segments. So a download at a
  pull request's revision asks, and in strict is refused.
- **What else a client calls.** Found so far by reading huggingface_hub; the
  frisket log is what says whether `datasets`, `transformers` or anything else
  reaches for more. An unmatched request in the log is a gap in the rules.
- **The ids are only as stable as the paths.** A derived id changes when the
  path does, so an exception or a project's allow-list naming one fails
  loudly at the next bump rather than silently matching nothing.
