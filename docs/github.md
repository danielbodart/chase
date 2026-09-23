# GitHub

The third app whose allowlist is generated from the provider's own API
description. Everything in [cloudflare.md](cloudflare.md)'s decisions 1–4 and
7 holds here unchanged, and [PLAN.md](../PLAN.md)'s decision 18 says what each
class is answered with. What follows is only where GitHub differs.

## Two apps, one credential

GitHub is spoken to in two protocols, and they are two apps:

- **`github`** is the API at `api.github.com`, REST and GraphQL, and gh,
  which speaks it.
- **`git`** is git's smart HTTP at `github.com`, and what github.com serves
  beside it: release downloads, archives, Git LFS.

Both put `chase.bindings.github.credentialFile` on the wire, and each has its
own `writes`, `guarded` and `unmatched`. So a tier can let git push while gh's
writes ask:

```nix
chase.tiers.trusted.apps.git.writes = "allow";
```

There is no `push` switch: frisket's git rule admits `git-receive-pack`
because git's writes are allowed, asks about it because they are asked about,
and refuses it otherwise. Asked about, the ref advertisement is let through —
it says no more than a fetch's — and the push itself is put to the asker once,
as the operation `git-receive-pack`, with the start of its body, which is the
refs it would update. A push asked about is held to the asker's 16 MiB.

## The spec

GitHub publishes OpenAPI 3.0 at
[github/rest-api-description](https://github.com/github/rest-api-description),
one file per API version, and it is pinned by commit, as Cloudflare's is, in
`apps/github/source.json`.

    scripts/operations.sh github

**Which version.** gh sends `X-GitHub-Api-Version: 2022-11-28`, and the
pinned file is `2026-03-10`. They describe the same 1221 operations, with the
same methods, paths, ids, summaries, parameters and categories; the newer one
only removes deprecated fields from responses, which frisket never reads. So
the classification is the same for either, and is done once, against the
newest. A version that adds or removes an operation shows in the diff of
`operations.json` when the pin is bumped.

What the generator takes from it:

- **Operation ids** are GitHub's own: `repos/get-content`, `git/delete-ref`.
- **Categories** are `x-github.category`: `repos`, `pulls`, `issues`,
  `actions`. A project can name one as `category:pulls`.
- **Slashes in a parameter.** GitHub marks a path parameter that holds
  slashes `x-multi-segment` — a file's path, a ref, a branch. As the last
  segment it is the rest of the path, and its operation a prefix:
  `GET /repos/*/*/contents` and everything under it. Anywhere else it is one
  segment, so a branch with a slash in `/branches/{branch}/protection` matches
  nothing and is answered as `unmatched` says.

## The exceptions

In `apps/github/exceptions.json`, each with its reason.

**Reads that are writes**: the secret-scanning alerts, each of which carries
the leaked secret itself.

**Writes that are reads**: Markdown rendering and the bulk attestation
listings, which are reads by POST.

**What the spec leaves out**, written by hand as `rules`: GraphQL. Every
query and every mutation is `POST /graphql`, and which it is is in the body,
where frisket does not yet look. Until it does, the whole endpoint is a write,
and gh — which does most of its work over GraphQL, reads included — asks for
nearly everything where writes ask. A tier that wants gh usable meanwhile
allows github's writes, and says so.

## Hosts

`api.github.com` is `github`'s, and `github.com` is `git`'s; each is
intercepted by its own app. Archives come from `codeload.github.com`, and raw
files, release assets and LFS objects from `*.githubusercontent.com`, under
presigned URLs or none: allowed, and never intercepted.

## Open

- **GraphQL by mutation.** The schema is published
  (`docs.github.com/public/fpt/schema.docs.graphql`); each mutation field
  would be an operation, and a query a read. frisket has to read the body to
  know which.
- **A push by the refs it updates.** The ref updates open the push's body in
  plain pkt-lines, so a push to the default branch, or one that deletes a ref,
  could be guarded while other pushes are writes. A force push cannot be seen
  there.
- **LFS by direction.** The batch API's body says `download` or `upload`;
  until frisket reads it, both are writes.
- **gh has no description.** What a gh command sends is what
  `GH_DEBUG=api`, or frisket's log, shows. An unmatched request in the log is
  a gap in the rules.
