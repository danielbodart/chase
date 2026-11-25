# Linear

Linear is the first app whose API is GraphQL only. Everything in
[cloudflare.md](cloudflare.md)'s decisions 1–4 and 7 holds here.
[PLAN.md](../PLAN.md)'s decision 18 says what each class is answered with.
This page says only where Linear is different.

## The schema

Linear publishes no OpenAPI description. Its SDK is generated from a GraphQL
schema in [linear/linear](https://github.com/linear/linear), at
`packages/sdk/src/schema.graphql`. `apps/linear/source.json` pins that file
by commit and hash, under `graphql`, and pins nothing else.

    nix develop -c chase-generate operations linear

A pin bump is a reviewed change. Read the diff of `operations.json`.

## Classes

A query is one read, whatever it reads. Each mutation is a write, except:

- A mutation whose last word is `Delete` is guarded. Linear puts the noun
  first and the verb last (`issueDelete`), so the endpoint's `names` in
  `exceptions.json` says `"verb": "last"`.
- `exceptions.json` makes these guarded too, each with its reason:
  - sign-in and sessions (`*UserAccountAuth`, `userRevokeSession`),
  - secrets and tokens that rotate (`*Rotate*`),
  - OAuth applications and webhooks, which send data out of Linear,
  - integrations, which connect a third party to the workspace,
  - the workspace itself (`organization*`), and who has access to what
    (`userChangeRole`, `userSuspend`, `teamMembership*`),
  - bulk imports and email intake addresses.

An archive is a write, not guarded: Linear can restore what is archived.

Subscriptions are in the schema too, and each is a write. Linear sends them
over a WebSocket, which frisket does not intercept, so no request matches
them.

## Categories

The schema has no categories. `"categories": true` in `names` gives each
mutation the first word of its name that is not the verb: `issue` for
`issueCreate` and for `issueLabelCreate`. A grant can then name
`category:issue` or `category:comment`.

## The key

A personal API key goes in `Authorization` with no scheme. The route sets
frisket's `bare = true`, so frisket puts the key there with no `Bearer`. The
session holds the placeholder in `LINEAR_API_KEY`.

Make the key in Linear's settings, under Security & access, Personal API
keys. Give it only the teams and permissions the tier needs. frisket is the
gate, and the key's own scope is a second one.

## Open items

- File uploads. The `fileUpload` mutation returns a signed URL on another
  host, and a client sends the file there. That host is not on any
  allowlist yet. Record a session that attaches a file
  (`chase record`) to find it, and then allow it by name.
- Files that Linear hosts, at `uploads.linear.app`, need the key too. They
  are not routed yet.
