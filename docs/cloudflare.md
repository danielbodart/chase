# Cloudflare — plan

The first provider-scoped app, and the first thing to put the confirmation gate
in front of a real API. Read [../PLAN.md](../PLAN.md) first: decisions 6, 9
and 14 are the ones this builds on.

## Goal

A test project, then talebrary, deploying to Cloudflare from inside a trusted
session, with:

- a token that exists only for that project, scoped to its account and, where
  it has one, its zone (decision 9);
- frisket adding it on the wire, the session holding the placeholder;
- every request the API knows to be harmless going straight through, and
  everything else — including anything nobody has classified yet — stopping at
  a dialog on the desktop that names the real request line.

## Decisions

**1. Secure by default: anything not known to be safe asks.** The allowlist is
the only way a request passes without a human. A write, a delete, and an
endpoint nobody has looked at are all the same case to the rule: not on the
list, so the default applies, and the default is the prompt. A feature
Cloudflare ships next month is therefore gated from the day it ships, without
anyone having to notice it exists.

**2. The allowlist is derived from Cloudflare's own API description, not
guessed and not learned from logs.** Cloudflare publishes the whole v4 API as
OpenAPI at `github.com/cloudflare/api-schemas` (`openapi.json`). Every
operation there is a method and a path template —
`DELETE /zones/{zone_id}/dns_records/{dns_record_id}` — which is exactly what
frisket matches on. So the classification is generated: enumerate the
operations, mark each safe or not, emit rules. This replaces the earlier plan
in PLAN.md's open question 3 of starting from "everything that is not a read"
and carving from the logs; the logs are now for checking the classification,
not for producing it.

**3. The spec is pinned, and regenerating is a reviewed change.** The
generated rules come from a specific commit of `api-schemas`, vendored or
fetched by hash. A newer spec is not picked up automatically, because that
would let a new endpoint be allowed without a person deciding it — the one
thing decision 1 exists to prevent. Bumping the pin produces a diff of newly
allowed operations, and that diff is what gets read.

**4. Safe is decided per operation, with a rule and a list of exceptions.**
The rule: `GET` and `HEAD` are safe. The exceptions go both ways and are
written down by operation id, with a line each saying why:

- reads that are not harmless — anything returning a secret or a token value
  rather than metadata about one is not safe to let a session fetch unasked;
- writes that are harmless and frequent enough that asking would train the
  human to click through — for example `POST /graphql`, which is Cloudflare's
  analytics *query* endpoint. Keep this list short; a prompt that fires too
  often is worse than none.

**5. The token is the floor, the allowlist is not.** Decision 6's order holds:
the narrowly minted token is what actually keeps talebrary out of everything
else. Zone scope alone is not enough: Workers scripts, KV, D1, R2 and the rest
belong to the *account*, so a token restricted to one zone can still overwrite
every Worker beside it. The unit of isolation is the account — a project that
needs keeping apart from others gets its own (one login can hold several), and
its token is restricted to that account, then to its zone where it has one.
The allowlist and the gate only decide which of the things the token *can* do
need a person. Nothing here is a substitute for minting the token narrowly.

**6. Where it lives.** The generated classification is general — anyone's
Cloudflare token hits the same API — so it ships in chase, as an app beside
Claude Code, codex and GitHub. What a project supplies is only its own: the
token and the zone. The app declares the credential, the project binds it
(decision 3).

**7. The dialog says what the operation does, in the spec's own words.**
Matching a request to an operation is how frisket decides allow or ask, so the
matched operation is already in hand when it asks — and every one of the
3,540 operations in the spec has a `summary`, and all but 19 a
`description`:

```
Delete DNS Record
Permanently removes a DNS record from the zone.

DELETE api.cloudflare.com/client/v4/zones/023e…/dns_records/372e…
```

A sentence you can read under time pressure, above the request line it
describes. Two rules keep it honest:

- **The words come only from the pinned spec, never from the request.** A
  session chooses its method, path, headers and body; it must not be able to
  choose what the dialog says about them. frisket looks the text up by the
  operation it matched, and nothing the workload sent is ever rendered as
  prose.
- **The real request line is always shown, under the description.** If a
  request matched the wrong operation, or none, the path still says what is
  actually being sent. A request that matched nothing says so, rather than
  borrowing the nearest description.

**8. The asker is a callback; zenity is an implementation detail of one
machine.** frisket defines the contract and ships no dialog. chase does not
know about one either. What prompts, and how, belongs to whoever runs the
machine — here, nix-config supplies a zenity asker the way it already supplies
the graphical sudo one.

The contract, deliberately small:

- frisket runs a configured command, as the user it runs as, once per pending
  decision;
- the decision arrives as one JSON document on stdin — method, host, path and
  query, the matched operation's id, summary and description if there was
  one, and which session and policy it came from;
- exit status 0 allows the request, 1 declines it; anything else refuses it
  too, and is logged as the asker failing rather than a person saying no;
- no asker configured means `ask` refuses. A gate with nobody to ask fails
  closed, never open.

JSON on stdin rather than arguments, so the asker needs no parsing of its own
and the document can grow a field without breaking one that ignores it. The
same asker then serves every provider that gets a gate, not just Cloudflare.

**9. One prompt at a time. Nothing cleverer, until the log says so.**
The invariant is that the human never faces a pile of dialogs: while one is
open, every other request that needs asking waits its turn behind it. That is
the whole of the first version.

Two things are deliberately left out, to be added only on evidence:

- **Collapsing identical requests.** A client that retries while a dialog is
  open will queue behind it and be asked about again once it is answered —
  sequential, not spam, but repetitive. If the log shows that happening,
  requests with the same method, URL and body join the pending decision
  instead. The body is what makes that hard, since it has to be read to be
  compared, so it waits until it is needed.
- **A timeout.** Neither frisket nor the asker gives up on its own. A client
  that stops waiting simply sees no response, which from its side is a
  failure — so a slow human already fails closed. If a stuck asker turns out
  to be a real problem, a timeout that refuses is the fix.

## What has to exist first

1. **frisket: `ask`.** A third outcome beside admit and refuse, holding the
   request while the asker (decision 8) decides, then injecting or refusing on
   the answer, one decision at a time (decision 9).
2. **frisket: path templates.** Scopes are matched by segment prefix today.
   Operations need a wildcard *segment* — `/zones/*/dns_records/*` — and an
   exact end, so that a rule for one operation does not also admit everything
   under it. Segment matching is already how prefixes work, so this extends it
   rather than replacing it.
3. **chase: the Cloudflare app**, declaring the route for
   `api.cloudflare.com`, the credential it needs, and the generated rules.
4. **The envelope**, so the token comes from the project rather than the
   machine. This is the larger piece (PLAN.md decisions 10, 11 and the
   required changes to flong and frisket), and it is *not* needed to prove
   1–3.

## Order of work

Prove the gate and the classification before the envelope. For the test
project, bind a token for a **sandbox account** from nix-config directly, and
mark that binding as temporary in a comment. It contradicts decision 9 on
purpose and for a short time: a disposable account's token is not a
"system-level cloud account", and it lets the gate be built and exercised
without waiting on the project-carried credential. When the envelope lands,
that binding goes and the project carries it.

1. A sandbox account, separate from talebrary's, with no zone — the gate only
   needs something to create and delete, and a KV namespace is that with no
   code. An account-owned token with only Workers KV Storage: Edit on that
   account, held in nix-config's sops as `cloudflare-test-token` beside
   `cloudflare-test-account-id`. *Done.*
2. Generate the classification from a pinned `openapi.json`. At the time of
   writing that is 3,540 operations, 1,741 of them `GET` — so roughly half
   pass on the rule alone and half ask. Read the exceptions list before
   writing any code that uses it. *Done:* `scripts/cloudflare-operations.sh`,
   pinned to `api-schemas` 8cb1993, writes `apps/cloudflare/operations.json` —
   1,680 allowed, 1,860 asked — with 61 reads that return a secret in
   `apps/cloudflare/exceptions.json`, and no harmless writes yet.
3. frisket: path templates, then `ask`, then the asker contract.
   nix-config: a zenity asker against that contract. *Done.*
4. chase: the Cloudflare app, wired to the generated rules. *Done:*
   `apps/cloudflare.nix`, binding a token and, optionally, an account id.
5. In a trusted session, `wrangler kv namespace create` then `delete` against
   the sandbox account — each should raise a dialog, the reads around them
   should not. Read frisket's
   log: every request should be either allowed by name or have raised a
   dialog. Anything else is a gap in the classification.
6. Then the envelope, then talebrary.

## Open

- **`POST /graphql` is not in the spec.** Decision 4 names it as the example
  of a harmless write, but the pinned spec does not describe it, so it cannot
  be an exception by operation id: today it matches nothing, and asks. If the
  log shows it firing often enough to matter, it is a hand-written rule beside
  the generated ones — which is the next point, arriving early.

- **Other hosts.** wrangler may talk to more than `api.cloudflare.com` —
  uploads, telemetry, `dash.cloudflare.com` for login. Discover from frisket's
  log in step 5 rather than guessing; login in particular should not be needed
  at all with an API token. *Step 5, KV only:* nothing but
  `api.cloudflare.com` and `registry.npmjs.org`, wrangler's update check. Every
  Cloudflare request matched a named operation; none fell through to
  unmatched. A deploy will say more.
- **Absent from the spec.** A path the pinned spec does not describe is not on
  the allowlist, so it asks. Whether it should instead be refused outright —
  on the grounds that the spec is authoritative and an undescribed path is
  either new or not an API call — is a choice to make once the log shows
  whether any real traffic lands there.
