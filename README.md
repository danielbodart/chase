<p align="center"><img src="logo.png" alt="chase" width="600"></p>

# chase

Agent policy for [NixOS](https://nixos.org/): which sandbox a checkout gets,
which apps run inside it, and which credential each of those is given.

> A *chase* is the iron frame that locks a page of composed type together, so
> the whole forme can be lifted and printed as one. [flong](https://github.com/danielbodart/flong)
> casts the plate; [frisket](https://github.com/danielbodart/frisket) decides
> what the sheet is allowed to take; chase is what holds the page.

The repository you start an agent in decides its tier, and the tiers are
yours: which there are, what puts a checkout in each, and what each may do. A
tier runs bare or in a flong container whose network and credentials go
through frisket. A credential is never mounted: the container holds a
placeholder, and frisket adds the real one on the wire, where the sandbox
cannot reach it.

chase holds no secrets, names no machine and ships no tiers. What it carries is
the machinery — the selector and its predicates, the containers, the apps and
what each app's credential looks like. Who the user is, which tiers there are,
what sorts a checkout into each and where a credential comes from all arrive
as options — so a project can declare what its agents need by depending on
chase, never on the configuration of the machine it is being worked on.

The design, what was decided and what was turned down, is in [PLAN.md](PLAN.md).

## Example

```nix
{
  inputs.chase.url = "github:danielbodart/chase";

  # In a NixOS module, with home-manager wired in as a NixOS module too:
  imports = [ inputs.chase.nixosModules.default ];

  chase = {
    user = "alice";
    uid = 1000;
    gid = 100;

    # Asked first to last; the first tier with a rule that holds wins, and
    # whatever none holds for is the fallback's.
    order = [ "host" "strict" "trusted" ];
    fallback = "strict";

    tiers.host = {
      bare = true;
      match = [ { paths = [ "/home/alice" ]; } ];
    };
    tiers.strict = {
      egress = "frisket";
      writes = "refuse"; guarded = "refuse"; unmatched = "refuse";
      apps.claude.state = "isolated";
      apps.git = { enable = true; anonymous = true; };
    };
    tiers.trusted = {
      match = [ { owners = [ "alice" ]; rootAuthorDomains = [ "example.com" ]; } ];
      egress = "direct";
      allow = [ "*" ];
      envelope = true;
      apps.claude = { state = "shared"; connectors = true; };
      apps.git.enable = true;
      apps.github.enable = true;
    };

    # What chase declares and you bind. An app names the package it runs and
    # the credential it needs; it never reaches for one, so the same app
    # serves a machine keeping secrets in sops and a project decrypting its
    # own.
    bindings = {
      claude.package = inputs.claude-code.packages.${system}.default;
      codex.package = inputs.codex-cli.packages.${system}.default;
      github.credentialFile = config.sops.secrets.gh_token.path;
    };
  };
}
```

`claude` and `codex` then go on `alice`'s PATH as wrappers: they sort the
directory you are standing in and either run bare or launch the matching
container. `chase shell` does the same with a login shell instead of an
agent: the session exactly as an agent would get it, credentials as
placeholders and all. `agent-tier --dry-run DIR...` explains a sorting without
running anything:

```
DIRECTORY                  TIER      REASON
alice                      host      path /home/alice
thing                      trusted   owner alice, first commit by alice@example.com
a-fork                     strict    first commit by someone@upstream.org
```

[examples/tiers.nix](examples/tiers.nix) is a fuller set, with the reasoning
behind each choice, and is what chase's own checks evaluate against.

## Tiers

A tier is a name and what it is: a container with a network, a seccomp
filter, the apps it runs and how their writes are answered — or `bare`, no
sandbox at all, for work a container cannot do: real sudo, `/dev/input`, KVM,
or the network namespaces these sessions are made of. Each tier that is not
bare becomes a container, a flong launcher and a frisket policy of the same
name. There can be as many as you like.

### What puts a checkout in a tier

A tier's `match` is a list of rules. A rule holds when every predicate it sets
holds, and a tier matches when any of its rules does:

| Predicate | Holds when |
|---|---|
| `paths` | the directory started in, links resolved, is exactly one of these |
| `checkouts` | `origin` is one of these `"owner/name"`s, and the checkout's root is the path given for it or beneath it |
| `repos` | `origin` is one of these `"owner/name"`s, wherever the checkout is |
| `owners` | `origin`'s owner is one of these |
| `rootAuthorDomains` | every root commit was authored at one of these email domains; never in a shallow clone |

Tiers are asked in `chase.order`, and the first with a rule that holds is the
checkout's. A rule that does not hold decides nothing: the next is asked.
What no rule holds for goes to `chase.fallback`, and so does anything that
goes wrong on the way — the wrapper, when the selector fails, launches the
fallback. The fallback cannot be bare.

**How far each predicate is believed is yours to decide, not chase's.** A path
is the one signal a checkout cannot forge. A remote, an owner and a first
commit's author are all strings anything in the checkout can set. So the
example lets a path alone put a checkout on the host, and lets the forgeable
predicates raise one no further than a sandbox — or lower one: a tier asked
before the others can list a repository by remote alone, and catch every copy
of it that is not where `checkouts` says it lives, rather than letting a copy
fall through to an owner rule.

A launcher checks the selector agrees before it starts a session, so one run
by hand on the wrong checkout refuses; the fallback's takes anything.

## Apps

What a tier switches on. Each declares what it needs and binds nothing itself
— a credential reaches a session on the wire or not at all, and no app here
mounts one.

chase ships the ones any machine running agents would want. Adding one of
your own takes no changes here.

**Claude Code.** frisket reads the host's own `~/.claude/.credentials.json`
and puts its token on each request, taking the expiry from
`claudeAiOauth.expiresAt` so a stale token answers 503 rather than 401 — which
Claude Code retries in the same turn instead of failing it. The container holds
a login shaped like the real one and made of placeholders, with scopes narrowed
per tier: one without `connectors` gets `user:inference` and nothing else. It never expires, so
the session never tries to refresh it, and the refresh endpoint and the Console
are routed only to be refused — no response can hand the sandbox a real token.
Claude Code's own sandbox is turned off, because bubblewrap cannot nest inside
the container that is already the boundary.

**codex.** The token comes from the host's `~/.codex/auth.json`, and the expiry
from the `exp` claim inside the access token itself, since the file records
only when it last refreshed. The placeholder cannot be an ordinary string here:
codex parses its own token as a JWT and refreshes five minutes before the `exp`
it finds, so what the container holds is a real-shaped unsigned JWT that
expires in 2100. Nothing verifies its signature — not codex, which only splits
on the dots, and not frisket, which compares the whole string. Refreshing stays
on the host, because a refresh token is single-use and a session racing the
host would burn it.

**GitHub**, as two apps sharing one credential, bound from outside as
`chase.bindings.github.credentialFile` — `gh auth token`'s, read by frisket.
`github` is the API and gh: its allowlist is generated from GitHub's own REST
description, and GraphQL's, where gh does most of its work, from GitHub's
schema: a query is a read, and each mutation an operation by its field. `git`
is git over HTTPS: remotes are rewritten from `git@github.com:` to HTTPS, so
git goes through frisket and no key is needed in the session, and the token
arrives as Basic auth's password under `x-access-token`. A fetch is a read and
a push a write, so a tier can let git push while gh's writes still ask; a push
asked about is asked about once, showing the refs it would update. A tier can
have both anonymous instead: clone, fetch and GET work with no credential in existence,
and a push stops at git's ref advertisement — refused on the request line
rather than by inspecting what `git` was asked to do, which is not something a
session can route around. See [docs/github.md](docs/github.md).

**Cloudflare.** wrangler, against an allowlist generated from Cloudflare's own
API description: what it calls harmless goes through, and everything else waits
for a person. A tier holds no token of its own by default — a project brings one
scoped to what it owns. See [docs/cloudflare.md](docs/cloudflare.md).

**Hugging Face.** `hf` and huggingface_hub, with a token bound as
`chase.bindings.huggingface.credentialFile` and put on requests to
`huggingface.co` alone. Its allowlist is generated from the Hub's own API
description, as Cloudflare's is: reads go straight through, and writes, the
reads that mint a token, and anything the description does not name wait for a
person. The files themselves come from presigned CDN URLs and Xet's store under
`hf.co`, which take tokens of their own, so they are allowed and never
intercepted. `anonymous` is for a tier running other people's code: public models download, and what would
ask is refused, Xet's write token among it, so a token the session brings of
its own cannot upload either. See [docs/huggingface.md](docs/huggingface.md). `shared` binds the host's download cache in, so a
model is downloaded once — not in a tier that runs other people's code, since
the host loads what is in it.

Anything else is yours. An app is an ordinary NixOS module written against
the options above — it reads `config.chase`, extends `chase.tiers.<tier>.apps`
with its own switch, and adds whatever binds or container configuration it
needs. It does not have to live here to do that, and the ones that are specific
to you should not: a Codex bridge that arrives with your plugins, the toolchain
manager you happen to use, sound for notifications. chase carries the apps any
machine running agents would want, and gets out of the way for the rest.

## Safe by default, from the provider's own description

An app whose credential reaches an API with thousands of endpoints cannot be
made safe by a list someone wrote from memory, or learned from whatever the log
happened to see. Where the provider publishes an OpenAPI description, chase
reads that instead: every operation it describes becomes one rule — a method
and a path template, in the spec's own words — and its class is simple enough
to state in a line: `GET` and `HEAD` are reads, `DELETE` is guarded, and
everything else is a write. A read goes straight through. A write waits for a
person, in a dialog that says what the operation does and shows the real
request line beneath it, and a guarded operation is refused. What the
description does not name asks too, so an endpoint the provider ships next
month is gated from the day it ships.

Those are the defaults. A tier says what each class is answered with for
every app in it — `writes`, `guarded` and `unmatched`, each `allow`, `ask` or
`refuse` — and an app in it may say otherwise for itself:

```nix
chase.tiers.trusted = {
  writes = "ask";                      # the default, for every app
  apps.cloudflare.guarded = "ask";     # this app's deletions are asked about
};
```

A tier with no one to ask on its behalf says `refuse` for all three, and an
anonymous app refuses all three whatever the tier says.

A project names what it wants otherwise in its envelope, per app — by
operation id, by the API's own category, or by method and path for an
endpoint the description does not name — and that decides before the tier
does:

```nix
chaseModules.default = {
  chase.bindings.github.allow = [ "category:pulls" ];
  chase.bindings.github.refuse = [ "repos/delete" ];
  chase.bindings.git.allow = [ "git-receive-pack" ];   # its pushes
};
```

It is part of what is approved, a name in two lists is refused before anyone
is asked, and a name the app does not have fails the launch. Not in a tier
that takes no envelope, nor for an app a tier has anonymously.

The line is only where the list starts. `exceptions.json` beside each app says,
operation by operation and with a reason each, where it is wrong: the reads
that are writes — the ones that return a secret, or mint a token — the few
writes that only read, the deletions easily undone and the writes that cannot
be. What a client needs that the description leaves out is written by hand,
with its class, and may not overlap an operation of another class.

The description is pinned by hash, and regenerating is a reviewed change —
the diff of `operations.json`, one operation per line, is the list of what is
newly allowed:

```sh
nix develop -c scripts/operations.sh cloudflare
nix develop -c scripts/operations.sh huggingface
nix develop -c scripts/operations.sh github
```

Cloudflare's and GitHub's are fetched from a commit of their own repositories;
the Hub's lives at a URL that moves, so it is vendored. Neither replaces minting the token
narrowly: the token's scope is the floor, and the rules only decide which of
the things it can do need a person. See [docs/cloudflare.md](docs/cloudflare.md)
and [docs/huggingface.md](docs/huggingface.md).

## Development

```sh
nix flake check
```

`checks.assertions` instantiates the module in a bare `nixosSystem` with none
of a consumer's configuration around it, so a coupling that creeps back in
fails there rather than on somebody's machine. It also proves the refusals:
a credential that is declared and left unbound must fail at evaluation rather
than quietly becoming a route frisket serves with nothing attached, and a
tier set up so it cannot work — a bare fallback, a rule with no predicate — must
fail the same way. Evaluation only — no system is built, which is what keeps it
in seconds.

`checks.selector` builds `agent-tier` from the example's rules and runs it
against real repositories: a pinned checkout at its path and elsewhere, a
fork, a stranger's, a shallow clone, a directory that is not a repository.

## Licence

MIT. See [LICENSE](LICENSE).
