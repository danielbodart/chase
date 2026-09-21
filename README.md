<p align="center"><img src="logo.png" alt="chase" width="600"></p>

# chase

Agent policy for [NixOS](https://nixos.org/): which sandbox a checkout gets,
which apps run inside it, and which credential each of those is given.

> A *chase* is the iron frame that locks a page of composed type together, so
> the whole forme can be lifted and printed as one. [flong](https://github.com/danielbodart/flong)
> casts the plate; [frisket](https://github.com/danielbodart/frisket) decides
> what the sheet is allowed to take; chase is what holds the page.

The repository you start an agent in decides its boundary. `host` runs bare;
`trusted` and `strict` run in a flong container whose network and credentials
go through frisket. A credential is never mounted: the container holds a
placeholder, and frisket adds the real one on the wire, where the sandbox
cannot reach it.

chase holds no secrets and names no machine. Who the user is, which
organisations are trusted, and where a credential comes from all arrive as
options — so a project can declare what its agents need by depending on chase,
never on the configuration of the machine it is being worked on.

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

    # Own-org repositories whose first commit is yours are trusted on the
    # heuristic. These are the exceptions, and a slug alone never raises a
    # tier -- the path has to agree.
    trustedOrgs = [ "alice" ];
    trustedAuthorDomains = [ "example.com" ];
    hostPaths = [ "/home/alice" ];
    hostRepos."alice/nix-config" = "/home/alice/Projects/nix-config";

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
running anything.

## Tiers

| | trusted | strict |
|---|---|---|
| For | your own code | someone else's, forks included |
| Network | its own, through pasta; frisket answers DNS | none but frisket |
| Credentials | added on the wire, never in the container | none but the model API's |
| GitHub | push and merge as you | anonymous: clone and fetch, never write |

`host` is the absence of a tier rather than one of them: it runs bare, for
work a container cannot do — real sudo, `/dev/input`, KVM, or the network
namespaces these sessions are made of.

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
per tier: strict gets `user:inference` and nothing else. It never expires, so
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

**GitHub.** A credential bound from outside, as
`chase.bindings.github.credentialFile` — `gh auth token`'s, read by frisket.
Remotes are rewritten from `git@github.com:` to HTTPS, so git goes through
frisket and no key is needed in the session, and the token arrives as Basic
auth's password under `x-access-token`. Strict is anonymous instead: clone,
fetch and GET work with no credential in existence, and a push stops at git's
ref advertisement — refused on the request line rather than by inspecting what
`git` was asked to do, which is not something a session can route around.

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
intercepted. `anonymous` is strict's: public models download, and what would
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
and a path template, in the spec's own words — and the rule for each is simple
enough to state in a line. A read goes straight through; anything else waits
for a person, in a dialog that says what the operation does and shows the real
request line beneath it. What the description does not name asks too, so an
endpoint the provider ships next month is gated from the day it ships.

The line is only where the list starts. `exceptions.json` beside each app says,
operation by operation and with a reason each, where it is wrong: the reads
that are not harmless — the ones that return a secret, or mint a token — ask,
and the few writes that only read are let through. What a client needs that
the description leaves out is written by hand, and may not overlap an
operation the description answers differently. In strict, whatever would ask
is refused.

The description is pinned by hash, and regenerating is a reviewed change —
the diff of `operations.json`, one operation per line, is the list of what is
newly allowed:

```sh
scripts/operations.sh cloudflare
scripts/operations.sh huggingface
```

Cloudflare's is fetched from a commit of its own repository; the Hub's lives
at a URL that moves, so it is vendored. Neither replaces minting the token
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
than quietly becoming a route frisket serves with nothing attached. Evaluation
only — no system is built, which is what keeps it in seconds.

## Licence

MIT. See [LICENSE](LICENSE).
