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
as options — so a project can declare what its agents need in a grant of its
own, never in the configuration of the machine it is being worked on.

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
      apps.claude = { enable = true; scope = "workspace"; };
      apps.git.enable = true;            # no credential: reads only
    };
    tiers.trusted = {
      match = [ { owners = [ "alice" ]; rootAuthorDomains = [ "example.com" ]; } ];
      egress = "direct";
      allow = [ "*" ];
      grants = true;
      caches = "tier";                   # downloads kept for every checkout
      apps.claude = { enable = true; scope = "host"; connectors = true; trust = true; };
      apps.git = { enable = true; authenticated = true; };
      apps.github = { enable = true; authenticated = true; };
    };

    # What each app runs and the credential it uses, for every tier that
    # does not say its own. chase names what an app needs and never reaches
    # for it, so the same app serves a machine keeping secrets in sops and a
    # project decrypting its own.
    apps = {
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
placeholders and all. Nothing of chase's runs inside a session: the agent's
argument list, what it adds to the container's environment and the files
seeded into its home — Claude Code's placeholder login among them — are
worked out on the host by flong's `exec` hook, `chase hook exec`, and flong
runs the agent with nothing between. `agent-tier --dry-run DIR...` explains a
sorting without running anything:

```
DIRECTORY                  TIER      REASON
alice                      host      path /home/alice
thing                      trusted   owner alice, first commit by alice@example.com
a-fork                     strict    first commit by someone@upstream.org
```

[examples/tiers.nix](examples/tiers.nix) is a fuller set, with the reasoning
behind each choice, and is what chase's own checks evaluate against.

## A project's grant

A tier is the machine's: which sandbox a checkout gets, and what it may do
there. A **grant** is the project's: what this one repository asks for on top
of its tier — a secret for an app, settings such as the Docker images it
runs, operations it wants let through or refused, a syscall its tests need.
It lives in the checkout as `chase.jsonc`: JSON, with comments and trailing
commas allowed, and nothing in it is ever run.

```jsonc
{
  "secrets": "secrets.yaml",  // sops, encrypted to admin keys
  "apps": {
    "cloudflare": {
      "credential": { "secret": "cloudflare-token" },
      "accountId": "023e105f4ecef8ad9ca31a8372d0c353",
      // Local development makes these too often to ask each time.
      "allow": ["workers-ai-post-run-model"],
    },
  },
  "seccomp": { "allow": ["io_uring_setup", "io_uring_enter"] },
}
```

The checkout belongs to the agent working in it, so an agent could write a
grant that widens its own sandbox. So nothing in it takes effect until a
person has approved it. At launch chase reads the tracked `chase.jsonc` and
refuses anything it does not recognise: a misspelt key, an image in a
spelling frisket would not match, or a port outside the range. When what it
asks for differs from what was last approved for that checkout,
`chase.approver` shows the difference and the launch waits for a yes. A
change to a comment, or to the order the file lists things in, asks nothing.
A new secret ciphertext or a changed origin does ask, because both are part
of what is approved. Only a tier with `grants = true` applies grants; one
for other people's code leaves it off, and the project gets the tier as it
is.

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

Every app is configured the same way. `chase.apps.<app>` is the machine's:
the package it runs and the credential it would use. A tier turns it on with
`chase.tiers.<tier>.apps.<app>.enable`, and may say its own package or
credential there in place of the machine's. An app with a credential uses it
only where the tier says `authenticated = true`; without it, the default, it
reads and nothing more. An app that keeps something says where with `scope`:

| scope | kept |
|---|---|
| `session` (the default) | in the session's home, which is memory, and gone with it |
| `workspace` | on the host, one for each checkout in the tier |
| `tier` | on the host, one for every checkout in the tier |
| `host` | the host's own, bound in |

An app that asks before it trusts a checkout — Claude Code's folder-trust
dialog, codex's, `mise trust` — is told to trust it only where the tier says
`trust = true`: for a tier of checkouts you vouch for, the dialog is
answered at launch. Off, the default, the app asks as it would anywhere. A
bare tier may say it too, and the wrapper then trusts the checkout on the
host before the agent starts.

A tier's `caches` is the same choice for what its tools download — packages,
toolchains, build caches — pointed at by the XDG cache and data homes and
each tool's own variable (npm, yarn, bun, Cargo, rustup, Go, Mix, Hex,
Gradle), under `~/.cache/chase/caches`. Never their settings or state, and
never `host`: what a tool runs from its cache is what an earlier session left
there.

**Claude Code.** frisket reads the host's own `~/.claude/.credentials.json`
and puts its token on each request, taking the expiry from
`claudeAiOauth.expiresAt` so a stale token answers 503 rather than 401 — which
Claude Code retries in the same turn instead of failing it. The container holds
a login shaped like the real one and made of placeholders, with scopes narrowed
per tier: one without `connectors` gets `user:inference` and nothing else. It never expires, so
the session never tries to refresh it, and the refresh endpoint and the Console
are routed only to be refused — no response can hand the sandbox a real token.
Claude Code's own sandbox is turned off, because bubblewrap cannot nest inside
the container that is already the boundary. With `trust`, its folder-trust
dialog is answered for the checkout at launch: in the `~/.claude.json` a
session is seeded with, or, at the `host` scope, in the host's own; without
it, the dialog is raised, and in a session that keeps nothing, at every
launch.

**codex.** The token comes from the host's `~/.codex/auth.json`, and the expiry
from the `exp` claim inside the access token itself, since the file records
only when it last refreshed. The placeholder cannot be an ordinary string here:
codex parses its own token as a JWT and refreshes five minutes before the `exp`
it finds, so what the container holds is a real-shaped unsigned JWT that
expires in 2100. Nothing verifies its signature — not codex, which only splits
on the dots, and not frisket, which compares the whole string. Refreshing stays
on the host, because a refresh token is single-use and a session racing the
host would burn it. With `trust`, codex is told on its command line that the
checkout is trusted, rather than in `config.toml`, which is the host's;
without it, codex asks, once for each home it keeps.

**GitHub**, as two apps sharing one credential, bound from outside as
`chase.apps.github.credentialFile` — `gh auth token`'s, read by frisket, in a
tier where the app is `authenticated`.
`github` is the API and gh: its allowlist is generated from GitHub's own REST
description, and GraphQL's, where gh does most of its work, from GitHub's
schema: a query is a read, and each mutation an operation by its field. `git`
is git over HTTPS: remotes are rewritten from `git@github.com:` to HTTPS, so
git goes through frisket and no key is needed in the session, and the token
arrives as Basic auth's password under `x-access-token`. A fetch is a read and
a push a write, so a tier can let git push while gh's writes still ask; a push
asked about is asked about once, showing the refs it would update. Without
`authenticated`, the default, clone, fetch and GET work with no credential in existence,
and a push stops at git's ref advertisement — refused on the request line
rather than by inspecting what `git` was asked to do, which is not something a
session can route around. See [docs/github.md](docs/github.md).

**Cloudflare.** wrangler, against an allowlist generated from Cloudflare's own
API description: what it calls harmless goes through, and everything else waits
for a person. A tier holds no token of its own by default — a project brings one
scoped to what it owns. See [docs/cloudflare.md](docs/cloudflare.md).

**Hugging Face.** `hf` and huggingface_hub, with a token bound as
`chase.apps.huggingface.credentialFile` and, where the app is
`authenticated`, put on requests to
`huggingface.co` alone. Its allowlist is generated from the Hub's own API
description, as Cloudflare's is: reads go straight through, and writes, the
reads that mint a token, and anything the description does not name wait for a
person. The files themselves come from presigned CDN URLs and Xet's store under
`hf.co`, which take tokens of their own, so they are allowed and never
intercepted. Without `authenticated`, the default, and the way for a tier running other people's code: public models download, and what would
ask is refused, Xet's write token among it, so a token the session brings of
its own cannot upload either. See [docs/huggingface.md](docs/huggingface.md). Its downloads are kept as the tier's
`caches` are, or at the `scope` it says; `host` binds the host's download cache in, so a
model is downloaded once — not in a tier that runs other people's code, since
the host loads what is in it.

**mise.** The toolchains a checkout's own `mise.toml` asks for, with their
shims on a session's PATH and the user's `~/.config/mise` bound read-only.
Its installs and downloads are kept as the tier's `caches` are, or at the
`scope` it says: `session` overlays the host's, readable; `tier` keeps a set
of the tier's own; `host` shares the host's. Its state — what `mise trust`
has trusted — is never kept: the host's is readable in every session, and
what a session trusts goes with it. With `trust`, the checkout is trusted
without asking, by naming it in `MISE_TRUSTED_CONFIG_PATHS` at launch, so
its config's env and hooks run and nothing is written to mise's records;
without it, a config the host has not trusted asks, as it would on the
host.

**Google Cloud.** gcloud and Google's client libraries, as a project's own
service account: the project binds its key in its grant, and the session
gets a key file of the same shape whose key Google has never seen. frisket
answers what it signs with the placeholder and puts the real token, which
chase renews, on every `*.googleapis.com` request. A tier names the APIs it
carries (`apps.gcloud.apis`), a project adds or removes, and each request is
answered by an allowlist generated from Google's own descriptions. Only in a
tier that takes grants. See [docs/gcloud.md](docs/gcloud.md).

**Docker.** The Docker CLI and Compose, against `chase.user`'s rootless
daemon, for a project whose tests start their services with Compose. A tier
turns it on with `chase.tiers.<tier>.apps.docker.enable`, and only a tier
that takes grants and whose egress is direct may: a container reaches
whatever the host does. The project names what it runs, in its grant:

```jsonc
{
  "apps": {
    "docker": {
      "images": ["postgres:18"],  // exactly as `docker pull` shortens it, with a tag or digest
      "ports": [64320],           // the host ports its containers publish
    },
  },
}
```

The project is its checkout's GitHub origin, `owner/repo`, read by chase from
the checkout's `.git` and never from anything the grant says, approved with
the grant and held to the tiers' pinned `checkouts`. frisket admits only
operations chase lists, and only on what is that project's own: containers,
volumes and networks it labelled when they were made, the images named, and no
bind mount, privilege or host namespace. Everything else is refused; nothing
asks. Each project has its own loopback address, a hash of its name
(`example/shop` is `127.101.170.171`), and its ports are published there: a
Compose file's `'64320:5432'`, which would bind every address, is bound to
that one. A session reaches them as `localhost`, through frisket's relay, and
by the project's names, `<repo>.internal` and `<repo>.<owner>.internal`
(`shop.internal`), which frisket answers for that session alone. On the
host, a name is only reliable where the machine's `/etc/hosts` gives it; any
other `.internal` name is asked of the upstream resolver, which a hostile
network can answer, so use the address. A machine that writes those entries derives them from
chase's `lib.docker`, and says which it wrote in
`/etc/chase/docker-hosts.json`, which is what chase reads before it calls a
name a host name. `chase docker [DIR]` prints a checkout's project, address,
names and approved ports, and says which names this host has.

chase runs no daemon: the machine runs rootless `dockerd` for `chase.user`,
with its socket at `/run/user/<uid>/docker.sock`, as NixOS's
`virtualisation.docker.rootless` does. See [docs/docker.md](docs/docker.md).

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
app that is not `authenticated` refuses all three whatever the tier says.

A project names what it wants otherwise in its grant, per app — by
operation id, by the API's own category, or by method and path for an
endpoint the description does not name — and that decides before the tier
does:

```jsonc
{
  "apps": {
    "github": { "allow": ["category:pulls"], "refuse": ["repos/delete"] },
    "git": { "allow": ["git-receive-pack"] },  // its pushes
  },
}
```

It is part of what is approved, a name in two lists is refused before anyone
is asked, and a name the app does not have fails the launch. Not in a tier
that takes no grant, nor for an app a tier has without `authenticated`.

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
nix develop -c chase-generate operations cloudflare
nix develop -c chase-generate operations huggingface
nix develop -c chase-generate operations github
nix develop -c chase-generate gcloud
```

Cloudflare's and GitHub's are fetched from a commit of their own repositories;
the Hub's lives at a URL that moves, so it is vendored. Google Cloud's are
generated per API, from its Discovery documents and its protos, each pinned
file by file. None of them replaces minting the token
narrowly: the token's scope is the floor, and the rules only decide which of
the things it can do need a person. See [docs/cloudflare.md](docs/cloudflare.md),
[docs/huggingface.md](docs/huggingface.md) and [docs/gcloud.md](docs/gcloud.md).

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

The selector's tests (internal/selector, internal/checkout) build real
repositories and sort them: a pinned checkout at its path and elsewhere, a
fork, a stranger's, a shallow clone, a directory that is not a repository,
and every layout a session could write to steer one. `checks.module-config`
holds the configuration the module writes to one the binary loads.

## Licence

MIT. See [LICENSE](LICENSE).
