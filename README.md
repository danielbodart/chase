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
container. `agent-tier --dry-run DIR...` explains a sorting without running
anything.

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

chase ships the three that any machine running agents would want. Adding one of
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

**GitHub.** The one credential bound from outside, as
`chase.bindings.github.credentialFile` — `gh auth token`'s, read by frisket.
Remotes are rewritten from `git@github.com:` to HTTPS, so git goes through
frisket and no key is needed in the session, and the token arrives as Basic
auth's password under `x-access-token`. Strict is anonymous instead: clone,
fetch and GET work with no credential in existence, and a push stops at git's
ref advertisement — refused on the request line rather than by inspecting what
`git` was asked to do, which is not something a session can route around.

Anything else is yours. An app is an ordinary NixOS module written against
the options above — it reads `config.chase`, extends `chase.tiers.<tier>.apps`
with its own switch, and adds whatever binds or container configuration it
needs. It does not have to live here to do that, and the ones that are specific
to you should not: a Codex bridge that arrives with your plugins, the toolchain
manager you happen to use, sound for notifications. chase carries the apps any
machine running agents would want, and gets out of the way for the rest.

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
