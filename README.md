<p align="center"><img src="logo.png" alt="chase" width="600"></p>

# chase

Agent policy for [NixOS](https://nixos.org/): which sandbox a checkout gets,
which apps run in it, and which credentials they use.

> A *chase* is the iron frame that locks a page of type together.
> [flong](https://github.com/danielbodart/flong) casts the plate,
> [frisket](https://github.com/danielbodart/frisket) masks what the sheet
> takes, and chase holds the page.

You start `claude`, `codex` or `chase shell` in a checkout. chase picks the
checkout's tier and runs the agent either on the host or in a flong container
whose network goes through frisket. The container holds placeholders, never
credentials: frisket swaps in the real one on each request.

chase ships no tiers and holds no secrets. The tiers, and where each
credential comes from, are your configuration; what a project needs on top is
its grant. The design and its decisions are in [PLAN.md](PLAN.md).

## Terms

| Term | Meaning |
|---|---|
| checkout | A git repository on disk. chase sorts checkouts into tiers. |
| tier | What a checkout gets: a sandbox, or `bare`. Defined in `chase.tiers`. |
| bare | Runs on the host, with no sandbox. |
| sandbox | A flong container with frisket as its network. One per tier. |
| session | One run of an agent or shell in a sandbox. |
| workspace | The checkout's root, mounted read-write into a session. |
| app | A tool a tier turns on: `claude`, `git`, `docker`… |
| placeholder | What a session holds instead of a credential. |
| operation | One endpoint of an app's API, classed as a read, a write or guarded. |
| answer | What frisket does with a request: `allow`, `ask` or `refuse`. |
| grant | A project's `chase.jsonc`: what it asks for beyond its tier. |
| approver | The program that asks you to approve a changed grant. |
| scope | Where an app keeps its state: `session`, `workspace`, `tier` or `host`. |

## Example

```nix
{
  imports = [ inputs.chase.nixosModules.default ];  # home-manager required

  chase = {
    user = "alice";
    uid = 1000;
    gid = 100;

    order = [ "host" "strict" "trusted" ];  # first tier whose rule holds wins
    fallback = "strict";                    # when none does

    tiers.host = {
      bare = true;
      match = [ { paths = [ "/home/alice" ]; } ];
    };

    tiers.strict = {
      egress = "frisket";
      writes = "refuse"; guarded = "refuse"; unmatched = "refuse";
      apps.claude = { enable = true; scope = "workspace"; };
      apps.git.enable = true;
    };

    tiers.trusted = {
      match = [ { owners = [ "alice" ]; rootAuthorDomains = [ "example.com" ]; } ];
      egress = "direct";
      allow = [ "*" ];
      grants = true;
      caches = "tier";
      apps.claude = { enable = true; scope = "host"; trust = true; };
      apps.git = { enable = true; authenticated = true; };
      apps.github = { enable = true; authenticated = true; };
    };

    # Each app's package and credential, for every tier that doesn't set its own.
    apps = {
      claude.package = inputs.claude-code.packages.${system}.default;
      codex.package = inputs.codex-cli.packages.${system}.default;
      github.credentialFile = config.sops.secrets.gh_token.path;
    };
  };
}
```

[examples/tiers.nix](examples/tiers.nix) is a fuller set, with the reasoning
for each choice.

## Commands

| Command | Does |
|---|---|
| `claude`, `codex` | Run the agent in the current directory's tier. |
| `chase shell` | A login shell in that tier's sandbox, as an agent gets it. |
| `chase tier --dry-run DIR…` | Show each directory's tier and why. |
| `chase docker [DIR]` | Show a checkout's project, its address and name, and its approved Docker ports. |
| `chase record [--default allow\|ask\|refuse] [--base tier\|none] AGENT` | Run the agent in its tier as a recording: what the tier would refuse or ask about is answered, by you or `--default`, and written down; at the end, a report and a proposal of the grant entries it needed. See [docs/record.md](docs/record.md). |
| `chase record apply [--last\|MACHINE]` | Add a recording's proposal to its checkout's `chase.jsonc`. |

```
$ chase tier --dry-run ~ ~/Projects/thing ~/Projects/a-fork
DIRECTORY                  TIER      REASON
alice                      host      path /home/alice
thing                      trusted   owner alice, first commit by alice@example.com
a-fork                     strict    first commit by someone@upstream.org
```

## Settings

| `chase.…` | Default | |
|---|---|---|
| `user`, `uid`, `gid` | | The account agents run as, with the same ids inside a sandbox. |
| `home` | `/home/<user>` | The same path inside a sandbox. |
| `order` | `[]` | Tiers to ask, first to last. |
| `fallback` | | The tier for a checkout no rule matches, or one that can't be sorted. Not bare. |
| `tiers.<name>` | | See [Tiers](#tiers). |
| `apps.<app>` | | Each app's package and credential. See [Apps](#apps). |
| `workspaceGroups` | `[]` | Checkouts mounted beside each other, read-write. |
| `approver` | `null` | The program that approves grants. Null approves none. |
| `placeholder` | `proxy-injected` | What a session holds in place of a credential. |

## Tiers

| `chase.tiers.<name>.…` | Default | |
|---|---|---|
| `match` | `[]` | Rules that put a checkout in this tier. |
| `bare` | `false` | Run on the host, with no sandbox. Takes no other setting but app `trust`. |
| `egress` | — | `direct`: its own network. `frisket`: frisket only. Required for a sandbox. |
| `allow` | `[]` | Names frisket resolves for it, beyond its apps' own. `"*"` for any. |
| `forwardPorts` | `[]` | Ports published on the host, at the [project's address](#project-addresses). `"auto"`: whatever a session listens on. |
| `seccomp` | `{}` | flong's syscall filter. `{}` is `strict`. |
| `grants` | `false` | Apply a checkout's grant, once approved. |
| `caches` | `session` | Where tools keep downloads: `session`, `workspace` or `tier`. |
| `writes`, `guarded`, `unmatched` | `ask`, `refuse`, `ask` | The answer for each class, in every app. See [Operations](#operations). |
| `record.enable` | `false` | `chase record` in this tier, which must take grants: a second launcher on its container, every connection through frisket. See [docs/record.md](docs/record.md). |
| `apps.<app>` | | See [Apps](#apps). |

### Rules

A rule holds when every predicate it sets holds. A tier matches when any of
its rules holds.

| Predicate | Holds when |
|---|---|
| `paths` | the directory is exactly one of these |
| `checkouts` | `origin` is one of these `owner/name`s and the checkout is at its path |
| `repos` | `origin` is one of these `owner/name`s, anywhere |
| `owners` | `origin`'s owner is one of these |
| `rootAuthorDomains` | every root commit was authored at one of these domains |

Only `paths` can't be forged: a checkout can set its own remote and commit
authors. So let a path alone put a checkout on the host, and let the other
predicates raise it no further than a sandbox. A tier asked first can use
`repos` to catch a copy of a repository that isn't where `checkouts` says it
lives.

## Apps

| App | Runs | `authenticated` | `scope` | `trust` | Operations |
|---|---|---|---|---|---|
| [claude](docs/apps/claude.md) | Claude Code | always | `session` `workspace` `host` | ✓ | |
| [codex](docs/apps/codex.md) | codex | always | `session` `workspace` `tier` `host` | ✓ | |
| [git](docs/apps/git.md) | git, over HTTPS to github.com | ✓ | | | ✓ |
| [github](docs/apps/github.md) | GitHub's API, and gh | ✓ | | | ✓ |
| [cloudflare](docs/apps/cloudflare.md) | wrangler | ✓ | | | ✓ |
| [huggingface](docs/apps/huggingface.md) | `hf` | ✓ | `session` `workspace` `tier` `host` | | ✓ |
| [gcloud](docs/apps/gcloud.md) | gcloud, as a project's service account | grant only | | | ✓ |
| [docker](docs/apps/docker.md) | Docker and Compose, on your rootless daemon | | | | |
| [ssh](docs/apps/ssh.md) | commands on a project's machines, or the tier's own, by SSH through frisket | | | | ✓ |
| [mise](docs/apps/mise.md) | mise toolchains | | `session` `tier` `host` | ✓ | |

Every app takes the same settings, where they apply:

| `chase.tiers.<name>.apps.<app>.…` | Default | |
|---|---|---|
| `enable` | `false` | Turn the app on in this tier. |
| `authenticated` | `false` | Use the tier's credential. |
| `scope` | `session` | Where the app keeps its state. |
| `trust` | `false` | Trust each checkout without the app asking. |
| `writes`, `guarded`, `unmatched` | the tier's | This app's answers. |
| `package`, `credentialFile`, … | `chase.apps.<app>.…` | This tier's own, in place of the machine's. |

| `scope` | State is kept |
|---|---|
| `session` | in the session, and lost when it ends |
| `workspace` | on the host, one for each workspace in the tier |
| `tier` | on the host, one for the whole tier |
| `host` | in the host's own directories, shared |

`caches` takes the same values for the tier's tools' downloads (npm, pnpm,
yarn, bun, pip, uv, Cargo, rustup, Go, Mix, Hex, Gradle and anything else
that follows XDG), kept under `~/.cache/chase/caches`. Settings and state are
never kept.

An app of your own is a NixOS module that adds an option under
`chase.tiers.<name>.apps` and reads `config.chase`. It doesn't need to live
here.

## Operations

Where a provider publishes an API description, every operation in it becomes
a rule, and each is answered by its class:

| Class | Operations | Default answer |
|---|---|---|
| read | `GET`, `HEAD` | allow |
| write | everything else | `writes`: ask |
| guarded | `DELETE`, and what can't be undone or widens access | `guarded`: refuse |
| unmatched | a request no operation matches | `unmatched`: ask |

`ask` puts the operation and its request line to you, through frisket's
asker. git, github and huggingface without `authenticated` refuse everything
but reads.

```nix
chase.tiers.trusted = {
  writes = "ask";                     # every app in the tier
  apps.cloudflare.guarded = "ask";    # this app only
};
```

`apps/<app>/exceptions.json` corrects the description where it is wrong: a
read that returns a secret is a write, and so on. Each description is pinned;
regenerating is a reviewed change, and the diff of `operations.json` is what
is newly allowed:

```sh
nix develop -c chase-generate operations cloudflare   # or huggingface, github
nix develop -c chase-generate gcloud
```

## Grants

A project's grant is `chase.jsonc` at its root: JSON with comments, read as
data and never run.

```jsonc
{
  "secrets": "secrets.yaml",   // sops file in the checkout
  "apps": {
    "cloudflare": {
      "credential": { "secret": "cloudflare-token" },
      "accountId": "023e105f4ecef8ad9ca31a8372d0c353",
      "allow": ["workers-ai-post-run-model"],
    },
    "github": { "allow": ["category:pulls"], "refuse": ["repos/delete"] },
  },
  "seccomp": { "allow": ["io_uring_setup", "io_uring_enter"] },
}
```

| Key | |
|---|---|
| `secrets` | The checkout's sops file. Each `credential.secret` is a key in it. |
| `apps.<app>` | The app's credential, its other settings, and `allow`, `ask` and `refuse` lists of operation ids or `category:<name>`. ssh's lists are each host's, and take command patterns too, `docker compose ps **` ([docs/apps/ssh.md](docs/apps/ssh.md)). |
| `network` | Names to `allow` beyond the tier's and its apps', for connections no route serves: exact, or `*.suffix` below a public suffix (never `*.com`). And `lan`, hosts on your own network, `{"name": "nas.home.arpa", "ports": [445]}`: each an exact name, reached at the private address its DNS gives, at those ports (every port when none are given), and put on the allowlist with it. Not a route's host or a project's name. |
| `seccomp` | Syscalls to `allow` or `deny` beyond the tier's filter. A grant's `allow` overrides the tier's `seccomp.deny`: the tier is the ready-made fit, the grant the tailored one. |

`chase record` writes most of a grant for you: run the agent again under it,
do what was refused, and apply the proposal it leaves
([docs/record.md](docs/record.md)).

A grant applies only in a tier with `grants = true`. An agent can write to its
own checkout, so nothing in a grant applies until you approve it: when it
differs from the one last approved, `chase.approver` shows you the diff and
the launch waits. Unknown keys and invalid values are refused before you're
asked. A change to comments or order isn't a difference; a changed secrets
file or `origin` is.

## Project addresses

Every checkout with a GitHub `origin` is a project, `owner/repo`, and has
an address of its own on the host's loopback, so one project's servers
never meet another's on the same port:

- **The name** is `<repo>.<owner>.internal`: `example/shop` is
  `shop.example.internal`.
- **The address** is `127.b1.b2.b3`, from the SHA-256 of `owner/repo`:
  `example/shop` is `127.101.170.171`. The same on every machine, with
  nothing to hand out or register.
- **Dev servers** are published there. In a tier that takes grants and has
  its own network, `forwardPorts` binds at the project's address rather
  than `127.0.0.1`, so a dev server on 3000 in one project is not
  another's 3000. A tier with `egress = "frisket"` has no network of its
  own, so nothing is forwarded.
- **Docker** publishes there too: the [docker](docs/apps/docker.md) app's
  containers bind their ports at the project's address, and a session
  reaches them as `localhost`.
- **`chase docker [DIR]`** shows a checkout's project, address and name,
  in any tier.

The project is read from the checkout's `origin`, never from anything in
it a session could write, and a checkout a tier pins is held to its path.
The name and address are frisket's feature, and chase calls frisket's own
functions for them: frisket's host DNS answers every project's name, with
no list to keep, and a session with Docker has its own project's answered
by the session's DNS. See frisket's
[Project addresses](https://github.com/danielbodart/frisket#project-addresses).

## Development

```sh
nix flake check
```

`checks.assertions` evaluates the module with nothing of a consumer's around
it, and checks that every invalid configuration is refused. The selector's
tests sort real repositories: forks, shallow clones, and every layout a
session could write to steer one.

## Licence

MIT. See [LICENSE](LICENSE).
