<p align="center"><img src="logo.png" alt="chase" width="600"></p>

# chase

Agent policy for [NixOS](https://nixos.org/): which sandbox a checkout gets,
which apps run in it, and which credentials they use.

> A *chase* is the iron frame that locks a page of type together.
> [flong](https://github.com/danielbodart/flong) casts the plate,
> [frisket](https://github.com/danielbodart/frisket) masks what the sheet
> takes, and chase holds the page.

You start `claude`, `codex`, `deepsec` or `chase shell` in a checkout.
chase picks the checkout's tier and runs the agent either on the host or in
a flong container whose network goes through frisket. The container holds
placeholders, never credentials: frisket swaps in the real one on each
request.

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
| grant | A project's `chase.json`, signed beside it as `chase.json.sig`: what it asks for beyond its tier. |
| approver | The program that asks you to approve a changed `chase.jsonc`, the grant's old form, read for this release only. A `chase.json` is signed instead, through quoin's signer. |
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
      ssh.agentSocket = "/run/user/1000/gcr/ssh";
    };
  };
}
```

[examples/tiers.nix](examples/tiers.nix) is a fuller set, with the reasoning
for each choice.

## Commands

| Command | Does |
|---|---|
| `claude`, `codex`, `deepsec` | Run the agent in the current directory's tier. |
| `chase shell` | A login shell in that tier's sandbox, as an agent gets it. |
| `chase tier --dry-run DIR…` | Show each directory's tier and why. |
| `chase docker [DIR]` | Show a checkout's project, its address and name, and its approved Docker ports. |
| `chase record [--default allow\|ask\|refuse] [--base tier\|none] [--by-operation] AGENT` | Run the agent in its tier as a recording: what the tier would refuse or ask about is answered, by you or `--default`, and written down; at the end, a report and a proposal of the grant entries it needed, a route's requests by their exact paths or, with `--by-operation`, by the operations they matched. See [docs/record.md](docs/record.md). |
| `chase record apply [--last\|MACHINE]` | Add a recording's proposal to its checkout's `chase.json`, and have it signed. |
| `chase check FILE` | Read FILE as a launch reads a project's `chase.json`, say what is wrong with it, and whether it is signed. |
| `chase fmt [-check] FILE` | Print FILE in its canonical form, the bytes it is signed over; with `-check`, only whether it is. |
| `chase sign [DIR]` | Write what is derived of the checkout into its `chase.json` -- the sops file's digest, its Docker project -- put it in its canonical form, and sign it through quoin's signer, which shows you the change. |
| `chase migrate [DIR]` | Write the checkout's `chase.jsonc` as a `chase.json`, say each comment it cannot keep, remove `chase.jsonc`, and sign the new file. |
| `chase schema` | Print a `chase.json`'s JSON Schema, frisket's own sections included. |
| `chase check -config FILE` | Read FILE as chase reads `/etc/chase/config.json`, and say what is wrong with it. |
| `chase schema -config` | Print that file's JSON Schema. |

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
| `approver` | `null` | The program that approves a `chase.jsonc`, for this release. Null approves none. |
| `placeholder` | `proxy-injected` | What a session holds in place of a credential. |

The module writes these, and what each app adds, to `/etc/chase/config.json`,
which every command, hook and unit reads, or the file given before the command
as `-config FILE`. It is read strictly: an unknown or misspelt key, a second
JSON value or a word an enum does not have is refused, never half obeyed. The
module runs `chase check -config` on the file when the system is built, so a
mistake fails the build rather than a launch; `chase schema -config` prints
the file's JSON Schema.

## Tiers

| `chase.tiers.<name>.…` | Default | |
|---|---|---|
| `match` | `[]` | Rules that put a checkout in this tier. |
| `bare` | `false` | Run on the host, with no sandbox. Takes no other setting but app `trust`. |
| `egress` | — | `direct`: its own network. `frisket`: frisket only. Required for a sandbox. |
| `allow` | `[]` | Names frisket resolves for it, beyond its apps' own. `"*"` for any. |
| `forwardPorts` | `[]` | Ports published on the host, at the [project's address](#project-addresses). `"auto"`: whatever a session listens on. |
| `seccomp` | `{}` | flong's syscall filter, `flong.seccomp`: a call by name in `syscalls`, systemd `@groups` in `allow` and `deny`. `{}` is `strict`. |
| `grants` | `false` | Apply a checkout's grant, once signed. |
| `caches` | `session` | Where tools keep downloads: `session`, `workspace` or `tier`. |
| `writes`, `guarded`, `unmatched` | `ask`, `refuse`, `ask` | The answer for each class, in every app. See [Operations](#operations). |
| `record.enable` | `false` | `chase record` in this tier, which must take grants: a second launcher on its container, every connection through frisket. See [docs/record.md](docs/record.md). |
| `apps.<app>` | | See [Apps](#apps). |
| `frisket`, `flong`, `signer`, `sudo` | `{}` | The tier as a layer: see below. |

A tier is a layer of the same shape as a project's [`chase.json`](#grants):
`frisket`, `flong`, `signer` and `sudo`, each that component's own section,
merged as RFC 7396's merge patch over what the options above and the tier's
apps make (an object merges key by key, `null` deletes, a list replaces).
So a tier can say anything a project can, and what only the host may, such
as a route's `ceiling`; the options above are sugar for the commonest of it.

```nix
chase.tiers.trusted = {
  allow = [ "*" ];                                          # sugar: frisket.allow."**" = true
  apps.git.writes = "allow";                                # sugar: frisket.routes.git.writes
  frisket.routes.github.operations."category:pulls" = "allow";
  frisket.routes.github.ceiling.guarded = "refuse";         # no project may lift it
  flong.seccomp.syscalls.io_uring_setup = "allow";
  flong.limits.MemoryMax = "8G";
};
```

`frisket` is checked by `frisket check` when the system is built and
installed as `/etc/chase/policies/<tier>.json`, the base a project's section
is merged over. `flong` is `flong.chase-<tier>`, typed and checked by flong's
module. `signer` and `sudo` are checked as a `chase.json`'s are and kept at
`/etc/chase/layers/<tier>.json`: neither quoin's signer nor its sudo gate
reads a tier's yet; each reads a project's file, and the gate's host rules
are its own `services.quoin.sudo.exec`.

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
| [deepsec](docs/apps/deepsec.md) | deepsec, through the tier's Claude Code or codex | always | | | |
| [git](docs/apps/git.md) | git, over HTTPS to github.com | ✓ | | | ✓ |
| [github](docs/apps/github.md) | GitHub's API, and gh | ✓ | | | ✓ |
| [cloudflare](docs/apps/cloudflare.md) | wrangler | ✓ | | | ✓ |
| [huggingface](docs/apps/huggingface.md) | `hf` | ✓ | `session` `workspace` `tier` `host` | | ✓ |
| [gcloud](docs/apps/gcloud.md) | gcloud, as a project's service account | grant only | | | ✓ |
| [docker](docs/apps/docker.md) | Docker and Compose, on your rootless daemon | | | | |
| [ssh](docs/apps/ssh.md) | commands on a project's machines, or the tier's own, by SSH through frisket | | | | ✓ |
| [mise](docs/apps/mise.md) | mise toolchains | | `session` `tier` `host` | ✓ | |
| [nix](docs/apps/nix.md) | the checkout's devShell, as `nix develop` would give it, where its grant turns it on: with the host's network where egress is direct and unfiltered; elsewhere, offline | | | | |

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

A project's grant is `chase.json` at its root: strict JSON, read as data and
never run, with a section for each component that reads it, in that
component's own shape. Every section is optional.

```json
{
  "chase": {
    "apps": {
      "cloudflare": {
        "accountId": "023e105f4ecef8ad9ca31a8372d0c353",
        "credential": {"secret": "cloudflare-token"}
      }
    },
    "secrets": "secrets.yaml",
    "secretsSHA256": "…"
  },
  "flong": {"seccomp": {"syscalls": {"io_uring_enter": "allow", "io_uring_setup": "allow"}}},
  "frisket": {
    "routes": {
      "cloudflare": {"operations": {"workers-ai-post-run-model": "allow"}},
      "github": {"operations": {"category:pulls": "allow", "repos/delete": "refuse"}}
    }
  },
  "signer": {"ssh": {"hosts": {"gateway": "allow"}}},
  "version": 2
}
```

| Section | |
|---|---|
| `version` | `2`. A file without it is no `chase.json`. |
| `frisket` | Merged over the tier's policy document, and checked by frisket's own project-layer check ([frisket's docs/policy.md](https://github.com/danielbodart/frisket/blob/trunk/docs/policy.md)). `routes.<app>.operations` answers `allow`, `ask` or `refuse` by operation id, `category:<name>` or `METHOD /path`, and a route's own `writes`, `guarded` and `unmatched` answer the rest. Only cloudflare, gcloud, git, github and huggingface take a project's answers, and only where the tier holds their credential: an answer for any other route, or an anonymous one, is said and left out. `allow` is names beyond the tier's and its apps', for connections no route serves, in frisket's host grammar, `"**.pythonhosted.org": true`, never `**` nor every name below a public suffix. `lan` is hosts on your own network, `"nas.home.arpa": {"ports": [445]}`: each an exact name, reached at the private address its DNS gives, at those ports (every port when none are given), and put on the allowlist with it; not a route's host or a project's name. `ssh.<machine>.exec` answers the tier's own machines by frisket's rule names. A field only the host sets is refused. |
| `flong` | `seccomp.syscalls`, a call by name to `allow`, `deny` or `log`, and `seccomp.allow` and `deny`, lists of systemd `@groups`, checked by `flong check --layer project` against the tier's filter. A grant's `allow` overrides the tier's `seccomp.deny`: the tier is the ready-made fit, the grant the tailored one. |
| `signer` | quoin's signer's `ssh.hosts` and `sshsig`, each `allow` or `ask`, read by the signer itself for what this checkout logs in to and signs. |
| `sudo` | The sudo gate's `exec`, the resolved command's pattern (`/run/current-system/sw/bin/journalctl **`) to `{"runAs": …, "answer": …}`, `allow`, `ask` or `refuse`, read by the gate itself for a sudo run in the checkout and merged over the host's rules; checked by the gate's own reading, quoin's `sudo.CheckExec`, and never deciding a danger ([quoin's docs/sudo.md](https://github.com/danielbodart/quoin/blob/trunk/docs/sudo.md#rules)). |
| `chase` | What no component owns. `secrets` is the checkout's sops file, each `credential.secret` a key in it, and `secretsSHA256` its digest. `apps.<app>` is what an app binds: its credential, Cloudflare's `accountId`, Docker's `project`, `images` and `ports`, and `build`, the repositories and namespaces ending in `/` it builds, which turns BuildKit on and lets any tag of them run ([docs/docker.md](docs/docker.md), decision 16), Google's `serviceAccount` and `apis`, and ssh's machines, whose lists still take the catalogue's ids, `category:<name>` and command patterns, `docker compose ps **` ([docs/apps/ssh.md](docs/apps/ssh.md)). `apps.nix.devShell`, `true`, turns the checkout's devShell on, in any tier with nix: none is evaluated without it, as with `direnv allow`, and it is realised with no network where the tier's egress is not direct and unfiltered ([docs/apps/nix.md](docs/apps/nix.md)). |

`chase schema` prints the whole shape, and `chase check` says what is wrong
with a file before a launch does. `chase record` writes most of a grant for
you: run the agent again under it, do what was refused, and apply the
proposal it leaves ([docs/record.md](docs/record.md)).

A grant applies only in a tier with `grants = true`. An agent can write to its
own checkout, so nothing in a grant applies until you have signed it:
`chase.json.sig` beside it, an SSH signature over the file's exact bytes in
the namespace `quoin-policy:<root>`, by a key `/etc/quoin/allowed_signers`
allows; a git worktree's `<root>` is its repository's, so the signature
committed in a checkout verifies in every worktree of it. A file whose signature verifies launches with nothing asked. One that
does not is put to quoin's signer, which shows you the diff against the
file git's `HEAD` signed and the launch waits; signed, the signature is
written beside the file and the launch goes on; refused, it ends. Where the
tier's `always` is on -- by default in a tier that takes grants and asks
someone -- a session's question on a route a project answers, with a
credential, or on an SSH machine offers Always too: the one rule asked about
is added to `chase.json`, signed, and admits for the rest of the session.
frisket offers it once its own Always is on, which `chase.signer.always =
true` does where the host runs quoin's signer and courier (its
`nixosModules.signer` and `nixosModules.policy`) for chase's user: frisket is
pointed at them, and they at `frisket.service`. Unknown keys
and invalid values are refused before you're asked, and a file not in its
canonical form is refused unsigned. What chase derives of the checkout is in
the signed bytes: the sops file's digest and, for a grant that binds Docker,
the `owner/repo` its `origin` names. A file saying otherwise is refused, so
new ciphertext or a changed `origin` is signed like any other change. `chase
sign` writes both, puts the file in its canonical form and signs it.

A checkout with only a `chase.jsonc`, the grant's old form, JSON with
comments, is still read for this release: approved by `chase.approver` as it
always was, applied as the `chase.json` it migrates to, and told to run
`chase migrate`, which writes that file, says each comment it cannot keep,
removes `chase.jsonc` and signs the new one.

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
- **A worktree is a project of its own**, `<worktree>.<repo>` of the same
  owner, its directory's name made one DNS label: a `claude -w` worktree
  `.claude/worktrees/fix-login` of `example/shop` is
  `fix-login.shop.example.internal`, at its own address, with its own dev
  servers and its own containers and volumes. Its grant, its signature and
  its approval stay the repository's.
- **A session says where it is served** as it starts, once, whether it has
  Docker or only forwards: `chase: serving as shop.example.internal at
  127.101.170.171`. A session that publishes nothing says nothing.
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
