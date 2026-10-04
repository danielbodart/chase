# nix

A checkout's devShell in its sessions, as `nix develop` would give it on the
host: flake.nix's `devShells.<system>.default`, or its shell.nix, flake.nix's
when it has both and git tracks it. The store is in every session already; the environment is
not, since a session starts clean. So the devShell is evaluated -- by the
launcher, as you, before the session starts, or by the session itself, over
a store of its own -- and the session is given its variables and its PATH,
and runs its shellHook.

Where it is evaluated is the tier's `store`. With the host's (`host`, the
default) it is for your own code alone: a tier whose `egress` is `direct`
and whose `allow` is `[ "*" ]`, and never a bare one, whose agent runs on
the host with its own `nix develop`. What is evaluated is the checkout
itself, on the host, and the checkout is what a session writes; nix runs in
a bubblewrap that shows it nothing of the host's but the store, the nix
daemon and the checkout, and its fetches are the host's own, neither
filtered nor logged. For the same reason a `chase record` launch's report
never names what a devShell fetched: that was the host, not the session.

Someone else's code takes a store of the session's own (`session`, below):
the session runs nix itself over it, evaluates its devShell there, ahead of
the agent, and every fetch is the session's, through frisket and on its
allowlist. Nothing of the checkout's Nix is evaluated on the host at all.

| `chase.apps.nix.…` | Default | |
|---|---|---|
| `package` | `config.nix.package` | The host's nix: it realises the devShell, as you, where the store is the host's, and roots what a session's own store looks at where it is the session's. |
| `sessionPackage` | `nixVersions.latest`, patched | The nix a session whose store is its own runs: the container's, on its `PATH`. Its read-only local store reads the host's database as any reader does, not as immutable, which upstream nix does not yet do (below). |
| `nixpkgs` | `pkgs.path` | What `<nixpkgs>` is to a shell.nix: the system's own, so importing it fetches nothing. |
| `timeout` | `1200` | Seconds a realisation may take before it is killed and counts as a failure. |

| `chase.tiers.<name>.apps.nix.…` | Default | |
|---|---|---|
| `enable` | `false` | The checkout's devShell. Not in a bare tier; with the host's store, only where `egress = "direct"` and `allow = [ "*" ]`. |
| `devShell` | `automatic` | `automatic`: whenever the checkout has one. `granted`: only when its approved grant asks (`apps.nix.devShell`), which takes `grants = true` and `store = "session"`. |
| `store` | `host` | `host`: realised by the launcher, as you. `session`: a store of the session's own, where the session evaluates it. |
| `maxBytes` | 8 GiB | Bytes a session's own store may hold before the session is stopped. |
| `maxInodes` | `500000` | Inodes a session's own store may hold before the session is stopped. |
| `maxRoots` | `20000` | Most of the host's paths rooted for one session's store. |
| `promote` | `true` | Whether what a session's store substituted is realised on the host after it, from the host's own caches. |
| `package`, `sessionPackage`, `nixpkgs`, `timeout` | the machine's | |

```nix
chase.tiers.trusted.apps.nix.enable = true;
chase.tiers.strict.apps.nix = { enable = true; devShell = "granted"; store = "session"; };
```

flake.nix, flake.lock and shell.nix are the checkout's, never approved: an
edit to them takes effect at the next launch.

## In the session

Its exported variables are the least of the session's environment: what
flong and the container set are theirs, and every variable chase sets --
the CA bundle frisket's, `HOME`, `TMPDIR`, a store's `CARGO_HOME` -- wins by
name, and the devShell's that lost are named once at launch. nix develop's
own build variables are left out (`HOME`, `TMPDIR`, `NIX_BUILD_TOP`, stdenv's
`SSL_CERT_FILE=/no-cert-file.crt`, `SHELL`, `TERM` and the rest), as are
those that would steer bash (`BASH_ENV`, `ENV`, `IFS`, `EXECIGNORE`, every
`BASH*`…) and those that steer the agent rather than your tools, which are
named: `LD_PRELOAD`, `LD_AUDIT`, `GCONV_PATH`, `NODE_OPTIONS`, `NODE_PATH`,
`NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `SSL_CERT_FILE`,
`SSL_CERT_DIR`, `ANTHROPIC_*`, `CLAUDE_*`, `CODEX_*`, `OPENAI_*`, `BUN_*`
and every `*_PROXY`. `LD_LIBRARY_PATH` is kept, which devShells rely on and
which can as well name a libc of the devShell's: the list keeps a devShell
from steering the agent by mistake, not one written to.

PATH is, in order: `/run/wrappers/bin`; mise's shims, where the tier has
mise, so a toolchain the checkout pins wins and a shim with nothing pinned
falls through; the devShell's; then the rest of the container's.
`XDG_DATA_DIRS` is the devShell's ahead of the container's.

A bash stands in front of the agent where a devShell is given: the
container's, as `chase shell` runs it. It orders PATH, runs the shellHook
when there is one, and execs the agent, which it finds on the container's
PATH before the devShell's is added: a devShell's own `claude` or `bash` is
never what runs. The hook runs in a subshell, with the devShell's functions
and variables, its stdin closed and its output on stderr, so whatever it
does to the bash it runs in -- a function named as a builtin, a readonly
variable, a `cd` -- goes with the subshell. The subshell hands back its
exported variables, as data, and nothing else: of those, the hook's changes
to the devShell's own and anything it added are taken, but none of the
container's or chase's, none that steer the agent, none that steer bash
(`BASH_ENV`, `ENV`, `IFS` and the like) and none of bash's own; what it
unset of the rest is unset, but never one of those. Its functions are never handed on, and
PATH is ordered again, so its own `PATH=$PWD/bin:$PATH` stays behind the
wrappers and the shims. Its status is ignored; an `exit` in it ends the
session, as in `nix develop`, and so does a hook that leaves its subshell
handing back nothing whole, which is said. `$PWD` in the hook is the
checkout, and it has no positional parameters, as under `nix develop`.

## How it is evaluated

As `nix develop` would evaluate it in the checkout, by your nix, as you, in
a bubblewrap of its own. It sees the store, the nix daemon's socket, the
machine's nix configuration (`/etc/nix`) and resolver, and the checkout,
read-only -- for a flake, the whole of the checkout it is in and that
checkout's git, a worktree's repository included -- and nothing else of the
host: not your home, `~/.ssh`, another checkout, or chase's state. Its
network is the host's. None of your environment reaches it: its `HOME` is
chase's own, `~/.local/state/chase/devshell/home`, where nix keeps its
fetcher and evaluation caches for every checkout; its PATH is nix and git
alone. So `~/.config/nix`, its `access-tokens`, `~/.config/nixpkgs` and its
overlays, a `NIXPKGS_ALLOW_UNFREE`, an editor's variables or a terminal's
are not read, and the devShell is the same from wherever it is launched. A
flake's `nixConfig` is never taken.

nix's own restrictions do not hold what it reads: a shell.nix's
`builtins.getFlake`, or a flake's `path:` or `git+file:` input, is any file
nix itself can open. The bubblewrap is what keeps a checkout -- which a
session writes -- from handing the session, or the world-readable store,
a file the session could not read itself.

- **A flake** is the checkout's own path, so nix reads it as `nix develop`
  does: from git, what is tracked, as the work tree has it. A flake.nix git
  does not track is said, as `nix develop` says it, and not evaluated: the
  checkout's shell.nix is taken instead, when it has one. One in a directory
  that is no git checkout is taken as it is. It is evaluated purely, and
  its lock is never written: an input it does not lock is fetched for that
  launch alone.
- **A shell.nix** is evaluated under `restrict-eval`, with `NIX_PATH` the
  system's nixpkgs and the checkout, and `allowed-uris` anything over https,
  in a bubblewrap that shows it the checkout's directory alone. It is told
  `inNixShell`, as nix-shell tells it.

Lazy trees keep the checkout out of the store on Determinate Nix, unless a
derivation refers to it; another nix as `package` warns of the setting and
copies what git tracks in, as its own `nix develop` does.

What the daemon builds for it is built on the host, a fixed-output build on
the host's own network: your own code, where nothing is filtered.

## What fails, and why

A devShell that works with `nix develop` and not here usually reaches for
what the clean evaluation leaves out:

- **unfree packages through the environment** (`NIXPKGS_ALLOW_UNFREE=1`) or
  through `~/.config/nixpkgs/config.nix`, which is silently not read: say
  `config.allowUnfree = true` in the import instead.
- **`--impure` flakes and devenv**, which read the environment or the
  working directory: not here.
- **private inputs**: no ssh agent, `~/.config/nix`, netrc or token of yours
  reaches the evaluation, so a `git+ssh` input, or a private one over
  https, is fetched only with `access-tokens` in the machine's nix
  configuration.
- **a flake or shell.nix that reads a file outside the checkout**, through
  `getFlake` or a `path:` or `git+file:` input: it is not there.
- **a shell.nix that reads a file outside the checkout**, or fetches by
  anything but https: refused by `restrict-eval`.
- **a checkout whose path has a `#` or `?`**, which nix would read as part
  of a flake reference, or, with a shell.nix, a `:` or `=`, which would make
  more of `NIX_PATH`.
- **one larger than a launch carries**: more than 512 KiB of variables,
  functions and hook together, or one of them over 128 KiB.

Each is said at launch, with what nix said, and the session starts without
it. A failure is kept for an hour, so a broken flake does not cost every
launch; an edit to the files it is keyed on (below) is tried at the next
launch, and a fix elsewhere -- an imported `.nix` file, the machine's nix
configuration -- sooner by removing what was kept:

```sh
rm ~/.local/state/chase/checkouts/*/devshell/state.json
```

## Caching and its roots

The realised devShell is cached on flake.nix and flake.lock, or shell.nix,
the system, the nix, the nixpkgs, and every setting the evaluation runs
with. A devShell split over other `.nix` files is realised again only when
one of those changes, as with nix-direnv. A change takes effect at the next
launch: exit and launch again.

Its GC root is a profile in `~/.local/state/chase/checkouts/<key>/devshell`,
never the checkout, the latest generation alone. A checkout that no longer
has either file has it let go of at its next launch, and one that is gone
at any launch that wants a devShell. Two tiers with nix that each launch one
checkout share its root, and each realises it again after the other. To let
go of them all:

```sh
rm -r ~/.local/state/chase/checkouts/*/devshell
```

## A store of the session's own

With `store = "session"` the session runs `nix` itself, single-user, as
you, over a store of its own (flong's PLAN §3): an overlay of the host's
`/nix/store`, its writes kept on disk in
`~/.cache/chase/nix/sessions/<machine>` for this one launch, and a
local-overlay store over it, whose lower is the host's store, read-only,
its database the host's, read live. What the host's store has, the session
has; what the session fetches or builds goes into its upper alone, and the
host's store is never written by it. A path of the host's store cannot be
unlinked in it: flong gives the upper's root the lower's mode and owner.

- **At binds**, before the grant is approved, chase makes the store, for a
  tier whose devShell is `automatic`, or for a checkout whose chase.jsonc
  asks for it as it is then; what it says decides only whether an empty
  store is made, and nothing uses it unless the grant approved after it
  asks too.
- **At exec**, the session's nix is told its store -- `NIX_REMOTE`, its log,
  the container's nix configuration and no user's -- and, where the
  checkout has a devShell, `chase-devshell` runs ahead of the agent. It
  evaluates the devShell with the session's nix, as the launcher does on
  the host -- a flake purely, a shell.nix restricted, nothing of the
  session's environment but what reaches its store and frisket's CA bundle
  -- gives the agent its variables behind the session's own, and execs the
  same bash. A path of the host's store being substituted by the host at
  that moment is waited on, after 1, 3 and 9 s.
- **While it runs**, `chase nix-watch`, in the session's cgroup, roots on
  the host every path of the host's that the session's database holds,
  read by sqlite3, read-only and defensively, each checked valid by the
  host's own daemon, at most `maxRoots` of them, as one indirect root, so the
  host's garbage collection takes nothing from under it; and stops the
  session once its upper is past `maxBytes` or `maxInodes`, saying so.
- **At postStop**, what the upper holds is promoted, where the tier
  promotes, by name alone -- never a derivation or a lock -- as a unit of
  your own: the host's daemon realises each from its own substituters, with
  no build, so nothing the session built, nor anything unsigned, reaches the
  host, and the next session finds the rest in the lower. Then the store is
  removed, its root last. A store a killed launcher left is removed by the
  next launch's binds, and hourly by `chase-nix-sweep.timer`.

The container's nix is `sessionPackage`, set for the local-overlay store and
the read-only one beneath it, with no sandbox -- nix turns it off itself in a
user namespace it cannot nest another in, and the build is the session's own
process, under its own filter -- no build users, a flake's own
configuration never taken, and the machine's caches, signatures required.
Its read-only local store is patched to read the host's database with
`mode=ro`, through its WAL, as any other reader: upstream opens it
immutable, which misses what the WAL holds and fails while the host
checkpoints, so a path the host added during the session could not be
read. Its schema must be the host's.

`caches` does not govern this store: it is always the session's alone, since
one shared would let one checkout plant a path the next one trusts.

The grant turns it on in a tier whose devShell is `granted`:

```jsonc
{ "apps": { "nix": { "devShell": true } } }   // the devShell, and the store
{ "apps": { "nix": { "store": true } } }      // the store alone
```

A devShell the grant asks for that cannot be evaluated ends the session
before its agent starts, with status 125 and the reason said; a recording
is never ended for it. In an `automatic` tier, `"devShell": false` leaves it
out.
