# nix

A checkout's devShell in its sessions, as `nix develop` would give it on the
host: flake.nix's `devShells.<system>.default`, or its shell.nix, flake.nix's
when it has both and git tracks it. The store is in every session already; the environment is
not, since a session starts clean. So the launcher realises the devShell
before the session starts, as you, keeps it rooted in chase's state, gives
the session its variables and its PATH, and runs its shellHook inside the
session. `nix` itself in a session is not this; it is flong's to give.

In every tier it is given only where the checkout's approved grant turns
it on, as `direnv allow` does:

```jsonc
{ "apps": { "nix": { "devShell": true } } }
```

so the tier must take grants. Without it nothing of the checkout's Nix is
evaluated, and a launch costs nothing more; a checkout with a shell.nix, or
a flake.nix that names `devShells`, is told so in a line. With it, a
devShell that cannot be realised refuses the launch, as any part of a grant
that cannot be applied does; to launch without it, set `"devShell": false`
or remove it, and approve that. Never a bare tier, whose agent runs on the
host with its own `nix develop`.

In a tier for your own code -- `egress` `direct` and `allow` `[ "*" ]` --
what is evaluated is the checkout itself, on the host, and the checkout is
what a session writes; nix runs in a bubblewrap that shows it nothing of the
host's but the store, the nix daemon and the checkout, and its fetches are
the host's own, neither filtered nor logged. For the same reason a `chase
record` launch's report never names what a devShell fetched: that was the
host, not the session.

In any other tier -- someone else's code -- it is realised with no network
at all: what it needs substituted from the machine's binary caches, nothing
built but nix's record of its environment ([Other people's
code](#other-peoples-code)).

| `chase.apps.nix.…` | Default | |
|---|---|---|
| `package` | `config.nix.package` | The nix that realises it, as you. |
| `nixpkgs` | `pkgs.path` | What `<nixpkgs>` is to a shell.nix: the system's own, so importing it fetches nothing. |
| `timeout` | `1200` | Seconds a realisation may take before it is killed and counts as a failure. |

| `chase.tiers.<name>.apps.nix.…` | Default | |
|---|---|---|
| `enable` | `false` | The checkout's devShell, where its grant turns it on, so the tier must have `grants = true`: with the host's network where `egress = "direct"` and `allow = [ "*" ]`, and with none in any other. Not in a bare tier. |
| `package`, `nixpkgs`, `timeout` | the machine's | |

```nix
chase.tiers.trusted.apps.nix.enable = true;
```

flake.nix, flake.lock and shell.nix are the checkout's, never approved: the
approval is of the grant that turns the devShell on, and an edit to them
afterwards takes effect at the next launch.

## Other people's code

Where egress is not direct and unfiltered, the devShell the grant turns on
is realised by nix in the same bubblewrap with no network at all, and with a
`HOME` of its own,
`~/.local/state/chase/devshell/offline-home`, so nothing an evaluation of
someone else's code leaves in nix's caches is read by one of yours:

1. The devShell's derivation alone is evaluated: nothing built as it is,
   and no import from derivation. A shell.nix is restricted as below, and
   fetches nothing; a flake's inputs are what the store already has.
2. The derivation is read, and refused if it asks for what a sandboxed
   build is not given: `__noChroot`, `__impure`, or the system features
   `recursive-nix` and `uid-range`.
3. Each of its inputs, as the outputs it takes, is substituted from the
   machine's binary caches, by the daemon, on the host's network, with no
   local build allowed: one in no cache refuses the launch, before anything
   is built.
4. `nix print-dev-env` records its environment, which is the one thing
   built: nix's own derivation of the devShell's attributes, every input
   already there, sandboxed by the daemon.

nix turns substitution off when it finds no network, so every run turns it
back on; what the daemon fetches is named by a derivation's hash, from the
caches the machine trusts, and checked against their keys. What cannot be
realised refuses the launch, as it does online, and is tried again at the
next. So a devShell of `import <nixpkgs> { }` and what the caches hold -- a Tauri app's WebKitGTK and GTK
libraries, a compiler, a database's client -- is given; one that fetches as
it is evaluated is not: a flake whose inputs are not in the store already, a
shell.nix that pins its nixpkgs by `fetchTarball`, any `builtins.fetch*`,
nor one that needs a build of its own, a `runCommand` or a package with
an override. Those wait on a store of the session's own, where the session
evaluates its devShell itself, its fetches through frisket (flong's PLAN
§3).

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
network is the host's, or none, [offline](#other-peoples-code). None of
your environment reaches it: its `HOME` is chase's own,
`~/.local/state/chase/devshell/home`, where nix keeps its fetcher and
evaluation caches for every checkout; its PATH is nix and git alone. So `~/.config/nix`, its `access-tokens`, `~/.config/nixpkgs` and its
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

Each refuses the launch, with what nix said, and how to launch without it:
`"devShell": false` in the grant, approved. A failure is never kept: the
next launch tries again, so a fix -- to the checkout, an imported `.nix`
file, the machine's nix configuration, or a network that was down -- takes
effect then.

## Caching and its roots

The realised devShell is cached on flake.nix and flake.lock, or shell.nix,
the system, the nix, the nixpkgs, and every setting the evaluation runs
with. A devShell split over other `.nix` files is realised again only when
one of those changes, as with nix-direnv. A change takes effect at the next
launch: exit and launch again.

Its GC root is a profile in `~/.local/state/chase/checkouts/<key>/devshell`,
never the checkout, the latest generation alone. A checkout that no longer
has either file, or whose grant no longer turns it on, has it let go of at
its next launch, and one that is gone
at any launch that wants a devShell. Two tiers with nix that each launch one
checkout share its root, and each realises it again after the other. To let
go of them all:

```sh
rm -r ~/.local/state/chase/checkouts/*/devshell
```
