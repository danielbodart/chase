# nix

A checkout's devShell in its sessions, as `nix develop` would give it on the
host: flake.nix's `devShells.<system>.default`, or its shell.nix, flake.nix's
when it has both. The store is in every session already; the environment is
not, since a session starts clean. So the launcher realises the devShell
before the session starts, as you, keeps it rooted in chase's state, gives
the session its variables and its PATH, and runs its shellHook inside the
session. `nix` itself in a session is not this; it is flong's to give.

It is for your own code alone: a tier whose `egress` is `direct`, and never a
bare one, whose agent runs on the host with its own `nix develop`. What is
evaluated is the checkout itself, on the host, with nothing to confine it
but nix's own settings, and the checkout is what a session writes.
Someone else's code waits on a store of the session's own, where the session
evaluates its devShell itself, its fetches through frisket (flong's PLAN
§3); until then, a tier of other egress is refused with nix enabled.

| `chase.apps.nix.…` | Default | |
|---|---|---|
| `package` | `config.nix.package` | The nix that realises it, as you. |
| `nixpkgs` | `pkgs.path` | What `<nixpkgs>` is to a shell.nix: the system's own, so importing it fetches nothing. |
| `timeout` | `1200` | Seconds a realisation may take before it is killed and counts as a failure. |

| `chase.tiers.<name>.apps.nix.…` | Default | |
|---|---|---|
| `enable` | `false` | The checkout's devShell, whenever it has one. Only where `egress = "direct"`, and not in a bare tier. |
| `package`, `nixpkgs`, `timeout` | the machine's | |

```nix
chase.tiers.trusted.apps.nix.enable = true;
```

flake.nix, flake.lock and shell.nix are the checkout's, never approved: an
edit to them takes effect at the next launch.

## In the session

Its exported variables are the least of the session's environment: what
flong and the container set are theirs, and every variable chase sets --
the CA bundle frisket's, `HOME`, `TMPDIR`, a store's `CARGO_HOME` -- wins by
name, and the devShell's that lost are named once at launch. nix develop's
own build variables are left out (`HOME`, `TMPDIR`, `NIX_BUILD_TOP`, stdenv's
`SSL_CERT_FILE=/no-cert-file.crt` and the rest), as are those that would
steer bash (`BASH_ENV`, `ENV`, `IFS`…) and those that steer the agent rather
than your tools, which are named: `LD_PRELOAD`, `LD_AUDIT`, `NODE_OPTIONS`,
`ANTHROPIC_*`, `CLAUDE_*`, `CODEX_*`, `OPENAI_*` and every `*_PROXY`.
`LD_LIBRARY_PATH` is kept.

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
unset of the devShell's is unset. Its functions are never handed on, and
PATH is ordered again, so its own `PATH=$PWD/bin:$PATH` stays behind the
wrappers and the shims. Its status is ignored; an `exit` in it ends the
session, as in `nix develop`, and so does a hook that leaves its subshell
handing back nothing whole, which is said. `$PWD` in the hook is the
checkout.

## How it is evaluated

As `nix develop` would evaluate it in the checkout, by your nix, as you,
with none of your environment but `HOME`: nix's own configuration, its
fetcher cache and any `access-tokens` in `~/.config/nix` are yours; a
`NIXPKGS_ALLOW_UNFREE`, an editor's variables or a terminal's are not, so the
devShell is the same from wherever it is launched. Its PATH is nix and git
alone. A flake's `nixConfig` is never taken.

- **A flake** is the checkout's own path, so nix reads it as `nix develop`
  does: from git, what is tracked, as the work tree has it. A flake.nix git
  does not track is said, as `nix develop` says it, and not evaluated; one in
  a directory that is no git checkout is taken as it is. It is evaluated
  purely, and its lock is never written: an input it does not lock is
  fetched for that launch alone.
- **A shell.nix** is evaluated under `restrict-eval`, with `NIX_PATH` the
  system's nixpkgs and the checkout, and `allowed-uris` anything over https:
  it reads nothing of the host outside the store and those two, and
  fetches nothing but https. It is told `inNixShell`, as nix-shell tells it.

What the daemon builds for it is built on the host, a fixed-output build on
the host's own network: your own code, where nothing is filtered.

## What fails, and why

A devShell that works with `nix develop` and not here usually reaches for
what the clean evaluation leaves out:

- **unfree packages through the environment** (`NIXPKGS_ALLOW_UNFREE=1`):
  say `config.allowUnfree = true` in the import instead.
- **`--impure` flakes and devenv**, which read the environment or the
  working directory: not here.
- **`git+ssh` inputs** not already in nix's fetcher cache: no agent socket
  reaches the evaluation. Fetch them over https with `access-tokens`.
- **a shell.nix that reads a file outside the checkout**, or fetches by
  anything but https: refused by `restrict-eval`.
- **a checkout whose path has a `#` or `?`**, which nix would read as part
  of a flake reference.
- **one larger than a launch carries**: more than 512 KiB of variables,
  functions and hook together, or one of them over 128 KiB.

Each is said at launch, with what nix said, and the session starts without
it. A failure is kept for an hour, so a broken flake does not cost every
launch.

## Caching and its roots

The realised devShell is cached on flake.nix and flake.lock, or shell.nix,
the system, the nix, the nixpkgs, and every setting the evaluation runs
with. A devShell split over other `.nix` files is realised again only when
one of those changes, as with nix-direnv. A change takes effect at the next
launch: exit and launch again.

Its GC root is a profile in `~/.local/state/chase/checkouts/<key>/devshell`,
never the checkout, the latest generation alone. A checkout that no longer
has either file has it let go of at its next launch, and one that is gone
at any launch that wants a devShell. To let go of them all:

```sh
rm -r ~/.local/state/chase/checkouts/*/devshell
```
