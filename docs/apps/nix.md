# nix

A checkout's devShell in its sessions, as `nix develop` would give it on the
host: flake.nix's `devShells.<system>.default`, or its shell.nix, flake.nix's
when it has both. The store is in every session already; the environment is
not, since a session starts clean. So the launcher realises the devShell
before the session starts, confined, keeps it rooted in chase's state, and
gives the session its variables and its PATH, and runs its shellHook inside
the session. `nix` itself in a session is not this; it is flong's to give.

| `chase.apps.nix.…` | Default | |
|---|---|---|
| `package` | `config.nix.package` | The nix that realises it, as you. |
| `nixpkgs` | `pkgs.path` | What `<nixpkgs>` is to a shell.nix: the system's own, so importing it fetches nothing. |
| `timeout` | `1200` | Seconds a realisation may take, every step together, before it is killed and counts as a failure. |

| `chase.tiers.<name>.apps.nix.…` | Default | |
|---|---|---|
| `enable` | `false` | Not in a bare tier: its agent runs on the host, whose `nix develop` is its own. |
| `devShell` | `granted` | `automatic`: whenever the checkout has one, for a tier of your own code; one that cannot be realised is said, and the session starts without it. `granted`: only when the checkout's approved grant asks, for a tier of other people's code, which must take grants; one that cannot be realised refuses the launch. |
| `package`, `nixpkgs`, `timeout` | the machine's | |

```nix
chase.tiers.trusted.apps.nix = { enable = true; devShell = "automatic"; };
chase.tiers.strict = { grants = true; apps.nix.enable = true; };
```

Grant:

```jsonc
"nix": {
  "devShell": true,   // in a `granted` tier, turns it on; anywhere, a failure refuses the launch
}
```

`false` leaves out a devShell the tier would give. The grant is approved once,
as any change to it is; flake.nix, flake.lock and shell.nix are not approved
with it, and an edit to them takes effect at the next launch. The
confinement below stands in for an approval.

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

## The confinement

Every nix run is in a bubblewrap of its own, with nothing of the host but the
store, the daemon's socket, nix's own configuration (`/etc/nix`, and
`/etc/static`, where NixOS links its files), a snapshot of what the
checkout tracks, at `/src/<its name>`, and a nix HOME of chase's,
`~/.local/state/chase/nix/direct`, or in a frisket tier one per allowlist,
`nix/frisket-<digest>`, so its fetcher cache never holds what a checkout
that may reach other names fetched; none of your environment; and stdin
closed. So the evaluation reads nothing of yours -- your home, `~/.ssh`,
`~/.config/nix`, a netrc, another checkout -- and runs as pure as nix can:
`restrict-eval` for a flake and a shell.nix alike, a shell.nix's `NIX_PATH`
the system's nixpkgs and the checkout alone, and never a flake's
`nixConfig`, a registry, or an update to its lock. What is evaluated is what
git tracks and the work tree has, never the checkout's `.git`: a flake.nix
you have not yet `git add`ed is said, and not evaluated, as `nix develop`
says it. Every step substitutes from the daemon's caches, which nix would
otherwise turn off where it finds no network.

| Step | `egress = "direct"` | `egress = "frisket"` |
|---|---|---|
| fetch the lock's inputs | – | by chase, with a network, from what the session's allowlist holds |
| evaluate | with a network, as the session's: `allowed-uris` any https | no network: `allowed-uris` the session's exact names, `--max-jobs 0` |
| the devShell's inputs | built locally where they must be | from the binary caches alone (`--max-jobs 0`) |
| the environment | built in the daemon's sandbox, no network | the same |

A network is pasta's, which keeps the host's loopback and gateway out. A
direct tier's local builds are the host daemon's, and a fixed-output build
there fetches on the host's own network, loopback included: the cost of
local builds where nothing is filtered.

In a frisket tier, the evaluation reaches nothing itself. A flake.lock's
inputs are fetched before it, by chase, from URLs it builds from each node:
`github`, `gitlab` and `sourcehut` archives by owner, repository, revision and
narHash, from their own host only; `tarball` and `file` from `https://<name>/`,
pinned by narHash; and a relative `path:` is the snapshot's own. A node of
type `git` (its submodules may name any host), one with `?host=`, an
absolute `path:` and an `indirect` one are fetched by nothing, and refuse the
devShell. A host the allowlist does not hold is named:
`network.allow` in the grant admits it. A `*.suffix` name cannot be said in
`allowed-uris`, which matches by prefix, and is said and left out. A
shell.nix that fetches as it evaluates -- `builtins.fetchTarball` -- does not
work in a frisket tier until evaluation goes through frisket itself.

If a tier with `egress = "frisket"` has nix and the machine has
`nix.buildMachines`, the system warns: inputs are never built locally, but a
remote builder builds for the daemon on its own network.

## What fails, and why

A devShell that works with `nix develop` and not here usually reaches for
what the confinement leaves out:

- **unfree packages through the environment** (`NIXPKGS_ALLOW_UNFREE=1`):
  say `config.allowUnfree = true` in the import instead.
- **`--impure` flakes and devenv**, which read the environment or the
  working directory: not here.
- **private inputs, and `git+ssh`**: nothing of yours, no key and no
  netrc, reaches the evaluation.
- **a flake whose nixpkgs is a `path:` in the store**, or that follows the
  system's registry: a `path:` is never in `allowed-uris`, in any tier, so
  pin it by `github:` instead.
- in a frisket tier, **a `git` lock node, `?host=`, an absolute `path:`
  input and a host off the allowlist**, as above; and **anything the
  devShell builds that no binary cache holds** -- a `writeShellScriptBin`
  of its own, a `runCommand` -- since nothing of its inputs is built
  locally there.
- **one larger than a launch carries**: more than 512 KiB of variables,
  functions and hook together, or one of them over 128 KiB.

Each is said at launch, with what nix said. In a tier where it is
automatic, a failure is kept for an hour, so a broken flake does not cost
every launch; one a grant asks for is tried again at every launch.

## Caching and its roots

The realised devShell is cached on flake.nix and flake.lock, or shell.nix,
the system, the tools, and every setting the evaluation runs with, the
allowlist's among them. A devShell split over other `.nix` files is realised
again only when one of those changes, as with nix-direnv. A change takes
effect at the next launch: exit and launch again.

Its GC root is a profile in `~/.local/state/chase/checkouts/<key>/devshell`,
never the checkout, the latest generation alone. A checkout that no longer
tracks either file has it let go of at its next launch, and one that is gone
at any launch that wants a devShell. To let go of them all:

```sh
rm -r ~/.local/state/chase/checkouts/*/devshell
```

## Caveats

- `toString ./.` is `/src/<name>`, the snapshot's path, and `self.rev` is
  unset: the snapshot is a path, not a git checkout.
- A devShell whose environment refers to its own source -- `src = ./.` --
  copies it into the store, which every session can read.
