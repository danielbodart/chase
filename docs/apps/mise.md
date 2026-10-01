# mise

The toolchains a checkout's `mise.toml` asks for, with their shims on PATH.
`mise trust` records are never kept: the host's are readable in every
session, and what a session trusts is lost when it ends.

| `chase.apps.mise.…` | Default | |
|---|---|---|
| `package` | `pkgs.mise` | Use the host's mise. |
| `config` | `~/.config/mise` | Your mise configuration, bound read-only. |

| `chase.tiers.<name>.apps.mise.…` | Default | |
|---|---|---|
| `enable` | `false` | |
| `scope` | `tier` if the tier's `caches` is, else `session` | Where installs and downloads are kept. `session`: the host's, read-only, with installs lost. `tier`: the tier's own. `host`: the host's, shared. |
| `trust` | `false` | Set `MISE_TRUSTED_CONFIG_PATHS` to the workspace. |
| `package`, `config` | the machine's | |

```nix
chase.tiers.trusted = { caches = "tier"; apps.mise = { enable = true; trust = true; }; };
```

No `workspace` scope: the shims go on PATH when the system is built. Not `host`
in a tier that runs other people's code: the host runs what is installed.
