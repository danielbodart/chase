# claude

Claude Code. frisket puts your host login's token on each request; the
session holds a placeholder login that never expires, and the refresh
endpoint is refused. Claude Code's own sandbox is off: the container is the
sandbox.

| `chase.apps.claude.…` | Default | |
|---|---|---|
| `package` | | Claude Code. Required. |

| `chase.tiers.<name>.apps.claude.…` | Default | |
|---|---|---|
| `enable` | `false` | |
| `scope` | `session` | `session`: nothing kept. `workspace`: this workspace's transcripts, where the host's `claude --resume` finds them. `host`: the host's sessions, history and plugins. |
| `connectors` | `false` | claude.ai's connectors (Gmail, Drive, Slack…). Without, the login has `user:inference` only. |
| `trust` | `false` | Answer the folder-trust dialog for the workspace. Without it, a `session` or `workspace` scope asks at every launch. |
| `package` | `chase.apps.claude.package` | |
| `managedSettings` | see below | Claude Code's managed settings, in the tier's container only. |

```nix
chase.tiers.trusted.apps.claude = { enable = true; scope = "host"; connectors = true; trust = true; };
chase.tiers.strict.apps.claude = { enable = true; scope = "workspace"; };
```

Each sandbox tier's container has Claude Code's managed settings,
`/etc/claude-code/managed-settings.json`, which outrank the user's, the
project's and `--settings`. The host's Claude Code never sees them. By
default they make the container the only boundary:

```nix
{
  # Ignore allow, ask and deny rules from every other file: a project's
  # checked-in deny list blocks even in bypassPermissions mode.
  allowManagedPermissionRulesOnly = true;
  # Start in auto mode; Shift+Tab still cycles to plan and bypass.
  permissions.defaultMode = "auto";
}
```

Each key is a default of its own, so a tier can set one, add others, or
`lib.mkForce { }` for no file. The project's CLAUDE.md, skills, agents and
hooks still load. With the rules gone, a permission prompt has no "always
allow".

A bare tier may set `trust`: the workspace is then trusted in the host's
`~/.claude.json` before Claude Code starts.
