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

```nix
chase.tiers.trusted.apps.claude = { enable = true; scope = "host"; connectors = true; trust = true; };
chase.tiers.strict.apps.claude = { enable = true; scope = "workspace"; };
```

A bare tier may set `trust`: the workspace is then trusted in the host's
`~/.claude.json` before Claude Code starts.
