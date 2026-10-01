# codex

codex. frisket puts your host login's token on each request. The session
holds a placeholder JWT that expires in 2100, so codex never refreshes it;
refreshing stays on the host, where `codex-refresh` keeps the login fresh.
codex's own sandbox is bypassed: the container is the sandbox.

| `chase.apps.codex.…` | Default | |
|---|---|---|
| `package` | | codex. Required. |

| `chase.tiers.<name>.apps.codex.…` | Default | |
|---|---|---|
| `enable` | `false` | |
| `scope` | `session` | Where `CODEX_HOME` is: `session`, `workspace`, `tier` or `host` (the host's `~/.codex`). A kept home gets the placeholder login afresh at every launch. |
| `trust` | `false` | Pass `-c projects."<workspace>".trust_level="trusted"`. |
| `package` | `chase.apps.codex.package` | |

Outside the `host` scope, frisket lets codex reach `/backend-api/codex/` and
nothing else on chatgpt.com.

```nix
chase.tiers.trusted.apps.codex = { enable = true; scope = "host"; trust = true; };
```
