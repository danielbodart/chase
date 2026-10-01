# github

GitHub's API at api.github.com, REST and GraphQL, and gh. Operations come
from GitHub's REST description and GraphQL schema: a query is a read, each
mutation an operation of its own. See [../github.md](../github.md).

| `chase.apps.github.…` | Default | |
|---|---|---|
| `package` | `pkgs.gh` | |
| `credentialFile` | `null` | A file holding a GitHub token, e.g. `gh auth token`'s. Also git's, unless git has its own. |

| `chase.tiers.<name>.apps.github.…` | Default | |
|---|---|---|
| `enable` | `false` | Without `authenticated`: REST reads, no gh. |
| `authenticated` | `false` | Use the token, and install gh. |
| `writes`, `guarded`, `unmatched` | the tier's | |
| `credentialFile`, `package` | the machine's | |

```nix
chase.apps.github.credentialFile = config.sops.secrets.gh_token.path;
chase.tiers.trusted.apps.github = { enable = true; authenticated = true; };
```

Grant: `apps.github.allow`, `ask` and `refuse`, by operation id or
`category:<name>`.
