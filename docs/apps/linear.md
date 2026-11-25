# linear

Linear's API at api.linear.app, which is GraphQL only. Operations come from
Linear's GraphQL schema: a query is a read, and each mutation is an
operation of its own. See [../linear.md](../linear.md).

| `chase.apps.linear.…` | Default | |
|---|---|---|
| `package` | `null` | A Linear CLI. nixpkgs has none, so give one, or the session gets the API only. |
| `credentialFile` | `null` | A file holding a Linear personal API key. One key is one workspace. |

| `chase.tiers.<name>.apps.linear.…` | Default | |
|---|---|---|
| `enable` | `false` | Without `authenticated`: queries only, no CLI. |
| `authenticated` | `false` | Use the key, and install the CLI. |
| `writes`, `guarded`, `unmatched` | the tier's | |
| `credentialFile`, `package` | the machine's | |

```nix
chase.tiers.work.apps.linear = {
  enable = true;
  authenticated = true;
  credentialFile = config.sops.secrets.linear-work-token.path;
  package = inputs.linear-cli.packages.${system}.default;
};
```

Grant: `frisket.routes.linear.operations`, by mutation name or
`category:<name>`, for example `category:issue`.
