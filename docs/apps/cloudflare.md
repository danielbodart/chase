# cloudflare

wrangler, against Cloudflare's API. Operations come from Cloudflare's own API
description. See [../cloudflare.md](../cloudflare.md).

| `chase.apps.cloudflare.…` | Default | |
|---|---|---|
| `package` | `pkgs.wrangler` | |
| `credentialFile` | `null` | A token for the tier itself. Usually none: a project brings its own. |
| `accountIdFile` | `null` | A file holding the account id, set as `CLOUDFLARE_ACCOUNT_ID`. |

| `chase.tiers.<name>.apps.cloudflare.…` | Default | |
|---|---|---|
| `enable` | `false` | |
| `authenticated` | `false` | Use `credentialFile` when the project brings no token. |
| `writes`, `guarded`, `unmatched` | the tier's | Applies to a project's token too. |
| `package`, `credentialFile`, `accountIdFile` | the machine's | |

```nix
chase.tiers.trusted = { grants = true; apps.cloudflare.enable = true; };
```

In the project's `chase.json`, the binding in chase's section and the
answers in frisket's:

```json
{
  "chase": {"apps": {"cloudflare": {"accountId": "023e105f4ecef8ad9ca31a8372d0c353", "credential": {"secret": "cloudflare-token"}}}},
  "frisket": {"routes": {"cloudflare": {"operations": {"workers-ai-post-run-model": "allow"}}}},
  "version": 2
}
```

Mint the token narrowly: its scope is the floor, and the answers only decide
which of what it can do need you.
