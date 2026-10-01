# huggingface

`hf` and huggingface_hub. Operations come from the Hub's own API description;
the token goes to huggingface.co only. Downloads come from `*.hf.co`, which
takes no token. See [../huggingface.md](../huggingface.md).

| `chase.apps.huggingface.…` | Default | |
|---|---|---|
| `package` | `huggingface-hub` | |
| `credentialFile` | `null` | A file holding a Hugging Face token. |

| `chase.tiers.<name>.apps.huggingface.…` | Default | |
|---|---|---|
| `enable` | `false` | Without `authenticated`: public models and datasets, nothing that writes or mints a token. |
| `authenticated` | `false` | Use the token. |
| `scope` | the tier's `caches` | Where downloads are kept. `host` shares the host's cache. |
| `writes`, `guarded`, `unmatched` | the tier's | |
| `package`, `credentialFile` | the machine's | |

```nix
chase.tiers.trusted.apps.huggingface = { enable = true; authenticated = true; scope = "host"; };
chase.tiers.strict.apps.huggingface.enable = true;
```

Not `host` in a tier that runs other people's code: the host loads what is in
the cache.
