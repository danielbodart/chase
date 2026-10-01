# gcloud

gcloud and Google's client libraries, as a project's service account. The
project's grant holds its key; the session gets a key file of the same shape
that Google has never seen, and frisket puts a real token, which chase renews,
on every `*.googleapis.com` request. Operations come from each API's
Discovery document. See [../gcloud.md](../gcloud.md).

| `chase.apps.gcloud.…` | Default | |
|---|---|---|
| `package` | `pkgs.google-cloud-sdk` | |

| `chase.tiers.<name>.apps.gcloud.…` | Default | |
|---|---|---|
| `enable` | `false` | Only in a tier with `grants = true`. |
| `apis` | `[]` | The APIs a session can reach, by Discovery name. |
| `writes`, `guarded`, `unmatched` | the tier's | |
| `package` | the machine's | |

```nix
chase.tiers.trusted = {
  grants = true;
  apps.gcloud = { enable = true; apis = [ "bigquery" "storage" ]; };
};
```

Grant:

```jsonc
"gcloud": {
  "credential": { "secret": "gcloud-key" },
  "serviceAccount": "ci@project.iam.gserviceaccount.com",
  "apis": { "add": ["pubsub"], "remove": ["storage"] },
}
```
