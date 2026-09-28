# gcloud spikes

The evidence behind [../../docs/gcloud.md](../../docs/gcloud.md), 2026-09-28.
Each directory's `FINDINGS.md` is the write-up; the scripts are as they ran,
with absolute paths into a session's scratch directory, so they are a record
and a starting point rather than something to run as is. Logs, module caches,
binaries and every key and token were left behind.

- `research/` — Google's documentation: metadata detection, token lifetimes,
  key policies, federation, scoping, hosts, Discovery, prior art.
- `metadata/` — a fake GCE metadata server against every client, offline.
  Built, and not taken.
- `credfiles/` — placeholder credential files (`authorized_user`,
  gcloud's store, a fake `service_account` key, `external_account`), offline.
- `frisket-code/` — what frisket needs: wildcard routes, gRPC, the metadata
  handler, answering a token endpoint, token files. `gcp-spike.patch`.
- `e2e/` — the metadata design against real Google through a prototype
  frisket, rootless `steer`/`connect`; found the alias leak.
- `wif/` — workload identity federation with our own key: `renew.sh` is the
  whole host flow.
- `artifact/` — Artifact Registry's token is the service account's, for 12
  hours, on every repository.
- `classify/` — Discovery and protos into chase's classes; `gen/gen.py` is
  the prototype generator, `gen/exceptions.json` its exceptions.
- `fakekey/` — the fake service-account key against real Google, the design
  taken. `fakekey.patch` is frisket's side.

The prototype frisket, whole, is on frisket's local branch `spike/gcloud`.
