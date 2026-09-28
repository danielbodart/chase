# Docker — plan

The first app whose upstream is not a remote HTTPS API but a daemon on the
host, and the first where whether a request is safe is decided by its body,
not its method and path. Read [../PLAN.md](../PLAN.md) first — decisions 15
and 16 (`hostPorts`, and ports and environment as one feature) are the ones
this depends on — and [cloudflare.md](cloudflare.md)'s decisions 1–4, which
hold here unchanged: anything not known to be safe asks, the rules come from
the provider's own description of its API, the spec is pinned, and safe is
decided per operation with a rule and a list of exceptions.

## Goal

A project whose tests start their services with Docker Compose runs them,
unchanged, in a trusted session. The first such project is `data-lab`: every
`./run test_only` there does `docker compose up -d` for a `postgres:18`, and
its scripts also use `docker compose down -v` and
`docker compose exec -T <service> pg_isready|psql`. Nothing else — no builds,
no pushes — is needed in a session. With:

- the session never holding the Docker socket, nor anything equivalent to it;
  frisket holds access to the daemon, as it holds a token for other apps;
- every Engine API operation refused or asked unless the project allows it,
  and `ContainerCreate` admitted only for an image the project names, with
  none of the fields that reach the host (bind mounts, privileges,
  capabilities, devices, host namespaces);
- a session able to see and touch only the containers, networks and volumes
  its own project created.

## Findings this rests on

Measured against a recording fake of the Engine API, with Docker CLI 29.8.0
(API 1.56) and Compose 5.4.0:

- **The client never names the daemon it means.** Over a Unix socket the
  `Host` header is the fixed placeholder `api.moby.localhost`; over TCP it is
  whatever `DOCKER_HOST` says (`127.0.0.1:23750`). The only identifying
  header is `User-Agent` (`Docker-Client/29.8.0 (linux)`, `compose/5.4.0`).
  So a route cannot be chosen from the request; it has to come from the
  endpoint connected to — for frisket, SNI.
- **Both clients do TLS with a CA and no client certificate.** With
  `DOCKER_TLS_VERIFY=1` and a `DOCKER_CERT_PATH` holding only `ca.pem`, the
  CLI and Compose both proceeded to the HTTPS request; neither asked for
  `cert.pem` or `key.pem`.
- **Both honour `HTTPS_PROXY`.** A session environment with a proxy set must
  exclude the Docker route host in `NO_PROXY`.
- **API versions differ between the two clients:** the CLI sent `/v1.56/...`,
  Compose `/v1.55/...`; `/_ping` goes unversioned.

frisket as it is ([frisket README](../../frisket/README.md), `internal/`):
every connection to the service address is TLS-terminated and routed by SNI;
upstreams must be `https://`; the egress dialer dials only IP addresses and
its classifier refuses loopback; bodies are read only for GraphQL; upgrades
go through `httputil.ReverseProxy`, which handles a `101`.

## Decisions

**1. Transport: TCP to frisket's service address, over TLS, on a synthetic
route host.** The route is declared for a name that exists only for frisket —
`docker.frisket.internal`, say — which frisket's DNS answers with the service
address, as it does for every intercepted host. The session is given:

    DOCKER_HOST=tcp://docker.frisket.internal:2376
    DOCKER_TLS_VERIFY=1
    DOCKER_CERT_PATH=<a directory whose ca.pem is /etc/frisket/ca.crt>

The session CA is name-constrained to the policy's route hosts, which this
name is one of, so SNI, the certificate and the `Host` check all work as they
do for any other app. *Rejected:* a Unix socket bound into the session. It
would need a downstream path outside steering and dispatch, without SNI, and
a new way to say which session a connection belongs to. *Rejected:* plain TCP.
frisket speaks TLS on every intercepted connection and should keep doing so.

**2. The upstream is a rootless daemon's Unix socket, reached with its own
dialer.** The host runs Docker rootless (nix-config's `modules/docker.nix`),
so the daemon is the user's, at `unix://$XDG_RUNTIME_DIR/docker.sock`, and
there is no `/run/docker.sock` and no `docker` group. A new upstream scheme,
`unix://`, plain HTTP on that hop, with a dialer of its own that does not go
through the egress classifier: the classifier governs the session's network
egress, and this is a local daemon the operator chose to expose, not egress.
frisket needs to reach that socket as the user it belongs to.

Rootless does not make the filter optional. A session with the raw socket
could still `docker run -v $HOME:/h` and walk out with everything flong and
frisket keep from it — `~/.ssh`, cloud credentials, sops keys, every other
checkout. The filter is the control; rootless is what bounds its failure:
a hole in it gives away the user, not root.

**3. The spec is `api/swagger.yaml` from moby/moby, pinned by commit and
hash.** It is Swagger 2.0, the Engine API's own definition, from which
Docker generates its client, server types and documentation: 98 paths on
master at API 1.56, every operation with an `operationId` (`ContainerCreate`,
`ExecStart`, `ImageCreate`, …), and full schemas for `ContainerConfig`,
`HostConfig`, `Mount` and the rest. It lives at a commit, so it is pinned by
URL and `sha256` as Cloudflare's is, not vendored as Hugging Face's is.

**4. `scripts/operations.sh` reads Swagger 2.0 as well as OpenAPI 3.** The
two are near enough that one generator handles both: `paths` →
method → `operationId` is the same; the differences are `basePath` where 3
has `servers[].url`, `definitions` where 3 has `components.schemas`, and body
parameters declared `in: body` where 3 has `requestBody`. The generator also
stops assuming the `server` is `https://` when stripping its prefix.

**5. The API version is an optional first segment, within a pinned range.**
Clients send `/v1.NN/...` and some requests unversioned. Rules match either;
a version outside the range the app pins (at least the two measured above) is
refused. Below some version the Engine hijacks with a raw `200` rather than a
`101`, which the proxy cannot carry (decision 10); the range's floor is above
that.

**6. Request bodies are matched, with a strict allow-list per operation.**
A new frisket capability, built the way GraphQL's is: `scope.decide` returns
a deferred verdict, and `serveHTTP` resolves it by reading the body up to a
bound and replacing `r.Body`. For `ContainerCreate` the body is decoded
strictly against the fields the policy allows, and **any field not allowed,
or not known, refuses** — so a field a newer API adds is refused from the
day it ships. The fields known are generated from the pinned spec's
`ContainerConfig` and `HostConfig` definitions, so bumping the pin shows new
fields in the diff to be read. Allowed, to begin with (to be confirmed by the
capture in Order of work, step 1):

- `Image` — one of the project's named images;
- `Env`, `Cmd`, `Entrypoint` unset or any, `Labels`, `ExposedPorts`,
  `Healthcheck`, `StopSignal`, `StopTimeout`;
- in `HostConfig`: `PortBindings`, `Tmpfs`, `RestartPolicy`, `NetworkMode`
  naming the project's own network, `Mounts` of `type: volume` only, with no
  driver options, `LogConfig` with the default driver;
- and nothing that reaches the host: `Binds`, bind or `tmpfs` mounts of host
  paths, `Privileged`, `CapAdd`, `Devices`, `DeviceRequests`, `SecurityOpt`,
  `Sysctls`, `PidMode`, `IpcMode`, `UsernsMode`, `CgroupnsMode`,
  `NetworkMode: host`, `VolumesFrom`, `Runtime` — each refused outright.

**7. A request that would reach the host is refused, not asked.** Decision 1
of cloudflare.md makes the default a prompt. Here the default for unmatched
operations stays a prompt, but a `ContainerCreate` carrying a host-reaching
field is refused without one: a dialog that says "bind-mount `/`" is one a
person clicks through the tenth time.

**8. Query strings are matched too.** `ImageCreate` only with
`fromImage` and `tag` (or digest) in the project's image list — the pull is
the one request where the daemon, not the session, reaches the network, as a
fixed-output derivation does for Nix; frisket sees and allows it by name, and
the registry traffic itself is out of its view. `ContainerCreate`'s `name`,
and the `filters` Compose sends to `ContainerList`, are read, not trusted.

**9. Ownership is by project, not session, and stamped by frisket.**
frisket adds a label — `frisket.project=<workspace identity from chase>` — to
every `ContainerCreate`, `NetworkCreate` and `VolumeCreate` it admits, and
admits an operation on an existing object (`/containers/{id}/…`,
`/exec/{id}/…`, volumes, networks) only after asking the daemon that the
object carries this project's label. Lists are answered only with this
project's objects. By project, because data-lab's `local-db` volume is meant
to outlive a session; two concurrent sessions of one project share its
databases, which is accepted.

**10. Exec is allowed on owned containers, and attach streams pass
through.** `ExecCreate` on an owned container with `Privileged` false; the
command is not restricted, since the container itself holds nothing of the
host. `ExecStart` and `ContainerAttach` send `Upgrade: tcp`; the daemon
answers `101`, and `ReverseProxy` hijacks both sides. This is expected to
work and has no test yet; the first test in Order of work proves it.

**11. Everything else in the API is refused.** Build, commit, export, image
save and load, push, plugins, swarm, secrets, configs, `/containers/{id}/archive`
(reads and writes files), system-wide `/events` unless filtered to the
project's label, `/system/df`. The exceptions file names each group with its
reason, as the other apps' do.

**12. The images and ports are the project's, in its envelope.**

    chase.bindings.docker.images = [ "postgres:18" ];

and the ports it publishes, through decision 15's `hostPorts`. Containers run
on the host's daemon, so what they publish is on the host's loopback, which a
session reaches only through `hostPorts`.

## What has to exist first

1. **chase: `hostPorts`**, in tiers and the envelope (PLAN.md decisions 15
   and 16). Without it a session starts Postgres and cannot connect to it.
2. **frisket: a Unix-socket upstream**, with its own dialer (decision 2).
3. **frisket: body and query rules**, as a deferred verdict (decisions 6, 8).
4. **frisket: rewriting a body**, to stamp the ownership label (decision 9).
5. **chase: `scripts/operations.sh` reads Swagger 2.0**, a non-`https`
   server, and the optional version segment (decisions 4, 5).
6. **chase: `apps/docker.nix`** — the route for the synthetic host, the
   environment of decision 1, the Docker CLI and Compose plugin in the
   container's packages, and frisket's access to the user's rootless socket.

## Order of work

1. **Capture what the target flows send**, outside any session: a recording
   proxy in front of the real daemon, and data-lab's `docker compose up -d`,
   `exec -T local-db pg_isready`, `exec -T local-db psql` and `down -v`
   through it. The result — every operation, query and body — is the fixture
   the rules are written against and the tests replay.
2. Generate the operations from the pinned spec. Read the list and write the
   exceptions: reads that leak (`ContainerLogs`, `ContainerExport`,
   `ContainerArchive`, `ImageGet`), and the refused groups of decision 11.
3. frisket: the Unix upstream; then body and query rules; then the label
   rewrite. Each with tests against the fixture from step 1, including the
   `Upgrade: tcp` exec stream.
4. chase: the Docker app, wired to the generated rules, first against a test
   project whose Compose file runs a single `postgres:18`.
5. data-lab in a trusted session: `./run test_only` in `core-data` passes, and
   frisket's log shows every request allowed by name or refused by a rule —
   none unmatched.

## Test plan

Each of these refused, and logged with the rule that refused it:
`ContainerCreate` with a bind mount, with a volume mount carrying driver
options, `Privileged`, `CapAdd`, `NetworkMode: host`, `PidMode: host`, an
image not in the list, and an unknown `HostConfig` field; `ImageCreate` of an
image not in the list; `ExecCreate`, `ContainerStop` and `ContainerDelete` on
a container without the project's label; `/build`, `/images/{name}/push`,
`/containers/{id}/archive`, and an unfiltered `/events`. And admitted: the
whole of step 1's fixture, in order, with the exec streams carrying
`pg_isready`'s and `psql`'s output.

## Open

- **Published ports bind every host address.** `'64320:5432'` in a Compose
  file sends an empty `HostIp`, which the daemon binds on `0.0.0.0` — a test
  database with a known password, on the LAN. Rewrite an empty `HostIp` to
  `127.0.0.1` (frisket already rewrites for decision 9), or refuse it and ask
  projects to write `127.0.0.1:64320:5432`. Rewriting changes nothing for
  the project; refusing changes data-lab's Compose files for everyone.
- **The route host's name.** `docker.frisket.internal` is a placeholder.
- **Concurrent sessions of one project** share its containers and ports.
  Separate sessions per project would need frisket to rewrite published
  ports and map them back — not planned.
- **`/events`.** Whether Compose needs it for the target flows, and whether
  a label filter added by frisket is enough to answer it, is for step 1 to
  say.
