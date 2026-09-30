# Docker

The first app whose upstream is not a remote HTTPS API but a daemon on the
host, and the first where whether a request is safe is decided by its body,
not its method and path. Read [../PLAN.md](../PLAN.md) first — decisions 15
and 16 (`hostPorts`, and ports and environment as one feature) are the ones
this sets aside for Docker (decision 12) — and
[cloudflare.md](cloudflare.md)'s decisions 2–4, which
hold here unchanged: the rules come from the provider's own description of
its API, the spec is pinned, and safe is decided per operation with a rule
and a list of exceptions. Its decision 1, that anything not known to be safe
asks, does not hold here (decision 7).

## Goal

A project whose tests start their services with Docker Compose runs them,
unchanged, in a trusted session. The first such project is `shop`: every
`./run test_only` there does `docker compose up -d` for a `postgres:18`, and
its scripts also use `docker compose down -v` and
`docker compose exec -T <service> pg_isready|psql`. With:

- the session never holding the Docker socket, nor anything equivalent to it;
  frisket holds access to the daemon, as it holds a token for other apps;
- every Engine API operation refused unless chase admits it, and
  `ContainerCreate` admitted only for an image the project names, with none
  of the fields that reach the host (bind mounts, privileges, capabilities,
  devices, host namespaces, the shared default network);
- a session able to see and touch only the containers, networks and volumes
  its own project created.

## Findings this rests on

Measured first against a recording fake of the Engine API, then against the
real rootless daemon through a recording proxy, with Docker CLI 29.8.0 (API
1.56) and Compose 5.4.0 running `up -d`, `exec -T pg_isready`, `exec -T psql`
and `down -v` on a two-service Compose file shaped like shop's: 60
requests, kept as the fixture the rules are written against.

- **The client never names the daemon it means.** Over a Unix socket the
  `Host` header is the fixed placeholder `api.moby.localhost`; over TCP it is
  whatever `DOCKER_HOST` says. The only identifying header is `User-Agent`.
  So a route cannot be chosen from the request; it has to come from the
  endpoint connected to — for frisket, SNI.
- **Both clients do TLS with a CA and no client certificate.** With
  `DOCKER_TLS_VERIFY=1` and a `DOCKER_CERT_PATH` holding only `ca.pem`, the
  CLI and Compose both proceeded; neither asked for `cert.pem` or `key.pem`.
- **Both honour `HTTPS_PROXY`.** A session environment with a proxy set must
  exclude the Docker route host in `NO_PROXY`.
- **API versions differ between the two clients:** the CLI sent `/v1.56/...`,
  Compose `/v1.55/...`; only `/_ping` went unversioned. Both negotiate down
  to the `Api-Version` the daemon's `_ping` answers.
- **Twenty operations, and nothing else.** `_ping`, `version`, the three
  lists, `ImageInspect`, `NetworkInspect` and `VolumeInspect`, the three
  creates, `ContainerInspect`, `Start`, `Stop` and `Delete`, `ContainerExec`,
  `ExecStart` and `ExecInspect`, and the two deletes. No `/events`, no pull
  (the image was present), no attach.
- **Compose names volumes in `Binds`, not `Mounts`.** A named volume is
  `HostConfig.Binds: ["core-data-local-db2:/var/lib/postgresql:rw"]`, and
  `Mounts` is empty; a service's `tmpfs:` is `HostConfig.Tmpfs`.
- **Compose sends every field, most of them zero.** About sixty fields of
  `HostConfig` arrive as `""`, `0`, `false`, `null` or `[]`. Zero is mostly
  unset, but not always: `MaskedPaths: []` means *mask nothing*, where
  `null` means the default set, and `NetworkMode: ""` means the daemon's
  default bridge, shared with every container made outside a session.
- **Compose sends `NetworkingConfig`.** The project network is named twice:
  in `HostConfig.NetworkMode` and as the one key of
  `NetworkingConfig.EndpointsConfig`, with `Aliases` and `DNSNames`.
- **Exec is owned through its container.** `ExecStart` and `ExecInspect`
  name only the exec's own ID; which container it runs in is only in
  `GET /exec/{id}/json`'s `ContainerID`. `ExecStart` sends `Upgrade: tcp`
  and the daemon answers `101`; the stream half-closes both ways.
- **Compose inspects before it creates.** `NetworkInspect` and
  `VolumeInspect` of names that do not yet exist answer `404`, and Compose
  reads that as "create it".
- **Published ports bind every host address.** `'64320:5432'` sends an
  empty `HostIp`, which the daemon binds on `0.0.0.0`.
- **The rootless daemon binds any loopback address it is given.** With
  rootlesskit's builtin port driver, a `HostIp` of `127.12.34.56` is bound
  there, and the port is reachable at that address and at no other.
- **pasta cannot send a session's port to such an address.** The pasta on
  this host (2025_09_19) forwards a session's `-T` port to the host's
  `127.0.0.1` only.
- **pasta's `-t auto` republishes loopback listeners.** Measured with that
  pasta: a session listening on `127.0.0.1`, `127.12.34.56` or `[::1]` port
  P is republished on the host as `*:P`, all addresses, both families,
  within a second. The host's `127.0.0.1:P` then reaches the session's
  listener. A later bind of `127.12.34.56:P` on the host fails with
  `Address already in use`. That later bind is what a published port is.
  pasta's `auto` has no exclusions (`auto,~P` is `Invalid port specifier`).
  frisket's own listeners follow the same rule. 53 is not republished,
  because pasta publishes nothing under 1024. 15001 would be, and it
  answers nothing that was not steered to it.
- **The daemon is in the host's network namespace.** rootlesskit runs with
  `--detach-netns` and `--disable-host-loopback`: containers cannot reach
  the host's loopback, but what the daemon itself dials — a pull, a log
  driver's address — can.
- **Compose's `down` finds its objects by label filter, not by name**, and
  those filters are ANDed with any others, so a label frisket adds narrows
  what it sees without breaking it.

frisket as it is ([frisket README](../../frisket/README.md), `internal/`):
every connection to the service address is TLS-terminated and routed by SNI;
upstreams must be `https://`; the egress dialer dials only IP addresses and
its classifier refuses loopback; bodies are read only for GraphQL; upgrades
go through `httputil.ReverseProxy`, which carries a `101`. A session has four
listeners, made by `frisket steer` inside its namespace: TCP on `15001` and
DNS on `53`, for each family. Everything else reaches them by TPROXY, which
keeps the address the client dialled. frisket routes each connection by that
address, and refuses one that dialled the listener itself. Its DNS answers
only names on the allowlist; a route's host is answered with the service
address.

## Decisions

**1. Transport: TCP to frisket's service address, over TLS, on a synthetic
route host.** The route is declared for `docker.frisket.internal`, which
frisket's DNS answers with the service address, as it does for every
intercepted host. The session is given, through the Docker app's `prepare`
and only when its envelope binds Docker:

    DOCKER_HOST=tcp://docker.frisket.internal:2376
    DOCKER_TLS_VERIFY=1
    DOCKER_CERT_PATH=/etc/chase/docker    # ca.pem is /etc/frisket/ca.crt

The route offers only `http/1.1`: `Upgrade: tcp` does not exist on HTTP/2.
*Rejected:* a Unix socket bound into the session. It would need a
downstream path outside steering and dispatch, without SNI, and a new way to
say which session a connection belongs to. *Rejected:* plain TCP. frisket
speaks TLS on every intercepted connection and should keep doing so.

**2. The upstream is a rootless daemon's Unix socket, reached with its own
dialer.** The host runs Docker rootless (nix-config's `modules/docker.nix`),
so the daemon is the user's, at `unix:///run/user/<uid>/docker.sock`. A new
upstream scheme, `unix://`, plain HTTP on that hop, valid only on a route
with a `docker` block and dialled only by that route's transport, never
through the egress classifier: the classifier governs the session's network
egress, and this is a local daemon the operator chose to expose.

Rootless does not make the filter optional. A session with the raw socket
could still `docker run -v $HOME:/h` and walk out with everything flong and
frisket keep from it. The filter is the control; rootless is what bounds its
failure: a hole in it gives away the user, not root. Containers have the
user's unfiltered egress, so Docker is only for tiers whose egress is
already direct, by assertion.

**3. The spec is `api/swagger.yaml` from moby/moby, pinned by commit and
hash.** Swagger 2.0, the Engine API's own definition, with an `operationId`
for every operation and full schemas for the bodies. Pinned by URL and
`sha256`, as Cloudflare's is.

**4. `chase-generate operations` reads Swagger 2.0 YAML as well as OpenAPI 3.**
`basePath` where 3 has `servers[].url`, `definitions` where 3 has
`components.schemas`, `in: body` where 3 has `requestBody`; the YAML is
read as YAML 1.1, as PyYAML read it before the port, after its bytes are hashed. A `HEAD` is added to a
`GET` only where the spec has none of its own. It also writes, for Docker,
every body field the spec defines — object properties, through `$ref` and
`allOf`, not into arrays or maps — so that a bump shows new fields in the
diff and a check fails until each is classified.

**5. The API version is an optional first segment, within 1.55–1.56.**
Anything that looks like a version outside that range, or spelled any other
way (`V1.55`, `v1.055`), is refused; only `/_ping` goes unversioned. The
range is what the tables were written against. frisket caps the
`Api-Version` the daemon answers at the top of the range, so when nixpkgs
moves the daemon and the CLI to 1.57 both keep speaking 1.56 until the pin is
bumped. *Rejected:* 1.44 and up. Every client in a session comes from the
same nixpkgs as the daemon; older versions are semantics nobody read.

**6. Request bodies are matched against a table per operation, strictly.**
A deferred verdict, as GraphQL's is: frisket reads the body to a bound,
refuses duplicate keys, invalid UTF-8 and anything but one JSON object, and
walks it against a flat table, one field per line, that chase keeps beside
the generated operations. Keys are matched exactly: the daemon's decoder
folds case, so `privileged` would set `Privileged`. **A key the table does
not list refuses even when its value is zero.** What frisket forwards is its
own re-encoding of what it checked, so the daemon parses exactly that. A
field is `any`, `zero` (unset: `null`, `""`, `0`, `false`, `[]`, `{}`),
`null` where `[]` means something (`MaskedPaths`, `ReadonlyPaths`), or one of
frisket's own checks:

- `Image` — one of the project's images, required;
- `HostConfig.NetworkMode` and each `EndpointsConfig` key — `none`, or a
  network of the project's own, required: `""` and `default` are the shared
  bridge. frisket sends each upstream as the full 64-hex ID it looked up
  under the network's name lock, not as the name: the daemon resolves a
  name again at every start, so a container created on a project's `X`,
  after `X` is deleted and another project creates its own `X`, would start
  on the other project's network;
- `HostConfig.Binds` — `<volume>:<container path>[:rw|ro]` only, the volume
  existing and the project's own: one that does not exist the daemon would
  create without a label;
- `HostConfig.Mounts` — `volume` or `tmpfs` only; a volume the project's
  own, or the anonymous volume of a container of the project's own (Compose
  carries it over when it recreates);
- `HostConfig.PortBindings` — decision 12;
- `LogConfig` — the default driver only: the daemon is in the host's network
  namespace, and a syslog or gelf driver would dial its loopback;
- `RestartPolicy` — never `always` or `unless-stopped`: nothing a session
  starts outlives the machine's next boot.

Everything that reaches the host — `Privileged`, `CapAdd`, `Devices`,
`SecurityOpt`, `Sysctls`, the namespace modes, `VolumesFrom`, `ExtraHosts`,
`Dns`, `Runtime` — is `zero`. frisket holds a floor of these in its own code,
and a table weaker than the floor does not load, so the session does not
start. `VolumeCreate` is the `local` driver with no options (`type=none,
o=bind` is a bind mount); `NetworkCreate` is `bridge` with no options, IPAM
or config network. *Rejected:* "set iff non-zero" as the whole rule. It lets
`MaskedPaths: []` unmask `/proc`, a missing `NetworkMode` join the shared
bridge, and a zero `hostIp` beside a real `HostIp` reach the daemon as the
last one it reads.

**7. Everything not admitted is refused; nothing on the route asks.** The
admitted operations are chase's, in `apps/docker/admit.json`, reviewed as an
exceptions file is; every other operation is generated as a refusal with its
name, and a request no rule matches is refused. *Rejected:* asking. Compose
sends requests in parallel and a second question finds the first still open;
and "may `3f2a9c1e0b7d` be stopped?" is not a question a person can answer.
*Rejected:* letting a project's lists admit more. Images are global: a
project allowed `ImageTag` or `ImageBuild` could change what another's
`postgres:18` runs, with that project's volumes mounted.

**8. Queries are matched too, and forwarded as frisket encodes them.** A
rule names each parameter it takes and a check for it; any other, or one
given twice, refuses. An operation that takes no body refuses one — moby
reads a form body as query parameters. `ImageCreate` only for a `fromImage`
and `tag` that spell an image in the project's list: the pull is the one
request where the daemon, not the session, reaches the network, as a
fixed-output derivation does for Nix. Images are matched as strings. The
envelope names each once, in the form `docker pull` shortens it to, with a
tag or digest, and never by an image's ID: `sha256:<hex>`, `sha256:<prefix>`
or a 64-hex component in any part of the name is refused, by chase and by
frisket, since the daemon would run whatever local image has that ID, made
or loaded by anyone. chase's `prepare` writes a Docker Hub image's other
spellings (`library/postgres:18`, `docker.io/library/postgres:18`, …) into
the route. A registry is Docker Hub or one of a fixed few public ones
(`ghcr.io`, `quay.io`, `gcr.io` and its regions, Artifact Registry's
`*-docker.pkg.dev`, …) whose names no project controls, and nothing else:
the daemon would pull from the host's own loopback by an address, by
`localhost`, or by any name `/etc/hosts` gives it, a project's `.internal`
name among them.

**9. Ownership is by project, named by the checkout's origin, and stamped
by frisket.** The project is `owner/repo`, lower-cased, from the checkout's
origin on GitHub (`git@github.com:`, `ssh://git@github.com/` or
`https://github.com/`, with or without `.git`). chase derives it on the host
in `approve` (`project` in internal/envelope), and never with a git that
reads the checkout's config, which a session can write and which can name
a command for git to run: the checkout is found from where the directory is
(`chase checkout`), and `chase origin` reads `remote.origin.url` from its
`.git`'s config files alone, as the selector does, refusing one that
includes another. Never `git config --local`, and never git's
`--show-toplevel`, which `core.worktree` moves. The origin must be exactly
one URL: none, or two, names no project.

A tier's `checkouts` pin it both ways: a pinned project only at its own
path, and a pinned path only as its own project, compared by the checkout's
real root. And only from the repository kept at that path itself — its own
`.git`, or a worktree of it — or in its `.bare`: a clone nested under a
pinned path writes its own `.git`, origin included. A project no tier pins
is a claim, shown in the approval, which a person approves. It goes into the
approved envelope as `dockerProject`, so a changed origin is a diff someone
approves, and from there into the Docker route of the session's own policy
document as `docker.project`. A checkout with no usable origin gets no
Docker: its launch is refused. Never from what the envelope says: a project
that could name itself could name another, and an envelope's own
`dockerProject` is dropped.

frisket adds `frisket.project=<owner/repo>` to every `ContainerCreate`,
`NetworkCreate` and `VolumeCreate` it admits, refuses any client label under
`frisket.`, and admits an operation on an existing object only after the
daemon says it carries that label — reads as well as writes. It then acts on
the container's or network's full ID, so what was checked is what is acted
on; a volume or network named by name is held, across frisket's sessions,
from its check until the daemon answers. Lists and `/events` are answered
only with the project's objects: frisket merges its label into their filter.

By project, because shop's volume is meant to outlive a session, and
every worktree of a repository shares one set of names and ports anyway.
*Rejected:* adopting objects without the label. A volume the host user made
by hand is his, and a session given it could delete it; `up` fails with a
refusal naming why until it is removed. *Rejected:* `COMPOSE_PROJECT_NAME`.
Compose's default, the directory's name, is already stable.

**10. A missing object's 404 passes through; one not the project's is
refused.** Compose inspects a network and a volume before creating them;
frisket's own lookup answers `404`, and frisket gives the client that answer
without forwarding the request. An object that exists without the label is a
`403`. That tells a session whether another project's name exists, which a
create's `409` would tell it anyway, and it is what tells a person why `up`
failed.

**11. Exec, attach, logs and the rest of Compose's own flows are allowed on
owned containers.** `ExecCreate` with `Privileged` false; the command is not
restricted, since the container itself holds nothing of the host.
`ExecStart` and `ContainerAttach` may upgrade to `tcp`, and nothing else may
upgrade. Also admitted behind ownership: `Logs`, `Wait`, `Kill`, `Restart`,
`Rename` (Compose recreates a changed service by renaming the old one), the
two resizes, and `/events` filtered to the project. Everything else is
refused: build, commit, export, image save, load, tag and push, archive
(`docker cp`), update, prune, plugins, swarm, secrets, configs, `/system/df`
and `/info`.

**12. A published port is the project's, on the project's own loopback
address.** Each project has an address in `127.0.0.0/8`, derived from its
name (decision 14). A `HostIp` that is empty, absent, `0.0.0.0` or
`127.0.0.1` is rewritten to it. The address itself is accepted. Anything
else refuses, IPv6 included: the daemon would bind `::` beside `0.0.0.0`,
and a v6 address is not the project's. The `HostPort` must be one the
envelope names in `chase.bindings.docker.ports` (1024 to 65535, at most 64,
never frisket's own 15001), never a range or a random one. Two projects that
both use 64320 now publish it at two addresses, and neither reaches the
other's.

A session reaches its ports at `127.0.0.1:P`, as the Compose file's
`localhost` expects, and at `[::1]:P` and the project's address. It does
this through frisket, not flong. A connection to one of those, for one of
the project's ports, is steered to frisket as a DNS query is, by the
session's own ruleset. frisket then relays it to the project's address on
the host, at the same port, and to nothing else. Before each dial it asks
the daemon whether a running container with the project's label publishes
exactly that address and port, and refuses the connection if none does.
Without that, the host's `<address>:P` is answered by anything bound to
every address on P while the project's container is down: a host Postgres,
or another session's listener that pasta republished as `*:P`. The relay
has no idle limit, since a database pool keeps idle connections open for
hours. Each connection is one log line, like any other. The ports come
from the Docker route in the session's policy document. Nothing new listens
in the session, so pasta's `-t auto` has nothing to republish.

*Rejected:* relaying on steering alone. What answers `<address>:P` on the
host is whichever socket the kernel picks, and a wildcard one is there
whenever the container is not.
*Rejected:* flong's `hostPorts`, given at launch by a hook, with a range per
tier. `-T` reaches only the host's `127.0.0.1`, which every project shares.
*Rejected:* frisket listening in the session on `127.0.0.1:P`. On a tier
with `forwardPorts = "auto"`, pasta republishes the listener as the host's
`*:P`, and then the daemon cannot bind the project's address (Findings).
*Rejected:* refusing an empty `HostIp` and asking projects to write the
address. Rewriting changes nothing for the project; refusing changes
shop's Compose files for everyone.

**13. frisket changes the request on this route, and says so.** Its
decision 13 — what goes upstream is what was read — gets a written
exception: on a `docker` route frisket forwards its own encoding of the
query and body, puts a verified full ID in the path, names each network a
created container attaches to by the full ID it checked rather than by
name, stamps its label on what is created and into list filters, binds an
unspecified or loopback published address to the project's own, and caps
the `Api-Version` it answers. Each only narrows what the daemon is asked,
and each is logged.

**14. A project's address and names are a function of its name, computed
the same way everywhere.** Take the project's `owner/repo`, lower-cased, and
its SHA-256 as 64 lower-case hex digits. The address is `127.b1.b2.b3`, from
the first three bytes. If `b1` is 0 (`127.0.0.0/16`, where `127.0.0.1`
and the host's resolvers are), or the address would be `127.255.255.255`,
hash the 64 hex digits again and take bytes from that result. Repeat until
the address is allowed. frisket does it in Go, in its public `docker`
package, and refuses a route whose address is not the one the project gives.
chase calls those same functions (`chase docker-address`), so there is
nothing of its own to drift. What has only Nix to evaluate cannot call them:
nix-config derives the address and names through chase's `lib.docker`
(`lib/docker.nix`, `builtins.hashString` and `lib.fromHexString`), and
chase's `docker-address` check holds it to what the binary gives.

| project | first bytes | address |
|---|---|---|
| `example/shop` | `65 aa ab` | `127.101.170.171` |
| `example/billing` | `0a 92 d6` | `127.10.146.214` |
| `danielbodart/frisket` | `67 ca ea` | `127.103.202.234` |
| `test/repo-66` | `00 80 2f`, then `d3 12 4b` | `127.211.18.75` |
| `bodar/bodar.ts` | `64 54 63` | `127.100.84.99` |

The names come from the repo part. It is lower-cased; every character
outside `[a-z0-9-]` becomes `-`; and leading and trailing `-` are trimmed.
A repo that leaves nothing, or more than 63 characters (the longest a DNS
label may be), has no names; its address still works. The short name is
`<repo>.internal`, `shop.internal`; the long one is
`<repo>.<owner>.internal`. A name that equals or falls under a reserved apex,
`frisket.internal` or `google.internal`, is never given: frisket's route host
`docker.frisket.internal` and `metadata.google.internal` are names of their
own. So `frisket/frisket` and `google/google` have no names,
`danielbodart/frisket` has only `frisket.danielbodart.internal`, and
`frisket/foo` has `foo.internal`, and `google/shop` has
`shop.internal`. frisket owns that list: `docker/reserved.json`, which its Go code embeds
and its flake exports as `lib.docker.reserved`. chase's binary has it
through frisket's `docker` package, and its `lib.docker` (`lib/docker.nix`)
reads it from its frisket input; the `docker-address` check holds the two
to the same answers.
nix-config derives its names through chase's `lib.docker` rather than
a copy of the rule.
Neither is unique: two owners can share a short name, and because `.` and
`_` fold to `-`, `bodar/bodar.ts` and `bodar/bodar-ts` share a long one.

In a session, frisket's DNS answers both names with the address, but only
for the session's own project, and before the allowlist rather than by
adding to it, so neither name is looked up upstream or reaches egress's
resolved set. frisket does not fence `.internal`: any other name under it,
another project's included, is an ordinary name and goes wherever the
tier's allowlist sends it. On a tier that allows `*`, `billing.internal`
is looked up upstream, and on the host's resolver `/etc/hosts` may answer
it; on a tier that does not allow it, it is `NXDOMAIN` and never leaves the
host. That is no reach into another project: the address it gives is not
steered to, and a session's connections go only to its own project's
address.

On the host, the names are only those nix-config knows. It writes
`networking.hosts` for every project in `home/repos.nix` and the tiers'
pinned checkouts, with only the names exactly one of them gives, short or
long, and writes the same map to `/etc/chase/docker-hosts.json`. chase
prints the address and names in the approval, in `chase shell`'s banner, and
from `chase docker`, and calls a name a host name only when that file gives
it this project's address. Otherwise it says to use the address: a name
missing from `/etc/hosts` would be asked of the upstream resolver, which a
hostile network answers.

No two projects on one host share an address. By accident, among 30
projects, the odds are about one in 40,000, and nix-config asserts that the
projects it knows do not. On purpose it takes seconds: 24 bits can be
searched for a repo name that lands on shop's address. So an address
is first come, first served on each host. `approve` keeps
`~/.local/state/chase/docker/addresses.json`, which project was first
approved at each address, written by nothing else and pruned only by hand.
It refuses a project whose address another holds there, among the projects
the tiers pin, or in `/etc/chase/docker-hosts.json`, whose addresses are
read as given, not derived again. It checks before anyone is asked and
again once the envelope is approved, and only then records the project: one
refused approval holds no address. frisket refuses to open a session
whose address a live session of another project holds. And the relay's
ownership check keeps a session from reaching another project's container
even so.

*Rejected:* handing addresses out, at approval or at launch. A hash needs no
allocation, and gives each project the same address on every machine;
`addresses.json` only remembers who came first, and holds nothing a new
machine needs.
*Rejected:* asking the resolver (`getent`) whether a name is on the host.
For a name `/etc/hosts` lacks, that is the upstream lookup a hostile
network answers.

**15. Docker is steered only where the steering file allows it.** The
steering file's ruleset gains two sets, `relay4` and `relay6`, which are
empty unless a session fills them. When frisket opens a session, it answers
with the session's relay destinations: the address and ports in its Docker
route. `frisket steer` adds them to the sets in the same `nft -f` that
loads the ruleset. The sets live in the session's namespace and die with it.
A restored session keeps its ruleset. A restored session whose document has
since dropped a port refuses connections to it.

## How it was built

1. **frisket: the Unix upstream and the Docker route** — its carve-out
   from decision 13 first, then a deferred verdict for any body, the body
   tables and floor, the route over the daemon's socket on HTTP/1.1 with
   versions, queries, upgrades, images and lists checked, ownership by the
   daemon's own report of the label, and an exec stream carried both ways
   past a half-close.
2. **frisket: the relay** — the `relay4` and `relay6` sets in
   `lib.steering`, filled by `frisket steer` from what `open` answers;
   `open` refusing an address another project's live session holds; and
   `internal/relay`, which sends a steered Docker port to the project's
   address only while the daemon reports a running container of the
   project publishing it there, and otherwise logs `no owned container
   publishes it`.
3. **frisket: the names** — its DNS answers exactly the session's own
   `.internal` names, from its Docker route, before the allowlist and never
   upstream; every other name, `.internal` or not, follows the allowlist as
   before. A route whose address or names are not the ones its project
   gives, or whose names equal or fall under a reserved apex, is refused.
   The reserved apexes are `docker/reserved.json`, exported as
   `lib.docker.reserved`.
4. **chase: the generator reads Swagger 2.0 YAML**, and writes every body
   field the spec knows (`apps/docker/known.json`); the hand-written tables
   (`apps/docker/fields.json`) are checked against it, and
   `apps/docker/admit.json` names the admitted operations.
5. **chase: the project's identity**, read from the checkout's `.git` by
   `chase origin`, never by a git that reads its config, bound both ways to
   the tiers' pins, approved as `dockerProject`, and first come, first
   served for its address (decisions 9 and 14). Its address and names are
   frisket's own `docker.Address` and `docker.Names`, printed by
   `chase docker-address`, and `lib.docker` in Nix.
6. **chase: `apps/docker.nix`** — `chase.tiers.<tier>.apps.docker.enable`,
   only on a direct-egress tier that takes envelopes;
   `chase.bindings.docker.images` and `.ports` in the envelope; the route,
   prepared per launch with the project, its address, names, images and
   ports, by an app with no credential; the Docker CLI and Compose in the
   container, and `DOCKER_HOST`, `DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH`
   in the session.
7. **chase: where it is** — the address and names in the approval, in
   `chase shell`'s banner, and from `chase docker [DIR]`.
8. **nix-config: `networking.hosts`** for the projects it knows, and
   `/etc/chase/docker-hosts.json` saying which names it wrote; and
   rootless Docker for the user.

flong needs nothing: no hook, no `hostPorts`, no range per tier.

## Test plan

Each of these refused, and logged with the rule and the field that refused
it: `ContainerCreate` with a bind path, `~` or `./x` in `Binds`, a `bind`
mount, `Privileged`, `CapAdd`, `NetworkMode` `host`, `""` or absent,
`MaskedPaths: []`, a `syslog` log driver, `restart: always`, an image not in
the list, a published port not in the list, or on `10.0.0.1`, `127.0.0.2`,
`::` or `::1`, a `frisket.` label, and `privileged` in lower case;
`VolumeCreate` with a bind through driver options; `ImageCreate` of an image
not in the list, or with `fromSrc`; `ExecCreate`, `ContainerStop` and
`VolumeDelete` on an object without the project's label; `/build`,
`/images/{name}/push`, `/containers/{id}/archive`; `/v1.57/…` and
`/V1.55/…`. And admitted: the whole capture, in order, with the exec streams
carrying `pg_isready`'s and `psql`'s output; a recreate after the Compose
file changes; attached `up`; and a cold pull. An empty, `0.0.0.0` and
`127.0.0.1` `HostIp` each reach the daemon as the project's address.

In a session: `psql -h localhost -p 64320`, `-h ::1` and `-h
shop.internal` all reach the container, and each is one `relay` line.
`127.0.0.1:64330`, a port the project does not name, reaches nothing and is
not steered. With shop's container down and a host listener on
`0.0.0.0:64320`, `127.0.0.1:64320` in the session reaches nothing, and the
line says `no owned container publishes it`; the same for a container of
another project, or one not running. A relayed connection left idle for more
than ten minutes is still open. `billing.internal` is not answered by
frisket itself: its line records the allowlist's decision, and it never
resolves to shop's address. `approve` refuses a project whose address
`addresses.json` gives another, and frisket refuses to open a session at an
address another project's live session holds. `approve` gives no Docker to a
checkout with no origin, or two, or one not on GitHub; to a pinned path
whose origin names another project, a pinned project found at another path,
or a clone nested under a pinned path; and runs no command the checkout's
config names while it looks. The names are frisket's vectors:
`danielbodart/frisket` has only `frisket.danielbodart.internal`,
`google/shop` only `shop.internal`, `frisket/frisket` and
`google/google` none, and `frisket/foo` has `foo.internal`. A second
session, of another project, cannot reach `127.101.170.171:64320`: nothing
steers it there, and the session's own loopback has nothing on it. On a tier
with `forwardPorts = "auto"`, the host has no `*:64320` while the session
runs, and `docker compose up` binds `127.101.170.171:64320`. On the host,
`shop.internal` resolves to `127.101.170.171`, and `chase docker` lists it
as a host name; for a project nix-config does not know, it says to use the
address.

## Open

- **Worktrees of one repository share containers, volumes and ports.**
  Concurrent sessions in two of them see one database, and one's `down -v`
  removes the other's.
- **Any session's listener on P, in any project on an auto tier, takes the
  host's `*:P`.** pasta's `auto` republishes it within a second, and a
  wildcard socket accepts every `127/8` address. Every project's later
  publish of P then fails with the daemon's `address already in use`, and in
  the other direction a Docker publish of P keeps pasta from forwarding P for
  sessions started later. A host process bound to every address on P does
  the same. A session's own listener on P is also never reached from inside
  it, because P is steered to frisket.
- **On the host, that is interception.** While shop's container is down
  (before `up`, or during a recreate or `down`/`up`), a host tool that dials
  `shop.internal:P` reaches whichever auto-tier session listens on P, so a
  host `psql` would send its login and queries to another project's server.
  Sessions are safe, since the relay checks ownership; the host's own tools
  do not go through frisket. The fixes are to forbid `forwardPorts = "auto"`
  while any tier has Docker, or to exclude a Docker port range from `auto`
  with pasta 2026_07_16. Neither is taken yet; this is the user's call.
- **Between the relay's check and its dial**, the container could stop and
  a wildcard listener take its place. The window is the lookup's round
  trip.
- **Anyone on the host reaches a project's containers.** The project's
  address is on the host's loopback, like everything else published there.
  It keeps projects' sessions apart, not the host's users.
- **Addresses are first come, first served per host.** A project whose
  address another approved first cannot have Docker on this host until a
  person edits `addresses.json`. The projects the tiers pin and those in
  nix-config's `/etc/chase/docker-hosts.json` are always held, so they win.
  A tier that pins a project's path makes its address the project's even
  before its first approval.
- **A `.internal` name not in `/etc/hosts` goes to the upstream resolver**,
  on the host and in a session whose tier allows it. chase never prints such
  a name as a host name, but a person can still type one. `.internal` is
  reserved for private use, so no public resolver should answer it, but
  nothing here stops the query leaving.
- **frisket's `15001` is republished too.** A trusted session's pasta should
  publish the host's `*:15001` for it, by the measurement above; this was
  not seen on a live session. It answers nothing, since a connection that
  dials the listener is refused, but the host's port is held while the
  session runs.
- **What frisket cannot see.** Containers run outside flong: their DNS is
  not frisket's, they have no pids or memory limit unless the project sets
  one, and their egress is the user's.
- **A project's containers reach every host listener bound to all
  addresses, and its session does not.** The rootless daemon's slirp4netns
  refuses only `127/8` and its gateway (`--disable-host-loopback`). A
  container that dials one of the host's other addresses, such as its LAN
  address, leaves through slirp4netns as a connection by dan and arrives on
  the host's loopback, past the firewall. Measured: a `postgres:18`
  container on a user-defined network reached a host listener on
  `0.0.0.0:47123` at `10.0.0.219`, while a session namespace built the way
  flong builds a trusted one (`pasta --config-net --no-map-gw`) was refused
  at the same address, because pasta copies the address into the session
  and the session dials itself. So project A's containers, with the image
  and command from A's envelope and Compose file, reach the host's wildcard
  services that the LAN is firewalled from, other auto-tier sessions'
  forwarded `*:P` listeners (another project's dev server) and frisket's
  `*:15001`. rootlesskit's pasta driver does not close it: it gives the
  namespace `10.0.2.100`, not the host's address, so the same probe still
  connected, and its only port driver, `implicit`, publishes
  `127.101.170.171:P` as the host's `0.0.0.0:P`, which would undo each
  project's address. A firewall rule for the daemon's traffic has nothing
  stable to match: its cgroup's ID changes on every restart, and
  `IPAddressDeny=` and `NFTSet=` do nothing in a user unit (measured:
  `IPAddressDeny=any` in `systemd-run --user` still connected). Not fixed
  yet.
- **Inspect shows host paths** — `GraphDriver`, a volume's `Mountpoint`,
  `LogPath` — as information, not access.
- **An image's own labels count as the container's.** A container dan runs
  by hand from an image that carries `frisket.project=…` would be that
  project's.
- **Compose's labels are not checked.** A session can make a container
  carrying another Compose project's name, which dan's own `docker compose`
  outside a session would then take for its own.
- **What shop does that is refused.** Every `test_ci` and `docker run`
  of a locally built image needs `docker build`; `docker cp` needs archive.
  Neither is planned.
- **Only a session's own names are answered by frisket,** and the host's
  `/etc/hosts` is not the container's. A tool in a session that names
  another project's containers gets whatever the allowlist and the upstream
  resolver give; even an address, it cannot reach, since nothing steers it
  there.
- **pasta after 2025_09_19 may differ.** flong's own lock has 2026_07_16,
  which has `-T` to an address and `auto` with exclusions. In a short test,
  it did not republish a loopback listener at all. This design does not
  depend on either version.
- **The route host's name.** `docker.frisket.internal` is a placeholder.
  It is under the reserved apex `frisket.internal`, so renaming it there
  changes no project's names.
