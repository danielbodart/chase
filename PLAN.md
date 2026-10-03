# chase — plan

> A *chase* is the iron frame that locks a page of composed type together, so
> the whole forme can be lifted and printed as one. flong casts the plate;
> frisket decides what the sheet is allowed to take; chase is what holds the
> page.

chase is agent policy: the tier a checkout is sorted into, the wrapper that
sorts it, the apps a sandbox is given, and the credential each of those needs.
It is being extracted from `nix-config/modules/agents`, where it works today.

Named in frisket's PLAN.md, decision 7, before there was anything to name:

> Agent policy — tiers, trusted checkouts, workspace groups, the agent
> wrappers — is a fourth thing and stays in nix-config. The printing name for
> it, if it is ever extracted, is **chase**: the frame that locks the type
> together so the page can be printed.

## Why a separate flake, and which way the arrows point

The reason is not tidiness. It is that a project must be able to say what it
needs without depending on the machine it is being worked on.

```
                 chase
                ↑     ↑
        nix-config     a project's chase.jsonc
```

Neither depends on the other. nix-config imports chase's module; a project
writes a grant in the vocabulary chase reads, and depends on nothing at all
— not a flake, not chase's source. The machine's configuration is private,
host-specific and no business of a project's — and a project is no business
of the machine's either.

**The machine never enumerates projects.** It knows the *shape* of what it will
find, not which projects exist. This is the distinction between an eval-time
dependency (nix-config lists the project in `flake.lock`) and a runtime one
(the launcher reads whatever directory it was started in). `chase tier`
already works the second way: it reads the checkout's origin at launch
rather than holding a list.

## Locked decisions

**1. Four layers, each ignorant of the next.** Extends frisket's decision 7,
which names three.

- **flong** gives a sandbox a network and a hook around its lifecycle. It knows
  nothing about frisket.
- **frisket** holds the credentials and puts them on the wire. It knows nothing
  about launchers.
- **the adapter** maps frisket onto flong's hooks. It stays in frisket, as
  `frisket.nixosModules.flong`, tested in frisket's CI against a pinned flong,
  because it is where the security properties meet and nothing else tests it.
- **chase** is agent policy. It knows about flong and frisket; neither knows
  about it.

The adapter and chase both know about both projects, differently: the adapter
is a *mechanism* the two must agree on — an ordering contract — and chase is
*policy* built on top of it. Only the second belongs here.

**2. A launcher has exactly the caller's privilege; the approver is the
gate.** flong's sessions are rootless: no sudo, no setuid, no root anywhere.
Every step of a launch — `workspace`, `binds`, `guard`, `seccompPolicy`,
`exec`, `postStop` — runs as the user who started it, and the launcher
itself is only a way of doing what that user could already do by hand. So
there is no privilege for a project to reach by building a launcher of its
own, and nothing to protect by pinning one's store path: a launcher a project
built can do no more than the caller running bwrap directly.

What stops a checkout from widening its own sandbox is therefore not who runs
the launcher but what the launcher applies. A project's grant is read
at launch, and nothing it says — an app's settings, a secret,
a syscall it wants back — takes effect until `chase.approver` has shown a
person the change and they have said yes (decision 17). `guard` stays, as a
consistency check between the wrapper and the launcher rather than a gate:
it catches a launcher started by hand on a checkout the wrapper would have
sorted differently.

The grant is data, and the launcher still validates it: chase refuses a key
it does not define and a value its field may not hold (decision 10), and
flong refuses a syscall name systemd does not list.

**3. Apps declare their credentials; they never reach for one.** An app says
*"github needs a credential of this shape"*. What binds it is the consumer:
nix-config binds a sops secret, a project binds its own decrypted file. An app
that hardcodes `/run/secrets/...` cannot be used by a project, which defeats
the point of extracting any of this.

The same holds for anything else an app needs — a host port, a bind, an allow
entry. The app declares, the consumer binds.

**4. Declared but unbound refuses; it never degrades.** frisket treats an empty
`credentialFile` as a legitimate route with no credential, so an app whose
credential was never bound would quietly become a scope-only route instead of
an error. That is the failure `DisallowUnknownFields` already exists to
prevent in frisket's own config loader: *"a misspelt key in a policy is a rule
that silently does not apply."*

**5. Trust is the machine's decision; capability is the project's.** A checkout
cannot be asked whether it is trustworthy, so which tiers exist and what sorts
a checkout into each — every tier's `match` — are the machine's. What a project
may then *ask for* is the project's to declare. Two different questions.

Note this does not put a project list back on the machine: a rule can sort by
owner and first-commit authorship, so projects are not enumerated in the
common case. Rules naming a single repository are exceptions.

**6. Per-project scoping is per-project credentials, not per-project matching.**
The strongest scope is one the provider enforces: a Cloudflare token minted for
one zone cannot touch another, whatever any matcher does or fails to do.

Three layers, cheapest and strongest first:

- **the token's own scope** is the floor — what the credential *cannot* do,
  enforced by the provider, and no bug here can undo it
- **the route's paths** are the policy — what this project *may* do with it
- **the confirmation gate** is the human — which of those needs a person

They are not substitutes. A correctly scoped token still deletes everything
inside its own scope, which is why the gate exists; and the gate is only ever
as good as its matcher, which is why the token's scope is underneath it.

**7. A project's secrets are checked in encrypted and decrypted outside the
workspace.** The ciphertext lives in the project, where it belongs and where
the agent may read it harmlessly. The plaintext is written somewhere the
session is not bound — never into the workspace, which is bind-mounted
read-write — and only frisket reads it. The sandbox holds the placeholder.

Recipients follow the decryption time: launch-time decryption is done as the
user, so project secrets are encrypted to **admin** keys, not host keys. A
machine alone cannot decrypt a project's credentials; the developer at the
keyboard can. (Activation-time decryption via sops-nix would need host keys,
and is the wrong shape here because it requires the machine to know the
project.)

**8. Report, do not refuse, what cannot be prevented anyway.** Inherited from
the existing selector, which reports a workspace group member's tier rather
than refusing it, *"because vendoring the same code into the workspace would
bypass a refusal anyway"*. A grant that opened a host port, or a project
secret that was decrypted, is printed at launch. The human sees what was
applied.

**9. There is never a system-level cloud account.** Cloudflare and gcloud
credentials are project-scoped by design, not by accident of not having set
one up yet. A machine holds no Cloudflare login; a project holds one minted
for itself, scoped to what that project owns. talebrary is the first, on
Cloudflare, with an account scoped to its zone.

This is what makes decision 6 more than a preference: there is no broad
credential to fall back to, so a project either has a narrow one or has none.

**10. A grant is data, not a program.** A project's grant is `chase.jsonc` at
its root: JSON with comments and trailing commas, which chase reads and never
runs. chase decodes it into a fixed schema that refuses a key it does not
name, and checks each value — an image in the one spelling frisket compares,
a port in range and named once, a syscall's name — so a misspelt key or a bad
value refuses the launch rather than quietly applying nothing (decision 4).
The project never loads chase, so there is no version to drift: it names
fields, and the machine's chase says what they mean.

This replaces a NixOS module, `chaseModules.default` in the project's flake,
evaluated against chase's options. That was chosen while chase was Nix, for
the module system's unknown-option check and typed options. Once chase was
Go, the module system was only a cost. Evaluating a flake fetches its inputs,
and an input can be any file of the user's or any URL, so the flake's own
files had to be approved before anything ran — and a module can import other
files, so what it evaluated to had to be approved again. Two dialogs for one
change. A module could also declare an option chase already defines, with a
type or an `apply` of its own, to put a value past chase's check, so every
check had to be written to survive that. A data file has none of this: what a
person approves is what is applied, and one dialog covers it (decision 17).
Nothing a project has used needs computing. If a grant ever does, the
project generates `chase.jsonc` and commits the result, which is then what is
approved.

Read as the caller, like everything else in a launch (decision 2).

**11. The launcher reads the grant; direnv is not the trigger.** It is
tempting to have `cd` into a project build the grant and the launcher read
the result. It does not work: direnv's hook only fires in a shell that
reaches a prompt, *"which no editor, script or coding agent has"* —
nix-config's own note on why containers get nothing from it. A launch from
an editor would silently get no grant.

So the launcher reads the checkout's `chase.jsonc` itself and is
self-sufficient. A project with no `chase.jsonc` costs a stat, which is the
ordinary case.

**12. chase ships the machinery, not the tiers.** A tier is a name and what it
is — a container, its network, its filter, its apps, how their writes are
answered — or `bare`, no sandbox at all. What puts a checkout in one is the
tier's `match`: rules made of predicates (`paths`, `checkouts`, `repos`,
`owners`, `rootAuthorDomains`), each a question the selector can ask of a
directory. Tiers are asked in `chase.order`, first match wins, and
`chase.fallback` takes what nothing matched and whatever the selector could
not sort. All of it is the consumer's configuration; chase knows no tier by
name.

A predicate says nothing about how far its answer should be believed. A path
cannot be forged; a remote, an owner and a first commit's author can. Which
predicates are enough for which tier is the tier's author's call, and chase's
job is to make it visible in one place — the machine's own tier definitions —
rather than to make it for them. There is one exception, where getting it
wrong has no recovery: the fallback cannot be bare, because what nothing
vouched for has to run in a sandbox.

A bare tier exists for work that needs the host: real sudo, `/dev/input`, KVM,
the network namespaces themselves. Root defeats every boundary flong or
frisket could draw around it — including the credential one, since frisket's
credential files are the user's own and a process with sudo simply reads
them, and since a netns can be left with `nsenter`. So there is nothing that
containerising such work would buy, for as long as it has root.

**13. A tier for other people's code takes no grant.** `grants` is a
tier's switch, and a tier that runs code nobody vouched for leaves it off: it
has no network to open a port on, and "nothing local is reachable" is the
whole of what such a tier is for. A project that ships a grant and is
sorted into it has it ignored.

**14. An app declares a credential's shape; a consumer binds its source.**
Nothing above frisket mentions files. frisket already has the vocabulary for
shape — a bearer token, Basic with a fixed user, a bare header, a field at a
dotted path in a JSON document, and an expiry beside it. An app names the shape
it needs.

What varies is the *source*: a sops secret the machine decrypted at activation,
a project's own file decrypted at launch, a path. chase materialises whichever
into a file, and only because that is frisket's interface — it reads the file
on the host and re-reads it on rename, which is how a rotated credential
reaches a running session.

**15. Reaching the host is `hostPorts`, and it is the shareable direction.**
flong has two: `hostPorts` lets a session reach a port on the host's loopback,
and `forwardPorts` publishes a session's port on the host. A grant uses the
first. The second is exclusive — *"a host port is one session's at a time. A
second concurrent session asking for the same one fails to attach its network,
and is ended rather than left running without it"* — and many sessions of one
project run at once, so a project that declared a forwarded port would break
its own second session. Reaching a dev server *inside* a sandbox is a separate
problem and frisket's open question 3.

Docker sets `hostPorts` aside ([docs/docker.md](docs/docker.md), decision
12). `-T` reaches only the host's `127.0.0.1`, which every project shares, and
a project's containers publish on its own loopback address instead. Its ports
reach the host by frisket's relay: the session's loopback steers each port
the grant names to frisket, which sends it on to the project's address and
to nothing else. flong is given no port for it.

**16. A port alone is not enough; the grant carries environment too.**
flong starts a session clean and direnv's hook never fires in it, so a session
with 5432 open still has no `DATABASE_URL` and nothing tells it to look. This
is why the grant is not a port list: ports and environment are the same
feature, and shipping one without the other opens a door nothing walks through.

nix-config's note that *"no tier that could use a devShell runs in one"* stops
being true when this lands, and wants rewriting.

Docker needs no environment beyond what its app sets: `DOCKER_HOST`,
`DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH`, which point the CLI and Compose at
frisket's route. A Compose file's `localhost` already reaches its ports,
through the relay, so a project names its ports and nothing else.

**17. Nothing of a checkout's takes effect until a person has approved it.**
The checkout is the agent's to edit, and nothing in it is hidden from the
session, so an agent could write a grant that widens its own sandbox. Each
launch therefore works on a snapshot of the checkout's tracked `chase.jsonc`,
and of the sops file it names, and approves once:

- **What it says, and what chase derives beside it.** The grant as chase
  reads it (decision 10), with the digest of its sops file and, for a grant
  that binds Docker, `dockerProject`: the `owner/repo` chase read from the
  checkout's origin rather than anything the grant says
  ([docs/docker.md](docs/docker.md), decision 9). If that is not what was
  last approved for the checkout, `chase.approver` is shown the difference
  and the launch waits for its answer. New ciphertext or a changed origin is
  a change like any other. A change that says nothing new — a comment, the
  order things are written in — asks nothing, and the comments never reach
  the dialog, so the project's words cannot argue for a change.

The approval runs before the session is built, in flong's `seccompPolicy`,
because a grant can name syscalls beyond its tier's filter, and a filter is
installed before anything in the session runs. The approved grant is staged
for `exec` under the session's name, which flong gives both, so two launches
of one checkout keep their approvals apart; `exec`, still before the session
is built, applies the rest — secrets, the policy document — without looking
at the checkout again, and hands what the grant exports and seeds straight to
the payload it prints, so nothing is written for a session to source. The
policy document is written for every launch, the tier's own for a checkout
with no grant, so frisket reads one path for every session of the tier.

A checkout with no `chase.jsonc` is the tier as it is, and is never asked
about. One whose `chase.jsonc` is not tracked is refused rather than passed
over: a grant that silently did not apply would be a session without what the
project asked for. Approvals live in `~/.local/state/chase/`, on the host and
bound into no session. Refused, the launch ends rather than running without
the grant. Working from the snapshot is what makes the approval mean
something: a session of the same checkout cannot change a file between the
approval and its use.

The snapshot is taken without running anything the checkout's config names:
which files are tracked is read from the index alone (`chase ls-files`,
internal/checkout), in an empty repository, never by `git ls-files` in the
checkout, whose `core.fsmonitor` is a command git would run; and each file is
copied (internal/snapshot) following no link above it, so a directory the
session made a link cannot bring a host file into what is approved and
decrypted.

This replaces decision 8's report for the grant itself: a line printed at
launch is easy to miss, and a dialog is not.

**18. Every app answers the same way: three classes, a tier's switch per
class, and a project's list by name.** Every operation an app knows gets one
of three classes, generated from the provider's own description as
[docs/cloudflare.md](docs/cloudflare.md) sets out, and with a reason for every
exception:

- **read**: a GET or HEAD. Allowed.
- **write**: anything else, and a read that mints a credential, which is a
  write reached by a read (Xet's write token). Asks.
- **guarded**: what cannot be taken back, or widens who can reach something:
  a DELETE by default, and by exception whatever else deletes, drops,
  transfers, makes public, or adds a collaborator, key or secret. A DELETE
  that is easily undone (a reaction, a label) is demoted to write by
  exception. Refused.

A request is answered by the most specific of these that says anything:

1. **The project, by name**: `apps.<app>.allow`, `.ask` and
   `.refuse`, each a list of operation ids, or methods and an exact path for
   an endpoint the description does not name. Any operation can be named,
   guarded ones too; the name is exact, and the list is part of what is
   approved (decision 17). One name in two lists is an error.
2. **The project, by category**: `"category:<name>"` in the same lists, the
   provider's own grouping (GitHub's `x-github.category`, Cloudflare's and
   Hugging Face's tags), so a project does not list thirty ids to allow its
   pull requests.
3. **The tier, for one app**: `chase.tiers.<tier>.apps.<app>.writes`,
   `.guarded` and `.unmatched`, each `allow`, `ask` or `refuse`.
4. **The tier, for every app**: `chase.tiers.<tier>.writes`, `.guarded` and
   `.unmatched`. An app that says nothing takes these, so a tier's posture is
   three lines, and one app differs from it in one more: git's writes
   allowed where Cloudflare's still ask.
5. **The defaults**: writes ask, guarded is refused, and anything unmatched,
   or that cannot be classified (a GraphQL document frisket cannot parse),
   asks, with the dialog showing what arrived. Not refused: when in doubt, a
   person decides.

**git is an app of its own, apart from github.** git's smart HTTP and LFS are
one app, `git`; GitHub's REST and GraphQL APIs are another, `github`, which
is what gh speaks. They share GitHub's credential binding but not their
switches, so a tier can let git push while gh's writes still ask. git's
operations are the protocol's, not GitHub's, so the app is ready for another
host when one is wanted.

**One way to say it.** There is no `push`: frisket's git rule admits
`git-receive-pack` because git's writes are allowed, and for no other reason.
No app keeps a switch of its own for what these three already say.

**A tier with no one to ask says so, and a project cannot loosen it.** A tier
for other people's code is `writes`, `guarded` and `unmatched` all `refuse`,
written out in the tier, not a conversion hidden in each app. frisket's asker is the machine's, not a
tier's, so there is nothing for a tier to be checked against: saying so is
what makes it so. An app without `authenticated` refuses all three whatever
its tier says.
A project's lists are ignored for both, and that is reported (decision 8):
such a tier takes no grant anyway (decision 13), and a project that needs
more goes into another tier, which is the machine's decision (decision 5), not
the checkout's.

This all resolves in chase: the tier's and the app's settings at eval, and a
project's lists at launch, against the tier's own policy document
(internal/policydoc). frisket gets rules that already say allow, ask or
refuse, and carries each operation's class and category only to show them. What frisket must add is the ability to name what it
cannot see in a method and a path: a GraphQL mutation by its field, the refs a
push updates, an LFS batch's operation. Each gets an operation id, so git,
GraphQL and LFS are listed, switched and named like any other app. GraphQL
has it: frisket reads the body, a query is a read, and each mutation is the
schema's operation of that name, generated as a REST operation is.

**Docker is not classed.** It is admitted per operation by
`apps/docker/admit.json`, reviewed as an exceptions file is, with a body
table for each body it admits; every other operation is generated as a
refusal, and nothing on its route ever asks
([docs/docker.md](docs/docker.md), decision 7). Its tier has only
`apps.docker.enable`, and a project names only its images and ports: an
operation cannot be allowed by name or category, since images are global and
one project's `ImageTag` would change what another's container runs.

**SSH is classed by a hand-written catalogue.** No machine publishes a
description of its commands, so `apps/ssh/operations.json` is written and
reviewed as Docker's admit.json is ([docs/apps/ssh.md](docs/apps/ssh.md)).
Its operations are answered by class and the tier's three answers, as here,
but a project's lists differ in four ways, each for a reason:

- **They are each machine's**, `apps.ssh.hosts.<name>.allow`, not
  `apps.ssh.allow`: one grant names several machines, and what may run on a
  gateway is not what may run on a build box.
- **They take command patterns** as well as ids, `docker compose ps **`: a
  machine's own commands are no catalogue's to name. A pattern has a space
  or a `*`, so it is never read as an id, nor an id as a pattern.
- **Some operations are an argument's**, not a command's: `find -exec`,
  `grep -r`, `apt -o`, every argument naming a secret. They only make a
  command stricter, never allow one, since a rule that allowed by an
  argument would allow whatever else the command said.
- **Allowing a category allows none of its guarded operations.** A category
  of commands is a topic -- `search`, `packages` -- not a danger, and what it
  guards runs something of the arguments' choosing (`find -exec`, `apt -o`):
  a project allowing `category:search` has asked for more searching, not for
  `find -exec`. Only its id allows a guarded operation, and asked or
  refused, a category is all of it. An HTTP app's category, the provider's
  own grouping, still allows all of it.

What a command is, chase reads by frisket's own matcher, its public
`execrule` package: the catalogue's tests decide commands with it, and what
a project's pattern ties or an argument operation overrules is put to it as
a command made to test it, rather than worked out by a copy that could
drift. So a grant's lists are checked against the catalogue when it is
approved, and again at launch, for one approved under an older catalogue.
Which variables a command may set in front of itself -- `LANG=C sort x` --
is the tier's `apps.ssh.env`, never a grant's: a name one program reads as
code makes every rule for it say less than it seems to, and that is the
machine owner's to weigh.
A tier may name machines of its own, `apps.ssh.hosts`, held to the
same checks and decided the same way, and only they say what logs in --
their own agent, key file or password file, or the machine's: a grant never
names a credential, since one naming a file to send as a password would
send any file of the user's to a machine of its choosing, and never one of
the tier's machines again. A tier with them and no grants is launched as
one that takes grants, for their routes, its checkouts' grants unread.

**19. Every app is configured the same way.** `chase.apps.<app>` is the
machine's: what an app runs, the credential it would use, the host files it
binds. `chase.tiers.<tier>.apps.<app>` turns it on with `enable` and may say
any of those again, for that tier alone. An app with a credential holds it
only where the tier says `authenticated`, and is read-only without: the
default is the stricter one, as everywhere else. Where an app keeps something
— an agent's history, a download — is its `scope`: `session`, `workspace`,
`tier` or `host`, `session` by default, each app offering the ones it can
honour. A tier's `caches` is the same choice for its tools' downloads. What
is kept on the host at `workspace` or `tier` is a store: a directory chase
makes and binds, and variables the module names; chase knows nothing of the
tools that use it. An app that asks before it trusts a checkout trusts it
only where the tier says `trust`, a bare tier's included, at launch: which
checkouts are trusted follows from what sorts them into a tier, not from a
list of paths kept beside it. No option means anything by being null: an
app is off or on, and a credential is bound or not.

**20. A recording finds what a grant needs; only a person starts one.**
Something is refused; `chase record --default allow claude` runs the same
checkout's tier again through its record launcher, the person does the one
action, and what the tier would have refused or asked about -- an operation
on a route, a command on a machine, a name off the allowlist, a syscall --
is let through and written down, then proposed as exactly the grant entries
that would give it, each in the list its answer says: `allow`, `ask` or
`refuse`, the same three words a person answers with when there is no
`--default` (Ask is what happens now, and what is proposed). Entries are what
was seen, never generalised, and a proposal changes nothing until `chase
record apply` adds it to `chase.jsonc` and the changed grant is approved as
any change is (decision 17). Recording is manual mode, guarded operations
included, and a call the tier's own `seccomp.deny` takes too: the tier is
the ready-made fit and the grant the tailored one, so a grant's `allow`
puts such a call back, as flong reads a project's lines over its
declaration. What no rule decides -- frisket's structural refusals, but
for a name on the local network, and flong's fixed filters -- stays
refused, and is reported. The record launcher is never a wrapper's, nothing in a checkout
selects it, its guard is the tier's, and what it records comes from the
environment of the person who ran it. A syscall is learnt from the kernel's
audit, by flong's `log` lines, and put down to the session in `chase
record` itself, by cgroup while the session lives: no hook runs while its
processes do. A recording that refuses everything learns no syscall, since
refused is what the filter does already. What a recording finds is widening
alone: one from scratch shows every call made, but does not yet propose
denying what the tier allows and the session never used. A name on the
local network, which frisket dials outside a recording only for a name in
its document's `lan`, is proposed for the grant's `network.lan` with the
ports it was dialled at. See [docs/record.md](docs/record.md).

## Recording: possible follow-ups (not decided)

Thoughts kept from the design of `chase record` so they are not lost. None
is decided or scheduled, and any may be dropped. frisket's PLAN.md keeps
its own (interception of names that are not routes', synthetic per-name
DNS, UDP and ICMP counts), which chase would turn into proposals as it does
the lines it reads today.

- **Narrowing.** A recording from scratch (`--base none`) already sees
  every call the session makes, so a proposal could also deny what the tier
  allows and the session never used -- a mould cut to what was done, tight
  where it can be and loose only where it must be. The same for network
  names. It needs a recording that is known to be complete, which seccomp's
  log is not quite: a burst can lose a call made once.
- **An eBPF recorder.** A root system service, filtered by the session's
  cgroup id (`bpf_get_current_cgroup_id`), keeping sets in kernel maps
  rather than a stream: every syscall, allowed ones too, with no audit
  flood or loss; files opened, read and written, which would let a
  recording propose binds and mounts as well; and every connect and send,
  UDP and the local network included. It would be the one recorder under
  every layer, frisket adding only HTTP's method and path. The kernel here
  has BTF and the BPF LSM. Its cost is a service running as root.
- **Templating paths.** A recorded path is proposed exactly as seen. A
  high-entropy segment (`/bot<token>/`, an id) could be proposed as a
  pattern instead, which a person would still see at approval.
- **What a recording on a direct tier misses.** The record launcher has no
  flong network, so forwarded dev-server ports and UDP are gone while
  recording, and what the host's daemons do for the session is unseen. A
  steering set that sent TCP through frisket and let UDP out directly,
  counted, would keep more of the tier's own behaviour.
- **One recording at a time.** Syscalls whose process is gone before its
  cgroup is read are put down to the session only when it is the sole
  recording; a per-user lock, or the eBPF recorder's cgroup ids, would make
  that exact.
- **A stacking asker.** Done outside chase and frisket, as galley
  (github.com/danielbodart/galley): zenity's command line, every question
  in one queue window. A machine's asker and approver use it when its
  socket is there; neither chase nor frisket depends on it.

## Considered and rejected

- **Per-project path matching in frisket, to scope a project to one zone.**
  Refuted by decision 6: a token minted for the zone is enforced by the
  provider and needs no matcher. Path rules are still wanted, for the
  confirmation gate and for read/write asymmetry, but not as the thing that
  keeps one project out of another's resources.

- **A NixOS module in the project's flake, `chaseModules.default`.** What
  chase first did, when chase was Nix and the module system was the
  validator it already had. Refused once chase was Go: a flake is a program,
  so approving it took two dialogs — its inputs before evaluation, its result
  after — and a module could re-declare chase's own options to get past their
  checks. The parser is now `encoding/json` and the validator Go chase
  already carries. Decision 10.

- **TOML, YAML or plain JSON for the grant.** Plain JSON has no comments,
  and a grant's reasons belong next to its values. TOML and YAML would each
  add a parser, and YAML many ways to write one value, to a path that runs
  before anyone has approved anything. JSON with comments is JSON once they
  are removed, so the privileged path parses only JSON. Decision 10.

- **nix-config importing a project as a flake input.** The arrow points the
  wrong way: it makes the machine enumerate its projects, pins each one in
  `flake.lock`, and makes a project's declaration unusable on any other
  machine. It also drags a private machine configuration into a project's
  dependency closure.

- **Moving frisket's flong adapter into chase**, on the grounds that chase is
  the layer that knows about both. Refused: the adapter carries the ordering
  guarantee — whatever `postStart` installs is in place before anything gives
  the namespace egress — and frisket's CI is the only thing that tests it
  against a pinned flong. A guarantee should be tested by the component that
  owns it, not by a consumer. Decision 1.

- **A host-declared ceiling on what a project's grant may ask for.** Built
  for a threat model a tier for your own code does not have. One already grants a
  real network stack with the host and LAN reachable; a declared loopback port
  is not a new surface, and the answer to an invisible change is decision 8,
  not a ceiling.

- **Hiding the project's grant from the session**, so only a person outside
  could edit it. The file is in the read-write workspace, and git can put an
  agent's version in place through a human's own checkout. Decision 17
  approves what the grant says instead, which covers every way it could
  change.

- **A Unix socket in the workspace instead of a host port.** Genuinely good
  where it works — a pathname `AF_UNIX` socket is governed by the filesystem
  rather than the network namespace, so a Postgres listening on one in the
  workspace is already reachable with no port, no egress rule and no collision
  between concurrent sessions. Not adopted as *the* mechanism because it only
  covers services that speak Unix sockets, which a dev server, an emulator or
  anything HTTP does not. Worth reaching for first in the cases where it fits.

## What moves out of nix-config

| | |
|---|---|
| `modules/agents/options.nix` | moves |
| `modules/agents/selector.nix` | moves — the selector (now `chase tier`), its predicates, the wrappers |
| `modules/agents/tiers/` | **stays**: which tiers a machine has, and what sorts a checkout into each, is its own (decision 12) |
| `modules/agents/apps/` | moves — claude, codex, github, dragoman, mise, audio |
| `modules/agents/default.nix` | **stays**: it is the instance, not the module |
| `frisket/nix/flong.nix`'s `caVariables` | moves here |

`default.nix` is `user = "dan"`, the tiers and the rules that sort into them —
the personal configuration, which is exactly what should not travel.

### Couplings to break first

- **`apps/github.nix`** reads `config.sops.secrets.gh_token.path` directly.
  Becomes a declared credential (decision 3).
- **`apps/claude.nix`** does `import ../../../home/repos.nix`, reaching out of
  the module into nix-config's tree for a personal repo list, and maps it
  through `${cfg.home}/Projects/${name}`. Two assumptions: that the list is
  nix-config's, and that projects live in `~/Projects`. Both go — nix-config
  passes paths.

  (What it does with them is unrelated to tiers: it sets
  `hasTrustDialogAccepted` in `~/.claude.json`, suppressing Claude Code's own
  folder prompt for checkouts this flake cloned. The word "trust" is doing
  double duty.)
- **`caVariables`** — the ~15 environment variables pointing a runtime's CA
  bundle at frisket's. Not a security property: a coverage list about which
  tool reads which variable, which drifts as tools change. frisket's contract
  is narrower and stays frisket's — *the CA is at
  `/etc/frisket/ca-bundle.crt`*. Which runtimes are taught to look there is
  chase's business.

## Required changes elsewhere

- **flong** — the network's port list computed at launch rather than at eval.
  Today `pastaPorts` is interpolated into the launcher at eval time, so a
  session's ports are frozen into the script. Wanted: the shape `binds`
  already has — a hook that runs per launch with `$workspace` exported. Generic;
  flong learns nothing about projects. *Partly overtaken:* `forwardPorts =
  "auto"` publishes whatever a session listens on, and a tier can use it, so a
  dev server needs no declaration. `hostPorts` — a session reaching the
  host's database, say — are still fixed at eval.
- **frisket** — *done, and wider than asked.* Every policy is a document a
  session names by path — the tiers' own under `/etc/frisket/policies`, a
  project's written by the launcher under `/run/user/<uid>/chase` — read when
  the session opens and again when it is restored. The control socket is
  the user's, and bound into no session, so what vouches for a project's
  policy is the approval that wrote it (decision 17), not who sent it.
- **frisket** — *done.* The confirmation gate on destructive requests (`ask`
  beside admit and refuse), so an irreversible operation stops at a dialog
  naming the real request line. What prompts is a callback frisket runs, not a dialog it
  owns; see [docs/cloudflare.md](docs/cloudflare.md), decisions 7 and 8. Separate from scoping: a correctly scoped token can still
  delete everything inside its own scope.
- **frisket** — decision 7 says three layers; it is four, and the chase line
  changes from *"if it is ever extracted"* to a pointer.

## Open questions

1. **How a credential's source is spelt**, given decision 14 settles that it is
   a source and not a path. The shapes are frisket's and already exist; what
   chase needs is the sum of the ways one can be *found* — and the two known
   members bind at different times, one at eval and one at launch.

   *Decided:* a project's credentials are one sops file in the project, the
   same kind nix-config keeps in `secrets/common.yaml` — structured, many
   secrets in one file, each under its own key, encrypted to admin keys. A
   project binds a credential by naming the file and the key. What remains is
   the exact option spelling beside a machine's plain path.
2. **Where a project's decrypted credential is written.** Outside the workspace
   is settled (decision 7), and so is the symmetry: whatever decrypts it
   chooses where it lives and is what removes it.

   The prior art is systemd's own — `LoadCredential` decrypts into a per-unit
   tmpfs at `$CREDENTIALS_DIRECTORY` and takes it away when the unit stops —
   and sops-nix does the same thing at activation scope. Neither fits directly:
   a flong session is a scope, not a service, and its credential has to be
   readable by frisket on the *host* rather than by the payload.

   `/run/user/<uid>/chase/<machine>/`: tmpfs, owned by the user frisket runs
   as, not bind-mounted into the session, and keyed on the name flong's
   `postStop` already receives. *Decided.* Note that neither of flong's existing
   directories works — `/run/flong/<container>-…` is the shared prepared-root
   cache rather than per-session, and the session's own `XDG_RUNTIME_DIR` is
   created *inside* the container, which is the one place this must not go.
3. **What `ask` matches on.** Answered for Cloudflare, and the answer is the
   pattern for the rest: derive the allowlist from the provider's own API
   description, pinned, and let anything not on it ask. See
   [docs/cloudflare.md](docs/cloudflare.md), and decision 18 for how the
   answer is chosen. Still open for providers that do not publish one. GitHub
   publishes three: REST as OpenAPI (`github/rest-api-description`, pinned by
   commit), GraphQL as a schema (`github/docs`, pinned by commit, and
   generated from as REST is: [docs/github.md](docs/github.md)),
   and git's smart HTTP and LFS as prose and JSON schemas in git's and
   git-lfs's own repositories. gh has none: what a command sends is what
   `GH_DEBUG=api`, or frisket's log, shows.
