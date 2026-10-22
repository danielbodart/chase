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

**10. A grant is data, not a program.** A project's grant is `chase.json` at
its root: strict JSON, `"version": 2`, which chase reads and never runs. It
has a section for each component that reads it — `frisket`, `flong`,
`signer`, `sudo` and `chase` — each in that component's own shape, every
one optional. chase decodes it strictly, refusing a key no section names,
and checks each value — an image in the one spelling frisket compares, a
port in range, a syscall's name, a field only the host may set — so a
misspelt key or a bad value refuses the launch rather than quietly applying
nothing (decision 4). What only the tier can say is checked by the
component it belongs to, at launch: frisket's section by frisket's own
project-layer check, merged over the tier's policy document; flong's by
`flong check --layer project`, against the tier's declaration; the
signer's by the signer, which reads it for itself on the host, and the
sudo gate's by the gate, likewise, merged over the host's own rules. chase's
own section holds only what no component owns: the sops file and its
digest, and what each app binds. The project never loads chase, so there is
no version to drift: it names fields, and the machine's components say what
they mean.

A tier is a layer of the same shape: `chase.tiers.<tier>.frisket`, `flong`,
`signer` and `sudo`, merged with RFC 7396's merge patch over what the tier's
other options and its apps make, as a project's sections are merged over the
tier's. The tier's own options -- `allow`, `writes`, `guarded`, `unmatched`,
`seccomp`, `forwardPorts`, the apps' -- are sugar for the commonest of it, and
a tier may set what a project's check refuses, a route's `ceiling` among
them. The result is what a project's section is merged over and checked
against: `/etc/chase/policies/<tier>.json` for frisket, `flong.chase-<tier>`
for flong. The signer's and the gate's are checked and kept at
`/etc/chase/layers/<tier>.json` until they read a tier's.

Before it, the grant was `chase.jsonc`, JSON with comments and trailing
commas, decoded into a schema of chase's own and translated, list by list,
into what each component reads. A launch still reads one for this release,
as the `chase.json` it migrates to, and `chase migrate` writes that file,
saying each comment it cannot keep.

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
person signs is what is applied, and one dialog covers it (decision 17).
Nothing a project has used needs computing. If a grant ever does, the
project generates `chase.json` and commits the result, which is then what is
signed.

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

**13. A tier for other people's code may take a grant, approved.** `grants` is
a tier's switch, and the machine decides it (decision 5). Leaving it off is
the stricter fit -- nothing a checkout ships loosens its sandbox -- but it
leaves one way to give someone else's project what it needs: move it to a
tier for one's own code, and give it everything that tier has. With it on,
the project keeps the tier, and what it needs beyond it is named entry by
entry -- a name to download from, a syscall its build makes -- as `chase
record` proposes, and nothing applies until a person has read the diff and
approved it. The approval is the boundary, not the tier: a checkout can write
its own `chase.jsonc`, and what it writes there is only ever a request. Its
lists for an anonymous app are still ignored (decision 18): there is no
credential to write with, and no one to ask.

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

nix-config's note that *"no tier that could use a devShell runs in one"*
stops being true with decision 21, for a tier that enables it, and is to
be rewritten there when nix-config does.

Docker needs no environment beyond what its app sets: `DOCKER_HOST`,
`DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH`, which point the CLI and Compose at
frisket's route. A Compose file's `localhost` already reaches its ports,
through the relay, so a project names its ports and nothing else.

**17. Nothing of a checkout's takes effect until a person has signed it.**
The checkout is the agent's to edit, and nothing in it is hidden from the
session, so an agent could write a grant that widens its own sandbox. Each
launch therefore works on a snapshot of the checkout's `chase.json`, its
signature `chase.json.sig`, and the sops file it names, and applies the file
only once a person has signed it:

- **What it says, and what chase derives beside it.** The file as chase
  reads it (decision 10), which holds, in chase's section, the digest of its
  sops file, `secretsSHA256`, and, for a grant that binds Docker,
  `apps.docker.project`: the `owner/repo` the checkout's origin names
  ([docs/docker.md](docs/docker.md), decision 9). Both are in the signed
  bytes, and a file that says other than the checkout does is refused, so
  new ciphertext or a changed origin is a change like any other; `chase
  sign` writes them, puts the file in its canonical form and signs it.
- **Who signed it.** `chase.json.sig` is a stock SSHSIG over the file's
  exact bytes, in the namespace `quoin-policy:<root>`, so a signature
  made for one checkout is no signature for another. A file whose
  signature verifies against `/etc/quoin/allowed_signers` launches with
  nothing asked. One that does not is put to quoin's signer, through its
  `policy-sign@quoin` extension, which shows the difference from the file
  git's HEAD signed, or the whole file when that does not verify, and the
  launch waits for its answer: signed, the signature is written beside the
  file and the launch goes on. A file not in its canonical form is refused
  before anyone is asked, and a file has no comments, so the project's words
  cannot argue for a change in the dialog.

The signature is checked, or asked for, before the session is built, in
flong's `seccompPolicy`, because a grant can name syscalls beyond its tier's
filter, and a filter is installed before anything in the session runs. The
grant is staged for `exec` under the session's name, which flong gives both,
so two launches of one checkout keep their grants apart; `exec`, still
before the session is built, applies the rest — secrets, the policy document
— without looking at the checkout again, and hands what the grant exports
and seeds straight to the payload it prints, so nothing is written for a
session to source. The policy document is written for every launch, the
tier's own for a checkout with no grant, so frisket reads one path for every
session of the tier.

A checkout with no `chase.json` and no `chase.jsonc` is the tier as it is,
and is never asked about. No approval is kept on the host: the signature is
the record of what a person agreed to, and it is committed beside the file.
Refused, the launch ends rather than running without the grant. Working from
the snapshot is what makes the signature mean something: a session of the
same checkout cannot change a file between the signature's check and its
use.

For this release, a checkout with only a `chase.jsonc` is approved as it
always was: its tracked file, read as decision 10's old schema, with its
sops file's digest and Docker project beside it, put to `chase.approver`
when it differs from what was last approved, in `~/.local/state/chase/`, on
the host and bound into no session; a change to comments or order asks
nothing. It is then applied as the `chase.json` it migrates to, and the
launch says to run `chase migrate`.

The snapshot is taken without running anything the checkout's config names:
which files are tracked is read from the index alone (`chase ls-files`,
internal/checkout), in an empty repository, never by `git ls-files` in the
checkout, whose `core.fsmonitor` is a command git would run; the file git's
HEAD signed is read from its objects alone, the same way; and each file is
copied (internal/snapshot) following no link above it, so a directory the
session made a link cannot bring a host file into what is signed and
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

1. **The project, by name**: `frisket.routes.<app>.operations` in its
   `chase.json`, a map of operation ids, or methods and a path pattern for
   an endpoint the description does not name, each to `allow`, `ask` or
   `refuse`. Any operation can be named, guarded ones too; an id the route
   does not have is refused, and the map is part of what is signed
   (decision 17). A map holds one answer for each.
2. **The project, by category**: `"category:<name>"` as a key of the same
   map, the provider's own grouping (GitHub's `x-github.category`,
   Cloudflare's and Hugging Face's tags), so a project does not list thirty
   ids to allow its pull requests.
3. **The tier, for one app**: `chase.tiers.<tier>.apps.<app>.writes`,
   `.guarded` and `.unmatched`, each `allow`, `ask` or `refuse`; or the
   project's own for the route, `frisket.routes.<app>.writes` and so on,
   which the merge puts in their place.
4. **The tier, for every app**: `chase.tiers.<tier>.writes`, `.guarded` and
   `.unmatched`. An app that says nothing takes these, so a tier's posture is
   three lines, and one app differs from it in one more: git's writes
   allowed where Cloudflare's still ask.
5. **The defaults**: writes ask, guarded is refused, and anything unmatched,
   or that cannot be classified (a GraphQL document frisket cannot parse),
   asks, with the dialog showing what arrived. Not refused: when in doubt, a
   person decides.

Only cloudflare, gcloud, git, github and huggingface take a project's
answers. What a project answers for any other route — Claude Code's,
Codex's, Docker's, whose answers are the machine's alone — or for a route
its tier does not have, is said and left out (decision 8), as is a
document-wide answer, which would be every route's.

**git is an app of its own, apart from github.** git's smart HTTP and LFS are
one app, `git`; GitHub's REST and GraphQL APIs are another, `github`, which
is what gh speaks. They share GitHub's credential binding but not their
switches, so a tier can let git push while gh's writes still ask. git's
operations are the protocol's, not GitHub's, so the app is ready for another
host when one is wanted.

**One way to say it.** There is no `push`: git's push is the operation
`git-receive-pack`, a write, admitted because git's writes are allowed or
because a project names it, and for no other reason.
No app keeps a switch of its own for what these three already say.

**A tier with no one to ask says so, and a project cannot loosen it.** A tier
for other people's code is `writes`, `guarded` and `unmatched` all `refuse`,
written out in the tier, not a conversion hidden in each app. frisket's asker is the machine's, not a
tier's, so there is nothing for a tier to be checked against: saying so is
what makes it so. An app without `authenticated` refuses all three whatever
its tier says, and its route carries a `ceiling` refusing all three, so
nothing merged over it can lift what it refuses; a project's answers for
such a route are left out, and that is reported (decision 8). That is the
only ceiling chase writes, and it is strict's: what strict holds an
authenticated app to is its three answers, and a project's answers reach
none of strict's apps while strict takes no grant. In such a tier a grant
can name what else it reaches (decision 13), never what an app answers; a
project that needs that goes into another tier, which is the machine's
decision (decision 5), not the checkout's.

**Always, where a project's answer would stand.** A tier's `always`, by
default on where it takes grants and one of its three answers asks, marks
`"always": true` on its routes a project answers that have a credential,
the tier's or the project's, and on every SSH machine, so frisket offers
Always on their questions and writes the one rule into the checkout's
`chase.json`, signed; an anonymous app's route, behind its ceiling, and a
tier that asks nobody, are never marked. frisket signs and writes that rule
through quoin's signer and courier, and frisket and quoin each know the
other only by what the host tells them, so chase, which is what uses the
three together, says it once: `chase.signer.always` gives frisket quoin's
sockets, its allowed signers and `chase.json`, and names `frisket.service`
among the signer's policy signers and the courier's peers. It is off by
default and never inferred from quoin being on, since letting a sandbox's
answer reach the host's signed files is the host's decision.

This all resolves in frisket, at request time, against a policy document of
frisket's version 2. chase renders each tier's at eval
(lib/operations.nix): each app's route with its generated operations as
`paths`, its writes, guarded and unmatched as class answers from the tier's
and the app's settings, and the ceiling above for an anonymous app; and at
launch, a project's `frisket` section is merged over it with RFC 7396's
merge patch by frisket's own project-layer check (`policy.CheckProjectLayer`),
after chase has refused what only the host says. No translation is left in
chase: internal/policydoc, which turned a project's lists into per-rule
booleans, is gone. What frisket had to add is the ability to name what it
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
one project's `ImageTag` would change what another's container runs. Its
one exception is a build: a project whose file names what it builds
reaches BuildKit, runs any tag of it, and accepts that its images are
global (docs/docker.md, decision 16).

**SSH is classed by a hand-written catalogue.** No machine publishes a
description of its commands, so `apps/ssh/operations.json` is written and
reviewed as Docker's admit.json is ([docs/apps/ssh.md](docs/apps/ssh.md)).
Its operations are answered by class and the tier's three answers, as here,
but a project's lists differ in four ways, each for a reason:

- **They are each machine's**, `chase.apps.ssh.hosts.<name>.allow`, not
  `chase.apps.ssh.allow`: one grant names several machines, and what may run
  on a gateway is not what may run on a build box.
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
drift. So a grant's lists are checked against the catalogue before anyone
is asked to sign it, and again at every launch, for one signed under an
older catalogue.

These lists stay chase's sugar, in chase's own section: the catalogue's ids
and categories mean nothing to frisket, so a launch turns each machine's
lists into exec answers on its route, by frisket's rule names, with the
catalogue operation under `commands`, and a project's lists of ids mean
what they did. A tier's own machines may be answered by those rule names
directly, `frisket.ssh.<machine>.exec`.
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
was seen, never generalised. The proposal, `proposal.json`, is strict JSON
in `chase.json`'s own shape, with a note beside each entry of what it was
made from, and changes nothing until `chase record apply` merges it into
`chase.json` and has quoin's signer sign the result, showing the change as
any change is shown (decision 17); refused, the file is written unsigned and
the next launch asks again. Recording is manual mode, guarded operations
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
its document's `lan`, is proposed for the grant's `frisket.lan` with the
ports it was dialled at. See [docs/record.md](docs/record.md).

**21. A checkout's devShell is realised by the launcher, and given to the
session as its environment, where its grant turns it on -- in a tier of
one's own code as `nix develop` would, and in any other offline.** The files are not the problem: flong binds the whole of
`/nix/store` read-only, so every library a devShell names is already there in
every tier. Its environment is: flong starts a session clean, so the
`PATH`, `PKG_CONFIG_PATH` and the rest of a `nix develop` on the host never
reach it. Passing the caller's environment through was considered and not
taken: it works only from a terminal that already ran `nix develop`, never
from an editor (decision 11), it is fixed at launch, and for someone else's
checkout it is the wrong order, since `nix develop` on the host runs their
`shellHook` as you, unsandboxed.

So exec, as the caller, after the grant and before the payload, realises
the checkout's devShell -- flake.nix's `devShells.<system>.default`, or its
shell.nix, flake.nix's when it has both -- in a tier whose `apps.nix` is
enabled, where the checkout's approved grant turns it on, `"apps": {"nix":
{"devShell": true}}`, and hands its environment to the payload
(internal/devshell). That is so in every tier, one's own code's too, as
`direnv allow` is: no checkout's Nix is evaluated unless it asks, and one
that does not costs a launch nothing but a look for the files, a checkout
with a shell.nix, or a flake.nix that names `devShells`, told in a line
what turns it on. Given whenever a checkout had one, as it first was, every
checkout with a flake.nix paid for an evaluation it may never have wanted,
and a failure was said and left out rather than asked for. So the module
refuses `apps.nix` in a tier that takes no grants. A devShell the grant
turned on that cannot be realised refuses the launch, as any part of a
grant does (decision 4), saying how to launch without it -- the key false,
or gone, approved -- and the failure is never kept, so the next launch
tries again: kept, a fetch outage would be an hour's refusal. What is
approved is the grant, not flake.nix or shell.nix, which are never
approved: an edit to them after it takes effect at the next launch.

What is evaluated is the checkout itself, on the host, as `nix develop`
would evaluate it there: a flake purely, from what git tracks, its
`nixConfig` never taken and its lock never written; a shell.nix under
`restrict-eval`, its `NIX_PATH` the system's nixpkgs and the checkout,
`allowed-uris` any https. nix's own restrictions do not hold what it reads
-- `builtins.getFlake` in a shell.nix, a flake's `path:` or `git+file`
input, is any file of the caller's -- and the checkout is what the session
writes, so evaluated as it is, a checkout would hand the session, and the
world-readable store, what the session cannot read: `~/.ssh`, the grant's
state, another checkout. So nix runs in a bubblewrap with nothing of the
host's but the store, the daemon's socket, the machine's nix configuration
and resolver, and the checkout, read-only -- for a flake the checkout it is
in and its git, a worktree's repository included -- with a `HOME` of
chase's own and none of the caller's environment. Its network is the
host's, and the daemon builds what it must, a fixed-output build on the
host's own network: fetches neither filtered nor logged, which is the cost
of one's own code, and nobody else's. So that is a tier whose egress is
direct and whose `allow` is `*`; the module refuses `apps.nix` in a bare
tier, whose agent runs on the host with its own `nix develop`; and a `chase
record` launch's report never names what a devShell fetched.

In any other tier -- someone else's code -- the devShell the grant turns on,
approved as every key of a grant is (decision 17), is realised offline: the
same bubblewrap,
with no network at all. nix, finding none, turns substitution off, so every
run turns it back on: the daemon substitutes from the machine's own binary
caches, their signatures checked, on the host's network -- accepted, since
what it fetches is named by a derivation's hash, from caches the machine
trusts, never a URL the checkout chose. The devShell's derivation is
evaluated alone, nothing built while it is and nothing imported from a
derivation; read, and refused if it asks for what a sandboxed build is not
given (`__noChroot`, `__impure`, the system features `recursive-nix` and
`uid-range`); each of its inputs substituted, as the outputs it takes and
never `^*`, which would be every debug output too, with no local build
allowed, one in no cache refusing it before anything is built; and only
then `print-dev-env`, whose one local build is nix's own record of the
environment, of the devShell's attributes and every input already there,
sandboxed by the daemon. So no fixed-output build, the one kind the daemon
gives a network, is ever run for it, nor anything of the checkout's own.
nix's HOME is one of its own, so nothing an evaluation of someone
else's leaves in nix's caches is read by one's own. What this cannot give
is anything that fetches as it is evaluated: a flake whose inputs are not
in the store already, a shell.nix that pins its nixpkgs by
`fetchTarball`, any `builtins.fetch*`. Those wait on `nix` inside the
session, with a store of its own over the host's (below): the session
evaluates its devShell itself, in its sandbox, every fetch through frisket
and on the allowlist, and nothing of theirs is evaluated on the host at
all. A design that fetched for it on the host, confined -- a lock's inputs
prefetched through pasta from the allowlist's names alone -- was built,
and is kept on the branch devshell-confined: the prefetching, the lock's
checks and the thousand lines of them existed only to fetch for someone
else's code, which the overlay store does without; what it refused of a
derivation is kept here.

The result is cached in chase's state, `checkouts/<key>/devshell`, bound
into no session, keyed on flake.nix and flake.lock, or shell.nix, the
system, the nix, the nixpkgs and every setting it was evaluated with; its
GC root is a profile there, the latest generation alone, never in the
checkout, and the store path it pointed to is kept with the key, so a
profile a killed launch switched is never taken for another's. One launch
of a checkout realises it at a time, under a lock, and the next finds what
it kept. A checkout whose grant no longer turns it on has its root let go
of at its next launch, and one that is gone at any launch that wants a
devShell. A launch stopped while it realises is stopped, never
launched without it, and nothing of it is kept.

The session gets it through exec's own output, as every variable it has:
the devShell's exported variables, but nix's own build variables, those
that steer bash and those that steer the agent -- `LD_PRELOAD`,
`NODE_OPTIONS`, `ANTHROPIC_*`, `CLAUDE_*`, `CODEX_*`, `OPENAI_*`, every
`*_PROXY` -- are the least of its environment, and flong's, the
container's and chase's own win by name. What exec cannot set is PATH's
order, and what it cannot run is the shellHook, which must run inside the
sandbox and never on the host. So where a devShell is given, one thing of
chase's runs in the session ahead of the agent: the container's bash, given
a fixed script and its data as argument words, never written for anything
to source. It finds the agent on the container's PATH, so a devShell's own
`claude` or `bash` is never what runs; puts PATH in order --
`/run/wrappers/bin`, then mise's shims, so a toolchain the checkout pins
wins and a shim with nothing pinned falls through, then the devShell's,
then the rest of the container's; runs the hook in a subshell, with the
devShell's variables and functions, its stdin closed and its output on
stderr, so what it does to the bash it runs in -- a function named as a
builtin, a readonly variable, a `cd` -- dies with the subshell, which hands
back its exported variables as data and nothing else; takes of those the
hook's changes to the devShell's own and what it added, but none of the
container's and chase's, none that steer the agent or bash, and none of
bash's own; orders PATH again, so the hook's own `PATH=$PWD/bin:$PATH`
stays behind the wrappers and the shims; and execs the agent. A hook that
exits, or leaves its subshell handing back nothing whole, ends the session,
said. Without a devShell there is no such bash.

`nix` itself inside a session is a later extension, flong's (its PLAN §3):
either the host daemon's socket, or a store of the session's own over the
host's, whose builds and fetches are the session's and so frisket's to see.
The second is preferred, and its spike works (flong's PLAN §3): the store
it needs is a cache, kept per session in a tier for other people's code,
and a GC root on the host for each host path it uses is the launcher's.

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
