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
        nix-config     a project's flake
```

Both depend on chase; neither depends on the other. A project imports the
envelope schema, overrides what it needs, and ships that in its own flake. The
machine's configuration is private, host-specific and no business of a
project's — and a project is no business of the machine's either.

**The machine never enumerates projects.** It knows the *shape* of what it will
find, not which projects exist. This is the distinction between an eval-time
dependency (nix-config lists the project in `flake.lock`) and a runtime one
(the launcher evaluates whatever directory it was started in). `agent-tier`
already works the second way: it reads `git remote get-url origin` at launch
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
`postStart`, `postStop` — runs as the user who started it, and the launcher
itself is only a way of doing what that user could already do by hand. So
there is no privilege for a project to reach by building a launcher of its
own, and nothing to protect by pinning one's store path: a launcher a project
built can do no more than the caller running bwrap directly.

What stops a checkout from widening its own sandbox is therefore not who runs
the launcher but what the launcher applies. A project's declaration is
evaluated dynamically, at launch, and nothing it says — a binding, a secret,
a syscall it wants back — takes effect until `chase.approver` has shown a
person the change and they have said yes (decision 17). `guard` stays, as a
consistency check between the wrapper and the launcher rather than a gate:
it catches a launcher started by hand on a checkout the wrapper would have
sorted differently.

The envelope is data, and the launcher still validates it: the module system
refuses an option chase does not define (decision 10), and flong refuses a
syscall name systemd does not list.

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
cannot be asked whether it is trustworthy, so `trustedOrgs`, the override lists
and the provenance check stay where the machine owns them. What a project may
then *ask for* is the project's to declare. Two different questions.

Note this does not put a project list back on the machine: trust is decided by
organisation and first-commit authorship, so projects are not enumerated in the
common case. The override lists are overrides.

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
bypass a refusal anyway"*. An envelope that opened a host port, or a project
secret that was decrypted, is printed at launch. The human sees what was
applied.

**9. There is never a system-level cloud account.** Cloudflare and gcloud
credentials are project-scoped by design, not by accident of not having set
one up yet. A machine holds no Cloudflare login; a project holds one minted
for itself, scoped to what that project owns. talebrary is the first, on
Cloudflare, with an account scoped to its zone.

This is what makes decision 6 more than a preference: there is no broad
credential to fall back to, so a project either has a narrow one or has none.

**10. The envelope is a module, not a document.** A project's flake output is a
NixOS module referencing chase's option names. chase evaluates it, with the
machine's own chase. Two things fall out for free: the module system rejects an
unknown option, so there is no schema language to invent and no validator to
write; and version drift disappears, because the project never evaluates chase
at all — it only names options that chase then defines.

Evaluated as the caller, like everything else in a launch (decision 2).

**11. The launcher evaluates; direnv is not the trigger.** It is tempting to
have `cd` into a project build the envelope and the launcher read the result.
It does not work: direnv's hook only fires in a shell that reaches a prompt,
*"which no editor, script or coding agent has"* — nix-config's own note on why
containers get nothing from it. A launch from an editor would silently get no
envelope.

So the launcher runs `nix build` itself and is self-sufficient. Nix caches
flake evaluation, so a repeat is cheap, and a project direnv has already warmed
is cheaper still — direnv is not the mechanism, it just does no harm. A
project with no `flake.nix` costs a stat, which is the ordinary case.

**12. Two tiers, three outcomes.** `trusted` and `strict` are tiers: a
container, its binds, what is steered, which apps. `host` today is the
*absence* of one — it runs bare, with no container, no frisket policy and no
envelope. The selector returns three strings and `tiers` holds two, which is
already true and worth saying out loud, because the name suggests otherwise.

This is a statement of the reason, not a promise about the future. host exists
for work that needs the host: real sudo, `/dev/input`, KVM, the network
namespaces themselves. Root defeats every boundary flong or frisket could draw
around it — including the credential one, since frisket's credential files are
the user's own and a process with sudo simply reads them, and since a netns can
be left with `nsenter`. So there is nothing yet that containerising host would
buy.

If that reason ever stops holding — a host-tier variant that gives up sudo, or
some boundary root does not defeat — the conclusion moves with it. What is
locked is that host gets no container *for as long as it has root*, not that it
never gets one.

chase ships both tiers, opinionated, and nix-config instantiates them. A
project overlays `trusted`. Nothing overlays `strict` (decision 13).

**13. strict never takes an envelope.** It has no network to open a port on,
and "nothing local is reachable" is the whole of what the tier is for. A
project that ships an envelope and is sorted into strict has it ignored, and
said so at launch (decision 8).

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
and `forwardPorts` publishes a session's port on the host. An envelope uses the
first. The second is exclusive — *"a host port is one session's at a time. A
second concurrent session asking for the same one fails to attach its network,
and is ended rather than left running without it"* — and many sessions of one
project run at once, so a project that declared a forwarded port would break
its own second session. Reaching a dev server *inside* a sandbox is a separate
problem and frisket's open question 3.

**16. A port alone is not enough; the envelope carries environment too.**
flong starts a session clean and direnv's hook never fires in it, so a session
with 5432 open still has no `DATABASE_URL` and nothing tells it to look. This
is why the envelope is not a port list: ports and environment are the same
feature, and shipping one without the other opens a door nothing walks through.

nix-config's note that *"no tier that could use a devShell runs in one"* stops
being true when this lands, and wants rewriting.

**17. Nothing of a checkout's runs until a person has approved it.** An
envelope is the project's own flake output, `chaseModules.default`, and
nothing is hidden from the session. Instead, each launch works on a snapshot
of the checkout's tracked files and approves in two stages:

- **The flake's own files, before anything runs.** `flake.nix` and
  `flake.lock` alone declare and pin its inputs, and evaluating a flake
  resolves them first — so an input could otherwise read any of the user's
  files, or fetch any URL, before anyone had looked. Different bytes from the
  ones last approved for that checkout go to `chase.approver` as a diff; only
  then is anything evaluated. Inputs that are files on this machine (`path:`,
  `git+file:`, relative ones) are refused outright: what they hold is in
  nothing approved.
- **What the chase section says, after.** It is evaluated purely, against
  chase's project options only, and can import other files of the project; a
  change to its result — which includes the digest of the project's sops file
  — is asked about too.

Both stages run before the session is built, in flong's `seccompPolicy`,
because what the chase section says includes the syscalls a project wants
beyond its tier's filter, and a filter is installed before anything in the
session runs. The approved result is staged for `postStart` under the
session's name, which flong gives both, so two launches of one checkout keep
their approvals apart; `postStart` applies the rest — secrets, the policy
document, the environment — without looking at the checkout again.

Only a `flake.nix` that says `chaseModules` is looked at, so an ordinary
project flake never prompts. Approvals live in `~/.local/state/chase/`, on
the host and bound into no session. Refused, the launch ends rather than
running without the envelope. Working from the snapshot is what makes the
approval mean something: a session of the same checkout cannot change a file
between the approval and its use.

This replaces decision 8's report for the envelope itself: a line printed at
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

1. **The project, by name**: `chase.bindings.<app>.allow`, `.ask` and
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

**A tier with no one to ask says so, and a project cannot loosen it.** strict
is `writes`, `guarded` and `unmatched` all `refuse`, written out in the tier,
not a conversion hidden in each app. frisket's asker is the machine's, not a
tier's, so there is nothing for a tier to be checked against: saying so is
what makes it so. An anonymous app refuses all three whatever its tier says.
A project's lists are ignored for both, and that is reported (decision 8):
strict takes no envelope anyway (decision 13), and a project that needs more
goes into another tier, which is the machine's decision (decision 5), not the
checkout's.

This all resolves in chase: the tier's and the app's settings at eval, and a
project's lists at launch, against the tier's own policy document
(`project/lists.jq`). frisket gets rules that already say allow, ask or
refuse, and carries each operation's class and category only to show them. What frisket must add is the ability to name what it
cannot see in a method and a path: a GraphQL mutation by its field, the refs a
push updates, an LFS batch's operation. Each gets an operation id, so git,
GraphQL and LFS are listed, switched and named like any other app.

## Considered and rejected

- **Per-project path matching in frisket, to scope a project to one zone.**
  Refuted by decision 6: a token minted for the zone is enforced by the
  provider and needs no matcher. Path rules are still wanted, for the
  confirmation gate and for read/write asymmetry, but not as the thing that
  keeps one project out of another's resources.

- **A `.chase.toml` (or any bespoke file) in the project.** A project already
  has a flake, and a NixOS module is already a validated, typed, composable
  declaration. A new format would mean a new parser, a new schema language and
  a new validator, all in the privileged path. Decision 10.

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

- **A host-declared ceiling on what a project's envelope may ask for.** Built
  for a threat model the trusted tier does not have. Trusted already grants a
  real network stack with the host and LAN reachable; a declared loopback port
  is not a new surface, and the answer to an invisible change is decision 8,
  not a ceiling.

- **Hiding the project's declaration from the session**, so only a person
  outside could edit it. A flake is not one file: its imports, its
  `flake.lock` and its `path:` inputs are all in the read-write workspace, and
  git can put an agent's version in place through a human's own checkout.
  Decision 17 approves what the declaration evaluates to instead, which covers
  every way it could change.

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
| `modules/agents/selector.nix` | moves — tiers, `agent-tier`, the wrappers |
| `modules/agents/tiers/` | moves |
| `modules/agents/apps/` | moves — claude, codex, github, dragoman, mise, audio |
| `modules/agents/default.nix` | **stays**: it is the instance, not the module |
| `frisket/nix/flong.nix`'s `caVariables` | moves here |

`default.nix` is `user = "dan"`, the repo lists and `trustedOrgs` — the personal
configuration, which is exactly what should not travel.

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
  "auto"` publishes whatever a session listens on, and trusted uses it, so a
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
   commit), GraphQL as a schema (`docs.github.com/public/fpt/schema.docs.graphql`),
   and git's smart HTTP and LFS as prose and JSON schemas in git's and
   git-lfs's own repositories. gh has none: what a command sends is what
   `GH_DEBUG=api`, or frisket's log, shows.
