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

**2. Privilege never follows evaluation.** A project's declaration can be
evaluated dynamically, at launch, in the project. What runs as root cannot be.
nix-config grants `NOPASSWD` to a launcher **by store path**, so a launcher a
project built has a path the sudoers rule never saw and does not get it. That
is not a limitation to work around: it is the fail-safe. A project that tries
to supply its own privileged launcher gets a password prompt, which is the
existing graphical-sudo gate doing its job.

So: the launcher is fixed and system-owned, the envelope is data, and the
launcher validates it. This is flong's existing split — `workspace` and `binds`
run as the caller, `guard` runs as root and checks what they produced.

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

Evaluated as the caller, never as root (decision 2).

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
nspawn starts a session clean and direnv's hook never fires in it, so a session
with 5432 open still has no `DATABASE_URL` and nothing tells it to look. This
is why the envelope is not a port list: ports and environment are the same
feature, and shipping one without the other opens a door nothing walks through.

nix-config's note that *"no tier that could use a devShell runs in one"* stops
being true when this lands, and wants rewriting.

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

- **Binding the project's declaration read-only into the session**, to stop an
  agent editing it. Unnecessary: the declaration is consumed on the host before
  the session exists, so editing it cannot affect the running session, and the
  next launch is covered by decision 8.

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
  flong learns nothing about projects.
- **frisket** — `frisket steer` to accept a policy *document*, not only a
  policy *name*. Policies are loaded once at daemon start and a session naming
  an unknown one is refused, so a project-supplied policy has no way in. The
  control socket is root-only and the caller is chase's fixed launcher, so root
  still vouches for every policy that reaches the daemon.
- **frisket** — the confirmation gate on destructive requests (`ask` beside
  admit and refuse), so an irreversible operation stops at a dialog naming the
  real request line. What prompts is a callback frisket runs, not a dialog it
  owns; see [docs/cloudflare.md](docs/cloudflare.md), decisions 7 and 8. Separate from scoping: a correctly scoped token can still
  delete everything inside its own scope.
- **frisket** — decision 7 says three layers; it is four, and the chase line
  changes from *"if it is ever extracted"* to a pointer.

## Open questions

1. **How a credential's source is spelt**, given decision 14 settles that it is
   a source and not a path. The shapes are frisket's and already exist; what
   chase needs is the sum of the ways one can be *found* — and the two known
   members bind at different times, one at eval and one at launch.
2. **Where a project's decrypted credential is written.** Outside the workspace
   is settled (decision 7), and so is the symmetry: whatever decrypts it
   chooses where it lives and is what removes it.

   The prior art is systemd's own — `LoadCredential` decrypts into a per-unit
   tmpfs at `$CREDENTIALS_DIRECTORY` and takes it away when the unit stops —
   and sops-nix does the same thing at activation scope. Neither fits directly:
   a flong session is a scope, not a service, and its credential has to be
   readable by frisket on the *host* rather than by the payload.

   `/run/user/<uid>/chase/<machine>/` looks right: tmpfs, owned by the user
   frisket runs as, not bind-mounted into the session, and keyed on the name
   flong's `postStop` already receives. Note that neither of flong's existing
   directories works — `/run/flong/<container>-…` is the shared prepared-root
   cache rather than per-session, and the session's own `XDG_RUNTIME_DIR` is
   created *inside* the container, which is the one place this must not go.
3. **What `ask` matches on.** Answered for Cloudflare, and the answer is the
   pattern for the rest: derive the allowlist from the provider's own API
   description, pinned, and let anything not on it ask. See
   [docs/cloudflare.md](docs/cloudflare.md). Still open for providers that do
   not publish one.
