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
one zone cannot touch another, whatever any matcher does or fails to do. Path
rules and the confirmation gate sit on top of that, not in place of it.

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
  real request line. Separate from scoping: a correctly scoped token can still
  delete everything inside its own scope.
- **frisket** — decision 7 says three layers; it is four, and the chase line
  changes from *"if it is ever extracted"* to a pointer.

## Open questions

1. **How a credential source is typed.** The two consumers bind at different
   times: nix-config at eval (a path known statically), a project at launch (a
   file that does not exist until the envelope is evaluated and `sops -d` has
   run). `types.path` cannot express both. This is most of the design work.
2. **What the envelope may contain**, and its version. A project pins chase in
   its own `flake.lock` and can drift from the machine's, so the launcher
   validates rather than trusts, and refuses a schema it does not recognise.
3. **The cost of evaluating a project's flake at launch.** Whether
   `nix build` in the workspace is fast enough to sit in the launch path, and
   what happens when it fails or the project has no envelope at all — which
   must be the ordinary case, costing nothing.
4. **Which apps get per-project support first.** gcloud and Cloudflare are the
   motivating pair; neither has a credential source on any machine yet
   (frisket's open question 6).
5. **Whether strict ever takes an envelope.** Currently no: it has no network
   to open a port on, and "nothing local is reachable" is the tier's whole
   goal. Worth writing down as a decision rather than an accident.
