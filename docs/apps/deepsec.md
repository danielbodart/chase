# deepsec

[deepsec](https://github.com/vercel-labs/deepsec), Vercel's vulnerability
scanner, run as an agent of its own: `deepsec` runs it in the checkout's
tier, as `claude` and `codex` do. It reaches its models through the tier's
Claude Code or codex, with the placeholder logins a session already holds,
so frisket's claude and codex routes carry its requests and nothing new is
given a credential. No `ANTHROPIC_*`, `OPENAI_*` or `AI_GATEWAY_*` key is set.

Once per checkout, set its workspace up to use those logins:

```sh
deepsec init
cd .deepsec
```

With the package's fixes `--model-auth` defaults to `local`, those logins,
for `init` and `setup` alike, and `--plan` asks Vercel nothing on that
route; npm's deepsec defaults to Vercel's AI Gateway, whose first step is a
Vercel login no session can finish. Another route is named with
`--model-auth` on every `setup` as well as `init`, since `setup` given none
takes `local` over what the checkout chose.

Then, from `.deepsec`, where deepsec looks for its `deepsec.config.ts`, run
`deepsec scan`, `deepsec process` and the rest as its own docs say -- but as
`deepsec`, chase's, never `pnpm deepsec` or `npx deepsec`, which the steps
`init` prints name. Those run the copy `init` installs into the workspace
from npm, which has none of the package's fixes below. That install needs
`registry.npmjs.org` on the tier's allowlist.

In a tier with Claude Code, `init` given no `--agent` is given `--agent
claude`, which it keeps in the checkout's `.deepsec/deepsec.config.ts` as
`defaultAgent`; nothing is added to any other run, so a checkout's own
choice stands. A tier with codex alone leaves deepsec's default, codex.

Inside a sandbox, `DEEPSEC_INSIDE_SANDBOX=1` turns deepsec's agents' own
sandboxes off -- they cannot nest in the container, which is the boundary --
and caps what deepsec itself writes to stdout and stderr: long lines are
cut short, and after 8 MiB it writes no more. `CLAUDE_CODE_EXECUTABLE` is
the tier's Claude Code, which runs under the tier's managed settings and
nothing else: not the tier's `--settings`, not the person's, not the
checkout's `.claude`. So where they deny Bash, deepsec's investigations read
and search but run no commands.

deepsec runs the checkout's own code. It loads the `deepsec.config.ts` it
finds, which a checkout can ship, and runs it as JavaScript: in a tier that
does not trust its checkouts, the container is the only boundary around it.

| `chase.apps.deepsec.…` | Default | |
|---|---|---|
| `package` | | deepsec. No default: the package must carry fixes for running in a session -- frisket's CA passed to its agents, its codex sandbox under `DEEPSEC_INSIDE_SANDBOX`, a workspace's `deepsec/config` import resolved to the package, its Claude Code's queries reading no settings files, `local` the model route given none, Claude Code with Opus 5.5 at medium the model given none, and 150 turns for its analysis of a repository. Without one there is no `deepsec` on the host. |

| `chase.tiers.<name>.apps.deepsec.…` | Default | |
|---|---|---|
| `enable` | `false` | Needs `claude` or `codex` in the tier, and a package. Not on a bare tier. |
| `package` | `chase.apps.deepsec.package` | |

```nix
chase.tiers.trusted.apps.deepsec.enable = true;
```

On a bare tier `deepsec` runs `deepsec-raw`, deepsec itself, with the host's
own logins and `CLAUDE_CODE_EXECUTABLE` defaulting to Claude Code rather than
the `claude` link. Outside codex's `host` scope frisket lets codex reach only
`/backend-api/codex/`.
