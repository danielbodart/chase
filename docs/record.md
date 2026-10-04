# Recording

Something is refused. You run the same thing again under `chase record`,
in the same checkout:

```
$ chase record --default allow claude
```

do the one action, and exit. chase says what the session needed that its
tier would have refused or asked about, and leaves a proposal: the grant
entries that would give it exactly that, each in the list its answer says.
`chase record apply` adds them to the checkout's `chase.jsonc`, and the
changed grant is put to you at the next launch, as any change is.

```
chase record [--default allow|ask|refuse] [--base tier|none] [--] AGENT [ARG...]
chase record apply [--last | MACHINE]
```

`AGENT` is `claude`, `codex` or `shell`, and everything after it is the
agent's own.

## Answers

Each thing the tier would refuse or ask about is a subject: an operation on
a route, a command on a machine, a name and port, a syscall. Each is
answered `allow`, `ask` or `refuse`, which is both what happens now and what
is proposed:

| Answer | Now | Proposed |
|---|---|---|
| `allow` | goes through | an entry in `allow` |
| `ask` | goes through | an entry in `ask` |
| `refuse` | refused, as the tier would | an entry in `refuse` |

A syscall is the one subject not put to you: the filter is fixed before
the session starts. Answered `allow` or `ask`, or by a person, every call of
`@known` the filter would refuse is allowed while recording, and proposed
for `allow`. With `--default refuse` the filter is left as it is, refusing
what it refuses, and no syscall is recorded or proposed; so `--default
refuse` with `--base none` is refused.

`--default` answers everything, with nobody asked. Without it, each subject
is put to you through frisket's asker, whose question carries `record:
true`, and `lan: true` for a connection to the local network; zenity's `--ok-label=Allow --cancel-label=Refuse --extra-button=Ask`
gives all three. A subject is answered once a session; asked about again,
the last answer stands.

Recording is manual mode: anything the tier's rules refuse can be answered,
guarded operations included, and so can a call the tier's `seccomp.deny`
takes: a grant's `seccomp.allow` puts one back, since the grant is the
tailored fit and the tier the ready-made one. What no rule decides stays
refused, and is reported as such: frisket's structural refusals, a
credential or Host that does not hold, a path that is not canonical,
anything on a Docker route, a command a shell route cannot read, an address
dialled by itself; and flong's fixed filters.

## What each layer records

| Layer | Recorded as |
|---|---|
| HTTP on a route | the operation's id, or the method and exact path where no operation matched; `apps.<app>.<answer>` for an app a grant has lists for (cloudflare, gcloud, git, github, huggingface) |
| SSH | the catalogue's operation, or the command itself as a pattern; `apps.ssh.hosts.<machine>.<answer>` for a machine the grant names |
| Other TCP | the name, `network.allow`; a name on the local network, `network.lan`, with the ports it was dialled at |
| DNS | the names resolved off the allowlist, reported |
| Syscalls | the call's name, `seccomp.allow`; nothing with `--default refuse` |

Every connection goes through frisket while recording, whatever the tier's
`egress`: the record launcher has no network of flong's, so a name off the
allowlist, a port and a host on the local network are all seen, and each is
answered as anything else is, by `--default` too. A tier with its own
network loses, for the recording, what pasta gives it: ports forwarded to
the project's address, and UDP.

Entries are exactly what was seen, never generalised. Edit the proposal to
widen one before applying it. What was answered and cannot be an entry --
a route no grant has lists for, a machine that is the tier's own, a
one-word command, a command frisket cut short at 4 KiB, a refusal of a
name, a project's own name -- is left out, and the report says why.

A name whose address is on the local network -- a NAS, a printer -- is
refused outside a recording whatever the allowlist says: frisket reaches a
private address only for a name in its `lan` list. So a name answered
`allow` or `ask` there is proposed for the grant's `network.lan`, once,
with every port it was dialled at; the launch puts it on the allowlist too.
Applied, a name the grant has already gains the ports it lacks, and one it
has for every port is left.

A grant is committed with its checkout, so a command or path that looks as
if it carries a secret is never proposed, nor repeated in a note: a flag,
variable or header named for one (`--password`, `DB_TOKEN=`,
`Authorization:`), a bearer token, a login in a URL, or a word shaped as a
token -- a service's own prefix such as `ghp_`, or 20 or more letters and
digits of both cases. The report names what it was taken for; write the
entry yourself, with `*` in its place. What the check misses is yours to see
in the proposal before applying it.

A name answered `ask` is proposed for `allow` or `lan`, as frisket cannot
ask about a name, and a syscall answered by a person is proposed for `allow`, as the
filter is fixed before the session starts and nothing is put to you: each
says so in its note.

## Syscalls

flong's filter is given `log` lines: every call it would refuse is allowed
and audited, as a SECCOMP record of type 1326. `chase record` follows them
in the journal (`_TRANSPORT=audit`, from journald's audit socket) while the
session runs and puts each down to the session by its process's cgroup,
`flong-sessions.service/<container>/<machine>`, or by a pid seen in that
cgroup. One whose process was gone before either is placed **probably**, by
when it was made, and only when no other recording ran beside it: it is in
the proposal as a comment, for you to uncomment.

`--base tier`, the default, learns against the tier's filter and the
grant's: what is logged is what the session needs beyond them, a call the
tier's `seccomp.deny` takes included. What the grant denies stays denied:
it is the project's own word.

`--base none` learns from scratch: nothing is allowed -- not the tier's
names, and its `seccomp.deny` is no part of it -- but a handful of calls
every process makes many times a second, which would otherwise be most of
the log --

```
read write readv writev pread64 pwrite64 lseek close
futex sched_yield nanosleep clock_nanosleep clock_gettime
mmap munmap mprotect madvise brk rt_sigreturn rt_sigprocmask
poll ppoll epoll_wait epoll_pwait epoll_pwait2 epoll_ctl getpid gettid
```

-- and every other call of systemd's `@known` is logged, so the report
shows every call the session made, each the grant allows already said as
the grant's and each the tier allows as the tier's. The proposal still holds
only what neither allows: it widens, and does not yet narrow -- a call the
tier allows that the session never made is not proposed for `deny`. Calls
outside `@known` stay `ENOSYS`, unlogged.

Reading the audit takes a user who may read the system journal: one in
`systemd-journal` (or `wheel`). The kernel's audit backlog can still
overflow in a large burst, so a call made once among thousands may be lost.

## A devShell

A recording realises the checkout's devShell as a session of its tier
would ([docs/apps/nix.md](apps/nix.md)): the same confinement, bounded by
the tier's allowlist and the grant's. It is never refused for it: one that
cannot be realised is said, and the recording starts without it, whatever
the grant says. A flake.lock that fetches from names the allowlist does not
hold names them, as what `network.allow` in the grant would admit; add them
by hand. The devShell's own fetches are made before the session starts,
outside it, so frisket does not see them and the proposal does not hold
them.

## What is kept

`~/.local/state/chase/records/<machine>/`, the user's own and seen by no
session:

| File | |
|---|---|
| `record.jsonl` | every line written down: frisket's, as its [docs/record.md](https://github.com/danielbodart/frisket/blob/trunk/docs/record.md) has them, and one of chase's own for each syscall, `kind` `syscall` |
| `meta.json` | the session, tier, checkout, options, start and end, its exit status, and when it was applied |
| `proposal.jsonc` | the proposal |

The last 20 recordings are kept, and any younger than 14 days. frisket's
own copy, in `/var/lib/frisket/records`, is removed once read.

## The proposal

The grant's own shape, as JSONC, each entry with what it was made from on
the line above, a loosening said as one:

```jsonc
// chase record: what chase-trusted-4127, a session of trusted in /home/alice/proj, needed beyond its grant.
// ...
{
  "apps": {
    "github": {
      "allow": [
        // DELETE api.github.com/repos/o/r/git/refs/heads/x; loosens: the tier would refuse (path)
        "git/delete-ref",
      ],
    },
  },
  "network": {
    "allow": [
      // port 443; loosens: the tier would refuse (not allowed)
      "registry.npmjs.org",
    ],
    "lan": [
      // on the local network, port 445; loosens: the tier would refuse (structural: private)
      {"name":"nas.home.arpa","ports":[445]},
    ],
  },
  "seccomp": {
    "allow": [
      // logged 3 times; loosens the tier's filter
      "ptrace",
      // high surface, io_uring: logged 1 time; loosens the tier's filter
      "io_uring_setup",
    ],
  },
}
```

A call of high kernel surface is said: io_uring, the kernel's keyrings,
userfaultfd, BPF, perf events.

`chase record apply` edits the checkout's `chase.jsonc` rather than
rewriting it: its comments and layout stay, each entry goes after the last
of its list -- on a line of its own where the list is on many, inline where
it is on one -- with its note; one already in its list is left, and one in
another of the same lists is moved, since a name in two lists is refused.
What comes out must be a grant chase reads, or nothing is written. Applying
twice adds nothing. The session could write `chase.jsonc`, so it is read as
approve takes it: a plain file of at most 1 MiB, never through a link or
from a pipe. Once the session ends, `^C` stops `chase record` itself.

## Setting it up

```nix
chase.tiers.trusted = {
  grants = true;
  record.enable = true;
};
```

A tier that records gets a second launcher, `flong.chase-<tier>-record`,
on the same container, with the tier's own binds, overlays, guard and
filter, steered whole through frisket (`set = "all"`), and chase's record
hooks in place of approve and exec. Only a tier whose seccompPolicy and
document chase writes records: one that takes grants, or is launched as
one for machines of its own. A bare tier has nothing to record.

Only you start a recording. No wrapper runs the record launcher, nothing a
checkout says selects it, and its guard is the tier's, so it runs a checkout
of its own tier and no other. What it records is said by the environment
`chase record` gives it, which no session reaches:

| Variable | |
|---|---|
| `CHASE_RECORD_DEFAULT` | `allow`, `ask` or `refuse`; empty, a person answers |
| `CHASE_RECORD_BASE` | `tier` or `none` |
| `CHASE_RECORD_TOKEN` | where approve leaves the session's name, for the `chase record` waiting on it |

frisket appends a recording's lines to `/var/lib/frisket/records/<machine>.jsonl`,
its `-record-dir`, and to its journal; `chase record` reads the sink, and
the journal when the sink cannot be read. flong's `flong-seccomp resolve`
names each call.
