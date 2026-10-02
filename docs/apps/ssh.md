# ssh

Commands on your own machines, by `ssh <name> <command>` from a session,
with no key in the session. frisket terminates the session's SSH, logs in to
the machine with your key, and decides each command: allowed, asked about,
or refused. Which machines, at which address, as whom and with which host
key, are a project's grant to name and yours to approve. No shell, no pty,
no forwarding. See frisket's docs/ssh.md for the route itself.

| `chase.apps.ssh.…` | Default | |
|---|---|---|
| `agentSocket` | `null` | Your ssh-agent's socket, e.g. gcr's `/run/user/1000/gcr/ssh`. Not under `/tmp`: the frisket daemon has a `/tmp` of its own. |
| `keyFile` | `null` | An unencrypted private key, in place of an agent. Exactly one of the two. |
| `identity` | `null` | The one agent key to offer, `SHA256:…` as `ssh-keygen -l` prints it. |

Each is a string, never a Nix path, which would copy a key into the store.

| `chase.tiers.<name>.apps.ssh.…` | Default | |
|---|---|---|
| `enable` | `false` | Only in a tier with `grants = true`. |
| `writes`, `guarded`, `unmatched` | the tier's | |
| `env` | `LANG`, `LC_*`, `TZ`, `COLUMNS`, `LINES`, `NO_COLOR`, `SYSTEMD_COLORS` | What a command may set in front of itself; see [What runs](#what-runs). |

```nix
chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh";
chase.tiers.trusted.apps.ssh.enable = true;
```

Grant:

```jsonc
"ssh": {
  "hosts": {
    "server": {                                  // `ssh server …` in the session
      "address": "192.168.1.10",                 // a literal IP, v4:port or [v6]:port; 22 by default
      "user": "ops",
      "hostKeys": ["ssh-ed25519 AAAAC3… server"], // its own key: never learnt on first use
      "allow": ["service-restart"],              // operation ids, category:<name>,
      "ask": ["docker compose ps **"],           //   or command patterns
      "refuse": ["category:packages"],
      "unmatched": "refuse",                     // in place of the tier's
    },
  },
}
```

`ssh-keyscan -t ed25519 <address>` prints a machine's key with its host in
front; the grant takes the rest of the line. A machine whose key is not one
of these is never reached.

## Commands

frisket reads a command as simple commands of plain, single-quoted or
double-quoted words, joined by `&&`, `||`, `;` or `|`, each ending, if it
likes, `>/dev/null` or `</dev/null`, which are no words of it. Anything
else -- `$` or a backtick, quoted or not, any other redirection,
`2>/dev/null` too, a glob, `~`, a word beginning `%`, an assignment of a
name `env` does not list, a command over 8 KiB -- is unreadable, and no
rule decides it: it is `unmatched` (frisket's
[docs/ssh.md](https://github.com/danielbodart/frisket/blob/trunk/docs/ssh.md#commands)
has the grammar exactly). Each simple command is decided on its own, and
the strictest decides the whole: `cd /etc && ls` is allowed only if both
are.

### What runs

A simple command is decided by what runs, with what only sets how it runs
taken off first: `exec`, `command` or `builtin` first, with no option;
`time`, with `-p` only after `env` or one of those -- zsh's `time` runs a
command named `-p` -- and `NAME=value` of a name the tier's `env` lists, as
the shell's assignment or after `env`. `LANG=C sort x`,
`env TZ=UTC date`, `time ls` and `command rm x` are decided as `sort x`,
`date`, `ls` and `rm x`. Any other name -- `PATH=/tmp ls`, `LD_PRELOAD=x
ls`, `PAGER=sh systemctl status` -- is unmatched, and so is an assignment
alone, `env` with an option, `command -v`, a precommand anywhere but first,
and `time` beside a shell assignment, which the shells read differently.
The values are not taken off from the argument operations, which see them:
`LANG=x/.ssh/id_rsa ls` is refused as `ls x/.ssh/id_rsa` would be.
frisket refuses a list naming what changes what any command runs -- `PATH`,
`LD_*`, `BASH_ENV`, `IFS`, glibc's `LOCPATH`, `NLSPATH` and
`GLIBC_TUNABLES` and their kin, or a `*` that covers one -- but a
name one program reads as code or a program to run, `PAGER`,
`SYSTEMD_PAGER`, `LESSOPEN`, `GIT_SSH_COMMAND`, `PYTHONPATH`, is for the
list to leave out: a rule for `systemctl status` would run whatever it names.
The default's locale and timezone names can name a file, and the library
that parses locale or zone data trusts it, so one the session wrote would be
parsed inside whatever program was allowed: frisket reads no value that
could name such a file -- one beginning `/`, `.` or `:`, or holding `..` or
`%` -- so `LC_ALL=/tmp/l ls` and `TZ=../../tmp/z date` are unmatched, and
`LANG=en_GB.UTF-8` and `TZ=Europe/London` are what they seem. The list is the tier's alone: a grant
cannot widen it. A machine whose login shell is csh, which has no
assignment before a command, has no use for one.

The catalogue, [apps/ssh/operations.json](../../apps/ssh/operations.json),
says what each command is, and the tier answers it by its class:

| Class | Commands | Default answer |
|---|---|---|
| read | `ls`, `cat`, `grep`, `find`, `diff -q`, `systemctl status`, `journalctl`, `ps`, `df`, `ip addr`, `apt list`, `docker ps`, … | allow |
| write | `systemctl restart`, `apt install`, `cp`, `mkdir`, `grep -r`, `diff`, `date -f`, `apt-cache -p`, `lspci -Q`, `lsof -i @<host>`, … | `writes`: ask |
| guarded | `rm`, `reboot`, `systemctl soft-reboot`, `lspci -H`, `lspci -x`, `systemctl start reboot.target`, `chmod`, `kill`, `apt remove`, `find -delete`, `find -exec`, `less +…`, `sort --compress-program`, `cat /dev/sda1`, `env`, `printenv`, … and any argument naming a secret | `guarded`: refuse |
| unmatched | anything else: `sudo`, `sh`, `awk`, `sed`, `python`, `xargs`, `tar`, `git`, `ss`, … | `unmatched`: ask |

A read is a command none of whose arguments can write, run something, or
reach the network. Where one can, the command is a read only in the forms
that can't (`hostname`, `ip`, `ps`, `mount`), or its dangerous arguments are
operations of their own that make it stricter: `find -exec`, `grep -r`,
`lspci -Q`, `less +cmd`, `sort --compress-program`, `sort --files0-from`,
`date 0101…`, `systemctl -H` and `-C`, `systemctl --image`, `apt -o`, `apt-cache -p` and `apt policy -p`.
A host name looked up is the network too: the machine's resolver asks DNS
for it, and a name of the argument's choosing carries what is written into
it off the machine, so `lspci -q` and `lsof -i @<host>` are writes. `ss`
is not catalogued at all: it looks up any filter word it does not know as a
host, `ss state listening` and `ss -f inet` too, so none of it is a read,
and guarding every word that is no option would be most of the catalogue's
globs for one command. Those catch every
spelling a command takes -- clustered short options, abbreviated long ones,
`--opt=value` -- so some are wider than the option: every `apt` option with
an `o` or a `c` in it is `apt -o`'s, `--no-install-recommends` too. Allow the
operation in a grant to lift it. Anything that runs code from its arguments
isn't catalogued at all.

The `secrets` operations refuse a command with an argument that names one,
whatever the command: `.ssh`, `id_*`, `ssh_host_*`, `*.pem`, `*.key`,
`*_key`, `keys.txt`, `shadow`, `*password*`, `.env`, `environ`, `secrets*`
(sops-nix's `/run/secrets.d` too), `sops*`, `*token*`, `*credential*`,
`.aws`, `.azure`, `gcloud`, `gh`, `.kube`, `.docker`, `.gnupg`, `.netrc`,
`*.tfstate`, `*_history`, `/dev/mem`, `/proc/*/mem`, and the rest of the catalogue's. A word is matched
whole, after its first `=`, and by each `/`-separated part -- but not after a
short option, so `-f.kube/config` is the parts `-f.kube` and `config`, and
names no secret. A read that prints a file named by an option is therefore
no read: `date -f`, `dmesg -F`, `file -f` and `-m`, `findmnt -F`,
and `last -f` are writes, which ask. The environment is a secret too, a
token as often a variable as a file: `read-environment` guards what prints
it -- `env` with no command (or with only options that run none, `env
-0`), `env` and `printenv` by their usual paths, the shells' `set`,
`export`, `declare`, `typeset` and `readonly`, zsh's `local`, csh's
`setenv`, `systemctl show-environment`, and `systemctl show` with no unit,
whose properties hold the same -- as `secret-environment` does
`/proc/<pid>/environ`, `process-environment` ps's `environ` column, and
`service-manager-environment` systemd's `Environment` properties. Other
spellings are not: `env` by a path it does not list is unmatched, and
asked about, and `systemctl show` with no unit and options it does not
list, `systemctl show --full`, is a read like `systemctl show nginx`.
They are names, so they catch a secret where it is
usually kept: a key named `prod`, or a token in a file whose name says
nothing of one in a directory that does not either -- a tool's `hosts.yml`,
`config.json` or `settings.ini` -- is read like any other file. A glob for
those would refuse every `config.json`.

**What this is, honestly.** The catalogue keeps an agent on reasonable
paths and stops obvious mistakes; it is not the boundary. The remote user's
own permissions are: run commands as a user who may do no more than you'd
let an agent do. A refusal only refuses what it can read -- `rm x; echo
$HOME` is unmatched, so it is asked about, not refused -- and only
`unmatched = "refuse"` refuses everything else. The secret paths catch a path spelled out,
not one an allowed command finds for itself: `grep -r` is a write for that
reason, and so is `diff` but for `diff -q`, since `diff dir1 dir2` prints
every file the two share by name, one level down, and a directory can't be
told from a file by its name, but `find / -type f` lists what `cat` then reads.
A disk read raw is refused where it is spelt from `/dev` -- `/dev/sda1`,
`/dev/root`, LVM's `/dev/ubuntu-vg/ubuntu-lv`, anything below `/dev` -- or
by a common disk's own name, `sda1` or `nvme0n1p2`, but not after `cd /dev`
by a name of its own: run commands as a user outside the `disk` group.
Memory read raw is refused the same way, `/dev/mem` and `/proc/<pid>/mem`
spelt from `/`, so that `grep mem /proc/meminfo` is not, but not `mem` after
`cd /dev`.

## Lists

A host's `allow`, `ask` and `refuse` take an operation's id
(`service-restart`), a category (`category:services`), or a command pattern
(`docker compose ps **`): words, `*` for one word, `**` last for any number.
A pattern has a space or a `*`; anything else is an id, so `tar` alone is
written `tar **`. An id decides before its category, and either before
the tier. A category is a topic, not a danger, so allowing one allows its
reads and writes but none of its guarded operations: `category:search`
does not allow `find -exec`, nor `category:read` `less +cmd`, nor
`category:packages` `apt -o`. Only its id allows a guarded operation; a
category asked or refused is all of it, and one allowed that has nothing
but guarded operations, `category:secrets`, is refused. A pattern replaces the catalogue's
rule of the same pattern, or adds one; the most literal pattern a command
matches decides it, and between patterns as literal as each other, the
stricter. So a pattern that answers less strictly than a catalogue pattern
as literal as it, which some command matches both of, would never decide,
and is refused: allow `systemctl restart *` ties the catalogue's
`systemctl restart **`, which asks. Name the operation
(`service-restart`), or a more literal pattern (`systemctl restart nginx`).
An argument operation decides after every pattern, and only ever more
strictly, so a pattern never lifts one: only allowing the operation's id
does. A pattern with a word an argument operation stricter than it catches
-- allow `grep -r **` (`search-recursive`), `date 2026-01-01`
(`date-set`), `cat /etc/ssh/ssh_host_ed25519_key.pub` (`secret-ssh`) --
would never decide, and is refused. A name in two lists is refused.

Each of these is refused when the grant is approved, before you are asked,
by the catalogue and the tier the approval is for, and again at every
launch, so that a grant approved under an older catalogue -- one naming
`sockets`, say, which is no more -- ends the launch rather than doing less
than it says.

A tier's `unmatched = "allow"` allows every readable command the catalogue
doesn't name, and refuses what can't be read.

## The session

frisket mounts `/etc/frisket/ssh_config`, a `Host` block for each machine,
and `/etc/frisket/ssh_known_hosts`, the session's SSH CA. The tier's ssh
config includes the first and trusts the second, so `ssh server uptime` just
works. The connection reaches frisket, never the machine; a private address
is reachable this way and no other.
