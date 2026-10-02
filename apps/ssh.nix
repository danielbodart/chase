{ config, lib, ... }:

# SSH through frisket (docs/apps/ssh.md): commands on the machines a
# project's grant names, each an SSH route frisket terminates, logging in
# with the user's own key, which never enters the session, and deciding
# every command by the catalogue's operations (./ssh/operations.json),
# answered as the tier says and the project's lists before it. frisket
# gives the session its ssh_config and the CA its host certificates are
# signed by, in /etc/frisket; what is here points ssh at them. Only in a
# tier that takes grants: which machines, and as whom, are a project's to
# name and a person's to approve.

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.chase;
  ops = import ../lib/operations.nix { inherit lib; };
  machine = cfg.apps.ssh;

  enabled = lib.filterAttrs (_: t: !t.bare && t.grants && t.apps.ssh.enable) cfg.tiers;
  wanted = lib.any (t: t.apps.ssh.enable) (lib.attrValues cfg.tiers);

  # A path the frisket daemon reaches as it is: absolute and clean, since
  # it has no working directory of the user's. Never in the store, which is
  # everyone's to read, and never under /tmp or /var/tmp, which the
  # daemon's PrivateTmp hides.
  pathProblem = p:
    if builtins.match "(/[^/]+)+" p == null then "is not an absolute path with nothing after its last /"
    else if lib.any (c: c == "." || c == "..") (lib.splitString "/" p) then "is not a clean path"
    else if lib.hasPrefix "${builtins.storeDir}/" p then "is in the store, which every user reads"
    else if lib.any (d: lib.hasPrefix d p) [ "/tmp/" "/var/tmp/" ] then "is under a /tmp the frisket daemon's PrivateTmp hides"
    else null;
  credentials = lib.filterAttrs (_: p: p != null) { inherit (machine) agentSocket keyFile; };
in
{
  options.chase.apps.ssh = {
    agentSocket = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/user/1000/gcr/ssh";
      description = ''
        The ssh-agent socket frisket logs in to every machine with: the
        user's own, holding their key. A path the daemon reaches, which has
        no SSH_AUTH_SOCK and a /tmp of its own, so never one under /tmp: an
        agent at /run/user/<uid>, as gcr's and gpg-agent's are. A string,
        never a Nix path: one would copy a socket into the store. Exactly
        one of this and `keyFile`.
      '';
    };
    keyFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/home/alice/.ssh/frisket";
      description = ''
        An unencrypted private key frisket logs in with, in place of an
        agent: a file the daemon's user reads, never in the store and never
        under /tmp. A string, never a Nix path, which would copy the key
        into the store for every user to read.
      '';
    };
    identity = mkOption {
      type = types.nullOr (types.strMatching "SHA256:[A-Za-z0-9+/]{43}");
      default = null;
      example = "SHA256:Lr8Pr7r6bsvXmV8bwNDaTqkB0M3h9G7oVqPgvs9uRkE";
      description = ''
        The one key of the agent's to offer, by its fingerprint as
        `ssh-keygen -l` prints it, where the agent holds several and a
        machine counts each one offered against its limit.
      '';
    };
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule ({ config, ... }: {
      options.apps.ssh = ops.appOptions config // {
        enable = mkEnableOption ''
          SSH in this tier, to the machines a project's grant names: ssh
          in a session reaches each by its name there, through frisket,
          which logs in with `chase.apps.ssh`'s credential and decides each
          command by the catalogue's operations -- a read allowed, the rest
          answered as `writes`, `guarded` and `unmatched` say. Only for a
          tier that takes grants'';
        env = mkOption {
          type = types.listOf (types.strMatching "[A-Za-z_][A-Za-z0-9_]*[*]?");
          default = [ "LANG" "LC_*" "TZ" "COLUMNS" "LINES" "NO_COLOR" "SYSTEMD_COLORS" ];
          example = [ "LANG" "LC_*" ];
          description = ''
            The variables a command may set for itself in front of it --
            `LANG=C sort x`, `env TZ=UTC date` -- which frisket takes off and
            decides the command after them as it would without; a command
            setting any other is unmatched. A name, or the start of one and
            a trailing `*`. frisket refuses a name that changes what any
            command runs -- `PATH`, `LD_*`, `BASH_ENV`, `IFS` and their kin --
            but cannot refuse one that a single program reads as code, or as
            a program to run: `PAGER`, `SYSTEMD_PAGER`, `LESSOPEN`,
            `GIT_SSH_COMMAND`, `PYTHONPATH`. Never list one: a rule for
            `systemctl status` would then run whatever it names. The tier's
            alone, never a grant's. The default's locale and timezone names
            can name a file, whose data the library parsing it trusts, so
            frisket reads no value that names one of the session's choosing
            -- beginning `/`, `.` or `:`, or holding `..` or `%`:
            `LC_ALL=/tmp/l ls` is unmatched, and `TZ=Europe/London date`
            what it seems. Its arg rules see the rest, so one naming a
            secret is refused as the secret is. frisket also refuses
            glibc's `LOCPATH`, `NLSPATH` and `GLIBC_TUNABLES`.
          '';
        };
      };
    }));
  };

  config = {
    assertions = lib.concatLists (lib.mapAttrsToList (name: tier: lib.optionals tier.apps.ssh.enable [
      {
        assertion = tier.grants;
        message = "chase.tiers.${name}.apps.ssh is enabled, but the tier takes no grant: which machines a session reaches, and as whom, are only ever a project's.";
      }
      {
        assertion = !tier.bare;
        message = "chase.tiers.${name}.apps.ssh is enabled, but the tier is bare: frisket is what holds the key, and a bare tier has no frisket.";
      }
    ]) cfg.tiers)
    ++ lib.optionals wanted ([
      {
        assertion = lib.length (lib.attrNames credentials) == 1;
        message = "chase.apps.ssh needs exactly one of agentSocket and keyFile: what frisket logs in to every machine with.";
      }
      {
        assertion = machine.identity == null || machine.agentSocket != null;
        message = "chase.apps.ssh.identity names a key of an agent's, and there is no agentSocket.";
      }
    ] ++ lib.mapAttrsToList (n: p: {
      assertion = pathProblem p == null;
      message = "chase.apps.ssh.${n} is '${p}', which ${toString (pathProblem p)}.";
    }) credentials);

    # ssh's own config, ahead of NixOS's `Host *`, as extraConfig always is:
    # frisket's Host blocks, and its CA as the known host of every one. ssh
    # takes the first value it reads, so this GlobalKnownHostsFile is the
    # one, with the system's own after it. The Include is frisket's file,
    # never a store path: ssh refuses an included file not owned by root or
    # the user, and the store's read as nobody's in a session, while
    # frisket's tmpfs is the session's root's, 0644. A session whose
    # document has no SSH route has no such file, and an Include of nothing
    # is nothing.
    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "chase-${name}" (mkIf (enabled ? ${name}) {
      config.programs.ssh.extraConfig = ''
        Include /etc/frisket/ssh_config
        GlobalKnownHostsFile /etc/frisket/ssh_known_hosts /etc/ssh/ssh_known_hosts
      '';
    })) cfg.tiers;

    # Made at launch, from each machine the grant names (internal/apps/ssh).
    chase.internal.projectApps = mkIf (enabled != { }) { ssh.credential = false; };
    chase.internal.config = mkIf (enabled != { }) {
      grant.ssh = {
        tiers = lib.mapAttrs (_: tier: ops.answers tier.apps.ssh // { inherit (tier.apps.ssh) env; }) enabled;
        catalogue = "${./ssh/operations.json}";
      } // lib.optionalAttrs (machine.agentSocket != null) { agent = machine.agentSocket; }
      // lib.optionalAttrs (machine.keyFile != null) { inherit (machine) keyFile; }
      // lib.optionalAttrs (machine.identity != null) { inherit (machine) identity; };
    };
  };
}
