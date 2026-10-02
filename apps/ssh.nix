{ config, lib, pkgs, ... }:

# SSH through frisket (docs/apps/ssh.md): commands on the machines a
# project's grant names, each an SSH route frisket terminates, logging in
# with the user's own key, which never enters the session, and deciding
# every command by the catalogue's operations (./ssh/operations.json),
# answered as the tier says and the project's lists before it. frisket
# gives the session its ssh_config and the CA its host certificates are
# signed by, in /etc/frisket; what is here points ssh at them. The
# machines are a project's grant's to name and a person's to approve, or
# the tier's own (`hosts`), in every session of it, each logging in with
# its own credential or the machine's. A machine that is no Linux machine --
# a modem's CLI -- names a catalogue of its own the machine offers
# (`catalogues`), which decides it in place of Linux's.

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.chase;
  ops = import ../lib/operations.nix { inherit lib; };
  machine = cfg.apps.ssh;

  enabled = lib.filterAttrs (_: t: !t.bare && (t.grants || t.apps.ssh.hosts != { }) && t.apps.ssh.enable) cfg.tiers;
  wanted = lib.any (t: t.apps.ssh.enable) (lib.attrValues cfg.tiers);
  # The machine's credential is what a grant's machines log in with, and a
  # tier's that names none of its own.
  needed = lib.any (t: t.apps.ssh.enable && (t.grants || lib.any (h: hostCredentials h == { }) (lib.attrValues t.apps.ssh.hosts)))
    (lib.attrValues cfg.tiers);

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
  hostCredentials = h: lib.filterAttrs (_: p: p != null) { inherit (h) agent keyFile passwordFile; };

  # A tier's machine as internal/apps/ssh reads it: what it leaves out is
  # the default there.
  hostConfig = h: lib.filterAttrs (n: v: v != null && v != [ ] && v != false && v != { }) {
    inherit (h) address user hostKeys allow ask refuse unmatched shell catalogue expect agent keyFile passwordFile identity;
  };

  # A catalogue's name, as a tier's machine names one: kebab-case, never a
  # path. A grant's machine names none, and is decided by the Linux one.
  catalogueName = "[a-z][a-z0-9]*(-[a-z0-9]+)*";
  # Each in the store, the one the system was built with and checked
  # against (system.checks, below), never a file a launch reads as it is
  # then.
  catalogues = lib.mapAttrs (_: p: "${p}") machine.catalogues;

  answer = types.enum [ "allow" "ask" "refuse" ];
  fingerprint = types.strMatching "SHA256:[A-Za-z0-9+/]{43}";

  host = types.submodule {
    options = {
      address = mkOption {
        type = types.str;
        example = "10.0.0.4";
        description = "A literal IP, v4:port or [v6]:port; 22 by default. Never a name: what is reached is fixed here.";
      };
      user = mkOption {
        type = types.str;
        example = "core";
        description = "Who the commands run as.";
      };
      hostKeys = mkOption {
        type = types.listOf types.str;
        example = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHp6lanvRi86XJnpME3lUbtyAWnykpE7SwLQXBzaXa/F" ];
        description = ''
          The machine's own keys, as known_hosts writes them less the host:
          the one trust in it, never learnt on first use.
        '';
      };
      allow = mkOption { type = types.listOf types.str; default = [ ]; description = "Operation ids, `category:<name>` or command patterns allowed on this machine, before the tier."; };
      ask = mkOption { type = types.listOf types.str; default = [ ]; description = "Likewise, asked about."; };
      refuse = mkOption { type = types.listOf types.str; default = [ ]; description = "Likewise, refused."; };
      unmatched = mkOption {
        type = types.nullOr answer;
        default = null;
        description = "What a command no rule matches is answered with, in place of the tier's `unmatched`.";
      };
      catalogue = mkOption {
        type = types.nullOr (types.strMatching catalogueName);
        default = null;
        example = "zyxel-vmg4005";
        description = ''
          The catalogue this machine's commands are decided by, by its name
          in `chase.apps.ssh.catalogues`, in place of the Linux one: its
          operations, its secrets and its topics alone, answered as the
          tier says. For a device whose CLI is no Linux shell, where `cat`
          and `uptime` are no command of its own. The tier's alone: a
          grant's machine names none, since one naming a device's catalogue
          for a Linux machine would take every Linux secret, write and
          guarded rule off it.
        '';
      };
      expect = mkOption {
        type = types.attrsOf (types.enum [ "allow" "ask" "refuse" ]);
        default = { };
        example = { "cat /etc/passwd" = "ask"; "sys atcr" = "refuse"; };
        description = ''
          What this machine's commands must be answered, by command,
          checked when the system is built: its catalogue's and the tier's
          answers pinned where they matter, so that an edit changing one
          fails the build rather than reaching a session. Every command
          answered otherwise is said together.
        '';
      };
      shell = mkOption {
        type = types.bool;
        default = false;
        description = ''
          For a device whose login shell ignores the command an exec
          carries -- a router's or a modem's CLI: frisket types each command
          into that shell on a terminal, and gives back what it printed.
          Only one simple command of plain words is readable there, none
          of its stdin is sent, and the tier's `env` is not taken off it.
        '';
      };
      agent = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "An ssh-agent's socket to log in to this machine with, in place of `chase.apps.ssh`'s credential.";
      };
      keyFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "An unencrypted private key to log in with, in place of `chase.apps.ssh`'s credential.";
      };
      passwordFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/secrets/modem-password";
        description = ''
          A file holding the password to log in with, for a machine that
          takes no key: read by frisket at each login, and never by the
          session, which is given nothing of it. A sops-nix secret's path,
          owned by the user.
        '';
      };
      identity = mkOption {
        type = types.nullOr fingerprint;
        default = null;
        description = "The one key of this machine's own `agent` to offer.";
      };
    };
  };
in
{
  options.chase.apps.ssh = {
    catalogues = mkOption {
      type = types.attrsOf types.path;
      default = { };
      example = lib.literalExpression "{ zyxel-vmg4005 = ./zyxel-vmg4005.json; }";
      description = ''
        Catalogues of a device's own commands, by the name a tier's
        machine's `catalogue` names each by; a grant's machine names none,
        and is decided by the Linux catalogue. Each is a list of
        operations in the shape of chase's apps/ssh/operations.json, its
        categories its own, kebab-case, held to the checks the Linux one
        is when the system is built and at every launch. Copied into the
        store.
      '';
    };
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
          tier that takes grants, or names machines of its own in `hosts`'';
        hosts = mkOption {
          type = types.attrsOf host;
          default = { };
          example = lib.literalExpression ''
            {
              server = { address = "10.0.0.4"; user = "core"; hostKeys = [ "ssh-ed25519 AAAA..." ]; };
              modem = { address = "192.168.1.1"; user = "admin"; hostKeys = [ "ssh-rsa AAAA..." ]; passwordFile = "/run/secrets/modem-password"; shell = true; };
            }
          '';
          description = ''
            The tier's own machines, by the name ssh knows each by in a
            session: in every session of the tier, whatever its checkout's
            grant says, and decided as a grant's machine is -- by the
            catalogue, the tier's answers and the machine's own lists. Each
            logs in with its own `agent`, `keyFile` or `passwordFile`, or,
            naming none, with `chase.apps.ssh`'s, and none of it is ever in
            the session: frisket reads it, at login. A grant adds machines
            beside these, and never one of the same name or address.
          '';
        };
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
        assertion = tier.grants || tier.apps.ssh.hosts != { };
        message = "chase.tiers.${name}.apps.ssh is enabled, but the tier takes no grant and names no machine of its own in hosts: a session would reach none.";
      }
      {
        assertion = !tier.bare;
        message = "chase.tiers.${name}.apps.ssh is enabled, but the tier is bare: frisket is what holds the key, and a bare tier has no frisket.";
      }
    ] ++ lib.concatLists (lib.mapAttrsToList (h: m: let at = "chase.tiers.${name}.apps.ssh.hosts.${h}"; creds = hostCredentials m; in [
      {
        assertion = builtins.match "[a-z0-9][a-z0-9.-]*" h != null;
        message = "${at}: '${h}' is not a host's name: lower-case letters, digits, dots and hyphens, starting with a letter or digit.";
      }
      {
        assertion = m.hostKeys != [ ];
        message = "${at}.hostKeys is empty: the machine's own key is the only trust in it, and none is ever learnt on first use.";
      }
      {
        assertion = lib.length (lib.attrNames creds) <= 1;
        message = "${at} names ${lib.concatStringsSep " and " (lib.attrNames creds)}: frisket logs in with one of agent, keyFile and passwordFile.";
      }
      {
        assertion = m.identity == null || m.agent != null;
        message = "${at}.identity names a key of the host's own agent, and it names no agent.";
      }
      {
        assertion = m.catalogue == null || machine.catalogues ? ${m.catalogue};
        message = "${at}.catalogue is '${toString m.catalogue}', which is no catalogue chase.apps.ssh.catalogues offers: it offers ${if machine.catalogues == { } then "none" else lib.concatStringsSep ", " (lib.attrNames machine.catalogues)}.";
      }
    ] ++ lib.mapAttrsToList (n: p: {
      assertion = pathProblem p == null;
      message = "${at}.${n} is '${p}', which ${toString (pathProblem p)}.";
    }) creds) tier.apps.ssh.hosts)) cfg.tiers)
    ++ lib.concatLists (lib.mapAttrsToList (name: tier: lib.optional (tier.apps.ssh.hosts != { }) {
      assertion = tier.apps.ssh.enable;
      message = "chase.tiers.${name}.apps.ssh.hosts names machines, and apps.ssh is not enabled.";
    }) cfg.tiers)
    ++ lib.mapAttrsToList (n: p: {
      assertion = builtins.match catalogueName n != null && lib.hasPrefix "${builtins.storeDir}/" p;
      message = "chase.apps.ssh.catalogues.${n}: a catalogue is named in kebab-case, as a machine's `catalogue` names it, and is a file in the store, as a Nix path is: '${p}'.";
    }) catalogues
    ++ lib.optionals wanted ([
      {
        assertion = lib.length (lib.attrNames credentials) <= 1;
        message = "chase.apps.ssh needs exactly one of agentSocket and keyFile: what frisket logs in to every machine with.";
      }
      {
        assertion = !needed || lib.length (lib.attrNames credentials) == 1;
        message = "chase.apps.ssh needs exactly one of agentSocket and keyFile: what frisket logs in to a grant's machines with, and a tier's that names none of its own.";
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

    # What a launch would refuse of the machine's own -- each catalogue,
    # the Linux one too, and each tier's machines -- refused by the
    # system's build instead, by the binary that launches it, rather than
    # by a session that does not start.
    system.checks = lib.optional (enabled != { }) (pkgs.runCommand "chase-ssh-check" { } ''
      ${lib.getExe cfg.package} -config ${config.environment.etc."chase/config.json".source} ssh-check
      touch $out
    '');

    # Made at launch, from each machine the grant names (internal/apps/ssh).
    chase.internal.projectApps = mkIf (enabled != { }) { ssh.credential = false; };
    # A tier with machines of its own and no grant is still launched as one
    # that takes grants, for its machines' routes (../grant.nix).
    chase.internal.launchedTiers = lib.attrNames (lib.filterAttrs (_: t: !t.grants) enabled);
    chase.internal.config = mkIf (enabled != { }) {
      grant.ssh = {
        tiers = lib.mapAttrs (_: tier: ops.answers tier.apps.ssh // { inherit (tier.apps.ssh) env; }
          // lib.optionalAttrs (tier.apps.ssh.hosts != { }) { hosts = lib.mapAttrs (_: hostConfig) tier.apps.ssh.hosts; }) enabled;
        catalogue = "${./ssh/operations.json}";
      } // lib.optionalAttrs (catalogues != { }) { inherit catalogues; }
      // lib.optionalAttrs (machine.agentSocket != null) { agent = machine.agentSocket; }
      // lib.optionalAttrs (machine.keyFile != null) { inherit (machine) keyFile; }
      // lib.optionalAttrs (machine.identity != null) { inherit (machine) identity; };
    };
  };
}
