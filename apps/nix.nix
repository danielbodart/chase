# nix: a checkout's devShell -- flake.nix's devShells.<system>.default, or
# its shell.nix -- in its sessions, as `nix develop` would give it on the
# host (PLAN.md, decision 21). The store is in every session already; what a
# session lacks is the environment, which flong starts clean. Where it is
# evaluated is the tier's `store`.
#
# `host`: the launcher, as the caller, realises the devShell before the
# session starts (internal/devshell): with none of the caller's environment
# but HOME, a flake purely and a shell.nix restricted; cached on its files
# and kept rooted in chase's state; and handed to the session's payload,
# whose wrapper puts its PATH behind the setuid wrappers and mise's shims
# and runs its shellHook inside the session. Only in a tier for one's own
# code, whose egress is direct and unfiltered: what is evaluated is the
# checkout itself, on the host, in a bubblewrap that shows it nothing of
# the host's but the store, the daemon and the checkout, its fetches the
# host's own.
#
# `session`: the session runs nix itself, single-user, over a store of its
# own (internal/nixstore, flong's PLAN §3) -- a local-overlay store whose
# lower is the host's, read-only, and whose upper is an overlay of
# /nix/store that flong keeps in a directory of the caller's for this one
# launch -- and chase-devshell evaluates the devShell in the session, ahead
# of the agent, its fetches the session's own, through its network. Nothing
# of the checkout's Nix is evaluated on the host. For a tier of other
# people's code, its egress frisket's; the host roots what the store looks
# at of its own, bounds it, and, after it, realises what it substituted
# from the host's own caches, by name.
#
# When is the tier's `devShell`: `automatic`, whenever the checkout has
# one; `granted`, only when its approved grant asks (`apps.nix.devShell`).
{ config, options, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkOption types;
  cfg = config.chase;
  apps = import ../lib/apps.nix { inherit lib; };
  machine = options.chase.apps.nix;
  chase = lib.getExe cfg.package;

  enabled = lib.filterAttrs (_: t: !t.bare && t.apps.nix.enable) cfg.tiers;
  inSession = lib.filterAttrs (_: t: t.apps.nix.store == "session") enabled;

  # The read-only local store, patched to read its database as any other
  # reader, through the WAL, rather than as immutable: a session's lower is
  # the host's live database, which an immutable read misses the WAL of and
  # fails on mid-checkpoint (flong's PLAN §3). Upstream's, once it is there.
  patched = nix: nix.appendPatches [ ./nix/read-only-local-store-mode-ro.patch ];
in
{
  options.chase.apps.nix = {
    package = mkOption {
      type = types.package;
      default = config.nix.package;
      defaultText = lib.literalExpression "config.nix.package";
      description = ''
        The host's nix: the one that realises a checkout's devShell, as the
        caller, where the tier's store is the host's, and roots on the host
        what a session's own store looks at where it is the session's. The
        machine's own, so what it evaluates is what `nix develop` on the
        host would evaluate.
      '';
    };
    sessionPackage = mkOption {
      type = types.package;
      default = patched pkgs.nixVersions.latest;
      defaultText = lib.literalExpression "pkgs.nixVersions.latest.appendPatches [ ./nix/read-only-local-store-mode-ro.patch ]";
      description = ''
        The nix a session whose store is its own runs: the container's, on
        its PATH, and what evaluates its devShell there. Its read-only local
        store must read the host's database as any other reader does, not
        as immutable, which the default is patched for; its database
        schema must be the host's.
      '';
    };
    nixpkgs = mkOption {
      type = types.path;
      default = pkgs.path;
      defaultText = lib.literalExpression "pkgs.path";
      description = ''
        What `<nixpkgs>` is to a checkout's shell.nix, the one entry of its
        NIX_PATH beside the checkout. The system's own, so a shell.nix that
        imports it fetches nothing.
      '';
    };
    timeout = mkOption {
      type = types.ints.positive;
      default = 1200;
      description = ''
        Seconds a devShell's realisation may take before it is killed and
        counts as a failure.
      '';
    };
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.nix = apps.overrides machine [ "package" "sessionPackage" "nixpkgs" "timeout" ] // {
        enable = mkEnableOption ''
          nix in this tier's sessions: the checkout's devShell -- flake.nix's
          devShells.<system>.default, or its shell.nix -- given to the
          session as its environment, evaluated where `store` says'';
        devShell = mkOption {
          type = types.enum [ "automatic" "granted" ];
          default = "automatic";
          description = ''
            When a checkout's devShell is given. `automatic`: whenever the
            checkout has one; one that cannot be had is said, and the session
            starts without it. `granted`: only when the checkout's approved
            grant asks for it (`apps.nix.devShell`), and one that cannot be
            had ends the session before its agent -- for a tier of other
            people's code, which takes grants, and whose store is the
            session's.
          '';
        };
        store = mkOption {
          type = types.enum [ "host" "session" ];
          default = "host";
          description = ''
            Where the devShell is evaluated. `host`: by the launcher, as you,
            before the session starts, its fetches the host's own -- for a
            tier of your own code alone, whose egress is direct and
            unfiltered; the session has no nix of its own. `session`: by the
            session itself, over a nix store of its own -- an overlay of the
            host's, kept for the one launch in
            ~/.cache/chase/nix/sessions/<machine> -- its fetches the
            session's, through its network; the session runs `nix` too.
            `caches` does not govern this store, which is always the
            session's alone.
          '';
        };
        maxBytes = mkOption {
          type = types.ints.positive;
          default = 8 * 1024 * 1024 * 1024;
          defaultText = lib.literalExpression "8 GiB";
          description = ''
            Bytes a session's own store may hold on disk, its upper, before
            the session is stopped, saying so. And the most a session's
            store may hold for what it substituted to be promoted after it.
          '';
        };
        maxInodes = mkOption {
          type = types.ints.positive;
          default = 500000;
          description = "Inodes a session's own store may hold before the session is stopped, saying so.";
        };
        maxRoots = mkOption {
          type = types.ints.positive;
          default = 20000;
          description = ''
            Most of the host's paths rooted for one session's store, those it
            looks at of the host's, so the host's garbage collection does not
            take one from under it. A flake like waydriver's looks at 8,521.
          '';
        };
        promote = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Whether what a session's own store substituted is realised on the
            host after it, by name, from the host's own substituters, with no
            build, so the next session finds it in the lower. Nothing a
            session built, nor anything unsigned, reaches the host: no cache
            has it.
          '';
        };
      };
    });
  };

  config = lib.mkMerge [
    {
      assertions = lib.concatLists (lib.mapAttrsToList (name: tier: let n = tier.apps.nix; in [
        {
          assertion = !(tier.bare && n.enable);
          message = "chase.tiers.${name}.apps.nix is enabled, but the tier is bare: its agent runs on the host, whose `nix develop` is its own.";
        }
        {
          assertion = tier.bare || !n.enable || n.store == "session" || (tier.egress == "direct" && tier.allow == [ "*" ]);
          message = "chase.tiers.${name}.apps.nix is enabled with the host's store, but the tier's egress is not direct and unfiltered: a devShell is then evaluated on the host, as you, its fetches the host's own, neither filtered nor logged, which is for your own code alone. Set `store = \"session\"`, where the session evaluates it itself, through its own network.";
        }
        {
          assertion = !(n.enable && n.devShell == "granted" && n.store != "session");
          message = "chase.tiers.${name}.apps.nix.devShell is `granted`, and its store is the host's: a tier that takes grants for its devShell is one whose Nix must never be evaluated on the host. Set `store = \"session\"`.";
        }
        {
          assertion = !(n.enable && n.devShell == "granted" && !tier.grants);
          message = "chase.tiers.${name}.apps.nix.devShell is `granted`, and ${name} takes no grants, so nothing could ever turn it on: set `grants = true`, or `devShell = \"automatic\"`.";
        }
      ]) cfg.tiers);

      # What exec gives a session of nix, for each tier that has it: the
      # tools at their store paths, never looked up on PATH.
      chase.internal.config.session.tiers = lib.mapAttrs (_: tier: {
        nix = {
          inherit (cfg.internal.config.selector) git emptySha1 emptySha256;
          inherit (tier.apps.nix) timeout store devShell;
          nix = lib.getExe tier.apps.nix.package;
          nixpkgs = "${tier.apps.nix.nixpkgs}";
          system = pkgs.stdenv.hostPlatform.system;
        } // (if tier.apps.nix.store == "host" then {
          bwrap = lib.getExe pkgs.bubblewrap;
          # The machine's, for the evaluation's https.
          caBundle = "${config.security.pki.caBundle}";
        } else {
          session = {
            root = "${cfg.home}/.cache/chase/nix/sessions";
            nix = lib.getExe tier.apps.nix.sessionPackage;
            devshell = "${cfg.package}/bin/chase-devshell";
            nixStore = "${tier.apps.nix.package}/bin/nix-store";
            sqlite = "${lib.getBin pkgs.sqlite}/bin/sqlite3";
            systemdRun = "${config.systemd.package}/bin/systemd-run";
            # The container's, which the container's nix.settings below
            # write: never the user's.
            confDir = "/etc/nix";
            inherit (tier.apps.nix) maxBytes maxInodes maxRoots promote;
          };
        });
      }) enabled;
    }

    (lib.mkIf (inSession != { }) {
      # The session's own nix, and what it is set to: the local-overlay
      # store and the read-only one beneath it; no sandbox, which nix turns
      # off itself in a user namespace it cannot make another in, and no
      # build users, since it runs single-user as you; a flake's own
      # configuration never taken; and the machine's caches, signatures
      # required. The store is told it per session, in NIX_REMOTE.
      containers = lib.mapAttrs' (name: tier: lib.nameValuePair "chase-${name}" {
        config = {
          # A NixOS container's nix is the host daemon's, which a session
          # of this tier never reaches: its store is exec's to name.
          environment.variables.NIX_REMOTE = lib.mkForce null;
          nix.package = lib.mkForce tier.apps.nix.sessionPackage;
          nix.settings = {
            experimental-features = [ "nix-command" "flakes" "local-overlay-store" "read-only-local-store" ];
            sandbox = lib.mkForce false;
            build-users-group = lib.mkForce "";
            accept-flake-config = false;
            substituters = lib.mkForce config.nix.settings.substituters;
            trusted-public-keys = lib.mkForce config.nix.settings.trusted-public-keys;
            require-sigs = true;
          };
        };
      }) inSession;

      # The store made at binds, its watcher started at postStart in the
      # session's cgroup, and the store promoted and removed at postStop:
      # the tier's own launcher's, and its recording's, which shares its
      # binds.
      flong = lib.mkMerge (lib.mapAttrsToList (name: tier: {
        "chase-${name}" = {
          postStart = [ [ chase "hook" "nix-poststart" name ] ];
          postStop = [ [ chase "hook" "nix-poststop" name ] ];
        };
      } // lib.optionalAttrs tier.record.enable {
        "chase-${name}-record" = {
          postStart = [ [ chase "hook" "nix-poststart" name ] ];
          postStop = [ [ chase "hook" "nix-poststop" name ] ];
        };
      }) inSession);

      # What a launcher killed before its postStop left, removed hourly, as
      # each launch's binds removes it, so a crash loop does not pile them
      # up.
      home-manager.users.${cfg.user} = {
        systemd.user.services.chase-nix-sweep = {
          Unit.Description = "Remove the nix stores of sessions no container holds";
          Service = {
            Type = "oneshot";
            ExecStart = "${chase} nix-sweep";
          };
        };
        systemd.user.timers.chase-nix-sweep = {
          Unit.Description = "Remove the nix stores of sessions no container holds, hourly";
          Install.WantedBy = [ "timers.target" ];
          Timer = {
            OnCalendar = "hourly";
            Persistent = true;
          };
        };
      };
    })
  ];
}
