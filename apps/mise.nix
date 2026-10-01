# mise: the toolchains a checkout's own mise.toml asks for, installed and on
# PATH in a session as on the host. No credential and no route of its own:
# what it downloads comes through frisket like anything else.
#
# What it keeps is its installs and its downloads, kept at its `scope` as a
# tier's caches are, and its state -- above all what `mise trust` has
# trusted, which lets a config's env and hooks run -- which is never kept:
# the host's is readable in every session, and what a session trusts goes
# with it (PLAN.md, decision 19).
{ config, options, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkMerge mkOption types;
  cfg = config.chase;
  apps = import ../lib/apps.nix { inherit lib; };
  machine = options.chase.apps.mise;

  # Where mise keeps its installs, its state and its downloads on the host,
  # and in a session that is not a store's: named, never left to
  # XDG_DATA_HOME and XDG_CACHE_HOME, which a tier keeping caches points
  # elsewhere.
  dirs = {
    MISE_DATA_DIR = "${cfg.home}/.local/share/mise";
    MISE_STATE_DIR = "${cfg.home}/.local/state/mise";
    MISE_CACHE_DIR = "${cfg.home}/.cache/mise";
  };

  # A tier's store: its directory is chase's (Root/<tier>/all), so its shims
  # are known when the system is built.
  storeRoot = "${cfg.home}/.cache/chase/mise";
  dataDir = name: tier:
    if tier.apps.mise.scope == "tier"
    then "${storeRoot}/${name}/all/data"
    else dirs.MISE_DATA_DIR;

  enabled = lib.filterAttrs (_: t: !t.bare && t.apps.mise.enable) cfg.tiers;
in
{
  options.chase.apps.mise = {
    package = mkOption {
      type = types.package;
      default = pkgs.mise;
      defaultText = lib.literalExpression "pkgs.mise";
      description = ''
        mise. The host's own, where the host has one, so a toolchain
        resolved on the host is the toolchain found in a session.
      '';
    };
    config = mkOption {
      type = types.listOf (types.strMatching "/.*");
      default = [ "${cfg.home}/.config/mise" ];
      defaultText = lib.literalExpression ''[ "''${config.chase.home}/.config/mise" ]'';
      description = ''
        The user's own mise configuration, bound read-only at the same paths:
        `all_compile = false` above all, without which mise in a session
        builds node and the rest from source rather than fetching the
        binaries the host uses. Made if missing. Empty: none.
      '';
    };
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule ({ config, ... }: {
      options.apps.mise = apps.overrides machine [ "package" "config" ] // {
        enable = mkEnableOption ''
          mise in this tier: the toolchains a checkout asks for, with their
          shims on PATH'';
        trust = mkEnableOption ''
          trusting each checkout in this tier in mise, as `mise trust`
          would, so the env and hooks of its config files run without
          asking: MISE_TRUSTED_CONFIG_PATHS names the checkout at launch,
          and nothing is written to mise's own records. For a tier of
          checkouts you vouch for; a bare tier may say it too, for mise run
          by an agent on the host'';
        scope = mkOption {
          type = types.enum [ "session" "tier" "host" ];
          default = if config.caches == "tier" then "tier" else "session";
          defaultText = lib.literalExpression ''"tier" where the tier's `caches` is, otherwise "session"'';
          description = ''
            Where mise's installs and downloads are kept, as the tier's
            `caches` say unless said here. `session`: the host's are
            overlaid, readable, and what a session installs goes with it.
            `tier`: kept on the host for every checkout in the tier, apart
            from the host's, under ~/.cache/chase/mise. `host`: the host's
            own, read-write, so a toolchain installed once is there in every
            session and on the host -- not for a tier that runs other
            people's code, since the host runs what is in it. No
            `workspace`, so a tier whose caches are a workspace's has
            `session`: the shims go on PATH when the system is built, before
            a workspace is known.
          '';
        };
      };
    }));
  };

  config = {
    # On the host: a bind's or an overlay's source must exist, and flong
    # makes none for it.
    systemd.tmpfiles.rules = mkIf (enabled != { }) (map
      (p: "d ${p} 0755 ${cfg.user} ${toString cfg.gid} -")
      (lib.unique (lib.attrValues dirs ++ lib.concatMap (t: t.apps.mise.config) (lib.attrValues enabled))));

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" (mkIf tier.apps.mise.enable {
      bindMounts = lib.listToAttrs (map
        (p: lib.nameValuePair p { hostPath = p; isReadOnly = true; })
        tier.apps.mise.config)
      // lib.optionalAttrs (tier.apps.mise.scope == "host") {
        ${dirs.MISE_DATA_DIR} = { hostPath = dirs.MISE_DATA_DIR; isReadOnly = false; };
        ${dirs.MISE_CACHE_DIR} = { hostPath = dirs.MISE_CACHE_DIR; isReadOnly = false; };
      };
      config = mkMerge [
        {
          # mise's generic-Linux binaries need a real /lib64 loader.
          programs.nix-ld.enable = true;
          environment.systemPackages = [ tier.apps.mise.package ];
          # mise is here where the host's home-manager puts it too: see the
          # host's systemPackages below.
          environment.etc."profiles/per-user/${cfg.user}/bin/mise".source = lib.getExe tier.apps.mise.package;
          # The shims on PATH, since nothing else puts them there: on the
          # host a shell hook does, and a session runs no shell init. flong
          # reads this into the session's environment when the system is
          # built. Each shim is a link to /run/current-system/sw/bin/mise,
          # which the container has above, and resolves the tool for
          # whatever directory it runs in.
          environment.extraInit = ''
            export PATH="${dataDir name tier}/shims:$PATH"
          '';
          # The state is the host's, overlaid, in every scope.
          environment.variables.MISE_STATE_DIR = dirs.MISE_STATE_DIR;
        }
        # A tier's store names the other two itself.
        (mkIf (tier.apps.mise.scope != "tier") {
          environment.variables = { inherit (dirs) MISE_DATA_DIR MISE_CACHE_DIR; };
        })
      ];
    })) cfg.tiers;

    # A tier's store; and trust, by naming the checkout at launch, never by
    # writing mise's own records: in a session (internal/session), or on
    # the host for a bare tier, by the wrapper.
    chase.internal.config.session.tiers = lib.mapAttrs (_: tier:
      lib.optionalAttrs (tier.apps.mise.scope == "tier") {
        stores.mise = {
          scope = "tier";
          root = storeRoot;
          env = { MISE_DATA_DIR = "data"; MISE_CACHE_DIR = "cache"; };
        };
      } // lib.optionalAttrs tier.apps.mise.trust {
        trustEnv = [ "MISE_TRUSTED_CONFIG_PATHS" ];
      }) enabled;
    chase.internal.config.selector.tiers = lib.mapAttrs (_: _: {
      trust.env = [ "MISE_TRUSTED_CONFIG_PATHS" ];
    }) (lib.filterAttrs (_: t: t.bare && t.apps.mise.trust) cfg.tiers);

    # Overlays: the host's state in every scope, and its installs in a
    # session's, readable, and whatever a session writes there discarded
    # with it. Safe only because mise keeps no sqlite.
    flong = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" {
      overlays = {
        ${dirs.MISE_STATE_DIR} = dirs.MISE_STATE_DIR;
      } // lib.optionalAttrs (tier.apps.mise.scope == "session") {
        ${dirs.MISE_DATA_DIR} = dirs.MISE_DATA_DIR;
      };
    }) enabled;

    # A shim is a link to whichever mise last reshimmed, by the path it ran
    # from: /etc/profiles/per-user/<user>/bin/mise on the host, where
    # home-manager puts it, and /run/current-system/sw/bin/mise in a session.
    # With the shims the host's, each side's reshim broke the other's. The
    # same mise at both paths on both sides makes every shim resolve
    # wherever it was written.
    environment.systemPackages = lib.optional
      (lib.any (t: t.apps.mise.scope == "host") (lib.attrValues enabled))
      cfg.apps.mise.package;
  };
}
