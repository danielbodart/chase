{ config, lib, ... }:

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.chase;

  # Dragoman's own directory: the thread rollout, which is what
  # `codex_continue` resumes from, and the per-run homes it builds beside it.
  # Whole, not just the store: a bind of one entry leaves nspawn to make the
  # parent, which it makes root's, and the bridge then cannot write its runs.
  # Each run takes a directory of its own, so the host's sessions and a
  # container's do not collide.
  dragomanDir = "${cfg.home}/.dragoman";
in
{
  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.dragoman.enable = mkEnableOption ''
        Dragoman's thread store in this agent tier, so a Codex thread it
        started outlives the session. The bridge itself arrives with Claude
        Code's plugins, and authenticates as codex does: the home it builds
        symlinks the login, which is the placeholder frisket replaces'';
    });
  };

  config = {
    # nspawn refuses to start if a bind source is missing.
    home-manager.users.${cfg.user} = { lib, ... }: {
      home.activation.dragomanHome = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        mkdir -p ${lib.escapeShellArg dragomanDir}
      '';
    };

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" (mkIf tier.apps.dragoman.enable {
      bindMounts.${dragomanDir} = { hostPath = dragomanDir; isReadOnly = false; };
    })) cfg.tiers;
  };
}
