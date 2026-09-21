{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.agents;
  mise = cfg.apps.mise.package;
in
{
  options.agents.apps.mise.package = mkOption {
    type = types.package;
    default = pkgs.mise;
    defaultText = lib.literalExpression "pkgs.mise";
    description = ''
      mise. Has a default, unlike the agents' own packages, because nixpkgs
      carries it -- but a consumer whose host mise comes from elsewhere should
      bind the same one here, so a toolchain resolved on the host is the
      toolchain found in the session.
    '';
  };

  options.agents.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.mise.enable = mkEnableOption "mise toolchains in this agent tier";
    });
  };

  config = {
    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" (mkIf tier.apps.mise.enable {
      config = {
        # mise's generic-Linux binaries need a real /lib64 loader.
        programs.nix-ld.enable = true;
        environment.systemPackages = [ mise ];
      };
    })) cfg.tiers;

    # Overlays: the host's installs and trust are readable, and anything
    # installed in the session is discarded with it. Safe only because mise
    # keeps no sqlite.
    flong = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" (mkIf tier.apps.mise.enable {
      overlays = {
        "${cfg.home}/.local/share/mise" = "${cfg.home}/.local/share/mise";
        "${cfg.home}/.local/state/mise" = "${cfg.home}/.local/state/mise";
      };
    })) cfg.tiers;
  };
}
