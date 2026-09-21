{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.chase;
in
{
  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.audio.enable = mkEnableOption "host audio in this agent tier";
    });
  };

  config.containers = lib.mapAttrs' (name: tier:
    lib.nameValuePair "agent-${name}" (mkIf tier.apps.audio.enable {
      bindMounts = {
        # Only the pulse directory: the rest of /run/user/<uid> includes the
        # session D-Bus, which can run commands on the host.
        "/run/user/${toString cfg.uid}/pulse" = {
          hostPath = "/run/user/${toString cfg.uid}/pulse";
          isReadOnly = false;
        };
        # allowedDevices only grants the cgroup permission; the node itself
        # has to be bound into nspawn's private /dev.
        "/dev/snd" = { hostPath = "/dev/snd"; isReadOnly = false; };
      };
      allowedDevices = [{ node = "/dev/snd"; modifier = "rw"; }];
      config.environment.systemPackages = [ pkgs.pulseaudio pkgs.sound-theme-freedesktop ];
    })) cfg.tiers;
}
