{ config, lib, pkgs, ... }:

let
  cfg = config.chase;
  renew = import ../lib/gcloud-renew.nix { inherit pkgs; };
in
{
  options.chase.internal.gcloudRenew = lib.mkOption {
    internal = true;
    type = lib.types.package;
    default = renew;
    description = ''
      Mints a session's Google token from its service-account key:
      `mint RUN` once, `loop RUN` as `chase-gcloud-renew@<machine>`.
    '';
  };

  config.home-manager.users.${cfg.user} = lib.mkIf (lib.any (t: t.apps.gcloud.enable) (lib.attrValues cfg.tiers)) {
    # One per session, started by its launch and stopped before its run
    # directory is removed.
    systemd.user.services."chase-gcloud-renew@" = {
      Unit.Description = "Renew session %i's Google Cloud token";
      Service = {
        ExecStart = "${lib.getExe cfg.internal.gcloudRenew} loop %t/chase/%i";
        Restart = "on-failure";
        RestartSec = 60;
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateUsers = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = "tmpfs";
        BindPaths = "%t/chase";
        ProtectProc = "invisible";
        ProtectClock = true;
        ProtectHostname = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        CapabilityBoundingSet = "";
        SystemCallArchitectures = "native";
        SystemCallFilter = "@system-service";
      };
    };
  };
}
