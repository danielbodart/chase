{ config, lib, ... }:

let
  cfg = config.chase;
in
{
  config.home-manager.users.${cfg.user} = lib.mkIf (lib.any (t: t.apps.gcloud.enable) (lib.attrValues cfg.tiers)) {
    # One per session, started by its launch and stopped before its run
    # directory is removed: `chase gcloud-renew loop` mints the session's
    # Google token from its service-account key, ten minutes before the last
    # one expires (internal/gcloud).
    systemd.user.services."chase-gcloud-renew@" = {
      Unit.Description = "Renew session %i's Google Cloud token";
      Service = {
        ExecStart = "${lib.getExe cfg.package} gcloud-renew loop %t/chase/%i";
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
