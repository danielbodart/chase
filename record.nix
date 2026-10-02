# RECORDING: `chase record`, a session of a checkout's own tier that
# finds out what it needs (internal/record, internal/grant's record.go).
#
# A tier that records has a second launcher, flong.chase-<tier>-record, on
# the same container and with the tier's own binds, overlays, guard and
# filter. It differs in three ways:
#
#   network        none of flong's: frisket's "all" set steers every
#                  connection to frisket, so a name off the allowlist, a
#                  port, a host on the local network is seen and decided,
#                  as a direct tier's pasta would never show it
#   seccompPolicy  `chase hook record-approve`: the grant approved as for
#                  any launch, and flong's `log` lines after its own, so
#                  every call the filter would refuse is allowed and
#                  audited -- against the tier, or with --base none
#                  against nothing but the calls every process makes
#   exec           `chase hook record-exec`: the session's document as any
#                  launch writes it, with frisket's record block: what the
#                  policy would refuse or ask about is put to a person, or
#                  answered by --default, and written down
#
# Only a person starts one, with `chase record` from outside any session:
# no wrapper runs the record launcher, nothing in a checkout selects it,
# and what it is to record comes from that person's environment, which
# `chase record` sets and no session reaches. Its guard is the tier's, so
# it runs a checkout of its own tier and no other.
#
# Recording takes a tier whose seccompPolicy chase writes -- one that takes
# grants, or is launched as one for machines of its own -- and the person
# who records must be able to read the system journal, where the kernel's
# audit records of logged calls are (systemd-journal or wheel); journald
# reads them from the audit netlink by its audit socket, which NixOS
# enables by default.
self:
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types;
  cfg = config.chase;
  recording = lib.filterAttrs (_: t: !t.bare && t.record.enable) cfg.tiers;
  chase = lib.getExe cfg.package;
  system = pkgs.stdenv.hostPlatform.system;
  # The tiers whose seccompPolicy is chase's (grant.nix).
  takes = cfg.internal.config.grantTiers or [ ];
in
{
  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.record.enable = lib.mkEnableOption ''
        `chase record` in this tier: a second launcher,
        flong.chase-<tier>-record, on the tier's container, through which a
        person runs a session that writes down whatever the tier would
        refuse or ask about -- a request on a route, an SSH command, a
        connection to a name off the allowlist, a syscall -- and turns it
        into a proposal for the checkout's grant. Every connection goes
        through frisket in it, whatever `egress` says. A tier that takes
        grants, or is launched as one'';
    });
  };

  config = lib.mkMerge [
    {
      assertions = lib.mapAttrsToList
        (name: t: {
          assertion = !(t.bare && t.record.enable);
          message = ''
            chase.tiers.${name}.record.enable, but ${name} is bare: a recording
            is a sandbox's, steered through frisket, and a bare tier has none.
          '';
        })
        cfg.tiers;
    }
    (lib.mkIf (recording != { }) {
      assertions = lib.mapAttrsToList
        (name: _: {
          assertion = lib.elem name takes;
          message = ''
            chase.tiers.${name}.record.enable, but ${name} takes no grant: a
            recording is learnt through the seccompPolicy and the document
            chase writes for a tier that takes one. Set `grants = true`.
          '';
        })
        recording;

      flong = lib.mapAttrs'
        (name: _:
          let tier = config.flong."chase-${name}"; in
          lib.nameValuePair "chase-${name}-record" {
            container = "chase-${name}";
            # The tier's own session, as its launcher has it: who runs, where,
            # beside what, under which filter, checked by its guard.
            inherit (tier) user seccomp workspace binds guard overlays masks limits path;
            seccompPolicy = [ [ chase "hook" "record-approve" name ] ];
            exec = [ chase "hook" "record-exec" name ];
            postStop = [ [ chase "hook" "poststop" name ] ];
          })
        recording;

      # Every connection steered, as a tier with `egress = "frisket"` is, to
      # the document exec writes, with the tier's own parameters.
      services.frisket.flong = lib.mapAttrs'
        (name: _:
          let tier = config.services.frisket.flong."chase-${name}"; in
          lib.nameValuePair "chase-${name}-record" {
            inherit (tier) policy policyFile params steering;
            set = "all";
          })
        recording;

      chase.internal.config = {
        selector.tiers = lib.mapAttrs
          (name: _: {
            recordLauncher = lib.getExe config.flong."chase-${name}-record".launcher;
          })
          recording;
        # frisket's -record-dir, which its module makes and passes: where a
        # recording session's lines are appended, one file a session.
        grant.recordDir = "/var/lib/frisket/records";
        record = {
          journalctl = "${config.systemd.package}/bin/journalctl";
          seccomp = "${self.inputs.flong.packages.${system}.seccomp}/bin/flong-seccomp";
          # What each tier's filter allows, for a recording from scratch to
          # tell what is new: the names flong compiles a project's policy
          # against, from the declaration it renders.
          names = lib.mapAttrs
            (name: _:
              let p = config.environment.etc."flong/chase-${name}-record.zon".source.declaration.seccompProject; in
              lib.mkIf (p != null) p.names)
            recording;
        };
      };
    })
  ];
}
