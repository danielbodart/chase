# nix: for now, a checkout's devShell -- flake.nix's devShells.<system>.default,
# or its shell.nix -- in its sessions, as `nix develop` would give it on the
# host (PLAN.md, decision 21). The store is in every session already; what a
# session lacks is the environment, which flong starts clean.
#
# So the launcher, as the caller, realises the devShell before the session
# starts (internal/devshell): with none of the caller's environment but
# HOME, a flake purely and a shell.nix restricted; cached on its files and
# kept rooted in chase's state; and handed to the session's payload, whose
# wrapper puts its PATH behind the setuid wrappers and mise's shims and runs
# its shellHook inside the session. Never `nix` itself inside one, which is
# flong's to give.
#
# Only in a tier for one's own code, whose egress is direct and unfiltered:
# what is evaluated is the checkout itself, on the host, in a bubblewrap
# that shows it nothing of the host's but the store, the daemon and the
# checkout, its fetches the host's own. Someone else's waits on a store of
# the session's own, where the session evaluates it itself, through frisket
# (flong's PLAN §3).
{ config, options, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkOption types;
  cfg = config.chase;
  apps = import ../lib/apps.nix { inherit lib; };
  machine = options.chase.apps.nix;

  enabled = lib.filterAttrs (_: t: !t.bare && t.apps.nix.enable) cfg.tiers;
in
{
  options.chase.apps.nix = {
    package = mkOption {
      type = types.package;
      default = config.nix.package;
      defaultText = lib.literalExpression "config.nix.package";
      description = ''
        The nix that realises a checkout's devShell, as the caller. The
        machine's own, so what it evaluates is what `nix develop` on the host
        would evaluate.
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
      options.apps.nix = apps.overrides machine [ "package" "nixpkgs" "timeout" ] // {
        enable = mkEnableOption ''
          nix in this tier's sessions: for now, the checkout's devShell --
          flake.nix's devShells.<system>.default, or its shell.nix --
          realised on the host, as you, whenever the checkout has one, and
          given to the session as its environment. Only where egress is
          direct and unfiltered: it is your own code, fetching as the host'';
      };
    });
  };

  config = {
    assertions = lib.concatLists (lib.mapAttrsToList (name: tier: [
      {
        assertion = !(tier.bare && tier.apps.nix.enable);
        message = "chase.tiers.${name}.apps.nix is enabled, but the tier is bare: its agent runs on the host, whose `nix develop` is its own.";
      }
      {
        assertion = tier.bare || !tier.apps.nix.enable || (tier.egress == "direct" && tier.allow == [ "*" ]);
        message = "chase.tiers.${name}.apps.nix is enabled, but the tier's egress is not direct and unfiltered: a devShell is evaluated on the host, as you, its fetches the host's own, neither filtered nor logged, which is for your own code alone. Other people's waits on a store of the session's own, where the session evaluates it itself, through frisket (flong's PLAN §3).";
      }
    ]) cfg.tiers);

    # What exec realises a devShell with, for each tier that has nix: the
    # tools at their store paths, never looked up on PATH.
    chase.internal.config.session.tiers = lib.mapAttrs (_: tier: {
      nix = {
        inherit (cfg.internal.config.selector) git emptySha1 emptySha256;
        inherit (tier.apps.nix) timeout;
        nix = lib.getExe tier.apps.nix.package;
        nixpkgs = "${tier.apps.nix.nixpkgs}";
        system = pkgs.stdenv.hostPlatform.system;
        bwrap = lib.getExe pkgs.bubblewrap;
        # The machine's, for the evaluation's https.
        caBundle = "${config.security.pki.caBundle}";
      };
    }) enabled;
  };
}
