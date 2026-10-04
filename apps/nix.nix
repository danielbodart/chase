# nix: for now, a checkout's devShell -- flake.nix's devShells.<system>.default,
# or its shell.nix -- in its sessions, as `nix develop` would give it on the
# host (PLAN.md, decision 21). The store is in every session already; what a
# session lacks is the environment, which flong starts clean.
#
# So the launcher, as the caller, realises the devShell before the session
# starts (internal/devshell): confined, with nothing of the host but the
# store, the daemon's socket and nix's own configuration, and a network only
# as the tier's egress gives one; cached on its files and kept rooted in
# chase's state; and handed to the session's payload, whose wrapper puts
# its PATH behind the setuid wrappers and mise's shims and runs its
# shellHook inside the session. Never `nix` itself inside one, which is
# flong's to give.
#
# When is the tier's: `automatic`, for one's own code, whenever the
# checkout has a devShell; `granted`, for other people's, only when its
# approved grant asks (`apps.nix.devShell`). Off where the tier does not
# enable it.
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
        Seconds a devShell's realisation may take, every step together,
        before it is killed and counts as a failure.
      '';
    };
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.nix = apps.overrides machine [ "package" "nixpkgs" "timeout" ] // {
        enable = mkEnableOption ''
          nix in this tier's sessions: for now, the checkout's devShell --
          flake.nix's devShells.<system>.default, or its shell.nix --
          realised on the host, confined, before the session starts, and
          given to it as its environment'';
        devShell = mkOption {
          type = types.enum [ "automatic" "granted" ];
          default = "granted";
          description = ''
            When a checkout's devShell is realised. `automatic`: whenever the
            checkout has one -- for a tier of your own code; one that cannot
            be realised is said, and the session starts without it.
            `granted`: only when the checkout's approved grant asks for it
            (`apps.nix.devShell`), and one that cannot be realised refuses
            the launch -- for a tier of other people's code, which takes
            grants.
          '';
        };
      };
    });
  };

  config = {
    assertions = lib.concatLists (lib.mapAttrsToList (name: tier: [
      {
        assertion = !(tier.bare && tier.apps.nix.enable);
        message = "chase.tiers.${name}.apps.nix is enabled, and ${name} is bare: its agent runs on the host, whose `nix develop` is its own.";
      }
      {
        assertion = !(tier.apps.nix.enable && tier.apps.nix.devShell == "granted" && !tier.grants);
        message = "chase.tiers.${name}.apps.nix.devShell is `granted`, and ${name} takes no grants, so nothing could ever turn it on: set `grants = true`, or `devShell = \"automatic\"`.";
      }
    ]) cfg.tiers);

    # Not refused: a frisket tier's devShell substitutes its inputs and
    # builds nothing locally (--max-jobs 0), but a remote builder builds for
    # the daemon, on its own network, and no untrusted client can turn one
    # off (`--option builders ""` is ignored, with a warning, from one).
    warnings = lib.optional
      (lib.any (t: t.egress == "frisket") (lib.attrValues enabled) && config.nix.buildMachines != [ ])
      "chase: a frisket tier's devShell inputs are substituted, never built locally; the machine's remote builders are outside that, and build for the daemon on their own network.";

    # What exec realises a devShell with, for each tier that has nix: the
    # tools at their store paths, never looked up on PATH; the tier's
    # settings its confinement is derived from -- its egress, never its
    # name -- and the tier's own allowlist, for a tier that takes no grant
    # and so writes no document of the session's own.
    chase.internal.config.session.tiers = lib.mapAttrs (name: tier: {
      nix = {
        inherit (cfg.internal.config.selector) git emptySha1 emptySha256;
        inherit (tier) egress;
        inherit (tier.apps.nix) devShell timeout;
        nix = lib.getExe tier.apps.nix.package;
        nixpkgs = "${tier.apps.nix.nixpkgs}";
        system = pkgs.stdenv.hostPlatform.system;
        bwrap = lib.getExe pkgs.bubblewrap;
        pasta = lib.getExe' pkgs.passt "pasta";
        # The machine's, for the evaluation's https: never frisket's, which
        # the evaluation does not go through.
        caBundle = "${config.security.pki.caBundle}";
        policy = "/etc/frisket/policies/${name}.json";
      };
    }) enabled;
  };
}
