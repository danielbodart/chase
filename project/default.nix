# A project's envelope, applied at launch (PLAN.md, decisions 7, 10, 11, 17).
#
# For a tier that takes envelopes, each launch:
#
#   binds          makes the checkout's environment directory, bound read-only
#   seccompPolicy  before the session is built: evaluates the checkout's
#                  `chaseModules.default` against ./options.nix; asks
#                  `chase.approver` if the result is not the one last
#                  approved for this checkout; stages the approved result for
#                  this launch's postStart, and prints its syscall
#                  loosenings for flong
#   postStart      before frisket's steps: decrypts the secrets the staged
#                  result binds into /run/user/<uid>/chase/<machine>/;
#                  prepares each bound app; writes the session's policy
#                  document there, and its environment beside the checkout's
#   frisket        steers the session under that document, or the tier's own
#   postStop       stops each app; removes
#                  /run/user/<uid>/chase/<machine>/ and anything staged for it
#
# All of it runs as the user who launched: a launcher has no privilege of its
# own (PLAN.md, decision 2). The approval is split from the rest because a
# syscall filter is installed before anything in the session runs, so what
# loosens it has to be known, and approved, before flong starts bwrap.
#
# A checkout with no flake, or a flake with no `chaseModules.default`, is the
# tier as it is. Anything that goes wrong on the way ends the launch: an
# envelope is applied whole or the session does not start.
#
# Each step is `chase hook ... TIER` (internal/envelope); what is here is
# its configuration, and the flake it evaluates an envelope with.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types;
  cfg = config.chase;
  tiers = lib.filterAttrs (_: t: t.envelope) cfg.tiers;
  chase = lib.getExe cfg.package;

  # Every tier's pinned checkouts, as the selector holds them: each
  # owner/repo, lower-cased, and every path any tier pins it at. What names a
  # checkout's Docker project is held to these both ways.
  checkouts = lib.zipAttrsWith (_: paths: lib.unique (lib.sort lib.lessThan paths))
    (lib.concatMap (t: lib.concatMap (rule: lib.mapAttrsToList (s: p: { ${lib.toLower s} = p; }) rule.checkouts) t.match)
      (lib.attrValues cfg.tiers));

  # The tiers apps/docker.nix gives Docker, which it asserts take envelopes.
  dockerTiers = lib.attrNames (lib.filterAttrs (_: t: !t.bare && (t.apps.docker.enable or false)) tiers);

  # WHAT EVALUATES AN ENVELOPE: a flake of chase's, in the store, whose one
  # input is the checkout -- given on the command line, never spliced into Nix
  # source -- evaluated PURELY. The checkout is the agent's to edit, and this
  # runs before anyone has approved anything: pure evaluation is what keeps
  # an envelope to its own source and locked inputs, rather than able to read
  # any file of the user's and fetch a URL with it in. nixpkgs' lib comes
  # along as a copy, so the flake needs nothing it does not carry.
  evaluator = pkgs.runCommand "chase-envelope-evaluator" { } ''
    mkdir -p "$out/nixpkgs"
    cp -r ${pkgs.path}/lib "$out/nixpkgs/lib"
    cp ${pkgs.path}/.version "$out/nixpkgs/.version"
    cp ${./options.nix} "$out/options.nix"
    cat > "$out/flake.nix" <<'EOF'
    {
      inputs.project.url = "path:/nonexistent";
      outputs = { project, ... }: {
        envelope =
          let lib = import ./nixpkgs/lib; in
          if project ? chaseModules && project.chaseModules ? default
          then (lib.evalModules { modules = [ ./options.nix project.chaseModules.default ]; }).config.chase
          else null;
      };
    }
    EOF
  '';
in
{
  options.chase = {
    approver = mkOption {
      type = types.nullOr (types.strMatching "/.*");
      default = null;
      description = ''
        The program that asks a person to approve a checkout's envelope when
        what it evaluates to has changed (PLAN.md, decision 17). It runs as
        the user, from the launch, with one JSON document on stdin: `kind`,
        `workspace` and `diff`. `kind` is `flake` -- the checkout's flake.nix
        or flake.lock changed, and nothing of it has run yet -- or `envelope`,
        what its chase section evaluates to changed; `diff` is unified. Exit 0
        approves; anything else ends the launch. Null: nothing is approved.
      '';
    };

    internal.projectApps = mkOption {
      internal = true;
      default = { };
      type = types.attrsOf types.anything;
      description = ''
        What an app becomes when a project binds it: its frisket `routes`, by
        tier, each a route or a list of them as the policy document holds
        one but for `credentialFile`; the names it adds to `allow`; the
        session's `env`; and `envFromBinding`, variables taken from the
        binding's other fields. An app whose routes are made at launch
        (Docker, Google Cloud) is Go instead (internal/apps), and needs an
        entry here only to say `credential = false`.

        `credential`, true by default, says the app is bound only with the
        project's secret, named by the binding's `credential.secret`, and
        not at all without one. False: the app has no credential, it is
        made from the binding alone, whenever the binding says anything,
        and nothing is decrypted.
      '';
    };
  };

  config = lib.mkIf (tiers != { }) {
    chase.internal.config.envelopeTiers = lib.attrNames tiers;
    chase.internal.config.envelope = {
      inherit (cfg.internal.config.selector) git emptySha1 emptySha256;
      inherit (cfg) uid home;
      hosts = "/etc/chase/docker-hosts.json";
      policies = "/etc/frisket/policies";
      inherit dockerTiers checkouts;
      apps = cfg.internal.projectApps;
      approver = if cfg.approver == null then "" else cfg.approver;
      evaluator = "${evaluator}";
      nix = lib.getExe pkgs.nix;
      sops = lib.getExe pkgs.sops;
      diff = "${pkgs.diffutils}/bin/diff";
    };

    flong = lib.mapAttrs' (name: _: lib.nameValuePair "agent-${name}" {
      # After the guard, before bwrap: the filter is fixed before anything in
      # the session runs, so this is where the envelope is approved.
      seccompPolicy = [ [ chase "hook" "approve" name ] ];
      postStart = lib.mkOrder 400 [ [ chase "hook" "launch" name ] ];
      postStop = [ [ chase "hook" "poststop" name ] ];
    }) tiers;

    services.frisket.flong = lib.mapAttrs' (name: _: lib.nameValuePair "agent-${name}" {
      policyFile = "$(${chase} envelope policy ${name} \"$machine\")";
    }) tiers;

    # Where a session's own document is written, which frisket reads from.
    services.frisket.policyRoots = [ "/run/user/${toString cfg.uid}/chase" ];

    chase.internal.tiers = lib.mapAttrs (name: _: {
      setupLines = [ ''
        chase_env=${cfg.home}/.local/state/chase/env/$(printf '%s' "$workspace" | sha256sum | cut -c1-32)/env
        if [ -r "$chase_env" ]; then
          # shellcheck disable=SC1090
          . "$chase_env"
        fi
      '' ];
    }) tiers;
  };
}
