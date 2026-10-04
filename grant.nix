# A project's grant, applied at launch (PLAN.md, decisions 7, 10, 11, 17).
#
# For a tier that takes grants, each launch:
#
#   seccompPolicy  before the session is built: reads the checkout's
#                  tracked `chase.jsonc` -- data, never evaluated -- checks
#                  it against what a grant may say; asks `chase.approver` if
#                  the grant is not the one last approved for this checkout;
#                  stages the approved grant for this launch's exec, and
#                  prints its syscall loosenings for flong
#   exec           still before the session is built: decrypts the secrets
#                  the staged result binds into /run/user/<uid>/chase/<machine>/;
#                  prepares each bound app; writes the session's policy
#                  document there -- the tier's own, for a checkout with no
#                  grant -- and gives what each app exports and seeds to
#                  the payload it prints (internal/session); then realises
#                  the checkout's devShell where the tier has nix
#                  (./apps/nix.nix)
#   frisket        steers the session under that document
#   postStop       stops each app; removes
#                  /run/user/<uid>/chase/<machine>/ and anything staged for it
#
# All of it runs as the user who launched: a launcher has no privilege of its
# own (PLAN.md, decision 2). The approval is split from the rest because a
# syscall filter is installed before anything in the session runs, so what
# loosens it has to be known, and approved, before flong starts bwrap. The
# rest is exec's because exec is the one hook whose output is the session's
# environment: nothing is written for a session to source, and nothing of
# chase's runs inside one but, where a devShell is given, the bash that
# orders its PATH, runs its shellHook and execs the agent, found on the
# container's PATH, given its script and data as arguments (PLAN.md,
# decision 21).
#
# A checkout with no `chase.jsonc` is the tier as it is. Anything that goes
# wrong on the way ends the launch: a grant is applied whole or the session
# does not start.
#
# Each step is `chase hook ... TIER` (internal/grant); what is here is its
# configuration.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types;
  cfg = config.chase;
  # And those launched as if they did, for routes of their own made at
  # launch, whose checkouts' grants are never read.
  tiers = lib.filterAttrs (n: t: t.grants || lib.elem n cfg.internal.launchedTiers) cfg.tiers;
  chase = lib.getExe cfg.package;

  # Every tier's pinned checkouts, as the selector holds them: each
  # owner/repo, lower-cased, and every path any tier pins it at. What names a
  # checkout's project is held to these both ways.
  checkouts = lib.zipAttrsWith (_: paths: lib.unique (lib.sort lib.lessThan paths))
    (lib.concatMap (t: lib.concatMap (rule: lib.mapAttrsToList (s: p: { ${lib.toLower s} = p; }) rule.checkouts) t.match)
      (lib.attrValues cfg.tiers));

  # The tiers apps/docker.nix gives Docker, which it asserts take grants.
  dockerTiers = lib.attrNames (lib.filterAttrs (_: t: !t.bare && (t.apps.docker.enable or false)) tiers);
in
{
  options.chase = {
    approver = mkOption {
      type = types.nullOr (types.strMatching "/.*");
      default = null;
      description = ''
        The program that asks a person to approve a checkout's grant when
        it has changed (PLAN.md, decision 17). It runs as the user, from the
        launch, with one JSON document on stdin: `workspace`, and `diff`,
        unified, of the grant last approved against the one proposed. Exit 0
        approves; anything else ends the launch. Null: nothing is approved.
      '';
    };

    internal.launchedTiers = mkOption {
      internal = true;
      default = [ ];
      type = types.listOf types.str;
      description = ''
        Tiers that take no grant but are launched as those that do, for
        routes of the tier's own made at launch -- its SSH machines
        (apps/ssh.nix). Each launch of one is the tier as it is, a
        checkout's `chase.jsonc` never read.
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
        (Docker, Google Cloud, SSH) is Go instead (internal/apps), and needs an
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
    chase.internal.config.grantTiers = lib.attrNames tiers;
    chase.internal.config.grant = {
      inherit (cfg.internal.config.selector) git emptySha1 emptySha256;
      inherit (cfg) uid home;
      policies = "/etc/frisket/policies";
      inherit dockerTiers checkouts;
      ungranted = lib.attrNames (lib.filterAttrs (_: t: !t.grants) tiers);
      apps = cfg.internal.projectApps;
      approver = if cfg.approver == null then "" else cfg.approver;
      sops = lib.getExe pkgs.sops;
      diff = "${pkgs.diffutils}/bin/diff";
    };

    flong = lib.mapAttrs' (name: _: lib.nameValuePair "chase-${name}" {
      # After the guard, before bwrap: the filter is fixed before anything in
      # the session runs, so this is where the grant is approved. It is
      # applied in the tier's exec, module.nix's, which runs next.
      seccompPolicy = [ [ chase "hook" "approve" name ] ];
      postStop = [ [ chase "hook" "poststop" name ] ];
    }) tiers;

    # The session's own document, which exec writes for every launch, the
    # tier's own when the checkout has no grant: one path, so frisket has
    # nothing to choose, and {machine} is frisket's own to fill in.
    services.frisket.flong = lib.mapAttrs' (name: _: lib.nameValuePair "chase-${name}" {
      policyFile = "/run/user/${toString cfg.uid}/chase/{machine}/policy.json";
    }) tiers;

    # Where a session's own document is written, which frisket reads from.
    services.frisket.policyRoots = [ "/run/user/${toString cfg.uid}/chase" ];
  };
}
