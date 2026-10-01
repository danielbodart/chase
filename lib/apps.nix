# What a tier may say of an app in place of the machine (chase.apps.<app>):
# its package, its credential, the host files it binds. Each is the
# machine's option again, under the tier's apps.<app>, defaulting to the
# machine's value.
{ lib }:

{
  # `machine` is the app's options (`options.chase.apps.<app>`), and
  # `names` those a tier may override.
  overrides = machine: names: lib.genAttrs names (n:
    let o = machine.${n}; in lib.mkOption {
      inherit (o) type;
      default = o.value;
      defaultText = lib.literalExpression "config.${lib.showOption o.loc}";
      description = "This tier's own, in place of `${lib.showOption o.loc}`.";
    });

  # AUTHENTICATED BUT UNBOUND IS A REFUSAL. frisket treats an empty
  # credentialFile as a legitimate route with no credential, so a null one
  # would not fail: it would quietly make a route that holds requests to
  # its scope and adds nothing, and the first sign of it would be a 401
  # inside a session.
  credentialAssertions = tiers: app: lib.mapAttrsToList (name: tier:
    let a = tier.apps.${app}; in {
      assertion = !(a.enable && a.authenticated) || a.credentialFile != null;
      message = "chase.tiers.${name}.apps.${app} is authenticated, but has no credentialFile. Bind one as chase.apps.${app}.credentialFile, or leave it unauthenticated.";
    }) tiers;
}
