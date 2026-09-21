# What a project's envelope may say (PLAN.md, decisions 10 and 17).
#
# Evaluated on its own with lib.evalModules -- not as part of any NixOS
# system -- against the project's `chaseModules.default`, so an option that is
# not here is refused rather than quietly applied somewhere else. What it
# evaluates to is the document a person approves: small, and every field in it
# means one thing.
#
#   chaseModules.default = {
#     chase.secrets = "secrets.yaml";
#     chase.bindings.cloudflare = {
#       credential.secret = "cloudflare-token";
#       accountId = "023e105f4ecef8ad9ca31a8372d0c353";
#     };
#   };
{ lib, ... }:

let
  inherit (lib) mkOption types;
  secretKey = types.nullOr (types.strMatching "[A-Za-z0-9_.-]+");
in
{
  options.chase = {
    secrets = mkOption {
      type = types.nullOr (types.strMatching "[^/].*");
      default = null;
      example = "secrets.yaml";
      description = ''
        The project's sops file, relative to the checkout: one file, many
        secrets, each under its own key, encrypted to admin keys. A string and
        not a path, so what is approved is where the file is and not whatever
        it happens to hold -- the ciphertext is the project's to rotate.
      '';
    };

    bindings.cloudflare = {
      credential.secret = mkOption {
        type = secretKey;
        default = null;
        example = "cloudflare-token";
        description = ''
          The key in `secrets` holding the project's Cloudflare API token.
          Decrypted at launch outside the session, and added on the wire by
          frisket; the session holds the placeholder.
        '';
      };
      accountId = mkOption {
        type = types.nullOr (types.strMatching "[0-9a-f]{32}");
        default = null;
        example = "023e105f4ecef8ad9ca31a8372d0c353";
        description = ''
          The Cloudflare account, set as CLOUDFLARE_ACCOUNT_ID in the session.
          Not a secret -- it names the account, it does not open it -- so it
          is written here, where it is approved, rather than in `secrets`.
        '';
      };
    };
  };
}
