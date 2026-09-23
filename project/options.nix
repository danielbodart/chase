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
#     chase.seccomp.allow = [ "io_uring_setup" "io_uring_enter" "io_uring_register" ];
#   };
{ lib, ... }:

let
  inherit (lib) mkOption types;
  secretKey = types.nullOr (types.strMatching "[A-Za-z0-9_.-]+");

  # A syscall's name or a systemd group's, as flong takes them. flong refuses
  # a name systemd does not list, at launch.
  syscallName = types.strMatching "@?[a-z0-9_-]+";

  # An operation the project may use without being asked: an operation id
  # from the API's own description, or -- for an endpoint the description
  # does not name -- methods and an exact path template.
  allowed = types.either (types.strMatching "[A-Za-z0-9_.:-]+") (types.submodule {
    options = {
      methods = mkOption { type = types.nonEmptyListOf (types.enum [ "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" ]); };
      path = mkOption { type = types.strMatching "/[^[:space:]]*"; };
    };
  });
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

    # Applied before the session starts, since a filter is installed before
    # anything in it runs: evaluated and approved with the rest, in flong's
    # seccompPolicy, and handed to flong as allow and deny lines.
    seccomp = {
      allow = mkOption {
        type = types.listOf syscallName;
        default = [ ];
        example = [ "io_uring_setup" "io_uring_enter" "io_uring_register" ];
        description = ''
          Syscalls, or systemd `@groups`, this project's sessions need beyond
          the tier's filter. Each one is kernel surface the session gains, and
          part of what is approved. The fixed filters stay whatever this says:
          no terminal injection, no audit socket, no namespaces of its own.
        '';
      };
      deny = mkOption {
        type = types.listOf syscallName;
        default = [ ];
        example = [ "ptrace" ];
        description = ''
          Syscalls, or `@groups`, taken away from the tier's filter, after
          `allow`, which this overrides.
        '';
      };
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
      allow = mkOption {
        type = types.listOf allowed;
        default = [ ];
        example = [
          "workers-ai-post-run-model"
          { methods = [ "POST" ]; path = "/client/v4/accounts/*/workers/subdomain/edge-preview"; }
        ];
        description = ''
          Writes this project makes often enough that asking every time would
          only train a person to click through: an operation id, which then
          goes through without a dialog, or methods and an exact path for an
          endpoint Cloudflare's description does not name. Part of what is
          approved, like everything here. A rule equally specific to one that
          asks still asks.
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
