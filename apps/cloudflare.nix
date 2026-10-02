{ config, options, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.chase;
  ops = import ../lib/operations.nix { inherit lib; };
  apps = import ../lib/apps.nix { inherit lib; };
  machine = options.chase.apps.cloudflare;
  host = "api.cloudflare.com";

  # EVERY OPERATION IN CLOUDFLARE'S OWN API DESCRIPTION, one rule each: a
  # read, a write or guarded, in the spec's own words, answered as the tier
  # and the app say (../lib/operations.nix). Generated from a pinned spec by
  # chase-generate operations (../internal/generate), with
  # ./cloudflare/exceptions.json saying which reads are writes and which
  # writes are reads; regenerating is a reviewed change, and its diff is the
  # list of what is newly allowed. See ../docs/cloudflare.md.
  operations = builtins.fromJSON (builtins.readFile ./cloudflare/operations.json);

  # The route in a tier, as a policy document holds it: shared by a tier that
  # is authenticated with the machine's token and by a project that brings
  # its own, so it answers as the tier and the app say whether or not the
  # tier has a token.
  route = tier: let s = ops.answers tier.apps.cloudflare; in {
    name = "cloudflare";
    inherit host;
    upstream = "https://${host}";
    placeholder = cfg.placeholder;
    # Secure by default: what the description does not name is asked
    # about unless the tier says otherwise, so an endpoint Cloudflare ships
    # next month is gated from the day it ships.
    unmatched = ops.unmatched s;
    paths = ops.paths s operations;
    # The GraphQL Analytics API, which wrangler reads metrics from, and
    # Cloudforce One's: a query is a read, and there is no schema to name
    # a mutation by, so one is unmatched.
    graphql = ops.graphql s operations;
    # Cloudflare's own error grant, which wrangler reads: it then says why
    # a request was refused, where plain text gets "a request to the
    # Cloudflare API failed" and nothing more.
    refusal = {
      contentType = "application/json";
      body = builtins.toJSON {
        success = false;
        errors = [{ code = 403; message = "{{message}}"; }];
        messages = [ ];
        result = null;
      };
    };
  };
in
{
  options.chase.apps.cloudflare = {
    package = mkOption {
      type = types.package;
      default = pkgs.wrangler;
      defaultText = lib.literalExpression "pkgs.wrangler";
      description = ''
        The wrangler a session gets. The consumer's to choose, as the other
        apps' packages are: wrangler moves faster than a stable nixpkgs.
      '';
    };
    credentialFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/run/secrets/cloudflare-token";
      description = ''
        A file holding a Cloudflare API token, alone, for every session of a
        tier that is `authenticated` for Cloudflare. frisket reads it on the
        host and adds it to the session's requests to ${host}; nothing inside
        a container ever sees it. Null, the usual case: a tier has no
        Cloudflare token of its own, and a project brings one in its grant
        (decision 9 -- there is never a system-level cloud account).

        Mint it narrowly: the token is the floor, and the allowlist only
        decides which of the things it can do need a person. Workers, KV, D1
        and R2 belong to an account, not a zone, so restrict it to one
        account -- one for this project alone, if it must be kept apart --
        and to a zone as well where there is one.
      '';
    };
    accountIdFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/run/secrets/cloudflare-account-id";
      description = ''
        A file holding the Cloudflare account id, alone. Read at each launch
        and set as CLOUDFLARE_ACCOUNT_ID in the session, so wrangler need not
        list memberships to find its account -- a permission a narrow token
        does not have. Null: the project says which account, in its own
        wrangler configuration.
      '';
    };
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule ({ config, ... }: {
      options.apps.cloudflare = ops.appOptions config // apps.overrides machine [ "package" "credentialFile" "accountIdFile" ] // {
        enable = mkEnableOption ''
          Cloudflare's API in this tier, through wrangler, with the token a
          project brings in its grant: what its API description calls a read
          goes straight through, and the rest -- writes, deletions, and
          anything the description does not name -- is answered as `writes`,
          `guarded` and `unmatched` say'';
        authenticated = mkEnableOption ''
          the tier's own Cloudflare token, `credentialFile`, on every session
          whose project brings none'';
      };
    }));
  };

  config = {
    assertions = apps.credentialAssertions cfg.tiers "cloudflare";

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "chase-${name}" (mkIf tier.apps.cloudflare.enable {
      config = {
        environment.systemPackages = [ tier.apps.cloudflare.package ];
        environment.variables.CLOUDFLARE_API_TOKEN = cfg.placeholder;
      };
    })) cfg.tiers;

    # The account id, read on the host at each launch and given to the
    # session as CLOUDFLARE_ACCOUNT_ID (internal/session). Not a credential
    # -- it names the account, it does not open it -- but it is kept beside
    # the token, so the file itself is never bound in.
    chase.internal.config.session.tiers = lib.mapAttrs (_: tier: {
      cloudflare.accountIdFile = tier.apps.cloudflare.accountIdFile;
    }) (lib.filterAttrs (_: t: !t.bare && t.apps.cloudflare.enable && t.apps.cloudflare.accountIdFile != null) cfg.tiers);

    # A route of the tier's own only with a token of the tier's own: without
    # one, api.cloudflare.com is intercepted only in a session whose project
    # brought one, and is otherwise an ordinary allowed name.
    services.frisket.policies = lib.mapAttrs (name: tier: mkIf (tier.apps.cloudflare.enable && tier.apps.cloudflare.authenticated) {
      # For a tier with an allowlist of names; one allowing `*` has it already.
      allow = lib.mkAfter [ host ];
      routes.cloudflare = removeAttrs (route tier) [ "name" ] // {
        credentialFile = tier.apps.cloudflare.credentialFile;
      };
    }) cfg.tiers;

    # A project that binds its own token, in its grant (internal/grant).
    chase.internal.projectApps.cloudflare = {
      routes = lib.mapAttrs (_: route) (lib.filterAttrs (_: t: !t.bare) cfg.tiers);
      allow = [ host ];
      env.CLOUDFLARE_API_TOKEN = cfg.placeholder;
      envFromGrant.CLOUDFLARE_ACCOUNT_ID = "accountId";
    };
  };
}
