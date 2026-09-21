{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.chase;
  bindings = cfg.bindings.cloudflare;
  host = "api.cloudflare.com";

  # EVERY OPERATION IN CLOUDFLARE'S OWN API DESCRIPTION, one rule each:
  # admitted if it is known to be harmless, asked about otherwise, in the
  # spec's own words. Generated from a pinned spec by
  # ../scripts/cloudflare-operations.sh, with ./cloudflare/exceptions.json saying
  # which reads are not harmless and which writes are; regenerating is a
  # reviewed change, and its diff is the list of what is newly allowed. See
  # ../docs/cloudflare.md.
  operations = builtins.fromJSON (builtins.readFile ./cloudflare/operations.json);

  # The route, as a policy document holds it: shared by a tier that binds a
  # token from the machine and by a project that binds its own.
  route = {
    name = "cloudflare";
    inherit host;
    upstream = "https://${host}";
    placeholder = cfg.placeholder;
    # Secure by default: what the description does not name is asked
    # about, so an endpoint Cloudflare ships next month is gated from the day
    # it ships.
    unmatched = "ask";
    paths = operations;
    # Cloudflare's own error envelope, which wrangler reads: it then says why
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

  # The account's id, copied where a session can read it. Not a credential --
  # it names the account, it does not open it -- but it is kept beside the
  # token, and a file there cannot be bound into a container: flong binds
  # directories. So each launch copies it into a directory of its own.
  stateDir = "${cfg.home}/.local/state/agents/cloudflare";
in
{
  options.chase.bindings.cloudflare = {
    credentialFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/run/secrets/cloudflare-token";
      description = ''
        A file holding a Cloudflare API token, alone. frisket reads it on the
        host and adds it to the session's requests to ${host}; nothing
        inside a container ever sees it.

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
    type = types.attrsOf (types.submodule {
      options.apps.cloudflare.enable = mkEnableOption ''
        Cloudflare's API in this tier, through wrangler: what its API
        description calls safe goes straight through, and everything else --
        writes, deletes, and anything the description does not name -- waits
        for a person to allow it, through frisket's asker'';
    });
  };

  config = {
    # Declared but unbound is a refusal, for the reason github's is.
    assertions = [{
      assertion = bindings.credentialFile != null
        || !(lib.any (t: t.apps.cloudflare.enable) (lib.attrValues cfg.tiers));
      message = "chase.bindings.cloudflare.credentialFile is null, but a tier enables cloudflare. Bind a token file.";
    }];

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" (mkIf tier.apps.cloudflare.enable {
      config = {
        environment.systemPackages = [ pkgs.wrangler ];
        environment.variables.CLOUDFLARE_API_TOKEN = cfg.placeholder;
      };
    })) cfg.tiers;

    chase.internal.tiers = lib.mapAttrs (name: tier: mkIf (tier.apps.cloudflare.enable && bindings.accountIdFile != null) (
      let dir = "${stateDir}/${name}"; in
      {
        # On the host, as the user: the file is theirs to read.
        bindLines = [ ''
          mkdir -p ${lib.escapeShellArg dir}
          install -m 0600 ${lib.escapeShellArg bindings.accountIdFile} ${lib.escapeShellArg "${dir}/account-id"}
          printf '%s\n' ${lib.escapeShellArg dir}
        '' ];
        # In the session, from the directory bound in read-only.
        setupLines = [ ''
          CLOUDFLARE_ACCOUNT_ID=$(< ${lib.escapeShellArg "${dir}/account-id"})
          export CLOUDFLARE_ACCOUNT_ID
        '' ];
      })) cfg.tiers;

    services.frisket.policies = lib.mapAttrs (name: tier: mkIf tier.apps.cloudflare.enable {
      # For a tier with an allowlist of names; trusted's `*` already covers it.
      allow = lib.mkAfter [ host ];
      routes.cloudflare = removeAttrs route [ "name" ] // {
        credentialFile = bindings.credentialFile;
      };
    }) cfg.tiers;

    # A project that binds its own token, in ../project/options.nix.
    chase.internal.projectApps.cloudflare = {
      inherit route;
      allow = [ host ];
      env.CLOUDFLARE_API_TOKEN = cfg.placeholder;
      envFromBinding.CLOUDFLARE_ACCOUNT_ID = "accountId";
    };
  };
}
