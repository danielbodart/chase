{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkMerge mkOption types;
  cfg = config.agents;
  every = [ "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" ];
  reads = [ "GET" "HEAD" ];

  # A checkout's remotes stay git@github.com: git rewrites them to HTTPS, so
  # they go through frisket, and no key is needed.
  https = {
    url."https://github.com/".insteadOf = [ "git@github.com:" "ssh://git@github.com/" ];
  };
in
{
  options.agents.apps.github.credentialFile = mkOption {
    type = types.nullOr types.path;
    default = null;
    example = "/run/secrets/gh_token";
    description = ''
      A file holding a GitHub token, alone — `gh auth token`'s. frisket reads
      it on the host and adds it to the session's requests; nothing inside a
      container ever sees it.

      Declared, never reached for: chase does not know whether the consumer
      keeps its secrets in sops, in systemd credentials, or decrypts them per
      project, and an app that hardcoded one of those could not be used with
      the others.

      Null with a tier that enables github non-anonymously is refused, not
      quietly downgraded — an unbound credential would otherwise become a
      route with no credential, which fails later and further away.
    '';
  };

  options.agents.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.github = {
        enable = mkEnableOption "GitHub in this agent tier: git over HTTPS, and gh";
        anonymous = mkEnableOption ''
          read-only GitHub with no credential of yours: clone, fetch and GET,
          and nothing that writes. No gh, which needs a login'';
      };
    });
  };

  config = {
    # DECLARED BUT UNBOUND IS A REFUSAL. frisket treats an empty
    # credentialFile as a legitimate route with no credential, so leaving this
    # null would not fail -- it would silently produce a route that holds
    # requests to its scope and adds nothing, and the first sign of it would
    # be a 401 from GitHub inside a session.
    assertions = [{
      assertion = cfg.apps.github.credentialFile != null
        || !(lib.any (t: t.apps.github.enable && !t.apps.github.anonymous) (lib.attrValues cfg.tiers));
      message = "agents.apps.github.credentialFile is null, but a tier enables github without `anonymous`. Bind a token file, or set `anonymous = true` for read-only GitHub with no credential.";
    }];

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" (mkIf tier.apps.github.enable {
      config = mkMerge [
        { programs.git = { enable = true; config = https; }; }
        (mkIf (!tier.apps.github.anonymous) {
          environment.systemPackages = [ pkgs.gh ];
          # gh makes no request until it thinks it is logged in, and hands git
          # the same placeholder as Basic auth's password.
          environment.variables = {
            GH_TOKEN = cfg.placeholder;
            GITHUB_TOKEN = cfg.placeholder;
          };
          programs.git.config.credential."https://github.com".helper = "!${lib.getExe pkgs.gh} auth git-credential";
        })
      ];
    })) cfg.tiers;

    services.frisket.policies = lib.mapAttrs (name: tier: mkIf tier.apps.github.enable (
      if tier.apps.github.anonymous then {
        # Intercepted with no credential, so the scope holds: a token the
        # session brings still reaches GitHub, but only to read.
        allow = lib.mkAfter [ "github.com" "api.github.com" "codeload.github.com" "*.githubusercontent.com" ];
        routes.github = {
          host = "api.github.com";
          upstream = "https://api.github.com";
          paths = [{ methods = reads; prefix = "/"; }];
        };
        routes.github-git = {
          host = "github.com";
          upstream = "https://github.com";
          paths = [{ methods = reads; prefix = "/"; }];
          git.repos = [ "*" ];
        };
      } else {
        # The `gh auth token` OAuth token, every method: the session can push
        # and merge as you, but never holds the token. git takes it only as
        # Basic auth's password.
        routes.github = {
          host = "api.github.com";
          upstream = "https://api.github.com";
          credentialFile = cfg.apps.github.credentialFile;
          placeholder = cfg.placeholder;
          paths = [{ methods = every; prefix = "/"; }];
        };
        routes.github-git = {
          host = "github.com";
          upstream = "https://github.com";
          credentialFile = cfg.apps.github.credentialFile;
          placeholder = cfg.placeholder;
          basicUser = "x-access-token";
          paths = [{ methods = every; prefix = "/"; }];
        };
      })) cfg.tiers;
  };
}
