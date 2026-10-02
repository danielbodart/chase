{ config, options, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkMerge mkOption types;
  cfg = config.chase;
  apps = import ../lib/apps.nix { inherit lib; };
  machine = options.chase.apps.codex;
  base = cfg.apps.codex.package;
  allow = [ "chatgpt.com" "*.chatgpt.com" "openai.com" "*.openai.com" ];
  every = [ "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" ];

  codexDir = "${cfg.home}/.codex";
  authFile = "${codexDir}/auth.json";
  # The placeholder login, and each tier's own CODEX_HOME. Under chase's
  # state directory: neither is the host's own login or state.
  stateDir = "${cfg.home}/.local/state/chase/codex";
  # Where an earlier chase kept it, moved from by the first `chase
  # codex-placeholder` or `codex-refresh` to run (internal/apps/codex).
  formerStateDir = "${cfg.home}/.local/state/agents/codex";
  placeholderFile = "${stateDir}/auth-placeholder.json";

  # What the container holds in place of the access token. cfg.placeholder
  # cannot be it: codex reads its own token as a JWT and refreshes 5 minutes
  # before the `exp` it finds, so the placeholder has to be JWT-shaped with an
  # expiry far away -- {"alg":"none","typ":"JWT"} over
  # {"exp":4102444800,"sub":"frisket-placeholder"}, 4102444800 being
  # 2100-01-01. Nothing verifies the signature: not codex, which only splits
  # on '.', and not frisket, which compares the whole string to this one.
  placeholderJWT = builtins.readFile ../internal/apps/codex/placeholder.jwt;

  # frisket reads the host's own login and puts its token on each request.
  # The expiry is the `exp` claim inside the access token: auth.json itself
  # records only when it last refreshed. Past it, 503 rather than a 401.
  codexRoute = paths: {
    host = "chatgpt.com";
    upstream = "https://chatgpt.com";
    credentialFile = authFile;
    credentialJSON = {
      token = "tokens.access_token";
      expiresJWT = "tokens.access_token";
    };
    placeholder = placeholderJWT;
    inherit paths;
  };

  # Refresh and revoke, logged and refused, so no response can hand a sandbox
  # a real token and nothing in one can end the host's login. No credential:
  # what a session brings is its own, and this admits none of it anyway.
  refusedRoute = {
    host = "auth.openai.com";
    upstream = "https://auth.openai.com";
    paths = [{ methods = every; prefix = "/"; refuse = true; }];
  };

  # `codex` on the host is the chase binary, which picks the checkout's
  # tier and runs codex there; `codex-raw` is codex itself. The placeholder
  # login and the refresher are internal/apps/codex.
  codexLinks = pkgs.runCommand "codex-links" { } ''
    mkdir -p $out/bin
    ln -s ${lib.getExe cfg.package} $out/bin/codex
    ln -s ${base}/bin/codex $out/bin/codex-raw
  '';

  bind = path: readOnly: { hostPath = path; isReadOnly = readOnly; };
in
{
  options.chase.apps.codex.package = mkOption {
    type = types.package;
    description = ''
      The codex CLI. Declared rather than pinned by chase, for the reason
      `chase.apps.claude.package` is.
    '';
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.codex = apps.overrides machine [ "package" ] // {
        enable = mkEnableOption "codex in this tier";
        trust = mkEnableOption ''
          trusting each checkout in this tier in codex, as you would by
          answering its dialog: it runs with the checkout's trust_level
          trusted. For a tier of checkouts you vouch for; a bare tier may
          say it too, for codex on the host'';
        scope = mkOption {
          type = types.enum [ "session" "workspace" "tier" "host" ];
          default = "session";
          description = ''
            Where codex's home, its threads, history and memories, is kept.
            `session`: the session's own, gone with it. `workspace`: one per
            workspace, and `tier`: one for the tier, each kept on the host
            and given the placeholder login afresh at every launch.
            `host`: the host's ~/.codex, with the placeholder in place of
            its login.
          '';
        };
      };
    });
  };

  config = {
    chase.internal.config = {
      # A home of a workspace's or the tier's, a store made on the host and
      # mounted at its own path, given the placeholder login afresh each
      # launch, so nothing a session leaves behind is what the next
      # authenticates with, and named to codex as CODEX_HOME
      # (internal/session); or the session's own, seeded with the
      # placeholder. A whole home, because everything codex keeps -- the
      # thread index, history, memories -- is one file per directory at the
      # top of it, with nothing per project to pick out the way
      # ~/.claude/projects has, so a workspace gets a home of its own or it
      # shares all of it. codex runs with its own sandbox bypassed, the
      # session being the sandbox, and, where the tier trusts it, the
      # workspace trusted by a -c override, since config.toml is the host's.
      session.tiers = lib.mapAttrs (_: tier: {
        codex = { inherit (tier.apps.codex) scope trust; placeholder = placeholderFile; };
      } // lib.optionalAttrs (lib.elem tier.apps.codex.scope [ "workspace" "tier" ]) {
        stores.codex = {
          inherit (tier.apps.codex) scope;
          root = stateDir;
          env.CODEX_HOME = "";
          files."auth.json" = placeholderFile;
        };
      }) (lib.filterAttrs (_: t: !t.bare && t.apps.codex.enable) cfg.tiers);
      # A bare tier's trust is the wrapper's, an override on the host.
      selector.tiers = lib.mapAttrs (_: _: { trust.codex = true; })
        (lib.filterAttrs (_: t: t.bare && t.apps.codex.trust) cfg.tiers);
      # On the host codex keeps its own sandbox; in a container it bypasses it.
      wrappers.codex.hostCommand = [ "${base}/bin/codex" ];
      codex = {
        auth = authFile;
        inherit stateDir formerStateDir;
        # To repoint each moved home's thread index (internal/apps/codex).
        sqlite = lib.getExe' pkgs.sqlite "sqlite3";
        placeholder = placeholderFile;
      };
    };

    home-manager.users.${cfg.user} = { lib, ... }: {
      home.packages = [ codexLinks ];

      # The placeholder is a bind source: flong refuses to start without it.
      home.activation.codexPlaceholder = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        ${lib.getExe cfg.package} codex-placeholder || echo "codex: no placeholder login written"
      '';

      systemd.user.services.codex-refresh = {
        Unit.Description = "Refresh the host's codex login before it expires";
        Install.WantedBy = [ "default.target" ];
        Service = {
          Restart = "always";
          RestartSec = 60;
          ExecStart = "${lib.getExe cfg.package} codex-refresh";
        };
      };
    };

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "chase-${name}"
      (mkIf tier.apps.codex.enable (mkMerge [
        { config.environment.systemPackages = [ tier.apps.codex.package ]; }
        (mkIf (tier.apps.codex.scope == "host") {
          # The host's ~/.codex whole, with the login covered by the
          # placeholder. Safe where ~/.claude was not: codex rewrites
          # auth.json in place, and only a rename or an unlink -- a `codex
          # logout` -- would detach this bind and uncover the real file.
          bindMounts = {
            "${codexDir}" = bind codexDir false;
            "${authFile}" = bind placeholderFile true;
          };
        })
      ]))) cfg.tiers;

    services.frisket.policies = lib.mapAttrs (_: tier:
      mkIf tier.apps.codex.enable {
        allow = lib.mkAfter allow;
        routes = {
          # The host's scope is the host's own session by another name. Any
          # other gets codex and nothing else: the same bearer reads and
          # writes your ChatGPT conversations everywhere else on the host.
          codex = codexRoute (
            if tier.apps.codex.scope == "host"
            then [{ methods = every; prefix = "/"; }]
            else [{ methods = every; prefix = "/backend-api/codex/"; }]
          );
          codex-auth = refusedRoute;
        };
      }) cfg.tiers;
  };
}
