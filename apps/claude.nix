{ config, lib, pkgs, ... }:

let
  inherit (lib) mkIf mkMerge mkOption types;
  cfg = config.chase;
  base = cfg.bindings.claude.package;
  every = [ "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" ];
  allow = [
    "anthropic.com" "*.anthropic.com"
    "claude.ai" "*.claude.ai"
    "claude.com" "*.claude.com"
  ];

  # frisket reads the host's own login and puts its token on each request.
  claudeRoute = host: {
    inherit host;
    placeholder = cfg.placeholder;
    upstream = "https://${host}";
    credentialFile = "${cfg.home}/.claude/.credentials.json";
    # Past expiresAt frisket answers 503, which Claude Code retries.
    credentialJSON = {
      token = "claudeAiOauth.accessToken";
      expiresMillis = "claudeAiOauth.expiresAt";
    };
    paths = [{ methods = every; prefix = "/"; }];
  };

  # Token refresh and the Console: logged and refused, so no response can hand
  # the sandbox a real token.
  claudeRefusedRoute = claudeRoute "platform.claude.com" // {
    paths = [{ methods = every; prefix = "/"; refuse = true; }];
  };

  # The plugins the host's Claude Code enables, for a tier to turn some off.
  # None, for a user whose home-manager configuration names none: each tier's
  # settings are written into chase's configuration, which every system
  # builds, so an absent list must not fail it.
  hostEnabledPlugins = builtins.attrNames
    (config.home-manager.users.${cfg.user}.programs.claude-code.settings.enabledPlugins or { });

  # --settings outranks user and project settings. Claude Code's own sandbox
  # is off: bwrap cannot nest in the container, which is the boundary anyway.
  tierSettings = tier: tierCfg:
    let
      disabled = [ "graphical-sudo" ]
        ++ lib.optional (!tierCfg.apps.audio.enable) "notification-sound";
    in
    pkgs.writeText "claude-${tier}-settings.json" (builtins.toJSON {
      sandbox.enabled = false;
      enabledPlugins = builtins.listToAttrs (
        map (id: { name = id; value = false; }) (
          builtins.filter
            (id: builtins.elem (builtins.head (lib.splitString "@" id)) disabled)
            hostEnabledPlugins
        )
      );
    });

  # `claude` on the host is the chase binary, which picks the checkout's
  # tier and runs Claude Code there; `claude-raw` is Claude Code itself.
  claudeLinks = pkgs.runCommand "claude-links" { } ''
    mkdir -p $out/bin
    ln -s ${lib.getExe cfg.package} $out/bin/claude
    ln -s ${base}/bin/claude $out/bin/claude-raw
  '';

  bind = path: readOnly: { hostPath = path; isReadOnly = readOnly; };
  claudeDir = "${cfg.home}/.claude";
in
{
  options.chase.bindings.claude = {
    package = mkOption {
      type = types.package;
      description = ''
        Claude Code itself. Declared rather than taken from a flake input of
        chase's own, so the version is the consumer's decision and chase does
        not pin one for them.
      '';
    };
    preTrustPaths = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "/home/alice/Projects/thing" ];
      description = ''
        Directories marked as already trusted in `~/.claude.json`, so Claude
        Code does not raise its folder-trust dialog for a checkout the
        consumer's own configuration put there.

        Paths, not repository slugs: where a checkout lives is the consumer's
        layout, and chase has no business assuming one.
      '';
    };
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.claude = {
        state = mkOption {
          type = types.nullOr (types.enum [ "shared" "isolated" ]);
          default = null;
          description = ''
            `shared`: sessions, history and plugins are the host's.
            `isolated`: settings only, and this workspace's transcripts.
            Non-null enables Claude Code in the tier.
          '';
        };
        connectors = mkOption {
          type = types.bool;
          default = false;
          description = "Whether claude.ai connectors (Gmail, Drive, Slack...) are available.";
        };
      };
    });
  };

  config = {
    chase.internal.config = {
      # Made on the host before each launch (internal/session): an isolated
      # tier's transcripts for the workspace, and a shared tier's bound
      # sources, which flong refuses a session over if one is missing. And
      # the session's payload: Claude Code with the tier's settings, and its
      # placeholder login, seeded into the session's home rather than bound,
      # since Claude Code replaces the file by rename -- shaped like the real
      # one, since Claude Code decides what to offer from its scopes, and
      # never expiring, so a session never tries to refresh it.
      session.tiers = lib.mapAttrs (name: tier: {
        claude = {
          inherit (tier.apps.claude) state connectors;
          settings = "${tierSettings name tier}";
        };
      }) (lib.filterAttrs (_: t: !t.bare && t.apps.claude.state != null) cfg.tiers);
      wrappers.claude.hostCommand = [ "${base}/bin/claude" "--allow-dangerously-skip-permissions" ];
      claude = {
        credentials = "${claudeDir}/.credentials.json";
        claude = "${base}/bin/claude";
        claudeJSON = "${cfg.home}/.claude.json";
        # Every checkout this flake clones, and every group member.
        trustPaths = lib.unique (
          [ cfg.home ]
          ++ cfg.bindings.claude.preTrustPaths
          ++ lib.concatLists cfg.workspaceGroups
        );
      };
    };

    home-manager.users.${cfg.user} = { lib, ... }: {
      # Pre-trust the configured workspaces (internal/apps/claude).
      home.activation.claudeTrustWorkspaces = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        ${lib.getExe cfg.package} claude-trust
      '';

      # Containers cannot refresh a placeholder, and frisket never refreshes,
      # so the host's login is kept fresh here (internal/apps/claude).
      systemd.user.services.claude-refresh = {
        Unit.Description = "Refresh the host's Claude Code login before it expires";
        Install.WantedBy = [ "default.target" ];
        Service = {
          Restart = "always";
          RestartSec = 60;
          ExecStart = "${lib.getExe cfg.package} claude-refresh";
        };
      };

      programs.claude-code.package = pkgs.symlinkJoin {
        name = "claude-code-tiered";
        paths = [ claudeLinks base ];
        inherit (base) meta;
      };
    };

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}"
      (mkIf (tier.apps.claude.state != null) (mkMerge [
        {
          # ~/.claude is the session's own, with only the entries below bound
          # in: no login, and no shell snapshots from the host's PATH.
          config.environment.systemPackages = [ base ];
          bindMounts = {
            "${claudeDir}/settings.json" = bind "${claudeDir}/settings.json" true;
            "${claudeDir}/statusline.sh" = bind "${claudeDir}/statusline.sh" true;
          };
        }
        (mkIf (!tier.apps.claude.connectors) {
          config.environment.variables.ENABLE_CLAUDEAI_MCP_SERVERS = "false";
        })
        (mkIf (tier.apps.claude.state == "shared") {
          bindMounts = {
            "${claudeDir}/projects" = bind "${claudeDir}/projects" false;
            "${claudeDir}/plugins" = bind "${claudeDir}/plugins" false;
            "${claudeDir}/file-history" = bind "${claudeDir}/file-history" false;
            "${claudeDir}/plans" = bind "${claudeDir}/plans" false;
            "${claudeDir}/paste-cache" = bind "${claudeDir}/paste-cache" false;
            "${claudeDir}/sessions" = bind "${claudeDir}/sessions" false;
            "${claudeDir}/history.jsonl" = bind "${claudeDir}/history.jsonl" false;
            "${cfg.home}/.claude.json" = bind "${cfg.home}/.claude.json" false;
            # Cross-session messaging.
            "/run/user/${toString cfg.uid}/cc-socks" = bind "/run/user/${toString cfg.uid}/cc-socks" false;
          };
        })
      ]))) cfg.tiers;

    # Host plugins readable; writes are discarded with the session.
    flong = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}"
      (mkIf (tier.apps.claude.state == "isolated") {
        overlays."${claudeDir}/plugins" = "${claudeDir}/plugins";
      })) cfg.tiers;

    services.frisket.policies = lib.mapAttrs (name: tier:
      mkIf (tier.apps.claude.state != null) {
        allow = lib.mkAfter allow;
        routes = {
          claude = claudeRoute "api.anthropic.com";
          claude-platform = claudeRefusedRoute;
        } // lib.optionalAttrs tier.apps.claude.connectors {
          claude-connectors = claudeRoute "mcp-proxy.anthropic.com";
        };
      }) cfg.tiers;
  };
}
