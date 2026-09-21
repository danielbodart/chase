{ config, lib, pkgs, ... }:

let
  inherit (lib) mkIf mkMerge mkOption types;
  cfg = config.chase;
  base = cfg.apps.claude.package;
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
    paths = [{ methods = [ "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" ]; prefix = "/"; }];
  };

  # Token refresh and the Console: logged and refused, so no response can hand
  # the sandbox a real token. A route needs a scope, so this one matches nothing.
  claudeRefusedRoute = claudeRoute "platform.claude.com" // {
    paths = [{ methods = [ "GET" ]; prefix = "/frisket-refuses-everything-here"; }];
  };

  trustedScopes = [ "user:file_upload" "user:inference" "user:mcp_servers" "user:profile" "user:sessions:claude_code" ];
  strictScopes = [ "user:inference" ];
  # Shaped like the real login, since Claude Code decides what to offer from
  # it. Never expires, so the container never tries to refresh it.
  claudePlaceholder = scopes: builtins.toJSON {
    claudeAiOauth = {
      accessToken = cfg.placeholder;
      refreshToken = cfg.placeholder;
      expiresAt = 4102444800000; # 2100-01-01
      refreshTokenExpiresAt = 4102444800000;
      inherit scopes;
      subscriptionType = "max";
    };
  };

  hostEnabledPlugins = builtins.attrNames
    config.home-manager.users.${cfg.user}.programs.claude-code.settings.enabledPlugins;

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

  # This workspace's transcripts only, written to the host so `claude --resume`
  # finds them later.
  transcriptBind = ''
    transcripts="${cfg.home}/.claude/projects/''${workspace//[^A-Za-z0-9]/-}"
    mkdir -p "$transcripts"
    printf '%s:rw\n' "$transcripts"
  '';

  claudeRaw = pkgs.writeShellApplication {
    name = "claude-raw";
    text = ''exec ${base}/bin/claude "$@"'';
  };
  claudeWrapped = cfg.internal.mkWrapper {
    name = "claude";
    agent = "claude";
    hostCommand = "${base}/bin/claude --allow-dangerously-skip-permissions";
  };

  bind = path: readOnly: { hostPath = path; isReadOnly = readOnly; };
  claudeDir = "${cfg.home}/.claude";
in
{
  options.chase.apps.claude = {
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
    home-manager.users.${cfg.user} = { lib, ... }: {
      # Pre-trust every checkout this flake clones, and every group member.
      home.activation.claudeTrustWorkspaces =
        let
          paths = lib.unique (
            [ cfg.home ]
            ++ cfg.apps.claude.preTrustPaths
            ++ lib.concatLists cfg.workspaceGroups
          );
        in
        lib.hm.dag.entryAfter [ "writeBoundary" ] ''
          f="$HOME/.claude.json"
          if [ -f "$f" ]; then
            t=$(mktemp) || exit 0
            if ${pkgs.jq}/bin/jq \
                 --argjson paths ${lib.escapeShellArg (builtins.toJSON paths)} \
                 'reduce $paths[] as $p (.; .projects[$p].hasTrustDialogAccepted = true)' \
                 "$f" > "$t" 2>/dev/null && [ -s "$t" ]; then
              if ! ${pkgs.diffutils}/bin/cmp -s "$t" "$f"; then
                chmod 0600 "$t" && mv "$t" "$f"
                echo "claude: pre-trusted ${toString (builtins.length paths)} workspaces"
              else
                rm -f "$t"
              fi
            else
              rm -f "$t"
            fi
          fi
        '';

      # nspawn refuses to start if a bind source is missing.
      home.activation.claudeSharedState = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        mkdir -p "$HOME"/.claude/{projects,plugins,file-history,plans,paste-cache,sessions}
        touch "$HOME/.claude/history.jsonl"
      '';

      # Containers cannot refresh a placeholder, and frisket never refreshes,
      # so the host's login is kept fresh here.
      systemd.user.services.claude-refresh = {
        Unit.Description = "Refresh the host's Claude Code login before it expires";
        Install.WantedBy = [ "default.target" ];
        Service = {
          Restart = "always";
          RestartSec = 60;
          ExecStart = lib.getExe (pkgs.writeShellApplication {
            name = "claude-refresh";
            runtimeInputs = [ pkgs.jq pkgs.coreutils claudeRaw ];
            text = ''
              cred=${cfg.home}/.claude/.credentials.json
              expires() { jq -er '.claudeAiOauth.expiresAt | numbers' "$cred" 2>/dev/null; }
              while true; do
                if ! exp=$(expires); then
                  echo "claude-refresh: no expiresAt in $cred; looking again in 5 minutes" >&2
                  sleep 300
                  continue
                fi
                # Wake 4 minutes before expiry, in steps short enough to survive suspend.
                wait=$(( (exp - 240000) / 1000 - $(date +%s) ))
                if (( wait > 0 )); then
                  sleep $(( wait < 300 ? wait : 300 ))
                  continue
                fi
                claude-raw -p --model haiku --no-session-persistence 'Reply with the single word: ok' \
                  > /dev/null 2>&1 || echo "claude-refresh: claude exited $?" >&2
                if [ "$(expires)" = "$exp" ]; then
                  echo "claude-refresh: expiresAt did not move; trying again in a minute" >&2
                  sleep 60
                else
                  echo "claude-refresh: refreshed" >&2
                fi
              done
            '';
          });
        };
      };

      home.packages = [ claudeRaw ];
      programs.claude-code.package = pkgs.symlinkJoin {
        name = "claude-code-tiered";
        paths = [ claudeWrapped base ];
        inherit (base) meta;
      };
    };

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}"
      (mkIf (tier.apps.claude.state != null) (mkMerge [
        {
          # Container-local, with only the entries below bound in: no login,
          # and no shell snapshots from the host's PATH.
          tmpfs = [ claudeDir ];
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

    chase.internal.tiers = lib.mapAttrs (name: tier:
      mkIf (tier.apps.claude.state != null) {
        bindLines = lib.optional (tier.apps.claude.state == "isolated") transcriptBind;
        # Written, not bound: Claude Code replaces the file by rename.
        setupLines = [
          ''
            (umask 077; printf '%s' ${lib.escapeShellArg (claudePlaceholder (
              if tier.apps.claude.connectors then trustedScopes else strictScopes
            ))} \
              > ${claudeDir}/.credentials.json)
          ''
        ] ++ lib.optional (tier.apps.claude.state == "isolated") ''
          jq -n --arg ws "$workspace" \
            '{hasCompletedOnboarding: true, projects: {($ws): {hasTrustDialogAccepted: true}}}' \
            > ${cfg.home}/.claude.json
        '';
        launchers.claude = ''
          claude)
            set -- claude \
              --settings ${tierSettings name tier} \
              --allow-dangerously-skip-permissions \
              ''${add_dirs[@]+--add-dir "''${add_dirs[@]}"} "$@"
            ;;
        '';
      }) cfg.tiers;
  };
}
