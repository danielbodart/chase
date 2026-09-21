{ config, lib, pkgs, ... }:

let
  inherit (lib) mkIf mkMerge mkOption types;
  cfg = config.chase;
  base = cfg.apps.codex.package;
  allow = [ "chatgpt.com" "*.chatgpt.com" "openai.com" "*.openai.com" ];
  every = [ "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" ];

  codexDir = "${cfg.home}/.codex";
  authFile = "${codexDir}/auth.json";
  # The placeholder login, and each tier's own CODEX_HOME. Under the host's
  # state directory: neither is the host's own login or state.
  stateDir = "${cfg.home}/.local/state/agents/codex";
  placeholderFile = "${stateDir}/auth-placeholder.json";

  # What the container holds in place of the access token. cfg.placeholder
  # cannot be it: codex reads its own token as a JWT and refreshes 5 minutes
  # before the `exp` it finds, so the placeholder has to be JWT-shaped with an
  # expiry far away -- {"alg":"none","typ":"JWT"} over
  # {"exp":4102444800,"sub":"frisket-placeholder"}, 4102444800 being
  # 2100-01-01. Nothing verifies the signature: not codex, which only splits
  # on '.', and not frisket, which compares the whole string to this one.
  placeholderJWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjQxMDI0NDQ4MDAsInN1YiI6ImZyaXNrZXQtcGxhY2Vob2xkZXIifQ.frisket";

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
  # a real token and nothing in one can end the host's login. A route needs a
  # scope, so this one matches nothing. No credential: what a session brings
  # is its own, and this admits none of it anyway.
  refusedRoute = {
    host = "auth.openai.com";
    upstream = "https://auth.openai.com";
    paths = [{ methods = [ "GET" ]; prefix = "/frisket-refuses-everything-here"; }];
  };

  # The placeholder auth.json, made from the host's login: codex decides what
  # to offer from the plan and account claims in the id_token, and sends
  # account_id as the ChatGPT-Account-ID header, so those are the host's own.
  # Only the tokens are replaced. The id_token keeps its claims and loses its
  # signature, which nothing checks.
  #
  # Written in place, never by rename: a container binds this file over its
  # own auth.json, and a rename over a mountpoint detaches that bind in every
  # other namespace -- which would uncover whatever is underneath.
  writePlaceholder = pkgs.writeShellApplication {
    name = "codex-placeholder";
    runtimeInputs = [ pkgs.jq pkgs.coreutils ];
    text = ''
      mkdir -p ${lib.escapeShellArg stateDir}
      auth=${lib.escapeShellArg authFile}
      out=${lib.escapeShellArg placeholderFile}
      # Logged in on the host or not, the file must exist: nspawn refuses to
      # start when a bind's source is missing.
      real='{}'
      if [ -f "$auth" ]; then real=$(cat "$auth"); fi
      jq -n \
        --argjson real "$real" \
        --arg access ${lib.escapeShellArg placeholderJWT} \
        '$real as $r
         | {
             auth_mode: ($r.auth_mode // "chatgpt"),
             OPENAI_API_KEY: null,
             tokens: {
               # The signature dropped, the claims kept.
               id_token: (($r.tokens.id_token // "") | split(".")[0:2] + ["frisket"] | join(".")),
               access_token: $access,
               refresh_token: "frisket-placeholder",
               account_id: ($r.tokens.account_id // "")
             },
             last_refresh: ($r.last_refresh // "2000-01-01T00:00:00Z")
           }' > "$out.new"
      # cat, not mv: see above. The temporary file is this script's own.
      cat "$out.new" > "$out"
      chmod 0600 "$out"
      rm -f "$out.new"
    '';
  };

  # codex refreshes only in the last 5 minutes before its access token expires,
  # and a refresh token is single-use: a second refresher racing the first
  # revokes the login. So this one runs a day early, where nothing else is
  # looking, and does the exchange itself.
  refresh = pkgs.writeShellApplication {
    name = "codex-refresh";
    runtimeInputs = [ pkgs.jq pkgs.coreutils pkgs.curl writePlaceholder ];
    text = ''
      auth=${lib.escapeShellArg authFile}
      # The client codex itself logs in as, from its source: without it the
      # token endpoint refuses the exchange.
      client_id=app_EMoamEEZ73f0CkXaXp7hrann

      # `exp`, out of the access token's own claims.
      expires() {
        jq -er '.tokens.access_token | split(".")[1]
                | gsub("-";"+") | gsub("_";"/")
                | . + ("=" * ((4 - (length % 4)) % 4))
                | @base64d | fromjson | .exp | numbers' "$auth" 2>/dev/null
      }

      while true; do
        if ! exp=$(expires); then
          echo "codex-refresh: no access token in $auth; looking again in 5 minutes" >&2
          sleep 300
          continue
        fi
        # Wake a day before expiry, in steps short enough to survive suspend.
        wait=$(( exp - 86400 - $(date +%s) ))
        if (( wait > 0 )); then
          sleep $(( wait < 300 ? wait : 300 ))
          continue
        fi

        refresh_token=$(jq -er '.tokens.refresh_token' "$auth") || {
          echo "codex-refresh: no refresh token; trying again in a minute" >&2
          sleep 60
          continue
        }
        if ! new=$(curl -fsS --max-time 60 https://auth.openai.com/oauth/token \
              -H 'Content-Type: application/json' \
              -d "$(jq -n --arg c "$client_id" --arg r "$refresh_token" \
                     '{client_id:$c, grant_type:"refresh_token", refresh_token:$r}')"); then
          echo "codex-refresh: the exchange failed; trying again in a minute" >&2
          sleep 60
          continue
        fi

        # In place, and only what came back: codex writes this file the same
        # way, and a rename would detach the bind covering it in a container.
        if merged=$(jq -e --argjson new "$new" '
              .tokens.id_token = ($new.id_token // .tokens.id_token)
              | .tokens.access_token = ($new.access_token // .tokens.access_token)
              | .tokens.refresh_token = ($new.refresh_token // .tokens.refresh_token)
              | .last_refresh = (now | todate)' "$auth"); then
          printf '%s\n' "$merged" > "$auth"
          codex-placeholder
          echo "codex-refresh: refreshed" >&2
        else
          echo "codex-refresh: the response held no tokens; trying again in a minute" >&2
          sleep 60
        fi
      done
    '';
  };

  codexRaw = pkgs.writeShellApplication {
    name = "codex-raw";
    text = ''exec ${base}/bin/codex "$@"'';
  };
  # On the host codex keeps its own sandbox; in a container it bypasses it.
  codexWrapped = cfg.internal.mkWrapper {
    name = "codex";
    agent = "codex";
    hostCommand = "${base}/bin/codex";
  };

  bind = path: readOnly: { hostPath = path; isReadOnly = readOnly; };

  # An isolated tier's CODEX_HOME, one per workspace. Everything codex keeps --
  # the thread index, history, memories -- is one file per directory at the top
  # of it, with nothing per project to pick out the way ~/.claude/projects has,
  # so a workspace gets a whole home of its own or it shares all of it.
  isolatedHome = ''codex_home=${stateDir}/''${workspace//[^A-Za-z0-9]/-}'';
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
      options.apps.codex.state = mkOption {
        type = types.nullOr (types.enum [ "shared" "isolated" ]);
        default = null;
        description = ''
          `shared`: threads, history and memories are the host's.
          `isolated`: a CODEX_HOME per workspace, and nothing of the host's.
          Non-null enables codex in the tier.
        '';
      };
    });
  };

  config = {
    home-manager.users.${cfg.user} = { lib, ... }: {
      home.packages = [ codexWrapped codexRaw ];

      # The placeholder is a bind source: nspawn refuses to start without it.
      home.activation.codexPlaceholder = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        ${lib.getExe writePlaceholder} || echo "codex: no placeholder login written"
      '';

      systemd.user.services.codex-refresh = {
        Unit.Description = "Refresh the host's codex login before it expires";
        Install.WantedBy = [ "default.target" ];
        Service = {
          Restart = "always";
          RestartSec = 60;
          ExecStart = lib.getExe refresh;
        };
      };
    };

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}"
      (mkIf (tier.apps.codex.state != null) (mkMerge [
        { config.environment.systemPackages = [ base ]; }
        (mkIf (tier.apps.codex.state == "shared") {
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
      mkIf (tier.apps.codex.state != null) {
        allow = lib.mkAfter allow;
        routes = {
          # A shared tier is the host's own session by another name. An
          # isolated one gets codex and nothing else: the same bearer reads
          # and writes your ChatGPT conversations everywhere else on the host.
          codex = codexRoute (
            if tier.apps.codex.state == "shared"
            then [{ methods = every; prefix = "/"; }]
            else [{ methods = every; prefix = "/backend-api/codex/"; }]
          );
          codex-auth = refusedRoute;
        };
      }) cfg.tiers;

    chase.internal.tiers = lib.mapAttrs (_: tier: mkIf (tier.apps.codex.state != null) {
      # A home per workspace, made on the host and mounted at its own path.
      # The placeholder login is put there fresh each session, so nothing a
      # session leaves behind is what the next one authenticates with.
      bindLines = lib.optional (tier.apps.codex.state == "isolated") ''
        ${isolatedHome}
        mkdir -p "$codex_home"
        install -m 0600 ${lib.escapeShellArg placeholderFile} "$codex_home/auth.json"
        printf '%s:rw\n' "$codex_home"
      '';

      setupLines = lib.optional (tier.apps.codex.state == "isolated") ''
        ${isolatedHome}
        export CODEX_HOME=$codex_home
      '';

      # Trust as a -c override, since config.toml is the host's. The workspace
      # is escaped because it lands inside a TOML string.
      #
      # ignore_default_excludes is codex's own default, set here because the
      # container depends on it: the excludes it would otherwise apply are
      # *KEY*, *SECRET* and *TOKEN*, which take GH_TOKEN off every command and
      # leave gh quietly unauthenticated.
      launchers.codex = ''
        codex)
          toml_workspace=''${workspace//\\/\\\\}
          toml_workspace=''${toml_workspace//\"/\\\"}
          codex_dirs=()
          for d in ''${add_dirs[@]+"''${add_dirs[@]}"}; do
            codex_dirs+=(--add-dir "$d")
          done
          set -- codex \
            --dangerously-bypass-approvals-and-sandbox \
            -c "projects.\"$toml_workspace\".trust_level=\"trusted\"" \
            -c shell_environment_policy.ignore_default_excludes=true \
            ''${codex_dirs[@]+"''${codex_dirs[@]}"} "$@"
          ;;
      '';
    }) cfg.tiers;
  };
}
