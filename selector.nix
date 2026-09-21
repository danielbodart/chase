{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types;
  cfg = config.agents;
  lines = builtins.concatStringsSep "\n";

  # Prints host, trusted or strict for a directory; --dry-run DIR... explains.
  agentTier = pkgs.writeShellApplication {
    name = "agent-tier";
    runtimeInputs = [ pkgs.git ];
    text = ''
      STRICT_REPOS=${lib.escapeShellArg (lines cfg.strictRepos)}
      TRUSTED_REPOS=${lib.escapeShellArg (lines (
        lib.mapAttrsToList (slug: path: "${slug}\t${path}") cfg.trustedRepos
      ))}
      HOST_REPOS=${lib.escapeShellArg (lines (
        lib.mapAttrsToList (slug: path: "${slug}\t${path}") cfg.hostRepos
      ))}
      HOST_PATHS=${lib.escapeShellArg (lines cfg.hostPaths)}
      TRUSTED_ORGS=${lib.escapeShellArg (lines cfg.trustedOrgs)}
      TRUSTED_AUTHOR_DOMAINS=${lib.escapeShellArg (lines cfg.trustedAuthorDomains)}

      decide() {
        local dir=$1 toplevel remote slug owner root_authors domain a_slug a_path abs

        # Paths first: the one signal a checkout cannot forge.
        abs=$(cd "$dir" 2>/dev/null && pwd -P) || abs=$dir
        while read -r a_path; do
          [ -n "$a_path" ] || continue
          [ "$abs" = "$a_path" ] || continue
          printf 'host\texplicit host path\n'; return
        done <<EOF
      $HOST_PATHS
      EOF

        toplevel=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null) \
          || { printf 'strict\tnot a git repository\n'; return; }

        # A shallow clone's first commit is its boundary, not the real root.
        [ "$(git -C "$dir" rev-parse --is-shallow-repository)" = false ] \
          || { printf 'strict\tshallow clone, first commit unknowable\n'; return; }

        remote=$(git -C "$dir" remote get-url origin 2>/dev/null) \
          || { printf 'strict\tno origin remote\n'; return; }

        # git@host:owner/repo.git | https://host/owner/repo.git | ssh://git@host/owner/repo
        slug=''${remote%.git}
        slug=''${slug##*:}
        slug=''${slug#//*/}
        slug=$(printf '%s' "''${slug#/}" | tr '[:upper:]' '[:lower:]')
        if [[ $slug != */* || $slug == */*/* ]]; then
          printf 'strict\tcannot parse owner/repo from %s\n' "$remote"; return
        fi
        owner=''${slug%%/*}

        if printf '%s\n' "$STRICT_REPOS" | grep -qxF "$slug"; then
          printf 'strict\texplicit override\n'; return
        fi
        while IFS=$'\t' read -r a_slug a_path; do
          [ -n "$a_slug" ] && [ "$a_slug" = "$slug" ] || continue
          case $toplevel in
            "$a_path" | "$a_path"/*)
              printf 'trusted\texplicit override, remote and path both matched\n'; return ;;
          esac
          printf 'strict\ttrusted repo %s, but %s is not under its declared path\n' \
            "$slug" "$toplevel"
          return
        done <<EOF
      $TRUSTED_REPOS
      EOF
        while IFS=$'\t' read -r a_slug a_path; do
          [ -n "$a_slug" ] && [ "$a_slug" = "$slug" ] || continue
          case $toplevel in
            "$a_path" | "$a_path"/*)
              printf 'host\texplicit override, remote and path both matched\n'; return ;;
          esac
          # A declared repo at the wrong path is what a spoofed remote looks like.
          printf 'strict\thost repo %s, but %s is not under its declared path\n' \
            "$slug" "$toplevel"
          return
        done <<EOF
      $HOST_REPOS
      EOF

        printf '%s\n' "$TRUSTED_ORGS" | grep -qxF "$owner" \
          || { printf 'strict\towner %s is not a trusted org\n' "$owner"; return; }

        # Every root commit by us; a fork's root is upstream's author.
        root_authors=$(git -C "$dir" log --max-parents=0 --format=%ae 2>/dev/null)
        [ -n "$root_authors" ] \
          || { printf 'strict\tno commits, no provenance to check\n'; return; }

        while read -r author; do
          domain=''${author##*@}
          printf '%s\n' "$TRUSTED_AUTHOR_DOMAINS" | grep -qxF "$domain" \
            || { printf 'strict\tfirst commit by %s, likely a fork\n' "$author"; return; }
        done <<EOF
      $root_authors
      EOF

        printf 'trusted\town org and first commit by %s\n' \
          "$(printf '%s\n' "$root_authors" | head -1)"
      }

      if [ "''${1-}" = --dry-run ]; then
        shift
        printf '%-26s %-9s %s\n' DIRECTORY TIER REASON
        for d in "$@"; do
          decide "$d" | while IFS=$'\t' read -r tier reason; do
            printf '%-26s %-9s %s\n' "$(basename "''${d%/}")" "$tier" "$reason"
          done
        done
      else
        decide "''${1-$PWD}" | cut -f1
      fi
    '';
  };

  # `claude` / `codex` on the host: pick the tier, then run bare or in its container.
  mkWrapper = { name, agent, hostCommand }: pkgs.writeShellApplication {
    inherit name;
    # Not pkgs.sudo: the store copy is not setuid.
    runtimeInputs = [ agentTier ];
    text = ''
      # Anything unexpected means strict.
      tier=$(agent-tier 2>/dev/null) || tier=strict
      case $tier in host|trusted|strict) : ;; *) tier=strict ;; esac

      case $tier in
        host)
          exec ${hostCommand} "$@"
          ;;
        trusted)
          exec /run/wrappers/bin/sudo --preserve-env=TERM,COLORTERM \
            ${lib.getExe config.flong.agent-trusted.launcher} ${agent} "$@"
          ;;
        strict)
          exec /run/wrappers/bin/sudo --preserve-env=TERM,COLORTERM \
            ${lib.getExe config.flong.agent-strict.launcher} ${agent} "$@"
          ;;
      esac
    '';
  };
in
{
  options.agents.internal = {
    agentTier = mkOption { type = types.package; readOnly = true; internal = true; };
    mkWrapper = mkOption { type = types.raw; readOnly = true; internal = true; };
  };

  config = {
    agents.internal = { inherit agentTier mkWrapper; };

    # The launchers are NOPASSWD, so trusted re-checks the workspace itself
    # rather than trusting the wrapper. Strict grants nothing the caller lacks.
    flong.agent-trusted = {
      path = lib.mkBefore [ agentTier ];
      guard = ''
        tier=$(agent-tier "$workspace") || tier=unknown
        if [ "$tier" != trusted ]; then
          echo "agent-container-trusted: refusing, this checkout is '$tier'" >&2
          exit 1
        fi

        # Group members are reported, not refused: vendoring the same code
        # into the workspace would bypass a refusal anyway.
        while IFS= read -r bind; do
          [ -n "$bind" ] || continue
          extra=''${bind%:*}
          extra_tier=$(agent-tier "$extra") || extra_tier=unknown
          echo "agent-container-trusted: mounting $extra ($extra_tier, ''${bind##*:})" >&2
        done <<< "$binds"
      '';
    };

    # Store paths, never systemd-nspawn itself, which would be root.
    security.sudo.extraRules = [{
      users = [ cfg.user ];
      commands = map (name: {
        command = lib.getExe config.flong."agent-${name}".launcher;
        options = [ "NOPASSWD" ];
      }) (builtins.attrNames cfg.tiers);
    }];

    home-manager.users.${cfg.user}.home.packages = [ agentTier ];
  };
}
