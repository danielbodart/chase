{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types;
  cfg = config.chase;
  lines = builtins.concatStringsSep "\n";
  q = lib.escapeShellArg;
  sandboxes = lib.filterAttrs (_: t: !t.bare) cfg.tiers;
  fallback = cfg.fallback;

  # Every tier's rules, first to last as `order` asks them, each numbered so
  # its shell function has a name whatever the tier is called.
  rules = lib.imap0 (i: r: r // { fn = "rule_${toString i}"; })
    (lib.concatMap (tier: map (rule: { inherit tier rule; }) cfg.tiers.${tier}.match) cfg.order);

  # One rule as a function: each predicate it sets, and all of them to hold.
  # Remotes and owners are compared lower-cased, as the remote is read.
  ruleFunction = { fn, rule, ... }: ''
    ${fn}() {
      found=()
      ${lines (
        lib.optional (rule.paths != [ ]) "at_path ${q (lines rule.paths)} || return 1"
        ++ lib.optional (rule.checkouts != { }) "in_checkout ${q (lines (lib.mapAttrsToList (s: p: "${lib.toLower s}\t${p}") rule.checkouts))} || return 1"
        ++ lib.optional (rule.repos != [ ]) "in_repos ${q (lines (map lib.toLower rule.repos))} || return 1"
        ++ lib.optional (rule.owners != [ ]) "by_owner ${q (lines (map lib.toLower rule.owners))} || return 1"
        ++ lib.optional (rule.rootAuthorDomains != [ ]) "first_commit_by ${q (lines (map lib.toLower rule.rootAuthorDomains))} || return 1"
      )}
    }
  '';

  # Prints a directory's tier; --dry-run DIR... explains, one line each.
  agentTier = pkgs.writeShellApplication {
    name = "agent-tier";
    runtimeInputs = with pkgs; [ git coreutils gnugrep ];
    text = ''
      # What the rule being asked has found, and why the rules asked so far
      # did not hold: --dry-run's reasons. A predicate that does not hold for
      # a reason worth telling -- not "some other path" -- says it with miss.
      found=()
      misses=()
      miss() {
        if [ -n "''${1-}" ]; then misses+=("$1"); fi
        return 1
      }

      # What git says of the directory, asked once and only if a rule needs it.
      need_toplevel() {
        if [ -z "$toplevel_state" ]; then
          if toplevel=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null); then
            toplevel_state=ok
          else
            toplevel_state="not a git repository"
          fi
        fi
        [ "$toplevel_state" = ok ] || miss "$toplevel_state"
      }

      need_origin() {
        need_toplevel || return 1
        if [ -z "$origin_state" ]; then
          local remote
          if ! remote=$(git -C "$dir" remote get-url origin 2>/dev/null); then
            origin_state="no origin remote"
          else
            # git@host:owner/repo.git | https://host/owner/repo.git | ssh://git@host/owner/repo
            slug=''${remote%.git}
            slug=''${slug##*:}
            slug=''${slug#//*/}
            slug=$(printf '%s' "''${slug#/}" | tr '[:upper:]' '[:lower:]')
            if [[ $slug != */* || $slug == */*/* ]]; then
              origin_state="cannot parse owner/repo from $remote"
            else
              owner=''${slug%%/*}
              origin_state=ok
            fi
          fi
        fi
        [ "$origin_state" = ok ] || miss "$origin_state"
      }

      # THE PREDICATES, each given its list one entry per line.

      at_path() {
        local p
        while IFS= read -r p; do
          if [ "$abs" = "$p" ]; then found+=("path $p"); return 0; fi
        done <<< "$1"
        return 1
      }

      in_checkout() {
        need_origin || return 1
        local s p
        while IFS=$'\t' read -r s p; do
          [ "$s" = "$slug" ] || continue
          case $toplevel in
            "$p" | "$p"/*) found+=("$slug at $p"); return 0 ;;
          esac
          miss "$slug is declared at $p, not $toplevel"
          return 1
        done <<< "$1"
        return 1
      }

      in_repos() {
        need_origin || return 1
        if grep -qxF "$slug" <<< "$1"; then found+=("repo $slug"); return 0; fi
        return 1
      }

      by_owner() {
        need_origin || return 1
        if grep -qxF "$owner" <<< "$1"; then found+=("owner $owner"); return 0; fi
        miss "owner $owner is not listed"
      }

      # Every root commit, since a history can have more than one. A shallow
      # clone's first commit is its boundary, not the real root.
      first_commit_by() {
        need_toplevel || return 1
        [ "$(git -C "$dir" rev-parse --is-shallow-repository)" = false ] \
          || { miss "shallow clone, first commit unknowable"; return 1; }
        local authors author domain
        authors=$(git -C "$dir" log --max-parents=0 --format=%ae 2>/dev/null) || authors=
        [ -n "$authors" ] || { miss "no commits, no provenance to check"; return 1; }
        while IFS= read -r author; do
          domain=$(printf '%s' "''${author##*@}" | tr '[:upper:]' '[:lower:]')
          grep -qxF "$domain" <<< "$1" || { miss "first commit by $author"; return 1; }
        done <<< "$authors"
        found+=("first commit by ''${authors%%$'\n'*}")
      }

      # THE RULES, as chase.tiers.<name>.match declares them.
      ${lines (map ruleFunction rules)}

      decide() {
        dir=$1
        abs=$(cd "$dir" 2>/dev/null && pwd -P) || abs=$dir
        toplevel_state="" origin_state="" toplevel="" slug="" owner=""
        misses=()
        local joined
        ${lines (map ({ fn, tier, ... }: ''
          if ${fn}; then
            joined=$(printf '%s, ' "''${found[@]}")
            printf '%s\t%s\n' ${q tier} "''${joined%, }"
            return
          fi'') rules)}
        # Why nothing held, each reason once.
        joined=
        local m
        for m in "''${misses[@]}"; do
          case "; $joined; " in
            *"; $m; "*) ;;
            *) joined+="''${joined:+; }$m" ;;
          esac
        done
        joined=''${joined:-no rule holds}
        printf '%s\t%s\n' ${q fallback} "$joined"
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

  # `claude` / `codex` on the host: pick the tier, then run bare or in its
  # container. Anything unexpected is the fallback.
  mkWrapper = { name, agent, hostCommand }: pkgs.writeShellApplication {
    inherit name;
    runtimeInputs = [ agentTier ];
    text = ''
      tier=$(agent-tier 2>/dev/null) || tier=${q fallback}

      case $tier in
      ${lines (lib.mapAttrsToList (tier: t: ''
        ${q tier})
          exec ${if t.bare then hostCommand else "${lib.getExe config.flong."agent-${tier}".launcher} ${agent}"} "$@"
          ;;'') cfg.tiers)}
        *)
          exec ${lib.getExe config.flong."agent-${fallback}".launcher} ${agent} "$@"
          ;;
      esac
    '';
  };

  # `chase shell`: a shell where `claude` would run, so a session can be
  # looked at, or used, with nothing in between. A subcommand rather than a
  # wrapper of its own, so the next thing like it has somewhere to go.
  chase = pkgs.writeShellApplication {
    name = "chase";
    text = ''
      usage() {
        echo "usage: chase shell [ARG...]   a shell where an agent would run in this checkout" >&2
        exit 2
      }
      [ $# -gt 0 ] || usage
      command=$1
      shift
      case $command in
        shell) exec ${lib.getExe (mkWrapper {
          name = "chase-shell";
          agent = "shell";
          hostCommand = ''"''${SHELL:-bash}"'';
        })} "$@" ;;
        *) usage ;;
      esac
    '';
  };
in
{
  options.chase.internal = {
    agentTier = mkOption { type = types.package; readOnly = true; internal = true; };
    mkWrapper = mkOption { type = types.raw; readOnly = true; internal = true; };
  };

  config = {
    chase.internal = { inherit agentTier mkWrapper; };

    # A consistency check, not a gate: the launcher runs as the caller, who
    # could run it with any workspace, or run bwrap without it. It catches
    # the wrapper and the launcher disagreeing about a checkout -- a launcher
    # started by hand, or a checkout whose remote changed since the wrapper
    # sorted it -- before a session is built around the wrong tier. What
    # gates a checkout's own changes to its session is chase.approver.
    #
    # Not the fallback's: it is where anything the selector could not place
    # goes, so it takes any checkout.
    flong = lib.mapAttrs' (name: _: lib.nameValuePair "agent-${name}" {
      path = lib.mkBefore [ agentTier ];
      # A command, never shell: a script of its own, under the options
      # flong's snippets once ran with, finding agent-tier on `path`.
      guard = [ [ "${pkgs.writeShellScript "chase-agent-${name}-guard" (''
        set -euo pipefail
      '' + lib.optionalString (name != fallback) ''
        tier=$(agent-tier "$workspace") || tier=unknown
        if [ "$tier" != ${q name} ]; then
          echo ${q "agent-${name}"}": refusing, this checkout is '$tier'" >&2
          exit 1
        fi
      '' + ''

        # Group members are reported, not refused: vendoring the same code
        # into the workspace would bypass a refusal anyway. Only checkouts:
        # the state directories apps bind are not code, and have no tier.
        while IFS= read -r bind; do
          [ -n "$bind" ] || continue
          extra=''${bind%:*}
          [ -e "$extra/.git" ] || continue
          extra_tier=$(agent-tier "$extra") || extra_tier=unknown
          echo ${q "agent-${name}"}": mounting $extra ($extra_tier, ''${bind##*:})" >&2
        done <<< "$binds"
      '')}" ] ];
    }) sandboxes;

    home-manager.users.${cfg.user}.home.packages = [ agentTier chase ];
  };
}
