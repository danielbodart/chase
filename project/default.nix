# A project's envelope, applied at launch (PLAN.md, decisions 7, 10, 11, 17).
#
# For a tier that takes envelopes, each launch:
#
#   binds      makes the checkout's environment directory, bound read-only
#   postStart  as the user, before frisket's steps: evaluates the checkout's
#              `chaseModules.default` against ./options.nix; asks
#              `chase.approver` if the result is not the one last approved
#              for this checkout; decrypts the secrets it binds into
#              /run/user/<uid>/chase/<machine>/; writes the session's policy
#              document there, and its environment beside the checkout's
#   frisket    steers the session under that document, or the tier's own
#   postStop   removes /run/user/<uid>/chase/<machine>/
#
# A checkout with no flake, or a flake with no `chaseModules.default`, is the
# tier as it is. Anything that goes wrong on the way ends the launch: an
# envelope is applied whole or the session does not start.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types;
  cfg = config.chase;
  tiers = lib.filterAttrs (_: t: t.envelope) cfg.tiers;

  apps = pkgs.writeText "chase-project-apps.json" (builtins.toJSON cfg.internal.projectApps);
  approver = if cfg.approver == null then "" else cfg.approver;

  envelope = pkgs.writeShellApplication {
    name = "chase-envelope";
    runtimeInputs = with pkgs; [ nix jq sops coreutils diffutils git ];
    text = ''
      uid=${toString cfg.uid}
      home=${lib.escapeShellArg cfg.home}
      state=$home/.local/state/chase
      apps=${apps}
      approver=${lib.escapeShellArg approver}

      # A checkout's key: its path, hashed, so a path with anything in it is
      # still one plain file name.
      key() { printf '%s' "$1" | sha256sum | cut -c1-32; }

      env_dir() { printf '%s/env/%s' "$state" "$(key "$1")"; }

      die() { echo "chase: $*" >&2; exit 1; }

      # The checkout's envelope, as JSON, or null if it has none. Evaluated
      # as the caller, against ./options.nix only: an option that is not
      # there is an error, not a setting applied somewhere else. The flake's
      # own nixConfig is not taken, and its lock is never written.
      evaluate() {
        local ws=$1 ref
        [ -f "$ws/flake.nix" ] || { echo null; return; }
        if git -C "$ws" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
          ref="git+file://$ws"
        else
          ref="path:$ws"
        fi
        # The reference goes in through the environment, never spliced into
        # the expression: a path is the caller's, and could hold anything.
        CHASE_FLAKE_REF=$ref nix eval --json --impure --no-write-lock-file \
          --option accept-flake-config false --expr '
            let
              flake = builtins.getFlake (builtins.getEnv "CHASE_FLAKE_REF");
              lib = import ${pkgs.path}/lib;
            in
            if flake ? chaseModules && flake.chaseModules ? default
            then (lib.evalModules { modules = [ ${./options.nix} flake.chaseModules.default ]; }).config.chase
            else null'
      }

      # Goes on only if this result is the one approved for this checkout,
      # or a person approves it now.
      approve() {
        local ws=$1 result=$2 file previous diff
        file=$state/approved/$(key "$ws").json
        if [ -f "$file" ] && [ "$(jq -cS .envelope "$file")" = "$(jq -cS . <<< "$result")" ]; then
          return
        fi
        previous=null
        if [ -f "$file" ]; then previous=$(jq -c .envelope "$file"); fi
        diff=$(diff -u --label approved --label proposed \
          <(jq -S . <<< "$previous") <(jq -S . <<< "$result")) || true
        [ -n "$approver" ] \
          || die "$ws: its envelope has changed, and there is no chase.approver to ask"
        if ! jq -n --arg workspace "$ws" --argjson previous "$previous" \
            --argjson proposed "$result" --arg diff "$diff" \
            '{workspace: $workspace, previous: $previous, proposed: $proposed, diff: $diff}' \
            | "$approver"; then
          die "$ws: its envelope was not approved"
        fi
        mkdir -p "$state/approved"
        jq -n --arg workspace "$ws" --argjson envelope "$result" \
          '{workspace: $workspace, envelope: $envelope}' > "$file.new"
        mv "$file.new" "$file"
      }

      # The secret an app binds, decrypted where frisket reads it and the
      # session cannot: /run/user/<uid> is bound into no container.
      decrypt() {
        local ws=$1 secrets=$2 secret=$3 out=$4 file
        [ -n "$secrets" ] || die "$ws: a binding names secret '$secret', and chase.secrets names no file"
        file=$(realpath -e -- "$ws/$secrets") || die "$ws: $secrets does not exist"
        case $file in
          "$ws"/*) ;;
          *) die "$ws: $secrets is outside the checkout" ;;
        esac
        sops --decrypt --extract "[\"$secret\"]" "$file" > "$out" \
          || die "$ws: could not decrypt '$secret' from $secrets"
        [ -s "$out" ] || die "$ws: '$secret' in $secrets is empty"
      }

      launch() {
        local tier=$1 ws=$2 machine=$3 result run doc envfile app secret
        # Everything written here is the user's alone: decrypted secrets
        # above all.
        umask 077
        [ -d /run/user/$uid ] || die "/run/user/$uid does not exist: log in first"
        run=/run/user/$uid/chase/$machine
        envfile=$(env_dir "$ws")/env

        result=$(evaluate "$ws") || die "$ws: its chaseModules.default does not evaluate"
        if [ "$result" = null ]; then
          rm -f "$envfile"
          return
        fi
        approve "$ws" "$result"

        [ -d "/run/user/$uid/chase" ] || mkdir -m 0700 "/run/user/$uid/chase"
        mkdir -m 0700 "$run" "$run/secrets"
        doc=$(cat "/etc/frisket/policies/$tier.json")
        local exports=""
        for app in $(jq -r 'keys[]' "$apps"); do
          secret=$(jq -r --arg a "$app" '.bindings[$a].credential.secret // empty' <<< "$result")
          [ -n "$secret" ] || continue
          decrypt "$ws" "$(jq -r '.secrets // empty' <<< "$result")" "$secret" "$run/secrets/$app"
          # The app's route, with the project's credential, in place of any
          # route of the same name the tier had.
          doc=$(jq --slurpfile apps "$apps" --arg a "$app" --arg cred "$run/secrets/$app" '
            $apps[0][$a] as $p
            | .routes = ([.routes[]? | select(.name != $p.route.name)] + [$p.route + {credentialFile: $cred}])
            | if (.allow | index("*")) then . else .allow = (.allow + $p.allow | unique) end
          ' <<< "$doc")
          exports+=$(jq -nr --slurpfile apps "$apps" --arg a "$app" --argjson r "$result" '
            $apps[0][$a] as $p
            | ($p.env + ($p.envFromBinding | map_values($r.bindings[$a][.]) | with_entries(select(.value != null))))
            | to_entries[] | "export \(.key)=\(.value | @sh)"
          ')$'\n'
          echo "chase: $ws: $app from $(jq -r .secrets <<< "$result"):$secret" >&2
        done
        printf '%s\n' "$doc" > "$run/policy.json"
        mkdir -p "$(dirname "$envfile")"
        printf '%s' "$exports" > "$envfile.new"
        chmod 0644 "$envfile.new"
        mv "$envfile.new" "$envfile"
      }

      case ''${1-} in
        # binds: the checkout's environment directory, for the session to read.
        env-dir)
          dir=$(env_dir "$2")
          mkdir -p "$dir"
          printf '%s\n' "$dir"
          ;;
        # postStart, as the user.
        launch) launch "$2" "$3" "$4" ;;
        # frisket steer's -policy: the session's own document, or the tier's.
        policy)
          if [ -f "/run/user/$uid/chase/$3/policy.json" ]; then
            printf '%s\n' "/run/user/$uid/chase/$3/policy.json"
          else
            printf '%s\n' "/etc/frisket/policies/$2.json"
          fi
          ;;
        *) die "usage: chase-envelope env-dir WS | launch TIER WS MACHINE | policy TIER MACHINE" ;;
      esac
    '';
  };
in
{
  options.chase = {
    approver = mkOption {
      type = types.nullOr (types.strMatching "/.*");
      default = null;
      description = ''
        The program that asks a person to approve a checkout's envelope when
        what it evaluates to has changed (PLAN.md, decision 17). It runs as
        the user, from the launch, with one JSON document on stdin:
        `workspace`, `previous` (null the first time), `proposed`, and `diff`,
        a unified diff of the two. Exit 0 approves; anything else ends the
        launch. Null: a changed envelope is never approved.
      '';
    };

    internal.projectApps = mkOption {
      internal = true;
      default = { };
      type = types.attrsOf types.anything;
      description = ''
        What an app becomes when a project binds it: its frisket `route`, as
        the policy document holds one but for `credentialFile`; the names it
        adds to `allow`; the session's `env`; and `envFromBinding`, variables
        taken from the binding's other fields.
      '';
    };
  };

  config = {
    flong = lib.mapAttrs' (name: _: lib.nameValuePair "agent-${name}" {
      path = [ envelope ];
      # As root, dropping to the user for the part that is theirs: their
      # flake, their approval, their key.
      postStart = lib.mkOrder 400 ''
        setpriv --reuid=${toString cfg.uid} --regid=${toString cfg.gid} --init-groups -- \
          env HOME=${lib.escapeShellArg cfg.home} XDG_RUNTIME_DIR=/run/user/${toString cfg.uid} \
          chase-envelope launch ${name} "$workspace" "$machine"
      '';
      postStop = ''
        rm -rf -- "/run/user/${toString cfg.uid}/chase/$machine"
      '';
    }) tiers;

    services.frisket.flong = lib.mapAttrs' (name: _: lib.nameValuePair "agent-${name}" {
      policyFile = "$(chase-envelope policy ${name} \"$machine\")";
    }) tiers;

    chase.internal.tiers = lib.mapAttrs (name: _: {
      bindLines = [ ''${lib.getExe envelope} env-dir "$workspace"'' ];
      setupLines = [ ''
        chase_env=${cfg.home}/.local/state/chase/env/$(printf '%s' "$workspace" | sha256sum | cut -c1-32)/env
        if [ -r "$chase_env" ]; then
          # shellcheck disable=SC1090
          . "$chase_env"
        fi
      '' ];
    }) tiers;
  };
}
