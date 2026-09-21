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

  # WHAT EVALUATES AN ENVELOPE: a flake of chase's, in the store, whose one
  # input is the checkout -- given on the command line, never spliced into Nix
  # source -- evaluated PURELY. The checkout is the agent's to edit, and this
  # runs before anyone has approved anything: pure evaluation is what keeps
  # an envelope to its own source and locked inputs, rather than able to read
  # any file of the user's and fetch a URL with it in. nixpkgs' lib comes
  # along as a copy, so the flake needs nothing it does not carry.
  evaluator = pkgs.runCommand "chase-envelope-evaluator" { } ''
    mkdir -p "$out/nixpkgs"
    cp -r ${pkgs.path}/lib "$out/nixpkgs/lib"
    cp ${pkgs.path}/.version "$out/nixpkgs/.version"
    cp ${./options.nix} "$out/options.nix"
    cat > "$out/flake.nix" <<'EOF'
    {
      inputs.project.url = "path:/nonexistent";
      outputs = { project, ... }: {
        envelope =
          let lib = import ./nixpkgs/lib; in
          if project ? chaseModules && project.chaseModules ? default
          then (lib.evalModules { modules = [ ./options.nix project.chaseModules.default ]; }).config.chase
          else null;
      };
    }
    EOF
  '';

  envelope = pkgs.writeShellApplication {
    name = "chase-envelope";
    runtimeInputs = with pkgs; [ nix jq sops coreutils diffutils git gnutar gnugrep ];
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

      # ASK, THEN RUN. Nothing of the checkout's is evaluated until a person
      # has approved the bytes that decide what evaluating it reaches: its
      # flake.nix and flake.lock, which alone declare and pin its inputs.
      # Approving what an envelope evaluates to could not be enough on its
      # own, because evaluating a flake resolves its inputs first -- and an
      # input can be any path of the user's, or any URL.
      #
      # All of it is done on a SNAPSHOT: the checkout's tracked files, copied
      # once. What is compared, shown, evaluated and decrypted is that copy,
      # so a session of the same checkout still running cannot change a file
      # between the approval and its use.

      ask() {
        local kind=$1 ws=$2 diff=$3
        [ -n "$approver" ] \
          || die "$ws: its $kind has changed, and there is no chase.approver to ask"
        jq -n --arg kind "$kind" --arg workspace "$ws" --arg diff "$diff" \
          '{kind: $kind, workspace: $workspace, diff: $diff}' | "$approver" \
          || die "$ws: its $kind was not approved"
      }

      # The checkout's tracked files, as they are now, in a directory of the
      # user's own that no session sees.
      snapshot() {
        local ws=$1 src=$2
        git -C "$ws" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
          || die "$ws: an envelope needs a git checkout, so what is evaluated is what git tracks"
        git -C "$ws" ls-files -z --cached \
          | tar -C "$ws" --null --no-recursion -T - -cf - \
          | tar -C "$src" -xf -
        [ -f "$src/flake.nix" ] && [ ! -L "$src/flake.nix" ] \
          || die "$ws: flake.nix is not a tracked file"
        [ ! -L "$src/flake.lock" ] || die "$ws: flake.lock is a link"
      }

      # Inputs that are files on this machine are refused: the lock names
      # them, but what they hold is not in anything that was approved.
      local_inputs() {
        local src=$1
        [ -f "$src/flake.lock" ] || return 0
        jq -r '
          .nodes | to_entries[] | .value as $n
          | [$n.locked?, $n.original?] | map(select(. != null))[]
          | select(.type == "path" or (.url? // "" | test("^(file:|git\\+file:|path:)")) or has("parent"))
          | "input: \(.path? // .url? // "a relative path")"
        ' "$src/flake.lock" | sort -u
      }

      # Stage one: the flake's own two files, against the copies approved.
      approve_source() {
        local ws=$1 src=$2 dir=$3 diff="" f
        for f in flake.nix flake.lock; do
          if ! cmp -s "$src/$f" "$dir/$f" 2>/dev/null \
             && ! { [ ! -e "$src/$f" ] && [ ! -e "$dir/$f" ]; }; then
            diff+=$(diff -u --label "approved/$f" --label "$f" \
              "$( [ -e "$dir/$f" ] && echo "$dir/$f" || echo /dev/null)" \
              "$( [ -e "$src/$f" ] && echo "$src/$f" || echo /dev/null)")$'\n' || true
          fi
        done
        [ -n "$diff" ] || return 0
        ask "flake" "$ws" "$diff"
        mkdir -p "$dir"
        for f in flake.nix flake.lock; do
          if [ -e "$src/$f" ]; then cp -- "$src/$f" "$dir/$f.new" && mv "$dir/$f.new" "$dir/$f"; else rm -f "$dir/$f"; fi
        done
      }

      # The chase section, evaluated purely from the snapshot against
      # ./options.nix only: an option that is not there is an error, not a
      # setting applied somewhere else. No nixConfig, no lock written, no
      # import-from-derivation.
      # Nix's own chatter -- the project input it was told to use is not in
      # the evaluator's lock, which is the point -- is kept unless it fails.
      evaluate() {
        local src=$1 log
        log=$(mktemp)
        if ! nix eval --json --no-write-lock-file --option accept-flake-config false \
            --option allow-import-from-derivation false \
            --extra-experimental-features 'nix-command flakes' \
            "path:${evaluator}#envelope" --override-input project "path:$src" 2> "$log"; then
          cat "$log" >&2
          rm -f "$log"
          return 1
        fi
        rm -f "$log"
      }

      # Stage two: what it evaluated to. The flake's files are approved by
      # now, but the chase section can import others, so a change to what it
      # says is asked about too.
      approve_envelope() {
        local ws=$1 result=$2 dir=$3 previous=null diff
        if [ -f "$dir/envelope.json" ]; then
          previous=$(jq -c . "$dir/envelope.json")
          [ "$(jq -cS . <<< "$previous")" != "$(jq -cS . <<< "$result")" ] || return 0
        fi
        diff=$(diff -u --label approved --label proposed \
          <(jq -S . <<< "$previous") <(jq -S . <<< "$result")) || true
        ask "envelope" "$ws" "$diff"
        mkdir -p "$dir"
        printf '%s\n' "$result" > "$dir/envelope.json.new"
        mv "$dir/envelope.json.new" "$dir/envelope.json"
      }

      # The secret an app binds, decrypted from the snapshot's copy of the
      # sops file -- whose digest was approved -- where frisket reads it and
      # the session cannot: /run/user/<uid> is bound into no container.
      decrypt() {
        local ws=$1 file=$2 secret=$3 out=$4
        [ -n "$file" ] || die "$ws: a binding names secret '$secret', and chase.secrets names no file"
        sops --decrypt --extract "[\"$secret\"]" "$file" > "$out" \
          || die "$ws: could not decrypt '$secret'"
        [ -s "$out" ] || die "$ws: '$secret' is empty"
      }

      launch() {
        local tier=$1 ws=$2 machine=$3 result run doc envfile app secret secrets dir file="" refused unknown
        # Everything written here is the user's alone: decrypted secrets
        # above all.
        umask 077
        envfile=$(env_dir "$ws")/env
        # Only a flake that says chaseModules is looked at at all: any other
        # is the tier as it is, and is never evaluated or asked about.
        if [ ! -f "$ws/flake.nix" ] || ! grep -q chaseModules "$ws/flake.nix"; then
          rm -f "$envfile"
          return
        fi
        [ -d /run/user/$uid ] || die "/run/user/$uid does not exist: log in first"
        [ -d "/run/user/$uid/chase" ] || mkdir -m 0700 "/run/user/$uid/chase"
        run=/run/user/$uid/chase/$machine
        mkdir -m 0700 "$run" "$run/secrets"
        dir=$state/approved/$(key "$ws")

        mkdir -p "$home/.cache/chase"
        src=$(mktemp -d "$home/.cache/chase/snapshot.XXXXXX")
        trap 'rm -rf -- "$src"' EXIT
        snapshot "$ws" "$src"
        refused=$(local_inputs "$src")
        [ -z "$refused" ] || die "$ws: its flake has inputs that are files on this machine, which an envelope may not: $refused"

        approve_source "$ws" "$src" "$dir"
        result=$(evaluate "$src") || die "$ws: its chaseModules.default does not evaluate"
        if [ "$result" = null ]; then
          rm -f "$envfile"
          return
        fi
        secrets=$(jq -r '.secrets // empty' <<< "$result")
        if [ -n "$secrets" ]; then
          file=$(realpath -e -- "$src/$secrets") || die "$ws: $secrets is not a tracked file"
          case $file in
            "$src"/*) ;;
            *) die "$ws: $secrets is outside the checkout" ;;
          esac
          result=$(jq --arg d "$(sha256sum < "$file" | cut -d' ' -f1)" '. + {secretsSHA256: $d}' <<< "$result")
        fi
        approve_envelope "$ws" "$result" "$dir"

        doc=$(cat "/etc/frisket/policies/$tier.json")
        local exports=""
        for app in $(jq -r 'keys[]' "$apps"); do
          secret=$(jq -r --arg a "$app" '.bindings[$a].credential.secret // empty' <<< "$result")
          [ -n "$secret" ] || continue
          decrypt "$ws" "$file" "$secret" "$run/secrets/$app"
          # The project's allow-list: every operation id it names must be one
          # the route has, so a typo is an error rather than a rule that
          # silently allows nothing.
          unknown=$(jq -nr --slurpfile apps "$apps" --arg a "$app" --argjson r "$result" '
            ([$apps[0][$a].route.paths[].operation.id? // empty]) as $ids
            | ($r.bindings[$a].allow // [])[] | strings | select(. as $x | $ids | index($x) | not)
          ')
          [ -z "$unknown" ] || die "$ws: $app allows operations it does not have: $unknown"
          # The app's route, with the project's credential and allow-list, in
          # place of any route of the same name the tier had.
          doc=$(jq --slurpfile apps "$apps" --arg a "$app" --arg cred "$run/secrets/$app" --argjson r "$result" '
            $apps[0][$a] as $p
            | ($r.bindings[$a].allow // []) as $allow
            | ($allow | map(strings)) as $ids
            | ($p.route
                | .paths = ([.paths[] | if ((.operation.id? // "") as $id | $ids | index($id)) then .ask = false else . end]
                    + [$allow[] | objects | {methods, path, ask: false}]))
              as $route
            | .routes = ([.routes[]? | select(.name != $route.name)] + [$route + {credentialFile: $cred}])
            | if (.allow | index("*")) then . else .allow = (.allow + $p.allow | unique) end
          ' <<< "$doc")
          exports+=$(jq -nr --slurpfile apps "$apps" --arg a "$app" --argjson r "$result" '
            $apps[0][$a] as $p
            | ($p.env + ($p.envFromBinding | map_values($r.bindings[$a][.]) | with_entries(select(.value != null))))
            | to_entries[] | "export \(.key)=\(.value | @sh)"
          ')$'\n'
          echo "chase: $ws: $app from $secrets:$secret" >&2
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
        the user, from the launch, with one JSON document on stdin: `kind`,
        `workspace` and `diff`. `kind` is `flake` -- the checkout's flake.nix
        or flake.lock changed, and nothing of it has run yet -- or `envelope`,
        what its chase section evaluates to changed; `diff` is unified. Exit 0
        approves; anything else ends the launch. Null: nothing is approved.
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

    # Where a session's own document is written, which frisket reads from.
    services.frisket.policyRoots = lib.mkIf (tiers != { }) [ "/run/user/${toString cfg.uid}/chase" ];

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
