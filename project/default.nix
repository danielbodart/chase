# A project's envelope, applied at launch (PLAN.md, decisions 7, 10, 11, 17).
#
# For a tier that takes envelopes, each launch:
#
#   binds          makes the checkout's environment directory, bound read-only
#   seccompPolicy  before the session is built: evaluates the checkout's
#                  `chaseModules.default` against ./options.nix; asks
#                  `chase.approver` if the result is not the one last
#                  approved for this checkout; stages the approved result for
#                  this launch's postStart, and prints its syscall
#                  loosenings for flong
#   postStart      before frisket's steps: decrypts the secrets the staged
#                  result binds into /run/user/<uid>/chase/<machine>/; runs
#                  each bound app's `prepare`; writes the session's policy
#                  document there, and its environment beside the checkout's
#   frisket        steers the session under that document, or the tier's own
#   postStop       runs each app's `stop`; removes
#                  /run/user/<uid>/chase/<machine>/ and anything staged for it
#
# All of it runs as the user who launched: a launcher has no privilege of its
# own (PLAN.md, decision 2). The approval is split from the rest because a
# syscall filter is installed before anything in the session runs, so what
# loosens it has to be known, and approved, before flong starts bwrap.
#
# A checkout with no flake, or a flake with no `chaseModules.default`, is the
# tier as it is. Anything that goes wrong on the way ends the launch: an
# envelope is applied whole or the session does not start.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types;
  cfg = config.chase;
  tiers = lib.filterAttrs (_: t: t.envelope) cfg.tiers;

  # An app with no credential is made from its binding alone, which only a
  # `prepare` can do: one without is refused here rather than at a launch.
  apps = pkgs.writeText "chase-project-apps.json" (builtins.toJSON (lib.mapAttrs (name: app:
    if (app.credential or true) == false && (app.prepare or null) == null
    then throw "chase.internal.projectApps.${name} has no credential and no prepare, so nothing could be made of its binding"
    else app) cfg.internal.projectApps));
  stops = lib.filter (s: s != null) (lib.mapAttrsToList (_: a: a.stop or null) cfg.internal.projectApps);

  # Every tier's pinned checkouts, as the selector holds them: each
  # owner/repo, lower-cased, and every path any tier pins it at. What names a
  # checkout's Docker project is held to these both ways (`project`, below).
  checkouts = pkgs.writeText "chase-checkouts.json" (builtins.toJSON (
    lib.zipAttrsWith (_: paths: lib.unique (lib.sort lib.lessThan paths))
      (lib.concatMap (t: lib.concatMap (rule: lib.mapAttrsToList (s: p: { ${lib.toLower s} = p; }) rule.checkouts) t.match)
        (lib.attrValues cfg.tiers))));

  # The tiers apps/docker.nix gives Docker, which it asserts take envelopes.
  dockerTiers = lib.attrNames (lib.filterAttrs (_: t: !t.bare && (t.apps.docker.enable or false)) tiers);

  # A flong hook is a command, never shell: one that needs a shell is a
  # script of its own, under the options flong's snippets once ran with. It
  # finds chase-envelope on the PATH flong gives it, from `path`, and reads
  # $workspace and $machine from its environment.
  hookScript = name: text: "${pkgs.writeShellScript "chase-${name}" ''
    set -euo pipefail
    ${text}
  ''}";
  approver = if cfg.approver == null then "" else cfg.approver;

  # What copies a checkout's tracked files into a snapshot, following no
  # link: see ./copy-tracked.py.
  copyTracked = pkgs.writers.writePython3Bin "chase-copy-tracked" { } (builtins.readFile ./copy-tracked.py);

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
    runtimeInputs = [ copyTracked cfg.internal.lsFiles cfg.internal.origin cfg.package ]
      ++ (with pkgs; [ nix jq sops coreutils diffutils gnugrep gnused util-linux ]);
    text = ''
      uid=${toString cfg.uid}
      home=${lib.escapeShellArg cfg.home}
      # Where chase keeps what it approved, where a launch leaves what it
      # stages, which of a project's names the host's /etc/hosts carries,
      # and where the tiers' own policy documents are: one line each, so a
      # test can put them elsewhere.
      state=$home/.local/state/chase
      runtime=/run/user/$uid
      hosts=/etc/chase/docker-hosts.json
      policies=/etc/frisket/policies
      # The tiers a project's Docker is routed in.
      docker_tiers=${lib.escapeShellArg (toString dockerTiers)}
      checkouts=${checkouts}
      apps=${apps}
      lists=${./lists.jq}
      merge=${./merge.jq}
      normal=${./normal.jq}
      approver=${lib.escapeShellArg approver}

      # A checkout's key: its path, hashed, so a path with anything in it is
      # still one plain file name.
      key() { local h; h=$(printf '%s' "$1" | sha256sum); printf '%s' "''${h:0:32}"; }

      env_dir() { printf '%s/env/%s' "$state" "$(key "$1")"; }

      # What is said can carry what a session wrote -- a path in its
      # checkout -- so no control byte but a newline reaches the terminal:
      # an escape sequence there could retitle it, redraw what the person
      # is reading, or write their clipboard. That is C0 and DEL, and C1
      # too, both as UTF-8 (\302\200-\302\237) and as the raw bytes
      # (\200-\237) a terminal not reading UTF-8 acts on. The raw bytes are
      # also continuations of other UTF-8 characters, which come out
      # mangled: a refusal read wrong is better than one that writes.
      say() {
        printf 'chase: %s\n' "$*" \
          | LC_ALL=C sed 's/\xc2[\x80-\x9f]/?/g' \
          | LC_ALL=C tr '\000-\011\013-\037\177-\237' '?' >&2
      }
      die() { say "$@"; exit 1; }

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

      # The approver's own output goes to stderr: under seccompPolicy,
      # stdout is the policy flong reads.
      ask() {
        local kind=$1 ws=$2 diff=$3
        [ -n "$approver" ] \
          || die "$ws: its $kind has changed, and there is no chase.approver to ask"
        jq -n --arg kind "$kind" --arg workspace "$ws" --arg diff "$diff" \
          '{kind: $kind, workspace: $workspace, diff: $diff}' | "$approver" >&2 \
          || die "$ws: its $kind was not approved"
      }

      # The checkout's tracked files, as they are now, in a directory of the
      # user's own that no session sees. Copied by chase-copy-tracked, which
      # follows no link at any component: anything that opens WS/dir/f by
      # its path, as tar did, lets the kernel resolve dir, so a tracked
      # dir/f whose dir a session has made a link to a host directory would
      # copy that host's f into what is evaluated and decrypted. A check for
      # such a link before and after the copy is no better, since another
      # live session of the same checkout can swap it in and back between.
      #
      # Which files are tracked is read by chase-ls-files, from the index
      # alone: never by a git in the checkout, whose config a session
      # writes, and which runs what core.fsmonitor names on any read of the
      # index -- here as the user, unsandboxed, before anyone is asked.
      snapshot() {
        local ws=$1 src=$2 list why
        list=$(mktemp)
        if ! chase-ls-files "$ws" > "$list"; then
          why=$(tr -d '\0' < "$list")
          rm -f -- "$list"
          die "$ws: an envelope needs a git checkout, so what is evaluated is what git tracks: $why"
        fi
        why=$(chase-copy-tracked "$ws" "$src" < "$list") || {
          rm -f -- "$list"
          die "$ws: ''${why:-its tracked files could not be copied}"
        }
        rm -f -- "$list"
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
          previous=$(jq -c -f "$normal" "$dir/envelope.json")
          [ "$(jq -cS . <<< "$previous")" != "$(jq -cS . <<< "$result")" ] || return 0
        fi
        diff=$(diff -u --label approved --label proposed \
          <(jq -S . <<< "$previous") <(jq -S . <<< "$result")) || true
        ask "envelope" "$ws" "$diff"
        mkdir -p "$dir"
        printf '%s\n' "$result" > "$dir/envelope.json.new"
        mv "$dir/envelope.json.new" "$dir/envelope.json"
      }

      # The secret an app binds, decrypted from the staged copy of the sops
      # file -- whose digest was approved -- where frisket reads it and the
      # session cannot: /run/user/<uid> is bound into no container.
      decrypt() {
        local ws=$1 file=$2 secret=$3 out=$4
        [ -n "$file" ] || die "$ws: a binding names secret '$secret', and chase.secrets names no file"
        sops --decrypt --extract "[\"$secret\"]" "$file" > "$out" \
          || die "$ws: could not decrypt '$secret'"
        [ -s "$out" ] || die "$ws: '$secret' is empty"
      }

      # Where seccompPolicy leaves an approved result for postStart: one file
      # per launch, named for the session flong gives both, under
      # /run/user/<uid>/chase, which no session sees. Per launch and not per
      # checkout, so two launches of one checkout approved at once each get
      # their own. A machine name never starts with a dot.
      staged() { printf '%s/chase/.envelope/%s.json' "$runtime" "$1"; }

      # A CHECKOUT'S DOCKER PROJECT (docs/docker.md, decision 9): the
      # owner/repo its origin names on GitHub. It decides which containers, volumes and
      # networks a session may touch, and at which address, so it is derived
      # here, from the checkout, and never taken from anything the envelope
      # says: the session writes that, and would name itself as another
      # project to reach its database.
      #
      # The checkout is chase-checkout's, found from where the directory
      # is, and its origin read by chase-origin as the selector reads it: git
      # here never reads a checkout's own config, which its session wrote
      # and which can name a command for git to run. Its root is that one,
      # never git's --show-toplevel, which core.worktree moves.
      #
      # Held both ways to the checkouts the tiers pin: a pinned project only
      # at its own path, and a pinned path only as its own project. And, as
      # the selector's in_checkout holds it, only from the repository kept at
      # that path itself or in its .bare: a clone nested under the path has
      # a session of its own, which writes its own .git, origin included. A
      # project no tier pins is a claim, shown in the approval, which a
      # person approves.
      #
      # TIER is not read yet: it is taken so that a tier can say more of a
      # project later without the call changing.
      project() { # WS TIER -> owner/repo on stdout, or die
        local LC_ALL=C ws=$1 out lines root common kind gitcommon url owner repo slug s p hit=""
        out=$(chase-origin "$ws" && echo .) || die "$ws: Docker needs a checkout, and this one cannot be sorted: $out"
        mapfile -t lines < <(printf '%s' "''${out%.}")
        IFS=$'\t' read -r root common kind gitcommon <<< "''${lines[0]}"
        [ "''${#lines[@]}" -eq 2 ] \
          || die "$ws: Docker needs exactly one origin URL, so its project has a name, and it has $((''${#lines[@]} - 1))"
        url=''${lines[1]%/}
        url=''${url%.git}
        if [[ $url =~ ^git@github\.com:([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)$ ]]; then
          owner=''${BASH_REMATCH[1]} repo=''${BASH_REMATCH[2]}
        elif [[ $url =~ ^(https://|ssh://git@)github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)$ ]]; then
          owner=''${BASH_REMATCH[2]} repo=''${BASH_REMATCH[3]}
        else
          die "$ws: origin $url is not github.com/owner/repo, so it names no project"
        fi
        owner=''${owner,,} repo=''${repo,,}
        case $repo in
          . | ..) die "$ws: origin $url names no repository" ;;
        esac
        slug=$owner/$repo
        while IFS=$'\t' read -r s p; do
          p=$(realpath -m -- "$p")
          case $root in
            "$p" | "$p"/*) ;;
            *) continue ;;
          esac
          [ "$s" = "$slug" ] || die "$ws: $root is under $p, where $s is pinned, but its origin says $slug"
          if [ "$common" != "$p" ] && [ "$gitcommon" != "$p/.bare" ]; then
            die "$ws: $root is under $p, where $slug is pinned, but is a $kind of $common, not of $p"
          fi
          hit=1
        done < <(jq -r 'to_entries[] | .key as $s | .value[] | "\($s)\t\(.)"' "$checkouts")
        if [ -z "$hit" ] && jq -e --arg s "$slug" 'has($s)' "$checkouts" >/dev/null; then
          die "$ws: its origin says $slug, which is pinned at $(jq -r --arg s "$slug" '.[$s] | join(", ")' "$checkouts"), not $root"
        fi
        chase docker-address "$slug" >/dev/null || die "$ws: $slug is not a project frisket can route"
        printf '%s\n' "$slug"
      }

      # NO TWO PROJECTS AT ONE ADDRESS (I10). The address is a hash of the
      # project's name, and 24 bits can be searched in seconds for a repo
      # name that lands on another project's: an approval saying `Docker as
      # evil/x at 127.101.170.171` would not be compared with shop's by
      # anyone. So an address is first come on this host: the projects
      # already approved here ($state/docker/addresses.json, which only this
      # writes, and from which nothing is ever removed but by hand), those
      # the tiers pin, and those whose names the host's /etc/hosts carries,
      # read as data. The directory is locked, not the file, since the file
      # is replaced whole.
      #
      # `check` refuses before anyone is asked; `record` checks again, once
      # the envelope is approved, and remembers the project: one that was
      # refused approval holds no address.
      claim() { # WS SLUG ADDRESS check|record
        local ws=$1 slug=$2 addr=$3 dir=$state/docker file held s a other
        file=$dir/addresses.json
        mkdir -p "$dir"
        exec 9<"$dir"
        flock 9
        [ -e "$file" ] || printf '{}\n' > "$file"
        held=$(jq -r 'to_entries[] | "\(.key)\t\(.value | strings)"' "$file") || die "$ws: $file cannot be read"
        if [ -e "$hosts" ]; then
          held+=$'\n'$(jq -r 'to_entries[] | "\(.key)\t\(.value.address | strings)"' "$hosts") || die "$ws: $hosts cannot be read"
        fi
        while IFS= read -r s; do
          a=$(chase docker-address "$s" 2>/dev/null) || continue
          held+=$'\n'$s$'\t'$(jq -r .address <<< "$a")
        done < <(jq -r 'keys[]' "$checkouts")
        while IFS=$'\t' read -r other a; do
          if [ -n "$other" ] && [ "''${other,,}" != "$slug" ] && [ "$a" = "$addr" ]; then
            die "$ws: $slug would be at $addr, which $other already holds"
          fi
        done <<< "$held"
        if [ "$4" = record ] && [ "$(jq -r --arg s "$slug" '.[$s] // empty' "$file")" != "$addr" ]; then
          jq --arg s "$slug" --arg a "$addr" '. + {($s): $a}' "$file" > "$file.new"
          mv -- "$file.new" "$file"
        fi
        exec 9<&-
      }

      # What the approval is read beside (3.8): the project, its address,
      # its names in a session, and its ports. The names are the session's,
      # which frisket answers. On the host a name is one only where
      # /etc/chase/docker-hosts.json, which nix-config writes with
      # /etc/hosts, gives it this project at this address: read as a file,
      # never looked up, since a name /etc/hosts lacks goes to the upstream
      # resolver, which a hostile network answers.
      host_names() { # WS SLUG ADDRESS-JSON -> the names the host has, as JSON
        local ws=$1 slug=$2 who=$3
        if [ -e "$hosts" ]; then
          jq -c --arg s "$slug" --argjson who "$who" '
            (.[$s] // {}) as $e
            | if ($e | type) == "object" and $e.address == $who.address then [$who.names[] | select(. as $x | any($e.names[]?; . == $x))] else [] end
          ' "$hosts" || die "$ws: $hosts cannot be read"
        else
          printf '[]\n'
        fi
      }

      docker_line() { # WS SLUG ADDRESS-JSON RESULT
        local ws=$1 slug=$2 who=$3 result=$4 addr names ports host line
        addr=$(jq -r .address <<< "$who")
        names=$(jq -r '.names | if . == [] then "no names" else join(", ") end' <<< "$who")
        ports=$(jq -r '.bindings.docker.ports // [] | if . == [] then "no ports" else "ports " + (map(tostring) | join(" ")) end' <<< "$result")
        host=$(host_names "$ws" "$slug" "$who") || exit 1
        line="$ws: Docker as $slug at $addr ($names), $ports"
        if [ "$host" = "[]" ]; then
          line+="; on this host, $addr only"
        elif [ "$host" != "$(jq -c .names <<< "$who")" ]; then
          line+="; on this host, $addr and $(jq -r 'join(", ")' <<< "$host") only"
        fi
        # The workspace is a path, which a session can name: said as die
        # says it.
        say "$line"
      }

      # `chase docker`: where a checkout's containers are, for a person to
      # read on the host. Its project and address, the names a session
      # answers, which of them this host's /etc/hosts carries (as
      # docker_line reads it), and the ports last approved for this project:
      # an approval of the checkout as another project, before its origin
      # changed, approved none of this one's. A tier without Docker still
      # has the address, since nix-config names it whatever the tier.
      docker() { # WS TIER
        local ws=$1 tier=$2 slug who addr root result host
        slug=$(project "$ws" "$tier") || exit 1
        who=$(chase docker-address "$slug") || die "$ws: $slug has no address"
        addr=$(jq -r .address <<< "$who")
        printf '%s\n  address  %s\n' "$slug" "$addr"
        case " $docker_tiers " in
          *" $tier "*) ;;
          *) printf '  (no Docker on %s)\n' "$tier"; return ;;
        esac
        printf '  session  %s\n' "$(jq -r '.names | if . == [] then "(none)" else join(" ") end' <<< "$who")"
        host=$(host_names "$ws" "$slug" "$who") || exit 1
        printf '  host     %s\n' "$(jq -r 'if . == [] then "(address only; not in this host'"'"'s /etc/hosts)" else join(" ") end' <<< "$host")"
        root=$(chase-origin "$ws") || die "$ws: its checkout cannot be sorted: $root"
        root=''${root%%$'\t'*}
        result=null
        if [ -f "$state/approved/$(key "$root")/envelope.json" ]; then
          result=$(jq -c . "$state/approved/$(key "$root")/envelope.json") || die "$ws: its approved envelope cannot be read"
        fi
        printf '  ports    %s\n' "$(jq -r --arg s "$slug" '
          [if .dockerProject? == $s then .bindings.docker.ports // [] | .[] | numbers else empty end]
          | if . == [] then "(none approved)" else "\(map(tostring) | join(" "))   (approved)" end' <<< "$result")"
      }

      # seccompPolicy: snapshot, approve, evaluate, approve, stage. Prints
      # the approved `allow` and `deny` lines, and nothing else, on stdout.
      approve() {
        local ws=$1 machine=$2 tier=$3 result dir secrets file="" stage out twice slug="" who addr=""
        exec 3>&1 1>&2
        umask 077
        [ -n "$machine" ] || die "no machine: flong names the session before seccompPolicy runs"
        [ -n "$tier" ] || die "no tier: the tier's seccompPolicy names it"
        [ -d "$runtime" ] || die "$runtime does not exist: log in first"
        # 0700, by the umask.
        [ -d "$runtime/chase/.envelope" ] || mkdir -p "$runtime/chase/.envelope"
        stage=$(staged "$machine")
        # Only a flake that says chaseModules is looked at at all: any other
        # is the tier as it is, and is never evaluated or asked about.
        if [ ! -f "$ws/flake.nix" ] || ! grep -q chaseModules "$ws/flake.nix"; then
          printf 'null\n' > "$stage.$$" && mv "$stage.$$" "$stage"
          return
        fi
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
          printf 'null\n' > "$stage.$$" && mv "$stage.$$" "$stage"
          return
        fi
        result=$(jq -c -f "$normal" <<< "$result")
        # What chase derives and adds below is never the envelope's to say:
        # a project module can declare options of its own under chase, and
        # one naming dockerProject would otherwise stand, unchecked, where
        # there is no Docker binding to derive it.
        result=$(jq -c 'del(.dockerProject, .secretsSHA256)' <<< "$result")
        # One name in two of an app's lists says two things: refused before
        # anyone is asked to approve it.
        twice=$(jq -r '.bindings | to_entries[] | .key as $app
          | [.value | (.allow, .ask, .refuse) // [] | unique[]] | group_by(.) | map(select(length > 1)[0])[]
          | "\($app): \(tojson)"' <<< "$result")
        [ -z "$twice" ] || die "$ws: named in two lists: $twice"
        secrets=$(jq -r '.secrets // empty' <<< "$result")
        if [ -n "$secrets" ]; then
          file=$(realpath -e -- "$src/$secrets") || die "$ws: $secrets is not a tracked file"
          case $file in
            "$src"/*) ;;
            *) die "$ws: $secrets is outside the checkout" ;;
          esac
          result=$(jq --arg d "$(sha256sum < "$file" | cut -d' ' -f1)" '. + {secretsSHA256: $d}' <<< "$result")
        fi
        # Docker, as the project the checkout's origin names, which is part
        # of what is approved: a changed origin is asked about again. An
        # envelope without Docker gains nothing, so one approved before
        # there was Docker still is.
        if jq -e '.bindings.docker != null' <<< "$result" >/dev/null; then
          slug=$(project "$ws" "$tier")
          who=$(chase docker-address "$slug") || die "$ws: $slug has no address"
          addr=$(jq -r .address <<< "$who")
          claim "$ws" "$slug" "$addr" check
          result=$(jq -c --arg p "$slug" '. + {dockerProject: $p}' <<< "$result")
          docker_line "$ws" "$slug" "$who" "$result"
        fi
        approve_envelope "$ws" "$result" "$dir"
        [ -z "$slug" ] || claim "$ws" "$slug" "$addr" record

        # What postStart applies is what was approved, with the snapshot's
        # sops file beside it: not the checkout, which a session may be
        # changing.
        if [ -n "$file" ]; then
          jq --rawfile s "$file" --arg n "$(basename -- "$file")" \
            '{result: ., secrets: {name: $n, text: $s}}' <<< "$result" > "$stage.$$"
        else
          jq '{result: ., secrets: null}' <<< "$result" > "$stage.$$"
        fi
        mv "$stage.$$" "$stage"

        out=$(jq -r '
          .seccomp // {} | (select(.allow? // [] | length > 0) | "allow \(.allow | join(" "))"),
                           (select(.deny? // [] | length > 0) | "deny \(.deny | join(" "))")
        ' <<< "$result")
        [ -z "$out" ] || printf '%s\n' "$out" >&3
      }

      # postStart: what seccompPolicy staged for this launch, applied.
      launch() {
        local tier=$1 ws=$2 machine=$3 stage staged_doc result run doc envfile app secret dir file="" secrets
        local binding prepare patch from docker_project
        # Everything written here is the user's alone: decrypted secrets
        # above all.
        umask 077
        envfile=$(env_dir "$ws")/env
        stage=$(staged "$machine")
        [ -f "$stage" ] || die "$ws: nothing was approved for this launch: the tier's seccompPolicy did not run"
        staged_doc=$(cat "$stage")
        rm -f -- "$stage"
        if [ "$staged_doc" = null ]; then
          rm -f "$envfile"
          return
        fi
        result=$(jq -c .result <<< "$staged_doc")
        secrets=$(jq -r '.secrets // empty' <<< "$result")
        run=$runtime/chase/$machine
        mkdir -m 0700 "$run" "$run/secrets"
        if [ -n "$secrets" ]; then
          dir=$(mktemp -d "$run/sops.XXXXXX")
          file=$dir/$(jq -r .secrets.name <<< "$staged_doc")
          jq -j .secrets.text <<< "$staged_doc" > "$file"
          [ "$(sha256sum < "$file" | cut -d' ' -f1)" = "$(jq -r .secretsSHA256 <<< "$result")" ] \
            || die "$ws: the staged $secrets is not the one approved"
        fi

        doc=$(cat "$policies/$tier.json")
        # The Docker project approve derived and staged, which is what was
        # approved: read, never derived again here. A prepare is given it,
        # and the session is not.
        docker_project=$(jq -r '.dockerProject // empty' <<< "$result")
        local exports=""
        for app in $(jq -r 'keys[]' "$apps"); do
          binding=$(jq -c --arg a "$app" '.bindings[$a] // empty' <<< "$result")
          [ -n "$binding" ] || continue
          prepare=$(jq -r --arg a "$app" '.[$a].prepare // empty' "$apps")
          # An app with a credential is bound only with the project's own,
          # decrypted; one with none is made by its prepare from the binding
          # alone. Not `.credential // true`: jq's // takes false as absent.
          if [ "$(jq -r --arg a "$app" '.[$a].credential != false' "$apps")" = true ]; then
            secret=$(jq -r '.credential.secret // empty' <<< "$binding")
            [ -n "$secret" ] || continue
            decrypt "$ws" "$file" "$secret" "$run/secrets/$app"
            from=$secrets:$secret
          else
            [ -n "$prepare" ] || die "$ws: $app has no credential and no prepare"
            from="no credential"
          fi
          # The app's routes, in place of any of the same names the tier had:
          # what its `prepare` made of the binding, or its own with the
          # project's credential.
          patch=$run/$app.patch.json
          if [ -n "$prepare" ]; then
            printf '%s\n' "$binding" \
              | chase_project=$docker_project "$prepare" "$tier" "$ws" "$run" "$(env_dir "$ws")" > "$patch" \
              || die "$ws: $app could not be prepared"
          else
            jq -c --arg a "$app" --arg tier "$tier" --arg cred "$run/secrets/$app" '
              .[$a] | {routes: [.routes[$tier] // empty | arrays // [.] | .[] | . + {credentialFile: $cred}], allow}
            ' "$apps" > "$patch"
          fi
          doc=$(jq --slurpfile patch "$patch" -f "$merge" <<< "$doc")
          exports+=$(jq -nr --slurpfile apps "$apps" --arg a "$app" --argjson r "$result" --slurpfile patch "$patch" '
            $apps[0][$a] as $p
            | (($p.env // {}) + ($patch[0].env // {})
               + ($p.envFromBinding // {} | map_values($r.bindings[$a][.]) | with_entries(select(.value != null))))
            | to_entries[] | "export \(.key)=\(.value | @sh)"
          ')$'\n'
          rm -f -- "$patch"
          echo "chase: $ws: $app from $from" >&2
        done
        [ -z "$file" ] || rm -rf -- "$(dirname -- "$file")"
        # What the project names in each app's lists, applied to the app's
        # route in this tier: one with the project's credential or the
        # tier's. Not to an app the tier does not have, or has anonymously
        # -- with no credential, and no one to ask for someone else's code --
        # which is said rather than refused (decision 8).
        for app in $(jq -r '.bindings // {} | to_entries[] | select([.value | (.allow, .ask, .refuse) // [] | length] | add > 0) | .key' <<< "$result"); do
          case $(jq -r --arg a "$app" '[.routes[]? | select(.name == $a)][0] | if . == null then "absent" elif .credentialFile then "bound" else "anonymous" end' <<< "$doc") in
            absent) echo "chase: $ws: $app's lists ignored: $tier has no $app" >&2; continue ;;
            anonymous) echo "chase: $ws: $app's lists ignored: $app is anonymous in $tier" >&2; continue ;;
          esac
          doc=$(jq --arg app "$app" --argjson lists "$(jq -c --arg a "$app" '.bindings[$a] | {allow, ask, refuse} | map_values(. // [])' <<< "$result")" \
            -f "$lists" <<< "$doc") || die "$ws: its $app lists do not apply"
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
          [ -d "$dir" ] || mkdir -p "$dir"
          printf '%s\n' "$dir"
          ;;
        # seccompPolicy: the approval, and the policy's lines.
        approve) approve "$2" "''${3:-}" "''${4:-}" ;;
        # A checkout's Docker project, as approve derives it.
        project) [ $# -eq 3 ] || die "usage: chase-envelope project WS TIER"; project "$2" "$3" ;;
        # `chase docker`: the checkout's project, address, names and ports.
        docker) [ $# -eq 3 ] || die "usage: chase-envelope docker WS TIER"; docker "$2" "$3" ;;
        # postStart: the approved envelope, applied.
        launch) launch "$2" "$3" "$4" ;;
        # frisket steer's -policy: the session's own document, or the tier's.
        policy)
          if [ -f "$runtime/chase/$3/policy.json" ]; then
            printf '%s\n' "$runtime/chase/$3/policy.json"
          else
            printf '%s\n' "$policies/$2.json"
          fi
          ;;
        *) die "usage: chase-envelope env-dir WS | approve WS MACHINE TIER | launch TIER WS MACHINE | policy TIER MACHINE | project WS TIER | docker WS TIER" ;;
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

    # chase-envelope, for `chase docker` on the host.
    internal.envelope = mkOption { type = types.package; readOnly = true; internal = true; };

    internal.projectApps = mkOption {
      internal = true;
      default = { };
      type = types.attrsOf types.anything;
      description = ''
        What an app becomes when a project binds it: its frisket `routes`, by
        tier, each a route or a list of them as the policy document holds
        one but for `credentialFile`; the names it adds to `allow`; the
        session's `env`; and `envFromBinding`, variables taken from the
        binding's other fields.

        Or, for an app whose routes are made at launch, `prepare`: a program
        run in postStart once the secret is at RUN/secrets/<app>, as
        `prepare TIER WORKSPACE RUN ENVDIR` with the approved binding on
        stdin, printing `{routes, allow, env}`; and `stop`, run in postStop
        as `stop MACHINE` before RUN is removed, to release what `prepare`
        started. `prepare` has `chase_project` in its environment: the
        Docker project approved for the checkout, or empty if its envelope
        binds no Docker.

        `credential`, true by default, says the app is bound only with the
        project's secret, named by the binding's `credential.secret`, and
        not at all without one. False: the app has no credential, its
        `prepare` -- which it must have -- is run from the binding alone,
        whenever the binding says anything, and nothing is decrypted.
      '';
    };
  };

  config = {
    flong = lib.mapAttrs' (name: _: lib.nameValuePair "agent-${name}" {
      path = [ envelope ];
      # After the guard, before bwrap: the filter is fixed before anything in
      # the session runs, so this is where the envelope is approved.
      seccompPolicy = [ [ (hookScript "agent-${name}-seccomp-policy" ''
        chase-envelope approve "$workspace" "$machine" ${name}
      '') ] ];
      postStart = lib.mkOrder 400 [ [ (hookScript "agent-${name}-poststart" ''
        chase-envelope launch ${name} "$workspace" "$machine"
      '') ] ];
      postStop = [ [ (hookScript "agent-${name}-poststop" ''
        ${lib.concatMapStrings (stop: ''
          ${stop} "$machine" || true
        '') stops}
        rm -rf -- "/run/user/${toString cfg.uid}/chase/$machine" \
          "/run/user/${toString cfg.uid}/chase/.envelope/$machine.json"
      '') ] ];
    }) tiers;

    services.frisket.flong = lib.mapAttrs' (name: _: lib.nameValuePair "agent-${name}" {
      policyFile = "$(chase-envelope policy ${name} \"$machine\")";
    }) tiers;

    # Where a session's own document is written, which frisket reads from.
    services.frisket.policyRoots = lib.mkIf (tiers != { }) [ "/run/user/${toString cfg.uid}/chase" ];

    chase.internal.envelope = envelope;

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
