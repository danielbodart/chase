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

  # GIT, ON THE HOST, OF A REPOSITORY A SESSION WROTE. chase-checkout and
  # agent-tier run as the user, unsandboxed, on every launch, against a
  # checkout whose .git -- config, HEAD, refs, objects, all of it -- a
  # session, the strict tier's included, may have written. A repository's
  # config names commands for git to run (core.fsmonitor on any read of
  # the index, hook.<name>.command, filter drivers, a pager, gpg.program,
  # core.sshCommand, credential.helper, and more with each release), and
  # files for it to read (include.path, objects/info/alternates). Turning
  # each off by name is a list that is never finished: hook.<name> and
  # filter.<name> are named by the repository.
  #
  # So git here never reads the repository's config at all. Every call is
  # this one, which shadows `git` (and runtimeInputs carry no other), so a
  # call added later is made the same way:
  #
  #   - no environment but its own: no GIT_* of the caller's, no system
  #     or global config (the user's own is not needed to sort a
  #     directory: only origin's URL and the root commits' authors are
  #     read, and neither takes anything from it), HOME an empty
  #     directory, no prompt, no lazy fetch, no optional locks, no
  #     replace objects, no pager;
  #
  #   - GIT_DIR an empty repository of its own in the store, not the
  #     checkout's: `git config --file F --no-includes` reads F and only
  #     F, and `git log` of a commit id resolved here reads the checkout's
  #     objects through GIT_OBJECT_DIRECTORY and nothing else of it --
  #     no config, index, hooks, attributes, grafts, replace refs, shallow
  #     file or promisor remote;
  #
  #   - every config-driven command git has for the reads made here
  #     overridden besides, for a call added later that reads more;
  #
  #   - bounded: objects a session wrote can be a delta cycle, or a zlib
  #     bomb, that git would chase with no end to its time or memory, and
  #     a config file can be sparse and a hundred gigabytes long. So each
  #     call has an address-space limit, small pack windows to fit it, and
  #     a timeout, and a call cut short is one that failed: nothing found,
  #     which falls to the fallback like any other miss.
  #
  # And what git is given to read is looked at first: a config file, a
  # ref or HEAD is read only as a plain file (not a link, not a pipe) no
  # larger than such a file ever is, and objects only where nothing in
  # them is a link and no alternates borrow any from elsewhere. Files read
  # here without git are held to the same sizes.
  emptyGit = format: pkgs.runCommand "chase-empty-git-${format}" { } ''
    mkdir -p $out/objects $out/refs
    echo 'ref: refs/heads/none' > $out/HEAD
    printf '[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tobjectFormat = %s\n' ${format} > $out/config
  '';
  gitSafely = ''
    git() { # [GIT_DIR=D] [GIT_OBJECT_DIRECTORY=D] [GIT_INDEX_FILE=F] ARG...
      local set=()
      while [[ ''${1-} == GIT_DIR=* || ''${1-} == GIT_OBJECT_DIRECTORY=* || ''${1-} == GIT_INDEX_FILE=* ]]; do set+=("$1"); shift; done
      # A hard limit already lower than this one cannot be raised, and
      # bounds git as well: failing to set it is not failing open.
      (ulimit -v 1048576 2>/dev/null || true
        cd / && exec env -i \
        PATH=${pkgs.git}/bin HOME=${emptyGit "sha1"} LC_ALL=C \
        GIT_DIR=${emptyGit "sha1"} GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_ATTR_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_NO_LAZY_FETCH=1 \
        GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 GIT_PAGER=cat PAGER=cat \
        "''${set[@]}" \
        ${pkgs.coreutils}/bin/timeout -k 1 20 \
        ${pkgs.git}/bin/git --no-pager --no-replace-objects \
          -c core.fsmonitor=false -c core.untrackedCache=false \
          -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null \
          -c core.pager=cat -c core.editor=false -c sequence.editor=false \
          -c core.askPass= -c credential.helper= -c core.sshCommand=false \
          -c core.gitProxy= -c core.alternateRefsCommand= -c protocol.allow=never \
          -c diff.external= -c log.showSignature=false -c gpg.program=false \
          -c gpg.ssh.program=false -c gpg.x509.program=false \
          -c log.mailmap=false -c mailmap.file= -c mailmap.blob= \
          -c uploadpack.packObjectsHook= -c gc.auto=0 -c maintenance.auto=false \
          -c core.packedGitWindowSize=16m -c core.packedGitLimit=128m \
          -c core.deltaBaseCacheLimit=32m -c core.bigFileThreshold=16m \
          "$@")
    }
    # A plain file: not a link, a pipe or a device, which git would follow
    # or wait on.
    regular() { [ -f "$1" ] && [ ! -L "$1" ]; }
    # A plain file of at most BYTES: a gitdir file, HEAD or a loose ref is
    # a line (4096), a config a few kilobytes (1048576), packed-refs a line
    # a ref (67108864). git itself caps a gitdir file.
    small() { # FILE BYTES
      regular "$1" && [ "$(stat -c %s -- "$1")" -le "$2" ]
    }
    # KEY: its values, in order, in each file git would read it from for
    # the repository at $gitdir (sharing $gitcommon) -- its config, and a
    # worktree's own config.worktree when the repository says it has one --
    # includes never followed: chase-checkout refuses a config with any.
    # Fails when one of them cannot be read.
    config_files() {
      printf '%s\n' "$gitcommon/config"
      if small "$gitcommon/config" 1048576 \
          && [ "$(git config --file "$gitcommon/config" --no-includes --type=bool --get extensions.worktreeConfig 2>/dev/null)" = true ]; then
        printf '%s\n' "$gitdir/config.worktree"
      fi
    }
    repo_config() {
      local f rc
      while IFS= read -r f; do
        if [ ! -e "$f" ] && [ ! -L "$f" ]; then continue; fi
        small "$f" 1048576 || return 2
        rc=0
        git config --file "$f" --no-includes --get-all "$1" || rc=$?
        [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ] || return 2
      done < <(config_files)
    }
  '';

  # WHICH CHECKOUT A DIRECTORY IS IN, found from where the directory really
  # is and never from what git says of it. git's answer is the repository's
  # to steer: core.worktree, a gitdir file, GIT_DIR and the rest all move
  # --show-toplevel, and any session can write its own checkout's
  # .git/config. A `checkouts` rule, and the workspace a launch mounts, both
  # stand on this answer, so it is a walk up from the resolved path to the
  # nearest .git, and a layout that would send git anywhere else is not
  # sorted at all -- a path cannot be forged only if nothing else is asked.
  #
  # Three kinds of redirection are let through, because they are how work
  # is done inside a checkout, and each is let through only in its own
  # shape, checked from both ends:
  #
  #   a linked worktree (`git worktree add`, Claude Code's
  #   .claude/worktrees/<name>): its .git is a file naming
  #   <common>/.git/worktrees/<name>, <common> is itself a checkout, and
  #   that gitdir shares <common>'s repository and names this .git back;
  #
  #   the same, of a bare repository (<bare>/worktrees/<name>, with <bare>
  #   holding core.bare = true), the layout some keep a checkout's
  #   worktrees side by side in;
  #
  #   a submodule: its .git is a file naming <super>/.git/modules/<path>,
  #   <super> is a checkout above it, and the one core.worktree git
  #   wrote there names this directory back.
  #
  # Where the repository is kept -- <common>, <bare>, <super> -- is the
  # rule's to judge: the selector asks it be the pinned checkout itself.
  # Anything else a .git file names is not sorted: a submodule of a linked
  # worktree among them (<common>/.git/worktrees/<name>/modules/<path>),
  # which is strict, a cost taken for a layout that would need a worktree
  # and a submodule each checked from both ends.
  #
  # Its config is read by no git but `git config --file --no-includes` of
  # each file, and one that includes another file is not sorted: what the
  # include says is not read, so what the repository means is not known.
  # Nor is one owned by someone else, as git itself refuses one.
  #
  # A directory with no .git of its own, inside one of the checkout's
  # submodules, is not sorted either: its session could write only that
  # submodule, and deleting its .git would otherwise leave a plain
  # directory of the checkout above it. The checkout's .gitmodules says
  # which paths are submodules -- read as a file, not from the index,
  # which git reads only with fsmonitor and the rest of its machinery --
  # and no session below the checkout can write it. A gitlink .gitmodules
  # does not list is not recognised: gutted, it is a directory of the
  # checkout, and the guard, asking the same question before a session
  # there starts, refuses that session a sandbox when the checkout's tier
  # is a bare one.
  #
  # Prints ROOT<TAB>HOLDER<TAB>KIND<TAB>GITCOMMON<TAB>GITDIR and succeeds,
  # or prints why the directory cannot be sorted and fails. HOLDER is the
  # checkout the repository is kept in, ROOT for a checkout of its own,
  # the bare repository for a bare one's worktree; KIND is checkout,
  # worktree or submodule; GITCOMMON is the repository's own directory,
  # GITDIR this checkout's (its HEAD, its config.worktree).
  #
  # --ignoring ROOT asks what the directory would be with ROOT's own .git
  # gone, which is what a session there could make it by deleting it.

  checkout = pkgs.writeShellApplication {
    name = "chase-checkout";
    runtimeInputs = with pkgs; [ coreutils ];
    text = ''
      export LC_ALL=C
      ${gitSafely}
      unsortable() {
        printf '%s\n' "$1"
        exit 1
      }

      # The caller's environment can point git anywhere, and a project's
      # .envrc could set it: said, rather than silently ignored, since the
      # agent would be started into it. The git asked here never sees it.
      redirects=()
      for v in GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
               GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS; do
        if [ -n "''${!v+set}" ]; then redirects+=("$v"); fi
      done
      [ ''${#redirects[@]} -eq 0 ] || unsortable "git is redirected by the environment: ''${redirects[*]}"

      ignoring=""
      if [ "''${1-}" = --ignoring ]; then
        ignoring=$(realpath -e -- "$2" 2>/dev/null) || unsortable "no such directory"
        shift 2
      fi
      abs=$(realpath -e -- "''${1-$PWD}" 2>/dev/null) || unsortable "no such directory"

      # The nearest .git, of whatever kind: which kind is decided below.
      root=$abs
      until { [ -e "$root/.git" ] || [ -L "$root/.git" ]; } && [ "$root" != "$ignoring" ]; do
        [ "$root" != / ] || unsortable "not a git repository"
        root=$(dirname -- "$root")
      done
      case $root in
        *$'\t'* | *$'\n'*) unsortable "a checkout whose path has a tab or a newline" ;;
      esac
      dotgit=''${root%/}/.git

      # A gitdir's own file naming another -- commondir, or the gitdir
      # back-pointer -- read as git reads it: relative to that gitdir.
      names() { # GITDIR FILE: where GITDIR/FILE points, resolved, or nothing
        local to
        small "$1/$2" 4096 || return 0
        to=$(head -n 1 -- "$1/$2" 2>/dev/null) || return 0
        [[ $to == /* ]] || to=$1/$to
        realpath -e -- "$to" 2>/dev/null || true
      }
      # The one core.worktree a submodule may carry; none for anything else.
      allowed_worktree=""
      kind=checkout
      if [ -L "$dotgit" ]; then
        unsortable "$dotgit is a symbolic link"
      elif [ -d "$dotgit" ]; then
        gitdir=$dotgit common=$root gitcommon=$dotgit
        # A commondir file makes a .git directory a worktree's in disguise.
        [ ! -e "$gitdir/commondir" ] && [ ! -L "$gitdir/commondir" ] \
          || unsortable "$dotgit shares another repository (commondir)"
      elif regular "$dotgit"; then
        small "$dotgit" 4096 || unsortable "$dotgit is too large to be a gitdir file"
        line=$(head -n 1 -- "$dotgit")
        [[ $line == "gitdir: "* ]] || unsortable "$dotgit is a file that names no gitdir"
        target=''${line#gitdir: }
        [[ $target == /* ]] || target=$root/$target
        gitdir=$(realpath -e -- "$target" 2>/dev/null) \
          || unsortable "$dotgit points at $target, which does not exist"
        [ -d "$gitdir" ] || unsortable "$dotgit points at $gitdir, which is not a directory"
        if [[ $gitdir =~ ^(/.*)/\.git/worktrees/[^/]+/modules/.+$ ]]; then
          unsortable "$dotgit is a submodule of a worktree of ''${BASH_REMATCH[1]}, which is not sorted"
        elif [[ $gitdir =~ ^(/.*)/\.git/modules/.+/worktrees/[^/]+$ ]]; then
          unsortable "$dotgit is a worktree of a submodule of ''${BASH_REMATCH[1]}, which is not sorted"
        elif [[ $gitdir =~ ^(/.*)/\.git/worktrees/[^/]+$ ]]; then
          kind=worktree common=''${BASH_REMATCH[1]} gitcommon=''${BASH_REMATCH[1]}/.git
          { [ -d "$gitcommon" ] && [ ! -L "$gitcommon" ] && [ ! -e "$gitcommon/commondir" ]; } \
            || unsortable "$dotgit is a worktree of $common, which is not a checkout"
        elif [[ $gitdir =~ ^(/.*)/\.git/modules/.+$ ]]; then
          kind=submodule common=''${BASH_REMATCH[1]} gitcommon=$gitdir
          { [ -d "$common/.git" ] && [ ! -L "$common/.git" ] && [ ! -e "$common/.git/commondir" ]; } \
            || unsortable "$dotgit is a submodule of $common, which is not a checkout"
          [[ $root == "$common"/* ]] \
            || unsortable "$dotgit is a submodule of $common, which is not above it"
          [ ! -e "$gitdir/commondir" ] && [ ! -L "$gitdir/commondir" ] \
            || unsortable "$gitdir shares another repository (commondir)"
          # git writes core.worktree into a submodule's gitdir itself, to
          # name the directory it is checked out in: one, and this one.
          small "$gitdir/config" 1048576 || unsortable "$gitdir/config is not a plain file of a config's size"
          allowed_worktree=$(git config --file "$gitdir/config" --no-includes --get-all core.worktree 2>/dev/null) || allowed_worktree=""
          { [ -n "$allowed_worktree" ] && [[ $allowed_worktree != *$'\n'* ]]; } \
            || unsortable "$gitdir does not name one directory it is checked out in"
          to=$allowed_worktree
          [[ $to == /* ]] || to=$gitdir/$to
          [ "$(realpath -e -- "$to" 2>/dev/null)" = "$root" ] \
            || unsortable "$gitdir is checked out in $allowed_worktree, not $root"
        elif [[ $gitdir =~ ^(/.*)/worktrees/[^/]+$ ]] && small "''${BASH_REMATCH[1]}/config" 1048576 \
            && [ "$(git config --file "''${BASH_REMATCH[1]}/config" --no-includes --type=bool --get core.bare 2>/dev/null)" = true ]; then
          kind=worktree common=''${BASH_REMATCH[1]} gitcommon=''${BASH_REMATCH[1]}
          { [ -d "$common/objects" ] && [ -e "$common/HEAD" ] && [ ! -e "$common/commondir" ]; } \
            || unsortable "$dotgit is a worktree of $common, which is not a repository of its own"
        else
          unsortable "$dotgit points at $gitdir, which is not a worktree's or a submodule's"
        fi
        if [ "$kind" = worktree ]; then
          [ "$(names "$gitdir" commondir)" = "$gitcommon" ] \
            || unsortable "$gitdir does not share $gitcommon"
          [ "$(names "$gitdir" gitdir)" = "$dotgit" ] \
            || unsortable "$gitdir belongs to $(small "$gitdir/gitdir" 4096 && head -n 1 -- "$gitdir/gitdir" 2>/dev/null || echo nothing), not $dotgit"
        fi
      else
        unsortable "$dotgit is neither a directory nor a gitdir file"
      fi

      # Owned by the user, as git itself insists (safe.directory): a
      # checkout someone else can write is theirs to sort.
      me=$(id -u)
      for d in "$root" "$dotgit" "$gitdir" "$gitcommon"; do
        [ "$(stat -c %u -- "$d")" = "$me" ] || unsortable "$d is owned by someone else"
      done

      # The layout is a checkout's. Its configuration can still send git
      # elsewhere: core.worktree, beyond the one a submodule is allowed, in
      # the repository's config or a worktree's config.worktree. Each file
      # is read alone and must say all it means itself: one that includes
      # another is not sorted, since that other is not read.
      while IFS= read -r f; do
        if [ ! -e "$f" ] && [ ! -L "$f" ]; then continue; fi
        regular "$f" || unsortable "$f is not a plain file"
        small "$f" 1048576 || unsortable "$f is too large to be a config"
        git config --file "$f" --no-includes --list >/dev/null 2>&1 \
          || unsortable "$f cannot be read"
        if git config --file "$f" --no-includes --name-only --get-regexp '^include(if)?\.' >/dev/null 2>&1; then
          unsortable "$f includes another file"
        fi
      done < <(config_files)
      worktree=$(repo_config core.worktree 2>/dev/null) || unsortable "the config of $root cannot be read"
      if [ -n "$worktree" ] && [ "$worktree" != "$allowed_worktree" ]; then
        unsortable "core.worktree sends git to ''${worktree//$'\n'/, }"
      fi

      # A directory below the root: not inside a submodule of it, as the
      # root's .gitmodules lists them.
      if [ "$abs" != "$root" ] && { [ -e "$root/.gitmodules" ] || [ -L "$root/.gitmodules" ]; }; then
        regular "$root/.gitmodules" || unsortable "$root/.gitmodules is not a plain file"
        small "$root/.gitmodules" 1048576 || unsortable "$root/.gitmodules is too large to be read"
        git config --file "$root/.gitmodules" --no-includes --list >/dev/null 2>&1 \
          || unsortable "$root/.gitmodules cannot be read"
        rel=''${abs#"''${root%/}"/}
        while IFS= read -r -d "" entry; do
          path=''${entry#*$'\n'}
          path=''${path#./}
          path=''${path%/}
          [ -n "$path" ] || continue
          case $rel in
            "$path" | "$path"/*)
              unsortable "$abs is inside $root/$path, a submodule with no .git of its own" ;;
          esac
        done < <(git config --file "$root/.gitmodules" --no-includes -z --get-regexp '^submodule\..*\.path$' 2>/dev/null || true)
      fi

      printf '%s\t%s\t%s\t%s\t%s\n' "$root" "$common" "$kind" "$gitcommon" "$gitdir"
    '';
  };

  # WHERE A CHECKOUT SAYS IT CAME FROM, for what names it by its origin
  # rather than sorts it: chase-envelope, which names a checkout's Docker
  # project. The checkout is chase-checkout's, found from where the directory
  # is, and its origin is read as agent-tier reads it, from the config files
  # alone by gitSafely's git, never by a git that reads the checkout's config
  # itself. Every URL is printed, not the first, since a checkout with two
  # names none of them.
  #
  # Prints ROOT<TAB>HOLDER<TAB>KIND<TAB>GITCOMMON, as chase-checkout gives
  # them, then each of origin's URLs on a line of its own, and succeeds; or
  # prints why the directory cannot be sorted, or its config read, and fails.
  # A URL git would read with a newline in it is two lines, which is not one
  # URL either.
  origin = pkgs.writeShellApplication {
    name = "chase-origin";
    runtimeInputs = [ checkout ] ++ (with pkgs; [ coreutils ]);
    text = ''
      export LC_ALL=C
      ${gitSafely}
      [ $# -eq 1 ] || { echo "usage: chase-origin DIR"; exit 2; }
      out=$(chase-checkout "$1") || { printf '%s\n' "''${out:-cannot find its checkout}"; exit 1; }
      IFS=$'\t' read -r root common kind gitcommon gitdir <<< "$out"
      # The dot keeps a last URL that is empty, which $(...) would drop.
      urls=$(repo_config remote.origin.url 2>/dev/null && echo .) \
        || { printf 'the config of %s cannot be read\n' "$root"; exit 1; }
      printf '%s\t%s\t%s\t%s\n%s' "$root" "$common" "$kind" "$gitcommon" "''${urls%.}"
    '';
  };

  # WHAT A CHECKOUT TRACKS, for what copies it: chase-envelope's snapshot.
  # `git ls-files` in the checkout would read its config, and with it
  # core.fsmonitor, a command git runs on any read of the index -- on the
  # host, as the user, before anything is approved. So the checkout is
  # chase-checkout's, found from where the directory is, and its index is
  # read by gitSafely's git in the empty repository of the checkout's
  # object format, GIT_INDEX_FILE naming a copy of the index and nothing
  # else of the checkout named at all: no config, no hooks, no work tree.
  # A copy, taken once without following a link or waiting on a pipe,
  # because git reads a split index's shared part from beside the index
  # it is given, which a session could make anything. An index that needs
  # more than itself -- that shared part, or a sparse index's trees, whose
  # directories git would otherwise drop from the list without a word --
  # fails.
  #
  # Prints the tracked paths at or below DIR, relative to DIR, each ended
  # by a NUL, and succeeds; or prints why they cannot be read and fails. A
  # checkout with no index yet tracks nothing.
  lsFiles = pkgs.writeShellApplication {
    name = "chase-ls-files";
    runtimeInputs = [ checkout ] ++ (with pkgs; [ coreutils ]);
    text = ''
      export LC_ALL=C
      ${gitSafely}
      [ $# -eq 1 ] || { echo "usage: chase-ls-files DIR"; exit 2; }
      out=$(chase-checkout "$1") || { printf '%s\n' "''${out:-cannot find its checkout}"; exit 1; }
      IFS=$'\t' read -r root _ _ gitcommon gitdir <<< "$out"
      abs=$(realpath -e -- "$1")
      if [ "$abs" = "$root" ]; then prefix=""; else prefix=''${abs#"''${root%/}"/}/; fi
      index=$gitdir/index
      if [ ! -e "$index" ] && [ ! -L "$index" ]; then exit 0; fi
      # An index is some hundred bytes a tracked file; 256MiB is well over
      # a million of them.
      small "$index" 268435456 || { printf '%s is not a plain file of an index'"'"'s size\n' "$index"; exit 1; }
      format=$(repo_config extensions.objectFormat 2>/dev/null) \
        || { printf 'the config of %s cannot be read\n' "$root"; exit 1; }
      case ''${format:-sha1} in
        sha1) empty=${emptyGit "sha1"} ;;
        sha256) empty=${emptyGit "sha256"} ;;
        *) printf '%s has an object format of %s\n' "$root" "$format"; exit 1 ;;
      esac
      tmp=$(mktemp -d)
      trap 'rm -rf -- "$tmp"' EXIT
      # Swapped since it was looked at, a link is not followed and a pipe
      # not waited on; grown since, it is cut short, and git refuses what
      # is left.
      timeout 20 dd if="$index" of="$tmp/index" iflag=nofollow,nonblock bs=1M count=257 status=none 2>/dev/null \
        && [ "$(stat -c %s -- "$tmp/index")" -le 268435456 ] \
        || { printf '%s cannot be copied\n' "$index"; exit 1; }
      # The empty repository never sets index.sparse, so git always
      # expands a sparse index to list it, from trees that repository does
      # not have: it says so on stderr, drops what is under them, and
      # succeeds. Anything it says is therefore the guard, and a failure.
      git GIT_DIR="$empty" GIT_INDEX_FILE="$tmp/index" ls-files -z --cached > "$tmp/list" 2> "$tmp/said" \
        || { printf 'the index of %s cannot be read on its own, as a split index cannot\n' "$root"; exit 1; }
      [ ! -s "$tmp/said" ] || { printf 'the index of %s is sparse, or cannot be read on its own\n' "$root"; exit 1; }
      while IFS= read -r -d "" p; do
        case $p in
          "$prefix"*) printf '%s\0' "''${p#"$prefix"}" ;;
        esac
      done < "$tmp/list"
    '';
  };

  # Prints a directory's tier; --dry-run DIR... explains, one line each.
  agentTier = pkgs.writeShellApplication {
    name = "agent-tier";
    runtimeInputs = [ checkout ] ++ (with pkgs; [ coreutils findutils gnugrep ]);
    text = ''
      # What is read, and how bash matches it, is not the caller's locale's.
      export LC_ALL=C
      # What the rule being asked has found, and why the rules asked so far
      # did not hold: --dry-run's reasons. A predicate that does not hold for
      # a reason worth telling -- not "some other path" -- says it with miss.
      found=()
      misses=()
      miss() {
        if [ -n "''${1-}" ]; then misses+=("$1"); fi
        return 1
      }

      # The checkout the directory is in, found once and only if a rule
      # needs it, by chase-checkout: from where the directory is, not from
      # what git says. What it cannot sort, no rule that asks git can place.
      need_checkout() {
        if [ -z "$checkout_state" ]; then
          local out
          if out=$(chase-checkout ''${ignoring:+--ignoring "$ignoring"} "$dir"); then
            IFS=$'\t' read -r root common kind gitcommon gitdir <<< "$out"
            checkout_state=ok
          else
            checkout_state=''${out:-cannot find its checkout}
          fi
        fi
        [ "$checkout_state" = ok ] || miss "$checkout_state"
      }

      # git, asked only as gitSafely asks it: never of the checkout's own
      # config, and never with the caller's environment.
      ${gitSafely}

      need_origin() {
        need_checkout || return 1
        if [ -z "$origin_state" ]; then
          # origin's first URL, as `git remote get-url` gives it, read from
          # the config files alone; the user's url.<base>.insteadOf is not
          # applied, and needs not be: owner/repo is parsed from either.
          local remote
          if ! remote=$(repo_config remote.origin.url 2>/dev/null); then
            origin_state="cannot read the config of $root"
          elif remote=''${remote%%$'\n'*}; [ -z "$remote" ]; then
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

      # The checkout at the path, or a worktree or submodule of it under
      # the path, as .claude/worktrees are: the repository has to be kept
      # in the checkout at the path itself, or in its .bare. Not merely
      # somewhere under it: a repository nested inside, a clone or a
      # submodule, has its own session, which can write its own .git and
      # would claim the path's remote the moment it did.
      in_checkout() {
        need_origin || return 1
        local s p
        while IFS=$'\t' read -r s p; do
          [ "$s" = "$slug" ] || continue
          case $root in
            "$p" | "$p"/*) ;;
            *) miss "$slug is declared at $p, not $root"; return 1 ;;
          esac
          if [ "$common" != "$p" ] && [ "$gitcommon" != "$p/.bare" ]; then
            if [ "$common" = "$root" ]; then
              miss "$root is a checkout of its own, not $p"
            else
              miss "$root is a $kind of $common, not of $p"
            fi
            return 1
          fi
          if [ "$common" = "$root" ]; then
            found+=("$slug at $p")
          else
            found+=("$slug at $p, a $kind of $common")
          fi
          return 0
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

      # The commit HEAD names, resolved here rather than by git, which would
      # read the checkout's config to find it: HEAD in the checkout's own
      # gitdir, a branch in refs/heads/ or packed-refs of the repository,
      # each a plain file inside it. A branch is any name git would give
      # one, as git itself checks it. Prints the commit, or fails printing
      # why HEAD was not read -- nothing when there is simply no commit.
      head_commit() {
        local ref=HEAD file line o name
        for _ in 1 2 3 4 5; do
          if [ "$ref" = HEAD ]; then
            file=$gitdir/HEAD
          elif [[ $ref == refs/heads/?* ]] && git check-ref-format "$ref" >/dev/null 2>&1; then
            file=$gitcommon/$ref
          else
            printf 'HEAD names %q, which is not a branch that is read\n' "$ref"
            return 1
          fi
          line=""
          if [ -e "$file" ] || [ -L "$file" ]; then
            if ! small "$file" 4096 || [ "$(realpath -e -- "$file")" != "$file" ]; then
              printf '%s is not a plain file the size of a ref, so HEAD is not read\n' "$file"
              return 1
            fi
            IFS= read -r line < "$file" || [ -n "$line" ] || return 1
            if [[ $line == "ref: "* ]]; then ref=''${line#ref: }; continue; fi
          elif [ "$ref" != HEAD ] && [ -e "$gitcommon/packed-refs" ]; then
            if ! small "$gitcommon/packed-refs" 67108864; then
              printf '%s is not a plain file of a size that is read\n' "$gitcommon/packed-refs"
              return 1
            fi
            while read -r o name; do
              if [ "$name" = "$ref" ]; then line=$o; break; fi
            done < <(grep -F -e " $ref" -- "$gitcommon/packed-refs" || true)
          fi
          [[ $line =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || return 1
          printf '%s\n' "$line"
          return 0
        done
        echo "HEAD names refs through more than five links, which are not followed"
        return 1
      }

      # Every root commit, since a history can have more than one. A shallow
      # clone's first commit is its boundary, not the real root. The
      # commits are read from the repository's objects alone, by a git
      # whose repository is otherwise an empty one of its own.
      first_commit_by() {
        need_checkout || return 1
        if [ -e "$gitcommon/shallow" ] || [ -L "$gitcommon/shallow" ]; then
          miss "shallow clone, first commit unknowable"; return 1
        fi
        local refs format empty objects oid authors author domain
        refs=$(repo_config extensions.refStorage 2>/dev/null) || refs=unreadable
        refs=''${refs##*$'\n'}
        [ -z "$refs" ] || [ "$refs" = files ] || { miss "refs kept as $refs, which is not read"; return 1; }
        format=$(repo_config extensions.objectFormat 2>/dev/null) || format=unreadable
        format=''${format##*$'\n'}
        case ''${format:-sha1} in
          sha1) empty=${emptyGit "sha1"} ;;
          sha256) empty=${emptyGit "sha256"} ;;
          *) miss "objects kept as $format, which are not read"; return 1 ;;
        esac
        objects=$gitcommon/objects
        { [ -d "$objects" ] && [ ! -L "$objects" ]; } || { miss "no objects to read"; return 1; }
        if [ -e "$objects/info/alternates" ] || [ -L "$objects/info/alternates" ]; then
          miss "objects borrowed from elsewhere (alternates), which are not read"; return 1
        fi
        if [ -n "$(find -P "$objects" ! -type f ! -type d -print -quit)" ]; then
          miss "objects that are links or pipes, which are not read"; return 1
        fi
        if ! oid=$(head_commit); then
          [ -z "$oid" ] || { miss "$oid"; return 1; }
        fi
        authors=""
        if [ -n "$oid" ]; then
          authors=$(git GIT_DIR="$empty" GIT_OBJECT_DIRECTORY="$objects" \
            log --no-mailmap --max-parents=0 --format=%ae "$oid" -- 2>/dev/null) \
            || { miss "the history of $oid cannot be read"; return 1; }
        fi
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
        checkout_state="" origin_state="" root="" common="" kind="" gitcommon="" gitdir="" slug="" owner=""
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

      # --if-gone DIR: DIR's tier were its own .git deleted, as a session
      # working in DIR could. The guard asks it of a sandbox's workspace.
      ignoring=""
      if [ "''${1-}" = --if-gone ]; then
        ignoring=$2
        decide "$2" | cut -f1
      elif [ "''${1-}" = --dry-run ]; then
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
  #
  # `chase docker`: where a checkout's containers are published, as the
  # tier it would run in has them, for use from the host.
  chase = pkgs.writeShellApplication {
    name = "chase";
    runtimeInputs = [ agentTier cfg.internal.envelope ];
    text = ''
      usage() {
        echo "usage: chase shell [ARG...]   a shell where an agent would run in this checkout" >&2
        echo "       chase docker [DIR]     where this checkout's Docker containers are reached" >&2
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
        docker)
          [ $# -le 1 ] || usage
          dir=''${1-$PWD}
          tier=$(agent-tier "$dir" 2>/dev/null) || tier=${q fallback}
          exec chase-envelope docker "$dir" "$tier"
          ;;
        *) usage ;;
      esac
    '';
  };
in
{
  options.chase.internal = {
    agentTier = mkOption { type = types.package; readOnly = true; internal = true; };
    checkout = mkOption { type = types.package; readOnly = true; internal = true; };
    origin = mkOption { type = types.package; readOnly = true; internal = true; };
    lsFiles = mkOption { type = types.package; readOnly = true; internal = true; };
    mkWrapper = mkOption { type = types.raw; readOnly = true; internal = true; };
  };

  config = {
    chase.internal = { inherit agentTier checkout origin lsFiles mkWrapper; };

    # A consistency check, not a gate: the launcher runs as the caller, who
    # could run it with any workspace, or run bwrap without it. It catches
    # the wrapper and the launcher disagreeing about a checkout -- a launcher
    # started by hand, or a checkout whose remote changed since the wrapper
    # sorted it -- before a session is built around the wrong tier. What
    # gates a checkout's own changes to its session is chase.approver.
    #
    # Not the fallback's: it is where anything the selector could not place
    # goes, so it takes any checkout. The one refusal below is everyone's.
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

        # A checkout the rules would put in another tier with its own .git
        # gone -- one nested in a checkout of that tier, not a submodule of
        # it -- is refused a sandbox: its session could delete that .git,
        # and its next launch would be that tier's, with the checkout above
        # it mounted. Tiers have no order of privilege to say which way is
        # up, so any change is refused but one to the fallback, which is
        # where anything unsorted goes already. This one is a gate, and
        # every sandbox's, the fallback's too: it guards against the
        # session, which cannot reach the launcher, not against the caller.
        if [ -e "$workspace/.git" ] || [ -L "$workspace/.git" ]; then
          now=$(agent-tier "$workspace") || now=${q fallback}
          gone=$(agent-tier --if-gone "$workspace") || gone=unknown
          if [ "$gone" != "$now" ] && [ "$gone" != ${q fallback} ]; then
            echo ${q "agent-${name}"}": refusing, $workspace is nested in a '$gone' checkout, and would be '$gone' without its .git, not '$now'; clone it elsewhere, or make it a submodule" >&2
            exit 1
          fi
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
