# chase's entry point. Curried on `self` so it can import flong's and
# frisket's modules from its own inputs: a consumer imports chase and gets
# all three, rather than having to know that frisket's adapter goes in and
# frisket's own module does not.
self:
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types;
  cfg = config.chase;
  # Every tier that is a container. A bare one is only a name the selector
  # can answer with.
  sandboxes = lib.filterAttrs (_: t: !t.bare) cfg.tiers;
  operations = import ./lib/operations.nix { inherit lib; };
  lines = builtins.concatStringsSep "\n";
  chomp = lib.removeSuffix "\n";
  indent = s: lines (map (l: if l == "" then l else "  " + l) (lib.splitString "\n" s));

  # flong's `binds`: the other members of every group the workspace is in, one
  # PATH:rw per line (a bare PATH would be read-only). Not transitive. Each
  # member's list is worked out here, sorted and without repeats, so a launch
  # only looks its workspace up and checks what exists, in builtins.
  groupPeers = lib.foldl'
    (acc: group: lib.foldl'
      (acc: m: acc // { ${m} = (acc.${m} or [ ]) ++ lib.filter (o: o != m) group; })
      acc
      group)
    { }
    cfg.workspaceGroups;
  groupBinds = lib.optionalString (groupPeers != { }) ''
    case $workspace in
    ${indent (lines (lib.mapAttrsToList (m: peers: ''
      ${lib.escapeShellArg m})
        for m in ${lib.escapeShellArgs (lib.unique (lib.sort lib.lessThan (map (o: "${o}:rw") peers)))}; do
          if [ -d "''${m%:rw}" ]; then printf '%s\n' "$m"; fi
        done
        ;;'') groupPeers))}
    esac
  '';

  # The checkout's root, so all of it is mounted wherever you start; otherwise
  # the directory itself, which only a `paths` rule can place. git's
  # answer and not a walk up to .git: a gitdir file, GIT_DIR, core.worktree
  # and safe.directory all change it.
  workspaceSnippet = ''
    ${lib.getExe pkgs.git} -C "$PWD" rev-parse --show-toplevel 2>/dev/null || pwd
  '';

  # A flong hook is a command, never shell: one that needs a shell is a
  # script of its own, under the options flong's snippets once ran with.
  hookScript = name: text: "${pkgs.writeShellScript "chase-${name}" ''
    set -euo pipefail
    ${text}
  ''}";

  # flong's `command`: runs in the container as the user, in the workspace,
  # and execs the agent named by the first argument.
  mkCommand = tier: contributions: pkgs.writeShellApplication {
    name = "agent-command-${tier}";
    text = ''
      workspace=$PWD

      ${lines (map chomp contributions.setupLines)}

      if [ $# -eq 0 ]; then
        echo "agent-container: no agent named" >&2
        exit 1
      fi
      agent=$1
      shift

      # Group mounts are passed to the agent as --add-dir. Only :rw ones:
      # codex's --add-dir means writable. Not ~/.claude, which is storage.
      add_dirs=()
      while IFS= read -r bind; do
        case $bind in
          ${cfg.home}/.claude/*) ;;
          *:rw) add_dirs+=("''${bind%:rw}") ;;
        esac
      done <<< "''${FLONG_BINDS:-}"

      # A closed list, so this cannot exec anything else on the container's PATH.
      case $agent in
        # `chase shell`: the session as an agent gets it, with no agent.
        shell)
          set -- bash -l "$@"
          ;;
      ${indent (lines (map chomp (lib.attrValues contributions.launchers)))}
        *)
          echo "agent-container: unknown agent '$agent'" >&2
          exit 1
          ;;
      esac

      exec "$@"
    '';
  };

  # "owner/name", as a remote URL carries it. Narrow because selector.nix
  # parses every entry as one, and a malformed slug would otherwise sit in the
  # configuration matching nothing until the day you wondered why. Compared
  # lower-cased, as the selector lower-cases the remote's.
  slug = types.strMatching "[^/[:space:]]+/[^/[:space:]]+";
  absPath = types.strMatching "/.*";

  # WHAT PUTS A CHECKOUT IN A TIER. Each predicate is one question the
  # selector can ask of a directory, and says nothing about how far its answer
  # should be believed: that is the tier's author's to judge. A path is the
  # one signal a checkout cannot forge; a remote, an owner and the author of a
  # first commit are all strings any checkout can claim.
  ruleType = types.submodule {
    options = {
      paths = mkOption {
        type = types.listOf absPath;
        default = [ ];
        example = [ "/home/alice" ];
        description = ''
          Directories, matched EXACTLY against the one the agent was started
          in, with its links resolved -- never as a prefix. Asks git nothing.
        '';
      };
      checkouts = mkOption {
        type = types.attrsOf absPath;
        default = { };
        example = { "alice/nix-config" = "/home/alice/Projects/nix-config"; };
        description = ''
          Repositories keyed by "owner/name", matched against `origin`'s URL,
          and valued by where that checkout lives: the remote has to be one of
          these AND the checkout's root that path or under it (a worktree
          kept inside the checkout, say). The same remote anywhere else does
          not match.
        '';
      };
      repos = mkOption {
        type = types.listOf slug;
        default = [ ];
        example = [ "someone/a-fork" ];
        description = ''
          Repositories by "owner/name" alone, matched against `origin`'s URL
          wherever the checkout is. A remote is a string any checkout can
          claim, so this is the predicate for a tier a checkout would not
          want to be in.
        '';
      };
      owners = mkOption {
        type = types.listOf (types.strMatching "[^/[:space:]]+");
        default = [ ];
        example = [ "alice" "her-employer" ];
        description = "Repository owners, the first half of `origin`'s \"owner/name\".";
      };
      rootAuthorDomains = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "example.com" ];
        description = ''
          Email domains, every one of the repository's FIRST commits having
          been authored at one of them. A fork's root commit is upstream's, so
          this is what gives a fork away when its remote looks like yours. A
          shallow clone, whose first commit is only where it was cut, never
          matches.
        '';
      };
    };
  };

  # WHERE THE BUNDLE IS is frisket's to say; which variables point at it is
  # not. frisket puts the session's CA at /etc/frisket/ca-bundle.crt and stops
  # there, because the list below is a fact about the TOOLS a sandbox runs --
  # it drifts as they come and go, and chase is what chose to run them.
  #
  # Each of these REPLACES a runtime's roots, bar NODE_EXTRA_CA_CERTS, which
  # adds to Node's own and takes the bundle as readily as the CA alone.
  caVariables =
    lib.genAttrs [
      "AWS_CA_BUNDLE"
      "CARGO_HTTP_CAINFO"
      "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"
      "CURL_CA_BUNDLE"
      "DENO_CERT"
      "GIT_SSL_CAINFO"
      "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"
      "HEX_CACERTS_PATH"
      "HTTPLIB2_CA_CERTS"
      "NIX_SSL_CERT_FILE"
      "NODE_EXTRA_CA_CERTS"
      "PIP_CERT"
      "REQUESTS_CA_BUNDLE"
      "SSL_CERT_FILE"
    ]
      (_: "/etc/frisket/ca-bundle.crt")
    // {
      DENO_TLS_CA_STORE = "system,mozilla";
      # uv's roots are compiled in; this makes it read the system's, which
      # SSL_CERT_FILE names.
      UV_NATIVE_TLS = "true";
    };

  tierType = types.submodule {
    # writes, guarded and unmatched: how every app in the tier answers what
    # it does not allow outright (PLAN.md, decision 18).
    options = operations.tierOptions // {
      match = mkOption {
        type = types.listOf ruleType;
        default = [ ];
        description = ''
          What puts a checkout in this tier: any one of these rules, each
          holding only when every predicate it sets does. Tiers are asked in
          `chase.order`, and the first with a rule that holds is the
          checkout's; a rule that does not hold decides nothing, and the next
          is asked.
        '';
      };
      bare = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Run with no sandbox at all: no container, no frisket, no envelope.
          For work a container cannot do -- real sudo, /dev/input, KVM, the
          network namespaces sessions are made of. Everything below is a
          sandbox's, and a bare tier sets none of it.
        '';
      };
      egress = mkOption {
        type = types.nullOr (types.enum [ "direct" "frisket" ]);
        default = null;
        description = ''
          `direct`: the container's own network (pasta), with frisket answering
          DNS. `frisket`: no network but frisket. Required unless the tier is
          `bare`.
        '';
      };
      allow = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Names frisket lets this tier resolve.";
      };
      apps = mkOption {
        type = types.submodule { };
        default = { };
        description = "Applications enabled in this tier; each app module declares its own.";
      };
      forwardPorts = mkOption {
        type = types.either (types.enum [ "auto" ]) (types.listOf types.attrs);
        default = [ ];
        description = ''
          For a tier with its own network: ports published on the host,
          flong's `network.forwardPorts`. `"auto"` publishes whatever TCP port
          a session listens on, at the same port, while it listens -- a dev
          server inside is reached from the host's browser. The host's
          firewall still decides whether anything beyond the host reaches it.
        '';
      };
      seccomp = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        example = { debug = true; };
        description = ''
          flong's `seccomp` for this tier's sessions: its tier, and the
          loosenings a tier's own work needs. Empty is flong's default,
          `strict`. A checkout's envelope can add to it, once approved.
        '';
      };
      envelope = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Whether a checkout's own envelope -- its `chaseModules.default` --
          is applied to its sessions in this tier, once approved. Not for a
          tier that runs other people's code (PLAN.md, decision 13).
        '';
      };
    };
  };
in
{
  imports = [
    self.inputs.flong.nixosModules.default
    # Imports frisket's daemon module too.
    self.inputs.frisket.nixosModules.flong
    ./selector.nix
    ./apps/git.nix
    ./apps/github.nix
    ./apps/claude.nix
    ./apps/codex.nix
    ./apps/cloudflare.nix
    ./apps/huggingface.nix
    ./project
  ] ++ map
    (name: lib.mkRemovedOptionModule [ "chase" name ] ''
      chase ships no tiers and no selector opinions: a tier says what puts a
      checkout in it, in `chase.tiers.<name>.match`, and `chase.order` says
      which is asked first. See chase's README.'')
    [ "strictRepos" "trustedRepos" "hostRepos" "hostPaths" "trustedOrgs" "trustedAuthorDomains" ];

  options.chase = {
    user = mkOption {
      type = types.str;
      example = "alice";
      description = ''
        Whose agents these are. The account the wrappers go on the PATH of,
        the account a session runs as inside its container, and the account
        frisket reads the credential files of -- the same name on both sides
        of the boundary, because a bind-mounted file has one owner.
      '';
    };
    uid = mkOption {
      type = types.ints.unsigned;
      example = 1000;
      description = ''
        `user`'s uid on the HOST, reused inside the container. The session's
        user namespace maps the caller to this same number, so a file
        bind-mounted in is owned by it on both sides and the session can read
        what it was given.
      '';
    };
    gid = mkOption {
      type = types.ints.unsigned;
      example = 100;
      description = "`user`'s primary gid on the host, reused inside the container, for the reason `uid` is.";
    };
    home = mkOption {
      type = types.strMatching "/.*";
      default = "/home/${cfg.user}";
      defaultText = lib.literalExpression ''"/home/''${config.chase.user}"'';
      description = ''
        `user`'s home, at the same path inside a session as outside: the
        agents' own state directories are bound through by absolute path, and
        a tool that writes one would otherwise write it somewhere else.
      '';
    };
    placeholder = mkOption {
      type = types.str;
      default = "proxy-injected";
      description = ''
        What a container holds in place of every credential, and the ONLY
        value frisket replaces: a request carrying anything else goes upstream
        as it was sent. Claude Code keeps a variable set to exactly this when
        it scrubs credentials from a subprocess's environment.
      '';
    };
    # The nixpkgs release the container guests are built against. Not the
    # host's: a container's stateVersion is a fact about the guest closure.
    stateVersion = mkOption {
      type = types.str;
      default = "26.05";
      example = "25.11";
      description = ''
        `system.stateVersion` for every tier's container. Separate from the
        host's, which is a fact about the machine rather than about these
        throwaway guests.
      '';
    };
    # HOW A CHECKOUT IS SORTED: tiers asked in `order`, each by its own
    # `match`, and `fallback` for whatever none of them claims. See
    # ./selector.nix, which is where the order is enforced.
    order = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "host" "strict" "trusted" ];
      description = ''
        The tiers the selector asks, first to last. The first with a rule in
        its `match` that holds is the checkout's, so a tier that should win
        over another is listed before it. Every tier with rules is here.
      '';
    };
    fallback = mkOption {
      type = types.str;
      example = "strict";
      description = ''
        The tier a checkout goes to when no tier's rules hold, and whenever
        sorting it fails at all. Never a bare one: what nothing vouched for
        runs in a sandbox.
      '';
    };
    workspaceGroups = mkOption {
      type = types.listOf (types.listOf absPath);
      default = [ ];
      example = [ [ "/home/alice/Projects/api" "/home/alice/Projects/web" ] ];
      description = ''
        Checkouts worked on together. Opening any member binds the others
        beside it, read-write, at the session's own tier -- for a service and
        the client generated from it, say.

        Not transitive, and the members are reported at launch rather than
        re-sorted: a group is a statement that these are one piece of work.
      '';
    };
    tiers = mkOption {
      type = types.attrsOf tierType;
      default = { };
      description = ''
        The tiers a checkout can be sorted into, by name. chase ships none:
        what each one is for, what puts a checkout in it and what it may do
        are the consumer's to say. Each that is not `bare` becomes a
        container, a flong launcher and a frisket policy of the same name.
      '';
    };
    # What apps add to each tier's command and binds. Separate from `tiers`,
    # which apps read, so contributing to it does not recurse.
    internal.tiers = mkOption {
      internal = true;
      default = { };
      type = types.attrsOf (types.submodule {
        options = {
          setupLines = mkOption { type = types.listOf types.lines; default = [ ]; };
          bindLines = mkOption { type = types.listOf types.lines; default = [ ]; };
          launchers = mkOption { type = types.attrsOf types.lines; default = { }; };
        };
      });
    };
  };

  config = {
    assertions =
      let
        names = lib.attrNames cfg.tiers;
        predicates = [ "paths" "checkouts" "repos" "owners" "rootAuthorDomains" ];
      in
      [
        {
          assertion = cfg.tiers ? ${cfg.fallback};
          message = "chase.fallback is '${cfg.fallback}', which is not one of chase.tiers: ${toString names}.";
        }
        {
          assertion = !(cfg.tiers.${cfg.fallback}.bare or false);
          message = "chase.fallback is '${cfg.fallback}', which is bare: what no rule vouched for must run in a sandbox.";
        }
        {
          assertion = lib.all (n: cfg.tiers ? ${n}) cfg.order && lib.allUnique cfg.order;
          message = "chase.order must name each of chase.tiers at most once, and nothing else: ${toString cfg.order}.";
        }
      ]
      ++ lib.concatLists (lib.mapAttrsToList (name: tier: [
        {
          assertion = tier.match == [ ] || lib.elem name cfg.order;
          message = "chase.tiers.${name} has rules in `match`, but is not in chase.order, so they would never be asked.";
        }
        {
          assertion = lib.all (rule: lib.any (p: rule.${p} != [ ] && rule.${p} != { }) predicates) tier.match;
          message = "chase.tiers.${name}.match has a rule that sets no predicate, which would hold for every checkout. That tier is chase.fallback's to be.";
        }
        {
          assertion = tier.bare || tier.egress != null;
          message = "chase.tiers.${name} is a sandbox and sets no `egress`: say `direct` or `frisket`.";
        }
        {
          assertion = !tier.bare || !(tier.envelope
            || config.containers ? "agent-${name}"
            || config.flong ? "agent-${name}"
            || config.services.frisket.policies ? ${name});
          message = "chase.tiers.${name} is bare, and something gives it a sandbox's settings: an app enabled in it, or `envelope`. A bare tier runs with none.";
        }
      ]) cfg.tiers);

    # The user whose credential files the routes read.
    services.frisket = {
      enable = true;
      user = cfg.user;
      policies = lib.mapAttrs (_: tier: { allow = tier.allow; }) sandboxes;
      flong = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" {
        policy = name;
        set = if tier.egress == "direct" then "service" else "all";
      }) sandboxes;
    };

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" {
      autoStart = false;
      privateNetwork = true;
      config = { pkgs, ... }: {
        system.stateVersion = cfg.stateVersion;
        # The host's uid, so bind-mounted files have the right owner.
        users.users.${cfg.user} = {
          isNormalUser = true;
          uid = cfg.uid;
          group = "users";
          home = cfg.home;
        };
        users.groups.users.gid = cfg.gid;
        services.openssh.enable = false;
        # NixOS's ssh_config includes a file the store owns, which reads as
        # nobody's inside a session, and ssh refuses a config it cannot trust.
        programs.ssh.systemd-ssh-proxy.enable = false;
        # Defaults: a container that wants one runtime pointed elsewhere says
        # so in its own declaration.
        environment.variables = lib.mapAttrs (_: lib.mkDefault) caVariables;
        environment.systemPackages = with pkgs; [ bun git coreutils gnugrep curl jq ];
      };
    }) sandboxes;

    flong = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" ({
      inherit (tier) seccomp;
      user = cfg.user;
      command = [ (lib.getExe (mkCommand name cfg.internal.tiers.${name})) ];
      workspace = [ (hookScript "agent-${name}-workspace" workspaceSnippet) ];
      # One script for every line, as the snippet was: one fork a launch.
      binds =
        let text = groupBinds + lines cfg.internal.tiers.${name}.bindLines; in
        lib.optional (lib.trim text != "") [ (hookScript "agent-${name}-binds" text) ];
    } // lib.optionalAttrs (tier.egress == "direct") {
      network = {
        inherit (tier) forwardPorts;
        # What is published by `auto` is a dev server, and those listen on
        # 127.0.0.1: the host's localhost has to arrive on the session's.
        hostLoopbackToSession = tier.forwardPorts == "auto";
      };
    })) sandboxes;
  };
}
