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
          these AND the checkout's root that path or under it. The same
          remote anywhere else does not match. The root is the nearest .git
          above the directory's resolved path, never git's --show-toplevel,
          which the checkout's own config can move; a layout that would send
          git elsewhere (core.worktree, a gitdir file, a linked .git, GIT_DIR),
          or a config that includes another file, which is never read,
          is not sorted. The repository has to be the one at the path: a
          linked worktree of it under the path matches, as .claude/worktrees
          do, as does one of a bare repository kept at <path>/.bare, and a
          submodule of it; a repository merely nested under the path (a
          clone, a `git init`) does not, since its own session writes its
          .git. Nor does a directory inside a submodule, as .gitmodules lists
          them, whose .git is gone, a submodule of a linked worktree, or a
          linked worktree of a submodule. A sandbox is refused a checkout
          nested in another that would be sorted into a tier other than its
          own, or the fallback, without its own .git, since its session
          could delete it. Every other predicate reads
          the same repository, so a layout not sorted here is not sorted
          by `repos`, `owners` or `rootAuthorDomains` either.
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
          matches; nor does a repository whose refs are kept as reftable, as
          HEAD is resolved from files and packed-refs alone, or one whose
          history cannot be read within the selector's time and memory.
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

  # WHERE A SESSION'S TOOLS KEEP WHAT THEY DOWNLOAD, in a tier that keeps
  # it (`caches`): relative to the tier's caches directory, as caVariables
  # is a fact about the tools a sandbox runs. The XDG cache and data homes
  # cover most -- pip, uv, poetry, pnpm, yarn's first version, corepack,
  # node-gyp, deno, nix, mise, zig and Go's build cache -- and each tool
  # that keeps its downloads elsewhere in the home is named, every runtime
  # caVariables points at frisket's bundle among them. Never
  # XDG_CONFIG_HOME or XDG_STATE_HOME: a tool's settings, its logins and
  # what it has been told to trust stay the session's, and go with it.
  cacheVariables = {
    XDG_CACHE_HOME = "cache";
    XDG_DATA_HOME = "data";
    npm_config_cache = "cache/npm"; # ~/.npm
    YARN_GLOBAL_FOLDER = "data/yarn"; # yarn 2 and later: ~/.yarn/berry
    BUN_INSTALL_CACHE_DIR = "cache/bun"; # ~/.bun/install/cache
    CARGO_HOME = "data/cargo"; # ~/.cargo: the registry, git checkouts
    RUSTUP_HOME = "data/rustup"; # ~/.rustup: toolchains
    GOPATH = "data/go"; # ~/go: the module cache, toolchains
    MIX_HOME = "data/mix"; # ~/.mix: Mix's archives
    HEX_HOME = "data/hex"; # ~/.hex: Hex's packages
    GRADLE_USER_HOME = "data/gradle"; # ~/.gradle
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
          Run with no sandbox at all: no container, no frisket, no grant.
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
          server inside is reached from the host's browser. In a tier that
          takes grants, they are published at the checkout's project address
          (README, "Project addresses"), so two projects' dev servers on one
          port do not meet. The host's firewall still decides whether
          anything beyond the host reaches it.
        '';
      };
      seccomp = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        example = { debug = true; };
        description = ''
          flong's `seccomp` for this tier's sessions: its tier, and the
          loosenings a tier's own work needs. Empty is flong's default,
          `strict`. A checkout's grant can add to it, once approved.
        '';
      };
      caches = mkOption {
        type = types.enum [ "session" "workspace" "tier" ];
        default = "session";
        description = ''
          Where what a session's tools download -- packages, toolchains,
          build caches -- is kept. `session`: in the session's home, which
          is memory, and goes with it. `workspace`: on the host, one
          directory for each workspace in the tier; `tier`: one for all of
          them, so a package is downloaded once. Under ~/.cache/chase/caches,
          and only the tools' caches and data, never their settings or
          state. What a tool runs from its cache is what an earlier session
          left there: `tier` shares that across every workspace in the tier.
        '';
      };
      grants = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Whether a checkout's own grant -- what its `chase.jsonc` asks for
          -- is applied to its sessions in this tier, once approved. In a
          tier that runs other people's code, too, where it fits the tier to
          one checkout rather than moving it to a looser one (PLAN.md,
          decision 13).
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
    ./apps/deepsec.nix
    ./apps/cloudflare.nix
    ./apps/huggingface.nix
    ./apps/gcloud.nix
    ./apps/docker.nix
    ./apps/ssh.nix
    ./apps/mise.nix
    ./apps/nix.nix
    ./apps/gcloud-renew.nix
    ./grant.nix
    (import ./record.nix self)
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
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.chase;
      defaultText = lib.literalExpression "chase.packages.\${system}.chase";
      description = ''
        The chase binary: what every hook flong is given, and every unit
        systemd is, runs.
      '';
    };
    # The chase binary's configuration, a section per part of chase that
    # needs one (internal/config): everything the module once spliced into
    # script text, as data. Installed at /etc/chase/config.json, where
    # every hook and unit reads it -- a runtime path rather than a store
    # one, because the selector's section names each tier's launcher, whose
    # declaration names the hooks.
    internal.config = mkOption {
      internal = true;
      type = types.submodule { freeformType = (pkgs.formats.json { }).type; };
      default = { };
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
          assertion = !tier.bare || !(tier.grants
            || config.containers ? "chase-${name}"
            || config.flong ? "chase-${name}"
            || config.services.frisket.policies ? ${name});
          message = "chase.tiers.${name} is bare, and something gives it a sandbox's settings: an app enabled in it, or `grants`. A bare tier runs with none.";
        }
      ]) cfg.tiers);

    # What each sandbox tier's sessions are given on the host before they
    # start (internal/session): its binds, and its payload, which flong's
    # exec prints, the apps adding what they run and seed.
    #
    # The container's environment is flong's own, read from the declaration
    # it renders: what the container's /etc/set-environment would set, one
    # final value per name -- environment.variables, profileRelativeEnvVars
    # spread over the profiles and joined with ':', extraInit's exports,
    # __NIXOS_SET_ENVIRONMENT_DONE, a reference to the launch's own HOME
    # kept as `''${HOME}` -- worked out by flong's module.nix at evaluation
    # (its environmentOf) and handed to its tests as the file's
    # passthru.declaration. flong refuses an exec that sets any name of it,
    # so exec is told exactly those, to say by name which of its own the
    # container already has rather than have flong refuse the launch. Not
    # environment.variables, which is only the first of them: a name set
    # through a profile or extraInit would go unjudged, and a value with a
    # `$HOME` in it would be compared as the text Nix holds rather than the
    # one flong gives.
    chase.internal.config.session = {
      inherit (cfg) home workspaceGroups placeholder;
      runtime = "/run/user/${toString cfg.uid}";
      tiers = lib.mapAttrs (name: tier: {
        environment = lib.listToAttrs
          config.environment.etc."flong/chase-${name}.zon".source.declaration.environment;
        # A tier with a network publishes its ports on its project's own
        # address, which exec gives flong per launch (internal/grant's
        # Exec): 127.0.0.1 is only where a checkout with no project's go.
        forward = tier.egress == "direct";
        # NixOS's setuid wrappers, first on the container's PATH, and first
        # still with a devShell's: a devShell's sudo or ping is no setuid
        # program.
        pathFront = lib.mkBefore [ "/run/wrappers/bin" ];
      } // lib.optionalAttrs (tier.caches != "session") {
        stores.caches = {
          scope = tier.caches;
          root = "${cfg.home}/.cache/chase/caches";
          env = cacheVariables;
        };
      }) sandboxes;
    };

    environment.etc."chase/config.json".source = (pkgs.formats.json { }).generate "chase-config.json" cfg.internal.config;

    # The user whose credential files the routes read.
    services.frisket = {
      enable = true;
      user = cfg.user;
      policies = lib.mapAttrs (_: tier: { allow = tier.allow; }) sandboxes;
      flong = lib.mapAttrs' (name: tier: lib.nameValuePair "chase-${name}" {
        policy = name;
        set = if tier.egress == "direct" then "service" else "all";
      }) sandboxes;
    };

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "chase-${name}" {
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

    flong = lib.mapAttrs' (name: tier: lib.nameValuePair "chase-${name}" ({
      inherit (tier) seccomp;
      user = cfg.user;
      # The payload, worked out on the host after seccompPolicy, from the
      # launcher's arguments -- the agent, one of a closed list, and its own
      # -- and printed for flong, which execs it in the workspace with
      # nothing between: its argument list, the variables it adds to the
      # container's environment, and the files seeded into its home, Claude
      # Code's placeholder login among them. Nothing of chase's runs in a
      # session but the agent (internal/session), and, where the checkout's
      # devShell is given (./apps/nix.nix), the bash that orders its PATH,
      # runs its shellHook and execs the agent, found on the container's
      # PATH. A tier that takes grants applies the approved one here first
      # (./grant.nix).
      exec = [ (lib.getExe cfg.package) "hook" "exec" name ];
      # The checkout's root, so all of it is mounted wherever you start;
      # otherwise the directory itself, which only a `paths` rule can place.
      # The root the selector sorted, never git's own answer, which a
      # session's core.worktree would steer. See internal/checkout.
      workspace = [ (lib.getExe cfg.package) "workspace" ];
      # What is bound beside the workspace: a group's other members, and
      # what the tier's apps make on the host for it (internal/session).
      binds = [ [ (lib.getExe cfg.package) "hook" "binds" name ] ];
    } // lib.optionalAttrs (tier.egress == "direct") {
      network = {
        inherit (tier) forwardPorts;
        # The host's localhost alone, never every address; a launch whose
        # checkout names a project puts it on that project's address
        # instead (exec's `forward:`).
        forwardAddress = "127.0.0.1";
        # What is published by `auto` is a dev server, and those listen on
        # 127.0.0.1: the host's localhost has to arrive on the session's.
        hostLoopbackToSession = tier.forwardPorts == "auto";
      };
    })) sandboxes;
  };
}
