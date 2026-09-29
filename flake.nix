{
  description = "Agent policy: which sandbox a checkout gets, and which credential each app is given";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # flong runs the sessions, frisket is their network and holds their
    # credentials. Both are REAL inputs, not test-only: chase's module imports
    # them, so a consumer importing chase gets all three wired together rather
    # than having to know the order they go in.
    #
    # `follows` on both, for the reason nix-config gives: the output taken from
    # flong is a NixOS module, which is a path and not a derivation, so it is
    # evaluated against whichever nixpkgs the consumer brings. frisket's is a
    # static Go binary built from source, so there is no glibc to relink
    # against. Following costs nothing either way and keeps one nixpkgs, and
    # one flong, in the lock.
    flong = {
      url = "github:danielbodart/flong";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    frisket = {
      url = "github:danielbodart/frisket";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flong.follows = "flong";
    };

    # TEST-ONLY. Nothing outside `checks` reads this. chase writes
    # `home-manager.users.<user>.*` -- the agent wrappers go on the user's
    # PATH, and Claude Code's settings are the user's -- so those options have
    # to exist, but they are the CONSUMER's to provide: a consumer already
    # running home-manager as a NixOS module has them, and chase importing a
    # second copy would fight the one they have.
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, home-manager, frisket, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      # Curried on `self` so the module can reach the flake's own inputs --
      # flong's and frisket's modules -- without a consumer having to pass
      # them in or import them first. See ./module.nix.
      nixosModules.chase = import ./module.nix self;
      nixosModules.default = self.nixosModules.chase;

      # A project's loopback address and names, from its owner/repo, as
      # chase-docker-address prints them: address, names, reserved and
      # isProject (see ./lib/docker.nix). Pure Nix and the same on every system, so a
      # consumer writing /etc/hosts derives them from here, not from a copy.
      # The reserved names are frisket's, which it exports as the list its Go
      # code embeds.
      lib.docker = import ./lib/docker.nix { lib = nixpkgs.lib; inherit (frisket.lib.docker) reserved; };

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          # The system envelopeHarness runs chase-envelope from, with CHASE
          # (more of the chase section), and the chase-envelope it has.
          harnessConfig = chase:
            let lib = nixpkgs.lib; in
            (lib.nixosSystem {
              inherit system;
              modules = [
                self.nixosModules.default
                home-manager.nixosModules.home-manager
                ./examples/tiers.nix
                {
                  boot.isContainer = true;
                  system.stateVersion = "26.05";
                  users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
                  home-manager.users.alice.home.stateVersion = "26.05";
                  chase = lib.recursiveUpdate {
                    user = "alice";
                    uid = 1000;
                    gid = 100;
                    bindings = {
                      claude.package = pkgs.hello;
                      codex.package = pkgs.hello;
                      github.credentialFile = "/run/secrets/gh_token";
                    };
                  } chase;
                }
              ];
            }).config;
          harnessEnvelope = config: nixpkgs.lib.findFirst (p: nixpkgs.lib.getName p == "chase-envelope")
            (throw "envelopeHarness: agent-trusted has no chase-envelope") config.flong.agent-trusted.path;

          # CHASE-ENVELOPE AS A TIER RUNS IT, where a test can watch it: the
          # one agent-trusted has, from a system with ./examples/tiers.nix
          # and CHASE (more of the chase section), copied to ./chase-envelope
          # with its one-line home, state, runtime and approver -- and each
          # of REWRITE, a name and its value -- put under the build
          # directory, and ./bin first on its PATH. There, nix prints
          # $ENVELOPE, as if the checkout evaluated to it, and the approver
          # logs what it is asked to ./approvals.jsonl and approves. Shell
          # for a check's own script, run first, needing jq.
          envelopeHarness = { chase ? { }, rewrite ? { } }:
            let
              lib = nixpkgs.lib;
              envelope = harnessEnvelope (harnessConfig chase);
              lines = {
                home = "$PWD/home";
                state = "$PWD/state";
                runtime = "$PWD/run";
                approver = "$PWD/bin/approver";
              } // rewrite;
            in
            ''
              mkdir -p bin run home
              cat > bin/nix <<'SH'
              #!${pkgs.runtimeShell}
              printf '%s\n' "$ENVELOPE"
              SH
              cat > bin/approver <<'SH'
              #!${pkgs.runtimeShell}
              ${pkgs.jq}/bin/jq -c . >> "$TMPDIR/approvals.jsonl"
              SH
              chmod +x bin/*
              touch approvals.jsonl
              sed -e "s|^export PATH=\"|export PATH=\"$PWD/bin:|" \
                ${lib.concatStrings (lib.mapAttrsToList (n: v: "-e \"s|^${n}=.*|${n}=${v}|\" ") lines)}\
                ${lib.getExe envelope} > chase-envelope
              for v in ${lib.concatStringsSep " " (lib.attrNames lines)}; do
                grep -q "^$v=$PWD/" chase-envelope || { echo "envelopeHarness: $v is not one line of chase-envelope's" >&2; exit 1; }
              done
              grep -q "^export PATH=\"$PWD/bin:" chase-envelope || { echo "envelopeHarness: PATH is not one line of chase-envelope's" >&2; exit 1; }
            '';
        in
        {
          # A refusal happens at evaluation, so it is checked by evaluating.
          # This is also the only thing that proves the module stands alone:
          # it is instantiated here with nothing of nix-config's around it, so
          # a coupling that crept back in fails the check rather than waiting
          # to fail on somebody's machine. Evaluation only -- no system is
          # built, which is what keeps it in seconds.
          assertions =
            let
              lib = nixpkgs.lib;
              configWith = extra:
                (lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.default
                    home-manager.nixosModules.home-manager
                    # chase ships no tiers: the example's are the baseline.
                    ./examples/tiers.nix
                    {
                      boot.isContainer = true;
                      system.stateVersion = "26.05";
                      users.users.alice = {
                        isNormalUser = true;
                        uid = 1000;
                        group = "users";
                      };
                      home-manager = {
                        useGlobalPkgs = true;
                        useUserPackages = true;
                        users.alice.home.stateVersion = "26.05";
                      };
                      chase = {
                        user = "alice";
                        uid = 1000;
                        gid = 100;
                        bindings = {
                          claude.package = nixpkgs.legacyPackages.${system}.hello;
                          codex.package = nixpkgs.legacyPackages.${system}.hello;
                          github.credentialFile = "/run/secrets/gh_token";
                        };
                      };
                    }
                    extra
                  ];
                }).config;
              chaseFailures = extra:
                let config = configWith extra; in
                lib.filter (m: lib.hasInfix "chase." m)
                  (map (a: lib.trim a.message)
                    (lib.filter (a: ! a.assertion) config.assertions));
              refused = what: extra: needle:
                let failures = chaseFailures extra; in
                lib.any (lib.hasInfix needle) failures
                || throw "assertions: ${what} was not refused; chase said: ${builtins.toJSON failures}";
            in
            assert chaseFailures { } == [ ]
              || throw "assertions: the baseline is refused: ${builtins.toJSON (chaseFailures { })}";
            # THE TIERS ARE THE CONSUMER'S, and what cannot work is refused:
            # a fallback that is not a tier, or is bare; a tier whose rules
            # are never asked; a rule that would hold for everything; a
            # sandbox with no network said; a bare tier given an app.
            assert refused "a fallback that is not a tier" { chase.fallback = lib.mkForce "nope"; } "chase.fallback is 'nope'";
            assert refused "a bare fallback" { chase.fallback = lib.mkForce "host"; } "which is bare";
            assert refused "a tier missing from the order" { chase.order = lib.mkForce [ "host" "strict" ]; } "not in chase.order";
            assert refused "a rule with no predicate" { chase.tiers.strict.match = [ { } ]; } "sets no predicate";
            assert refused "a sandbox with no egress" { chase.tiers.extra.apps.git.enable = true; } "sets no `egress`";
            assert refused "a bare tier with an app" { chase.tiers.host.apps.claude.state = "shared"; } "is bare";
            # A bare tier is no container, launcher or policy; every other is.
            assert
              (let config = configWith { }; in
              ! config.containers ? agent-host && ! config.flong ? agent-host
              && ! config.services.frisket.policies ? host
              && config.containers ? agent-strict && config.flong ? agent-trusted
              && config.services.frisket.policies ? strict)
              || throw "assertions: a bare tier was given a sandbox, or a sandbox was not";
            # The old selector options say where their replacement is.
            assert refused "a removed selector option" { chase.trustedOrgs = [ "alice" ]; } "chase.tiers.<name>.match";
            # DECLARED BUT UNBOUND REFUSES (PLAN.md, decision 4). trusted
            # enables github without `anonymous`, so a null credential file is
            # a route frisket would serve with no credential at all.
            assert refused "an unbound github credential"
              { chase.bindings.github.credentialFile = lib.mkForce null; }
              "credentialFile is null";
            # ... and is fine when no tier asks for a credentialled github or
            # git.
            assert chaseFailures {
              chase.bindings.github.credentialFile = lib.mkForce null;
              chase.tiers.trusted.apps = { github.anonymous = true; git.anonymous = true; };
            } == [ ]
              || throw "assertions: an anonymous-only github still demanded a credential";
            # git is github's credential too: one that pushes without it is
            # refused just the same.
            assert refused "an unbound credential for git alone"
              { chase.bindings.github.credentialFile = lib.mkForce null; chase.tiers.trusted.apps.github.anonymous = true; }
              "credentialFile is null";
            # A PUSH IS A WRITE (decision 18), answered as git's writes say:
            # asked about in trusted by default, allowed where git says so
            # whatever gh's writes are, and refused in strict. gh's GraphQL
            # is by operation: a query is a read, a mutation is answered as
            # github's writes or guarded say, and what frisket cannot
            # classify as github's unmatched does.
            assert
              (let
                policies = extra: (configWith extra).services.frisket.policies;
                byDefault = policies { };
                gitAllows = policies { chase.tiers.trusted.apps.git.writes = "allow"; };
                ghAllows = policies { chase.tiers.trusted.apps.github = { writes = "allow"; unmatched = "allow"; }; };
                graphql = p: lib.head p.trusted.routes.github.graphql;
                mutation = p: field: lib.findFirst (m: m.field == field) null (graphql p).mutations;
              in
              byDefault.trusted.routes.git.git.push == "ask"
              && gitAllows.trusted.routes.git.git.push == "allow"
              && byDefault.strict.routes.git.git.push == "refuse"
              && byDefault.strict.routes.git.credentialFile == null
              && (graphql byDefault).path == "/graphql" && ! (graphql byDefault).query.ask && ! (graphql byDefault).query.refuse
              && (mutation byDefault "closePullRequest").ask && (mutation gitAllows "closePullRequest").ask
              && ! (mutation ghAllows "closePullRequest").ask && (mutation ghAllows "deleteIssue").refuse
              && (graphql byDefault).unmatched == "ask" && (graphql ghAllows).unmatched == "allow"
              && ! lib.any (r: r.path or null == "/graphql") byDefault.trusted.routes.github.paths
              || throw "assertions: git's push or gh's GraphQL was not answered as their writes say");
            # Cloudflare needs no token of the tier's own -- a project brings
            # one -- and without one the tier has no Cloudflare route.
            assert
              (let config = configWith { chase.tiers.trusted.apps.cloudflare.enable = true; }; in
              lib.all (a: a.assertion) config.assertions
              && ! (config.services.frisket.policies.trusted.routes ? cloudflare))
              || throw "assertions: cloudflare without a token of the tier's own did not hold together";
            # Bound, it holds together: no assertion fails, chase's or
            # frisket's, and frisket's configuration -- every generated
            # operation, through frisket's own option types -- is written.
            # Forcing ExecStart forces the file it names.
            assert
              (let
                config = configWith {
                  chase.tiers.trusted.apps.cloudflare.enable = true;
                  chase.bindings.cloudflare.credentialFile = "/run/secrets/cloudflare-token";
                };
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
              in
              failed == [ ] && lib.hasInfix "-config /nix/store/" config.systemd.services.frisket.serviceConfig.ExecStart
                || throw "assertions: a bound cloudflare did not hold together: ${builtins.toJSON failed}");
            # Hugging Face as github is: a tier with a credential it was not
            # given is refused ...
            assert refused "an unbound huggingface credential"
              { chase.tiers.trusted.apps.huggingface.enable = true; }
              "huggingface.credentialFile is null";
            # ... and an anonymous one needs none, holds none, and refuses
            # the token Xet would write with.
            assert
              (let
                config = configWith { chase.tiers.strict.apps.huggingface = { enable = true; anonymous = true; }; };
                route = config.services.frisket.policies.strict.routes.huggingface;
              in
              lib.all (a: a.assertion) config.assertions
              && route.credentialFile == null
              && lib.any (p: p.refuse or false && p.path or "" == "/api/models/*/*/xet-write-token/*") route.paths
              && ! lib.any (p: p.ask or false) route.paths)
              || throw "assertions: an anonymous huggingface did not hold together";
            # Google Cloud is only ever a project's (PLAN.md, decision 9): a
            # tier that takes no envelope cannot enable it, an API it names
            # must exist, and a tier that has it gets gcloud and nothing in
            # its own document.
            assert refused "gcloud in a tier that takes no envelope"
              { chase.tiers.strict.apps.gcloud.enable = true; } "takes no envelope";
            assert refused "an unknown Google API"
              { chase.tiers.trusted.apps.gcloud = { enable = true; apis = [ "bigquery" "nope" ]; }; } "names no Google API: nope";
            assert
              (let
                config = configWith { chase.tiers.trusted.apps.gcloud = { enable = true; apis = [ "bigquery" ]; }; };
                env = config.containers.agent-trusted.config.environment;
                policy = config.services.frisket.policies.trusted;
              in
              lib.all (a: a.assertion) config.assertions
              && lib.any (p: lib.getName p == lib.getName pkgs.google-cloud-sdk) env.systemPackages
              && env.variables.CLOUDSDK_CONFIG == "/run/user/1000/gcloud"
              && env.variables.CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE == "/etc/frisket/ca-bundle.crt"
              && env.variables.GRPC_DEFAULT_SSL_ROOTS_FILE_PATH == "/etc/frisket/ca-bundle.crt"
              && ! lib.any (lib.hasPrefix "gcloud") (lib.attrNames policy.routes)
              && ! lib.elem "*.googleapis.com" policy.allow
              && ! config.containers.agent-strict.config.environment.variables ? CLOUDSDK_CONFIG)
              || throw "assertions: gcloud in trusted did not hold together";
            # A CLASS IS ANSWERED AS THE TIER AND THE APP SAY (PLAN.md,
            # decision 18). By default a read is allowed, a write asks and a
            # guarded operation is refused; the tier's settings are every
            # app's, and an app's own override them.
            assert
              (let
                answers = extra:
                  let
                    config = configWith {
                      imports = [ extra ];
                      chase.tiers.trusted.apps.cloudflare.enable = true;
                      chase.bindings.cloudflare.credentialFile = "/run/secrets/cloudflare-token";
                    };
                    route = config.services.frisket.policies.trusted.routes.cloudflare;
                    of = class: lib.unique (map (p: if p.refuse or false then "refuse" else if p.ask or false then "ask" else "allow")
                      (lib.filter (p: (p.operation.class or null) == class) route.paths));
                  in
                  { read = of "read"; write = of "write"; guarded = of "guarded"; inherit (route) unmatched;
                    catchAll = lib.any (p: p.prefix or null == "/" && p.operation or null == null) route.paths; };
                byDefault = answers { };
                tierAllows = answers { chase.tiers.trusted.writes = "allow"; };
                appRefuses = answers { chase.tiers.trusted = { writes = "allow"; apps.cloudflare.writes = "refuse"; guarded = "ask"; unmatched = "allow"; }; };
              in
              byDefault == { read = [ "allow" ]; write = [ "ask" ]; guarded = [ "refuse" ]; unmatched = "ask"; catchAll = false; }
              && tierAllows.write == [ "allow" ] && tierAllows.guarded == [ "refuse" ]
              && appRefuses == { read = [ "allow" ]; write = [ "refuse" ]; guarded = [ "ask" ]; unmatched = "refuse"; catchAll = true; }
              || throw "assertions: classes were not answered as the tier and the app say: ${builtins.toJSON [ byDefault tierAllows appRefuses ]}");
            # The example's strict says refuse for all three, and an app in it
            # that sets nothing asks about nothing.
            assert
              (let tier = (configWith { }).chase.tiers.strict; in
              tier.writes == "refuse" && tier.guarded == "refuse" && tier.unmatched == "refuse"
              && tier.apps.huggingface.writes == "refuse")
              || throw "assertions: strict does not refuse what it does not allow";
            # NO PRIVILEGE ANYWHERE (PLAN.md, decision 2). flong runs every
            # session as its caller, nothing is granted through sudo, and flong
            # accepts what chase declares: none of flong's own assertions fail.
            assert
              (let
                config = configWith { };
                agents = lib.filterAttrs (n: _: lib.hasPrefix "agent-" n) config.flong;
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
              in
              agents != { }
              && ! lib.any (r: lib.elem "alice" (r.users or [ ])) config.security.sudo.extraRules
              && failed == [ ]
                || throw "assertions: a session is granted sudo, or flong refused them: ${builtins.toJSON failed}");
            # The example tiers' filters: trusted can debug, strict cannot;
            # only a tier that takes envelopes asks the checkout for more.
            assert
              (let config = configWith { }; in
              config.flong.agent-trusted.seccomp.debug
              && config.flong.agent-trusted.seccompPolicy != [ ]
              && config.flong.agent-strict.seccomp.tier == "strict"
              && ! config.flong.agent-strict.seccomp.debug
              && config.flong.agent-strict.seccompPolicy == [ ])
              || throw "assertions: the tiers' seccomp is not what they say";
            pkgs.runCommand "assertions" { } "touch $out";

          # THE SELECTOR, run against real repositories. Its rules are the
          # example's shape at paths under a sentinel, which the test puts
          # where its build directory is: agent-tier compares resolved paths,
          # and where a build runs is not known at evaluation.
          selector =
            let
              lib = nixpkgs.lib;
              root = "/chase-selector-test";
              config = (lib.nixosSystem {
                inherit system;
                modules = [
                  self.nixosModules.default
                  home-manager.nixosModules.home-manager
                  ./examples/tiers.nix
                  {
                    boot.isContainer = true;
                    system.stateVersion = "26.05";
                    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
                    home-manager.users.alice.home.stateVersion = "26.05";
                    chase = {
                      user = "alice";
                      uid = 1000;
                      gid = 100;
                      bindings = {
                        claude.package = pkgs.hello;
                        codex.package = pkgs.hello;
                        github.credentialFile = "/run/secrets/gh_token";
                      };
                      tiers.host.match = lib.mkForce [
                        { paths = [ "${root}/home" ]; }
                        { checkouts."alice/nix-config" = "${root}/p/nix-config"; }
                        { checkouts."alice/bare" = "${root}/p/bare"; }
                      ];
                      tiers.strict.match = lib.mkForce [ { repos = [ "alice/nix-config" ]; } ];
                      tiers.trusted.match = lib.mkForce [
                        { owners = [ "alice" ]; rootAuthorDomains = [ "example.com" ]; }
                      ];
                    };
                  }
                ];
              }).config;
            in
            pkgs.runCommand "selector" { nativeBuildInputs = [ pkgs.git pkgs.python3 ]; } ''
              export HOME=$TMPDIR
              r=$(cd "$TMPDIR" && pwd -P)/root
              sed "s|${root}|$r|g" ${lib.getExe config.chase.internal.agentTier} > agent-tier
              fail() { echo "selector: $*" >&2; exit 1; }
              repo() { # DIR REMOTE AUTHOR
                mkdir -p "$1"
                git -C "$1" init -q
                git -C "$1" -c user.name=x -c user.email="$3" commit -q --allow-empty -m first
                git -C "$1" remote add origin "$2"
              }
              expect() { # DIR TIER REASON-SUBSTRING
                got=$(bash ./agent-tier --dry-run "$1" | tail -1)
                tier=$(bash ./agent-tier "$1")
                [ "$tier" = "$2" ] || fail "$1 is '$tier', not '$2': $got"
                case $got in *"$3"*) ;; *) fail "$1: expected '$3' in: $got" ;; esac
              }

              mkdir -p "$r/home" "$r/plain"
              repo "$r/p/nix-config" git@github.com:alice/nix-config.git a@example.com
              repo "$r/p/nix-config/nested" https://github.com/alice/nix-config a@example.com
              repo "$r/elsewhere/nix-config" git@github.com:alice/nix-config.git a@example.com
              repo "$r/p/mine" git@github.com:Alice/Mine.git a@Example.com
              repo "$r/p/fork" https://github.com/alice/fork.git x@upstream.org
              repo "$r/p/other" ssh://git@github.com/bob/thing a@example.com
              git clone -q --depth 1 "file://$r/p/mine" "$r/p/shallow"

              expect "$r/home" host "path $r/home"
              expect "$r/p/nix-config" host "alice/nix-config at $r/p/nix-config"
              # A repository nested inside the pinned checkout is not it,
              # remote or no: its own session writes its .git.
              expect "$r/p/nix-config/nested" strict "repo alice/nix-config"
              # Its remote, anywhere else: strict, because strict is asked
              # before trusted and lists it.
              expect "$r/elsewhere/nix-config" strict "repo alice/nix-config"
              expect "$r/p/mine" trusted "owner alice, first commit by a@Example.com"
              expect "$r/p/fork" strict "first commit by x@upstream.org"
              expect "$r/p/other" strict "owner bob is not listed"
              expect "$r/plain" strict "not a git repository"
              git -C "$r/p/shallow" remote set-url origin git@github.com:alice/mine.git
              expect "$r/p/shallow" strict "shallow clone"

              # WHAT A SESSION COULD WRITE TO BE RUN ON THE HOST NEXT TIME.
              # Each claims the pinned checkout's remote, so only the layout
              # stands between it and host: none of them may get there, and
              # each says why.
              forged() { # DIR: a repository claiming the pinned remote
                repo "$1" git@github.com:alice/nix-config.git a@example.com
              }
              # core.worktree, in the repository's own config.
              forged "$r/forge"
              git -C "$r/forge" config core.worktree "$r/p/nix-config"
              expect "$r/forge" strict "core.worktree sends git to $r/p/nix-config"
              # ... by an include, and by an includeIf on its gitdir: the included
              # file is never read, so a config that includes one is not sorted.
              forged "$r/inc"
              printf '[core]\n\tworktree = %s\n' "$r/p/nix-config" > "$r/inc.cfg"
              git -C "$r/inc" config include.path "$r/inc.cfg"
              expect "$r/inc" strict "$r/inc/.git/config includes another file"
              forged "$r/incif"
              git -C "$r/incif" config "includeIf.gitdir:$r/incif/.path" "$r/inc.cfg"
              expect "$r/incif" strict "$r/incif/.git/config includes another file"
              # A .git file pointing into the pinned checkout from outside it.
              mkdir -p "$r/evil"
              echo "gitdir: $r/p/nix-config/.git" > "$r/evil/.git"
              expect "$r/evil" strict "which is not a worktree's"
              # A .git that is a link to it.
              mkdir -p "$r/link"
              ln -s "$r/p/nix-config/.git" "$r/link/.git"
              expect "$r/link" strict "is a symbolic link"
              # The environment.
              export GIT_DIR=$r/p/nix-config/.git GIT_WORK_TREE=$r/p/nix-config
              expect "$r/plain" strict "redirected by the environment: GIT_DIR GIT_WORK_TREE"
              expect "$r/p/nix-config" strict "redirected by the environment"
              unset GIT_DIR GIT_WORK_TREE

              # WORKTREES, as work inside a checkout is done: one under the
              # pinned path holds, as Claude Code keeps them and anywhere
              # else under it, and so does a directory inside one.
              pinned=$r/p/nix-config
              git -C "$pinned" worktree add -q "$pinned/.claude/worktrees/feat"
              git -C "$pinned" worktree add -q "$pinned/tree"
              mkdir -p "$pinned/.claude/worktrees/feat/deep/er" "$pinned/sub/deep"
              expect "$pinned/.claude/worktrees/feat" host "alice/nix-config at $pinned, a worktree of $pinned"
              expect "$pinned/.claude/worktrees/feat/deep/er" host "a worktree of $pinned"
              expect "$pinned/tree" host "a worktree of $pinned"
              expect "$pinned/sub/deep" host "alice/nix-config at $pinned"
              expect "$pinned" host "alice/nix-config at $pinned"
              # One kept elsewhere is its remote anywhere else.
              git -C "$pinned" worktree add -q "$r/elsewhere/away"
              expect "$r/elsewhere/away" strict "repo alice/nix-config"
              # One inside the pinned path, of a checkout that is not: its remote
              # anywhere else, too.
              git -C "$r/elsewhere/nix-config" worktree add -q "$pinned/.claude/worktrees/intruder"
              expect "$pinned/.claude/worktrees/intruder" strict "repo alice/nix-config"
              # A .git file naming a genuine worktree's gitdir from outside:
              # that gitdir names its own worktree back, not this one.
              mkdir -p "$r/evil2"
              echo "gitdir: $pinned/.git/worktrees/feat" > "$r/evil2/.git"
              expect "$r/evil2" strict "belongs to $pinned/.claude/worktrees/feat/.git"
              # A worktree's own config, which git reads with worktreeConfig.
              git -C "$pinned" worktree add -q "$pinned/.claude/worktrees/bent"
              git -C "$pinned" config extensions.worktreeConfig true
              git -C "$pinned/.claude/worktrees/bent" config --worktree core.worktree "$r/elsewhere"
              expect "$pinned/.claude/worktrees/bent" strict "core.worktree sends git to $r/elsewhere"
              expect "$pinned/.claude/worktrees/feat" host "a worktree of $pinned"

              # THE WORKSPACE a launch mounts is the root the selector sorted,
              # and a layout it would not sort is the directory alone.
              workspace() { (cd "$1" && ${lib.escapeShellArgs config.flong.agent-strict.workspace}); }
              [ "$(workspace "$pinned/sub/deep")" = "$pinned" ] || fail "workspace of sub/deep: $(workspace "$pinned/sub/deep")"
              [ "$(workspace "$pinned/.claude/worktrees/feat/deep")" = "$pinned/.claude/worktrees/feat" ] \
                || fail "workspace of a worktree: $(workspace "$pinned/.claude/worktrees/feat/deep")"
              [ "$(workspace "$r/forge")" = "$r/forge" ] || fail "workspace of a forged checkout: $(workspace "$r/forge")"
              [ "$(workspace "$r/evil")" = "$r/evil" ] || fail "workspace of a gitdir file: $(workspace "$r/evil")"

              # SUBMODULES are sorted as the repositories they are, and a
              # directory inside one mounts all of it.
              repo "$r/lib-src" git@github.com:alice/lib.git a@example.com
              git -C "$r/p/mine" -c protocol.file.allow=always submodule add -q "file://$r/lib-src" vendor/lib
              sub=$r/p/mine/vendor/lib
              git -C "$sub" remote set-url origin git@github.com:alice/lib.git
              mkdir -p "$sub/deep"
              expect "$sub" trusted "owner alice, first commit by a@example.com"
              expect "$sub/deep" trusted "owner alice"
              [ "$(workspace "$sub/deep")" = "$sub" ] || fail "workspace of a submodule: $(workspace "$sub/deep")"
              # Its gitdir, named from somewhere it is not checked out.
              mkdir -p "$r/evil3"
              echo "gitdir: $r/p/mine/.git/modules/vendor/lib" > "$r/evil3/.git"
              expect "$r/evil3" strict "which is not above it"
              mkdir -p "$r/p/mine/other"
              echo "gitdir: $r/p/mine/.git/modules/vendor/lib" > "$r/p/mine/other/.git"
              expect "$r/p/mine/other" strict "is checked out in"
              # Its core.worktree, moved, or joined by another from an include.
              git -C "$sub" config core.worktree "$r/p/mine/other"
              expect "$sub" strict "is checked out in $r/p/mine/other"
              git -C "$sub" config core.worktree ../../../../vendor/lib
              expect "$sub" trusted "owner alice"
              git -C "$sub" config include.path "$r/inc.cfg"
              expect "$sub" strict "includes another file"
              git -C "$sub" config --unset include.path
              expect "$sub" trusted "owner alice"
              # A worktree of a submodule: not sorted, and said so.
              git -C "$sub" worktree add -q "$r/p/mine/libwt"
              expect "$r/p/mine/libwt" strict "a worktree of a submodule of $r/p/mine"

              # WORKTREES OF A BARE REPOSITORY kept beside it, as some lay a
              # checkout out: pinned when the bare repository is under the path.
              git clone -q --bare "file://$r/p/mine" "$r/p/bare/.bare"
              git -C "$r/p/bare/.bare" remote set-url origin git@github.com:alice/bare.git
              git -C "$r/p/bare/.bare" worktree add -q "$r/p/bare/trunk"
              expect "$r/p/bare/trunk" host "alice/bare at $r/p/bare, a worktree of $r/p/bare/.bare"
              [ "$(workspace "$r/p/bare/trunk")" = "$r/p/bare/trunk" ] || fail "workspace of a bare worktree: $(workspace "$r/p/bare/trunk")"
              # One whose bare repository is elsewhere is not.
              git clone -q --bare "file://$r/p/mine" "$r/elsewhere/bare.git"
              git -C "$r/elsewhere/bare.git" remote set-url origin git@github.com:alice/bare.git
              git -C "$r/elsewhere/bare.git" worktree add -q "$r/p/bare/intruder"
              expect "$r/p/bare/intruder" trusted "owner alice"
              # A directory that says it is bare and is not a repository.
              mkdir -p "$r/fake/worktrees/w" "$r/fakewt"
              printf '[core]\n\tbare = true\n' > "$r/fake/config"
              echo "gitdir: $r/fake/worktrees/w" > "$r/fakewt/.git"
              expect "$r/fakewt" strict "is not a repository of its own"

              # A REPOSITORY NESTED IN A PINNED CHECKOUT, in a sandbox of its
              # own, and what its session can make of its .git. Each rewrite
              # claims the pinned remote; none may reach host.
              repo "$r/opus-src" https://github.com/xiph/opus.git a@xiph.org
              git -C "$pinned" -c protocol.file.allow=always submodule add -q "file://$r/opus-src" vendor/opus
              git -C "$pinned" -c user.name=x -c user.email=a@example.com commit -q -m opus
              opus=$pinned/vendor/opus
              git -C "$opus" remote set-url origin https://github.com/xiph/opus.git
              expect "$opus" strict "owner xiph is not listed"
              # Swapped for a repository of its own.
              mv "$opus/.git" "$r/opus.gitfile"
              git -C "$opus" init -q
              git -C "$opus" remote add origin git@github.com:alice/nix-config.git
              expect "$opus" strict "repo alice/nix-config"
              git -C "$opus" remote set-url origin git@github.com:alice/bare.git
              mkdir -p "$r/p/bare/opus"
              git -C "$r/p/bare/opus" init -q
              git -C "$r/p/bare/opus" remote add origin git@github.com:alice/bare.git
              expect "$r/p/bare/opus" strict "$r/p/bare/opus is a checkout of its own, not $r/p/bare"
              # Deleted: a directory inside a submodule, not of the checkout.
              rm -rf "$opus/.git"
              expect "$opus" strict "inside $pinned/vendor/opus, a submodule with no .git of its own"
              mkdir -p "$opus/deep"
              expect "$opus/deep" strict "a submodule with no .git of its own"
              [ "$(workspace "$opus/deep")" = "$opus/deep" ] || fail "workspace of a gutted submodule: $(workspace "$opus/deep")"
              mv "$r/opus.gitfile" "$opus/.git"
              expect "$opus" strict "owner xiph is not listed"
              # A clone kept untracked in it, its remote rewritten.
              git clone -q "file://$r/opus-src" "$pinned/scratch"
              git -C "$pinned/scratch" remote set-url origin https://github.com/xiph/opus.git
              expect "$pinned/scratch" strict "owner xiph is not listed"
              git -C "$pinned/scratch" remote set-url origin git@github.com:alice/nix-config.git
              expect "$pinned/scratch" strict "repo alice/nix-config"

              # ... and what a deleted .git would leave, which the selector
              # cannot tell from a directory of the checkout: the guard asks
              # it before the session starts, and refuses a sandbox there.
              [ "$(bash ./agent-tier --if-gone "$pinned/scratch")" = host ] || fail "scratch without its .git is not host"
              [ "$(bash ./agent-tier --if-gone "$opus")" = strict ] || fail "a submodule without its .git is not strict"
              [ "$(bash ./agent-tier --if-gone "$r/p/other")" = strict ] || fail "p/other without its .git is not strict"
              mkdir -p bin
              cp agent-tier bin/agent-tier
              chmod +x bin/agent-tier
              guard() { # WORKSPACE: the strict tier's guard, as flong runs it
                PATH=$PWD/bin:$PATH workspace=$1 binds="" ${lib.escapeShellArgs (lib.head config.flong.agent-strict.guard)}
              }
              if guard "$pinned/scratch" 2> guard.err; then fail "the guard let a clone nested in a host checkout into a sandbox"; fi
              grep -q "would be 'host' without its .git" guard.err || fail "guard: $(cat guard.err)"
              guard "$opus" 2> guard.err || fail "the guard refused a submodule: $(cat guard.err)"
              guard "$r/p/other" 2> guard.err || fail "the guard refused p/other: $(cat guard.err)"
              # A worktree of another checkout, kept in the pinned one.
              if guard "$pinned/.claude/worktrees/intruder" 2> guard.err; then fail "the guard let a foreign worktree nested in a host checkout into a sandbox"; fi
              # A strict clone nested in a trusted checkout: deleting its .git
              # would make it trusted, and mount the checkout above it.
              git clone -q "file://$r/opus-src" "$r/p/mine/nested"
              git -C "$r/p/mine/nested" remote set-url origin https://github.com/bob/evil.git
              expect "$r/p/mine/nested" strict "owner bob is not listed"
              [ "$(bash ./agent-tier --if-gone "$r/p/mine/nested")" = trusted ] || fail "p/mine/nested without its .git is not trusted"
              if guard "$r/p/mine/nested" 2> guard.err; then fail "the guard let a strict clone nested in a trusted checkout into a sandbox"; fi
              grep -q "would be 'trusted' without its .git, not 'strict'" guard.err || fail "guard: $(cat guard.err)"
              # ... and a worktree of the trusted checkout, which stays trusted.
              git -C "$r/p/mine" worktree add -q "$r/p/mine/.claude/worktrees/w"
              guard "$r/p/mine/.claude/worktrees/w" 2> guard.err || fail "the guard refused a worktree of its own checkout: $(cat guard.err)"

              # COMMANDS A SESSION NAMES IN ITS REPOSITORY, which git would run
              # on the host, as the user, as the selector reads it: every key
              # git reads as a command, a hooks directory, a filter the
              # checkout's .gitattributes asks for, set in a checkout, in a
              # worktree's own config and in a submodule's, and in a file a
              # repository includes. Each is asked of from the root, a
              # directory below it, the worktree and the submodule, as the
              # selector, the workspace and the guard ask. None may run.
              printf '#!/bin/sh\necho "$0 $*" >> %s\nexit 1\n' "$r/ran" > "$r/cmd"
              chmod +x "$r/cmd"
              mkdir -p "$r/hooks"
              for h in applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit \
                       prepare-commit-msg commit-msg post-commit pre-rebase post-checkout post-merge \
                       pre-push pre-receive update proc-receive post-receive post-update \
                       reference-transaction push-to-checkout pre-auto-gc post-rewrite \
                       sendemail-validate fsmonitor-watchman post-index-change; do
                ln -s "$r/cmd" "$r/hooks/$h"
              done
              arm() { # CONFIG-FILE: every command it can name, the marker
                for kv in core.fsmonitor="$r/cmd" core.hooksPath="$r/hooks" \
                    core.pager="$r/cmd" pager.log="$r/cmd" pager.config="$r/cmd" \
                    pager.ls-files="$r/cmd" pager.rev-parse="$r/cmd" pager.remote="$r/cmd" \
                    diff.external="$r/cmd" diff.x.textconv="$r/cmd" diff.x.command="$r/cmd" \
                    filter.x.process="$r/cmd" filter.x.clean="$r/cmd" filter.x.smudge="$r/cmd" \
                    filter.x.required=true merge.x.driver="$r/cmd" \
                    core.sshCommand="$r/cmd" core.gitProxy="$r/cmd" core.askPass="$r/cmd" \
                    credential.helper="!$r/cmd" uploadpack.packObjectsHook="$r/cmd" \
                    core.alternateRefsCommand="$r/cmd" gc.recentObjectsHook="$r/cmd" \
                    gpg.program="$r/cmd" gpg.ssh.program="$r/cmd" log.showSignature=true \
                    core.editor="$r/cmd" sequence.editor="$r/cmd" \
                    core.untrackedCache=true gc.auto=1 gc.autoDetach=false \
                    hook.chase.command="$r/cmd" hook.chase.event=post-index-change \
                    remote.origin.receivepack="$r/cmd" remote.origin.uploadpack="$r/cmd"; do
                  git config --file "$1" --add "''${kv%%=*}" "''${kv#*=}"
                done
                for e in post-checkout reference-transaction pre-auto-gc pre-commit; do
                  git config --file "$1" --add hook.chase.event "$e"
                done
              }

              armed=$r/p/armed
              repo "$armed" git@github.com:alice/armed.git a@example.com
              mkdir -p "$armed/sub/deep"
              touch "$armed/sub/deep/f"
              printf '* filter=x diff=x merge=x\n' > "$armed/.gitattributes"
              repo "$r/armlib-src" git@github.com:alice/armlib.git a@example.com
              git -C "$armed" -c protocol.file.allow=always submodule add -q "file://$r/armlib-src" vendor/lib
              git -C "$armed" -c protocol.file.allow=always submodule add -q "file://$r/armlib-src" vendor/inc
              git -C "$armed" add sub/deep/f .gitattributes
              git -C "$armed" -c user.name=x -c user.email=a@example.com commit -q -m armed
              armlib=$armed/vendor/lib
              arminc=$armed/vendor/inc
              git -C "$armlib" remote set-url origin git@github.com:alice/armlib.git
              git -C "$arminc" remote set-url origin git@github.com:alice/armlib.git
              mkdir -p "$armlib/deep"
              git -C "$armed" worktree add -q "$armed/.claude/worktrees/w"
              armwt=$armed/.claude/worktrees/w
              mkdir -p "$armwt/deep"
              # A root commit that says it is signed, as a session can write,
              # and every ref packed, so HEAD is read through packed-refs.
              signed=$(git -C "$armed" cat-file commit "$(git -C "$armed" rev-list --max-parents=0 HEAD)" \
                | sed '/^committer /a gpgsig -----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----' \
                | git -C "$armed" hash-object -t commit -w --stdin)
              git -C "$armed" replace "$(git -C "$armed" rev-list --max-parents=0 HEAD)" "$signed"
              git -C "$armed" pack-refs --all
              git -C "$armed" config extensions.worktreeConfig true
              arm "$armed/.git/config"
              arm "$armed/.git/worktrees/w/config.worktree"
              arm "$armed/.git/modules/vendor/lib/config"
              for h in "$r"/hooks/*; do ln -s "$r/cmd" "$armed/.git/hooks/$(basename "$h")"; done
              # ... and a file a repository includes, which names them all.
              arm "$r/attack.cfg"
              git -C "$armed/.git/modules/vendor/inc" config include.path "$r/attack.cfg"
              repo "$r/p/included" git@github.com:alice/included.git a@example.com
              mkdir -p "$r/p/included/sub/deep"
              git -C "$r/p/included" worktree add -q "$r/p/included/.claude/worktrees/w"
              git -C "$r/p/included" config include.path "$r/attack.cfg"

              # They do run, for a git that is not the selector's.
              git -C "$armed" status >/dev/null 2>&1 || true
              [ -s "$r/ran" ] || fail "the checkout's commands never run, so their absence proves nothing"
              rm "$r/ran"
              git -C "$armwt" status >/dev/null 2>&1 || true
              [ -s "$r/ran" ] || fail "the worktree's commands never run"
              rm "$r/ran"
              git -C "$armlib" status >/dev/null 2>&1 || true
              [ -s "$r/ran" ] || fail "the submodule's commands never run"
              rm "$r/ran"
              git -C "$r/p/included" status >/dev/null 2>&1 || true
              [ -s "$r/ran" ] || fail "the included commands never run"
              rm "$r/ran"

              expect "$armed" trusted "owner alice, first commit by a@example.com"
              expect "$armed/sub/deep" trusted "owner alice, first commit by a@example.com"
              expect "$armwt" trusted "owner alice, first commit by a@example.com"
              expect "$armwt/deep" trusted "owner alice, first commit by a@example.com"
              expect "$armlib" trusted "owner alice, first commit by a@example.com"
              expect "$armlib/deep" trusted "owner alice, first commit by a@example.com"
              expect "$arminc" strict "$armed/.git/modules/vendor/inc/config includes another file"
              expect "$r/p/included" strict "includes another file"
              expect "$r/p/included/sub/deep" strict "includes another file"
              expect "$r/p/included/.claude/worktrees/w" strict "includes another file"
              for d in "$armed/sub/deep" "$armwt/deep" "$armlib/deep" "$arminc" \
                       "$r/p/included/sub/deep" "$r/p/included/.claude/worktrees/w"; do
                workspace "$d" >/dev/null
                bash ./agent-tier --if-gone "$d" >/dev/null
                guard "$d" 2>/dev/null || true
              done
              [ "$(workspace "$armed/sub/deep")" = "$armed" ] || fail "workspace of armed/sub/deep: $(workspace "$armed/sub/deep")"
              [ "$(workspace "$armlib/deep")" = "$armlib" ] || fail "workspace of an armed submodule: $(workspace "$armlib/deep")"
              [ ! -e "$r/ran" ] || fail "the selector ran a command the repository named: $(cat "$r/ran")"

              # FILES A SESSION NAMES for git to read, or wait on, in its
              # stead: a config that is a pipe or a link, objects borrowed
              # from elsewhere, a HEAD that is a link. None is read.
              repo "$r/p/piped" git@github.com:alice/piped.git a@example.com
              rm "$r/p/piped/.git/config"
              mkfifo "$r/p/piped/.git/config"
              expect "$r/p/piped" strict "is not a plain file"
              repo "$r/p/linked" git@github.com:alice/linked.git a@example.com
              mv "$r/p/linked/.git/config" "$r/linked.cfg"
              ln -s "$r/linked.cfg" "$r/p/linked/.git/config"
              expect "$r/p/linked" strict "is not a plain file"
              git clone -q --shared "$r/p/mine" "$r/p/borrowed"
              git -C "$r/p/borrowed" remote set-url origin git@github.com:alice/borrowed.git
              expect "$r/p/borrowed" strict "alternates"
              repo "$r/p/headlink" git@github.com:alice/headlink.git a@example.com
              mv "$r/p/headlink/.git/HEAD" "$r/headlink.HEAD"
              ln -s "$r/headlink.HEAD" "$r/p/headlink/.git/HEAD"
              expect "$r/p/headlink" strict "$r/p/headlink/.git/HEAD is not a plain file the size of a ref"

              # FILES NO LARGER THAN THEIR KIND, and history read in bounded
              # time and memory: a sparse gitdir file, config or ref, and a
              # pack whose objects are deltas of each other.
              mkdir -p "$r/huge/x"
              truncate -s 1G "$r/huge/.git"
              expect "$r/huge/x" strict "is too large to be a gitdir file"
              repo "$r/p/hugecfg" git@github.com:alice/hugecfg.git a@example.com
              git -C "$r/p/hugecfg" config extensions.worktreeConfig true
              truncate -s 1G "$r/p/hugecfg/.git/config.worktree"
              expect "$r/p/hugecfg" strict "config.worktree is too large to be a config"
              repo "$r/p/hugeref" git@github.com:alice/hugeref.git a@example.com
              truncate -s 1G "$r/p/hugeref/.git/$(git -C "$r/p/hugeref" symbolic-ref HEAD)"
              expect "$r/p/hugeref" strict "is not a plain file the size of a ref"
              mkdir -p "$r/p/cyclic"
              git -C "$r/p/cyclic" init -q
              git -C "$r/p/cyclic" remote add origin git@github.com:alice/cyclic.git
              python3 ${./tests/selector/cyclic-pack.py} 1111111111111111111111111111111111111111 \
                2222222222222222222222222222222222222222 "$r/p/cyclic/.git/objects/pack"
              echo 1111111111111111111111111111111111111111 > "$r/p/cyclic/.git/$(git -C "$r/p/cyclic" symbolic-ref HEAD)"
              timeout 60 bash ./agent-tier "$r/p/cyclic" >/dev/null || fail "a cyclic pack was not given up on"
              expect "$r/p/cyclic" strict "the history of 1111111111111111111111111111111111111111 cannot be read"

              # BRANCHES are any name git would give one, whatever the locale;
              # a name it would not is said to be one.
              repo "$r/p/branchy" git@github.com:alice/branchy.git a@example.com
              for b in 'issue#12' 'wip,1' 'fix/ümlaut'; do
                git -C "$r/p/branchy" checkout -q -b "$b"
                expect "$r/p/branchy" trusted "owner alice, first commit by a@example.com"
                LC_ALL=C expect "$r/p/branchy" trusted "owner alice, first commit by a@example.com"
              done
              echo 'ref: refs/heads/a..b' > "$r/p/branchy/.git/HEAD"
              expect "$r/p/branchy" strict "HEAD names refs/heads/a..b, which is not a branch that is read"
              # Refs kept as reftable, which are not read.
              mkdir -p "$r/p/reftable"
              git -C "$r/p/reftable" init -q --ref-format=reftable
              git -C "$r/p/reftable" -c user.name=x -c user.email=a@example.com commit -q --allow-empty -m first
              git -C "$r/p/reftable" remote add origin git@github.com:alice/reftable.git
              expect "$r/p/reftable" strict "refs kept as reftable, which is not read"
              # A submodule of a worktree: not sorted, and said so.
              git -C "$armwt" -c protocol.file.allow=always submodule update --init -q vendor/lib
              expect "$armwt/vendor/lib" strict "a submodule of a worktree of $armed"
              touch $out
            '';

          # A PROJECT'S LISTS (PLAN.md, decision 18), as launch applies them
          # to a policy document: a name before a category, a category before
          # the tier, git's push by its operation, and a name the route does
          # not have an error rather than a rule that decides nothing.
          lists = pkgs.runCommand "lists" { nativeBuildInputs = [ pkgs.jq ]; } ''
            doc='{"routes": [
              {"name": "github", "paths": [
                {"methods": ["POST"], "path": "/repos/*/*/pulls", "ask": true, "operation": {"id": "pulls/create", "summary": "s", "class": "write", "category": "pulls"}},
                {"methods": ["PUT"], "path": "/repos/*/*/pulls/*/merge", "ask": true, "operation": {"id": "pulls/merge", "summary": "s", "class": "write", "category": "pulls"}},
                {"methods": ["DELETE"], "path": "/repos/*/*/git/refs/*", "refuse": true, "operation": {"id": "git/delete-ref", "summary": "s", "class": "guarded", "category": "git"}}]},
              {"name": "git", "git": {"repos": ["*"], "push": "ask"}, "paths": []},
              {"name": "gh", "paths": [], "graphql": [{"path": "/graphql", "unmatched": "ask",
                "query": {"operation": {"id": "graphql-query", "summary": "s", "class": "read", "category": "graphql"}},
                "mutations": [
                  {"field": "mergePullRequest", "ask": true, "operation": {"id": "mergePullRequest", "summary": "s", "class": "write", "category": "pulls"}},
                  {"field": "closePullRequest", "ask": true, "operation": {"id": "closePullRequest", "summary": "s", "class": "write", "category": "pulls"}},
                  {"field": "deleteIssue", "refuse": true, "operation": {"id": "deleteIssue", "summary": "s", "class": "guarded", "category": "issues"}}],
                "subscriptions": []}]}]}'
            apply() { jq -c --arg app "$1" --argjson lists "$2" -f ${./project/lists.jq} <<< "$doc"; }
            answer() { jq -r --arg id "$1" '.routes[].paths[] | select(.operation.id? == $id) | if .refuse then "refuse" elif .ask then "ask" else "allow" end'; }
            fail() { echo "lists: $*" >&2; exit 1; }

            got=$(apply github '{"allow": ["category:pulls"], "ask": ["git/delete-ref"], "refuse": ["pulls/merge"]}')
            [ "$(answer pulls/create <<< "$got")" = allow ] || fail "a category did not decide"
            [ "$(answer pulls/merge <<< "$got")" = refuse ] || fail "a name did not decide before its category"
            [ "$(answer git/delete-ref <<< "$got")" = ask ] || fail "a guarded operation named could not be asked about"
            got=$(apply github '{"allow": ["category:git"]}')
            [ "$(answer git/delete-ref <<< "$got")" = allow ] || fail "a category did not decide its guarded operation"

            got=$(apply github '{"allow": [{"methods": ["POST"], "path": "/markdown/x"}], "ask": [], "refuse": []}')
            jq -e '.routes[0].paths[-1] == {"methods": ["POST"], "path": "/markdown/x"}' <<< "$got" >/dev/null \
              || fail "an endpoint the description does not name was not added"

            # A GraphQL mutation is named, and its category decided, as any
            # operation is; and GraphQL's path is not a project's to name.
            field() { jq -r --arg f "$1" '.routes[2].graphql[0].mutations[] | select(.field == $f) | if .refuse then "refuse" elif .ask then "ask" else "allow" end'; }
            got=$(apply gh '{"allow": ["category:pulls", "deleteIssue"], "ask": [], "refuse": ["mergePullRequest"]}')
            [ "$(field closePullRequest <<< "$got")" = allow ] || fail "a GraphQL category did not decide"
            [ "$(field mergePullRequest <<< "$got")" = refuse ] || fail "a GraphQL mutation's name did not decide before its category"
            [ "$(field deleteIssue <<< "$got")" = allow ] || fail "a guarded GraphQL mutation named could not be allowed"
            got=$(apply gh '{"allow": [], "ask": [], "refuse": ["graphql-query"]}')
            jq -e '.routes[2].graphql[0].query.refuse' <<< "$got" >/dev/null || fail "GraphQL's query was not decided by its name"
            ! apply gh '{"allow": [{"methods": ["POST"], "path": "/graphql"}]}' 2>/dev/null \
              || fail "GraphQL's path was allowed as an endpoint"

            got=$(apply git '{"allow": ["git-receive-pack"], "ask": [], "refuse": []}')
            [ "$(jq -r '.routes[1].git.push' <<< "$got")" = allow ] || fail "git's push was not decided by its operation"

            for bad in '{"allow": ["pulls/nope"]}' '{"allow": ["category:nope"]}'; do
              ! apply github "$bad" 2>/dev/null || fail "an unknown name was applied: $bad"
            done
            ! apply cloudflare '{"allow": ["x"]}' 2>/dev/null || fail "an app the tier does not have was applied"
            # A path an operation describes is that operation, and is named:
            # a literal would otherwise outrank the guarded rule unnamed.
            ! apply github '{"allow": [{"methods": ["DELETE"], "path": "/repos/me/app/git/refs/main"}]}' 2>/dev/null \
              || fail "a path an operation describes was allowed without naming it"

            # An envelope approved before its apps' empty fields were left
            # out reads as the same envelope now.
            normal() { jq -cS -f ${./project/normal.jq}; }
            old='{"secrets": "s.yaml", "seccomp": {"allow": [], "deny": []}, "bindings": {"github": {"allow": ["x"], "ask": [], "refuse": []}, "cloudflare": {"allow": [], "credential": {"secret": null}, "accountId": null}}}'
            new='{"secrets": "s.yaml", "bindings": {"github": {"allow": ["x"]}}}'
            [ "$(normal <<< "$old")" = "$(normal <<< "$new")" ] || fail "an envelope approved before reads as another: $(normal <<< "$old")"
            [ "$(normal <<< '{"secrets": "s.yaml"}')" = '{"secrets":"s.yaml"}' ] || fail "an envelope without bindings was changed"
            # Docker's binding is new: an envelope that names no image and no
            # port reads as one approved before there was a binding to name.
            old='{"secrets": "s.yaml", "bindings": {"github": {"allow": ["x"]}}}'
            new='{"secrets": "s.yaml", "bindings": {"github": {"allow": ["x"]}, "docker": {"images": [], "ports": []}}}'
            [ "$(normal <<< "$old")" = "$(normal <<< "$new")" ] || fail "an envelope without Docker reads as another: $(normal <<< "$new")"
            jq -e '.bindings.docker == {"images": ["postgres:18"]}' <<< "$(normal <<< '{"bindings": {"docker": {"images": ["postgres:18"], "ports": []}}}')" >/dev/null \
              || fail "an envelope's Docker images were not kept"
            jq -e '.bindings.docker == {"ports": [5432]}' <<< "$(normal <<< '{"bindings": {"docker": {"images": [], "ports": [5432]}}}')" >/dev/null \
              || fail "an envelope's Docker ports were not kept"
            touch $out
          '';

          # GOOGLE CLOUD AT LAUNCH (docs/gcloud.md, decisions 2, 3, 5 and 9):
          # the tier's APIs and the project's changes to them, answered as
          # the tier says and then as the project's lists say; the session's
          # key, made once and never the real one; the first token and the
          # renewer; and a document frisket accepts. The renewer and
          # systemctl are stand-ins that say what they were asked.
          gcloud-launch =
            let
              lib = nixpkgs.lib;
              config = (lib.nixosSystem {
                inherit system;
                modules = [
                  self.nixosModules.default
                  home-manager.nixosModules.home-manager
                  ./examples/tiers.nix
                  {
                    boot.isContainer = true;
                    system.stateVersion = "26.05";
                    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
                    home-manager.users.alice.home.stateVersion = "26.05";
                    chase = {
                      user = "alice";
                      uid = 1000;
                      gid = 100;
                      bindings = {
                        claude.package = pkgs.hello;
                        codex.package = pkgs.hello;
                        github.credentialFile = "/run/secrets/gh_token";
                      };
                      tiers.trusted.apps.gcloud = { enable = true; apis = [ "bigquery" "storage" ]; };
                      tiers.loose = {
                        egress = "direct";
                        envelope = true;
                        unmatched = "allow";
                        guarded = "allow";
                        apps.gcloud = { enable = true; apis = [ "bigquery" ]; };
                      };
                      tiers.closed = {
                        egress = "direct";
                        envelope = true;
                        writes = "refuse";
                        guarded = "refuse";
                        unmatched = "refuse";
                        apps.gcloud.enable = true;
                      };
                    };
                  }
                ];
              }).config;
              frisket = self.inputs.frisket.packages.${system}.default;
            in
            pkgs.runCommand "gcloud-launch" { nativeBuildInputs = [ pkgs.jq pkgs.openssl frisket ]; } ''
              fail() { echo "gcloud-launch: $*" >&2; exit 1; }
              mkdir bin run run/secrets env
              cat > bin/chase-gcloud-renew <<'EOF'
              #!${pkgs.runtimeShell}
              echo "$CHASE_GCLOUD_SA $*" >> "$TMPDIR/renew.log"
              printf '{"access_token": "t", "expiry": 1}' > "$2/gcloud-token.json"
              exit "''${RENEW_RC:-0}"
              EOF
              cat > bin/systemctl <<'EOF'
              #!${pkgs.runtimeShell}
              echo "$XDG_RUNTIME_DIR $*" >> "$TMPDIR/systemctl.log"
              EOF
              chmod +x bin/*
              sed "s|^export PATH=\"|export PATH=\"$PWD/bin:|" ${config.chase.internal.projectApps.gcloud.prepare} > prepare
              run=$PWD/run/agent-trusted-1-2
              mkdir -p "$run/secrets"
              sa=agent@p.iam.gserviceaccount.com
              openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null \
                | jq -Rs --arg e "$sa" '{type: "service_account", project_id: "p", private_key_id: "real", private_key: ., client_email: $e, client_id: "1"}' > real.json
              cp real.json "$run/secrets/gcloud"
              prepare() { # TIER BINDING
                jq -c . <<< "$2" | bash ./prepare "$1" /ws "$run" "$PWD/env"
              }
              binding() { jq -nc --arg sa "$sa" --argjson apis "$1" '{serviceAccount: $sa, credential: {secret: "gcloud-key"}, apis: $apis}'; }
              answer() { jq -r --arg id "$1" '[.routes[] | select(.name == "gcloud") | .paths[] | select(.operation.id? == $id)] | if . == [] then "absent" else .[0] | if .refuse then "refuse" elif .ask then "ask" else "allow" end end'; }

              patch=$(prepare trusted "$(binding '{"add": ["pubsub"], "remove": ["storage"]}')") || fail "a binding was not prepared"
              route=$(jq -c '.routes[] | select(.name == "gcloud")' <<< "$patch")
              carried() { jq -c '[.paths[].operation.category // empty] | unique'; }
              [ "$(carried <<< "$route")" = '["bigquery","google.iam.v1.IAMPolicy","pubsub"]' ] \
                || fail "the APIs are not the tier's with the project's changes: $(carried <<< "$route")"
              jq -e '.paths | group_by([.methods, .path, .prefix]) | all(length == 1)' <<< "$route" >/dev/null || fail "a rule is there twice"
              jq -e '.unmatched == "ask" and .credentialFile == "'"$run"'/gcloud-token.json" and .credentialJSON == {token: "access_token", expiresMillis: "expiry"}
                and .host == "*.googleapis.com" and .upstream == "https://*.googleapis.com" and .placeholder == "proxy-injected"
                and .sessionKey.issuer == "'"$sa"'" and .sessionKey.grants == ["oauth2.googleapis.com/token", "www.googleapis.com/oauth2/v4/token"]' <<< "$route" >/dev/null \
                || fail "the route is not Google's: $(jq -c 'del(.paths)' <<< "$route")"
              jq -e '.routes[] | select(.name == "gcloud-mtls") | .host == "*.mtls.googleapis.com" and .paths[0].refuse and .paths[0].prefix == "/" and (has("credentialFile") | not)' <<< "$patch" >/dev/null \
                || fail "the mtls hosts are not refused whole"
              [ "$(answer bigquery.datasets.get <<< "$patch")" = allow ] || fail "a read is not allowed"
              [ "$(answer bigquery.datasets.insert <<< "$patch")" = ask ] || fail "a write does not ask"
              [ "$(answer pubsub.projects.topics.delete <<< "$patch")" = refuse ] || fail "a guarded operation is not refused"

              # Every API's guarded operations are in the route, carried or
              # not, answered as the tier's guarded says: what returns a
              # credential too, and a carried API's "*" does not decide them.
              credentials="bigquery.batch iamcredentials.projects.serviceAccounts.generateAccessToken google.iam.credentials.v1.IAMCredentials.SignJwt
                sts.token iam.projects.serviceAccounts.keys.create storage.projects.hmacKeys.create secretmanager.projects.secrets.versions.access
                google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion contactcenterinsights.projects.locations.conversations.generateSignedAudio
                google.cloud.edgecontainer.v1.EdgeContainer.GenerateAccessToken"
              for id in $credentials storage.buckets.delete compute.instances.delete; do
                [ "$(answer "$id" <<< "$patch")" = refuse ] || fail "$id is not refused by default"
              done
              [ "$(jq -r '.paths[] | select(.path == "/v1/projects/*/locations/*/conversations/*:generateSignedAudio" and .methods[0] == "GET") | .refuse' <<< "$route")" = true ] \
                || fail "another API's signed audio is not refused"
              [ "$(jq -r '[.paths[] | select(.operation.id? == "iamcredentials.projects.serviceAccounts.generateAccessToken")][0].operation | has("category") or has("description")' <<< "$route")" = false ] \
                || fail "an API the session does not carry has a category in it"

              # The session's key: the service account and its project, a key
              # of its own, and its public half in the route.
              key=$(jq -r .env.GOOGLE_APPLICATION_CREDENTIALS <<< "$patch")
              case $key in "$PWD"/env/gcloud-key-*.json) ;; *) fail "the key is not the checkout's: $key" ;; esac
              [ "$(jq -r .env.CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE <<< "$patch")" = "$key" ] || fail "gcloud is not given the key"
              jq -e --arg e "$sa" '.type == "service_account" and .client_email == $e and .project_id == "p" and .private_key_id != "real" and (has("client_id") | not)' "$key" >/dev/null \
                || fail "the session's key is not the service account's shape"
              [ "$(jq -r .sessionKey.publicKey <<< "$route")" = "$(jq -r .private_key "$key" | openssl pkey -pubout)" ] || fail "the route does not hold the session key's public half"
              [ "$(jq -r .sessionKey.publicKey <<< "$route")" != "$(jq -r .private_key real.json | openssl pkey -pubout)" ] || fail "the session holds the real key"
              id=$(jq -r .private_key_id "$key")
              prepare trusted "$(binding '{}')" > /dev/null
              [ "$(jq -r .private_key_id "$key")" = "$id" ] || fail "the checkout's key was made again"
              grep -qx "$sa mint $run" renew.log || fail "no first token was minted: $(cat renew.log)"

              # Another account, launched from the same checkout, has a key of
              # its own and leaves this one's for the session that has it.
              other=$PWD/run/agent-trusted-3-4
              mkdir -p "$other/secrets"
              jq '.client_email = "other@p.iam.gserviceaccount.com"' real.json > "$other/secrets/gcloud"
              theirs=$(jq -c '.serviceAccount = "other@p.iam.gserviceaccount.com"' <<< "$(binding '{}')" | bash ./prepare trusted /ws "$other" "$PWD/env" | jq -r .env.GOOGLE_APPLICATION_CREDENTIALS)
              [ "$theirs" != "$key" ] && [ "$(jq -r .client_email "$theirs")" = other@p.iam.gserviceaccount.com ] || fail "another account took this one's key"
              [ "$(jq -r .private_key_id "$key")" = "$id" ] && [ "$(jq -r .client_email "$key")" = "$sa" ] || fail "another account's launch changed this one's key"
              grep -qx "/run/user/1000 --user start chase-gcloud-renew@agent-trusted-1-2.service" systemctl.log || fail "the renewer was not started: $(cat systemctl.log)"

              # Merged into the tier's document, with a project's lists.
              doc=$(jq -c --slurpfile patch <(printf '%s' "$patch") -f ${./project/merge.jq} <<< '{"name": "trusted", "allow": ["github.com"], "routes": [{"name": "gcloud", "host": "x"}]}')
              jq -e '.allow == ["*.googleapis.com", "github.com"] and ([.routes[].name] == ["gcloud", "gcloud-mtls"])' <<< "$doc" >/dev/null \
                || fail "the routes were not merged: $(jq -c '{allow, names: [.routes[].name]}' <<< "$doc")"
              listed=$(jq -c --arg app gcloud --argjson lists '{"allow": ["category:bigquery"], "ask": ["pubsub.projects.topics.delete"], "refuse": []}' -f ${./project/lists.jq} <<< "$doc")
              [ "$(answer bigquery.datasets.insert <<< "$listed")" = allow ] || fail "category:bigquery did not decide"
              [ "$(answer pubsub.projects.topics.delete <<< "$listed")" = ask ] || fail "a name did not decide"
              [ "$(answer bigquery.datasets.delete <<< "$listed")" = allow ] && [ "$(answer bigquery.batch <<< "$listed")" = allow ] \
                || fail "category:bigquery did not decide its guarded operations"
              [ "$(answer iamcredentials.projects.serviceAccounts.generateAccessToken <<< "$listed")" = refuse ] || fail "a category decided another API's"
              ! jq -c --arg app gcloud --argjson lists '{"allow": ["category:storage"], "ask": [], "refuse": []}' -f ${./project/lists.jq} <<< "$doc" 2>/dev/null \
                || fail "a category of an API the session does not carry was applied"

              # Any operation can be named, guarded ones too, and one of an
              # API the session does not carry.
              named=$(jq -c --arg app gcloud --argjson lists '{"allow": ["iamcredentials.projects.serviceAccounts.generateAccessToken"], "ask": ["storage.buckets.delete"], "refuse": []}' -f ${./project/lists.jq} <<< "$doc") \
                || fail "a guarded operation of an API the session does not carry could not be named"
              [ "$(answer iamcredentials.projects.serviceAccounts.generateAccessToken <<< "$named")" = allow ] || fail "a name did not allow what returns a credential"
              [ "$(answer storage.buckets.delete <<< "$named")" = ask ] || fail "a name did not ask for another API's guarded operation"
              [ "$(answer iamcredentials.projects.serviceAccounts.signJwt <<< "$named")" = refuse ] || fail "a name decided another operation"
              printf '%s' '{"access_token": "t", "expiry": 1}' > "$run/gcloud-token.json"
              printf '%s\n' "$listed" > policy.json
              frisket check policy.json || fail "frisket refused the document"
              printf '%s\n' "$named" > named.json
              frisket check named.json || fail "frisket refused a document naming an API the session does not carry"

              # What is unmatched is allowed where the tier says so, and every
              # guarded operation, what returns a credential too, is allowed
              # where guarded is.
              loose=$(prepare loose "$(binding '{}')")
              jq -e '.routes[0].paths[-1] == {methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], prefix: "/"} and .routes[0].unmatched == "refuse"' \
                <<< "$loose" >/dev/null || fail "an unmatched allow has no catch-all"
              for id in bigquery.datasets.delete $credentials; do
                [ "$(answer "$id" <<< "$loose")" = allow ] || fail "$id was not allowed where guarded is"
              done

              # A tier that carries no API and refuses everything still has a
              # route frisket takes, and refuses what returns a credential.
              closed=$(prepare closed "$(binding '{}')")
              for id in $credentials; do
                [ "$(answer "$id" <<< "$closed")" = refuse ] || fail "$id is not refused where nothing is carried"
              done
              jq -c --slurpfile patch <(printf '%s' "$closed") -f ${./project/merge.jq} <<< '{"name": "closed", "allow": [], "routes": []}' > closed.json
              frisket check closed.json || fail "frisket refused a tier that carries no API"

              # Refused: an API with no name, a key for someone else, and
              # Google refusing the key. Google out of reach only warns.
              refused() { # WHAT NEEDLE TIER BINDING
                if said=$(prepare "$3" "$4" 2>&1 >/dev/null); then fail "$1 was not refused"; fi
                case $said in *"$2"*) ;; *) fail "$1: expected '$2' in: $said" ;; esac
              }
              refused "an unknown API" "no Google API named nope" trusted "$(binding '{"add": ["nope"]}')"
              refused "no service account" "no serviceAccount" trusted '{"credential": {"secret": "gcloud-key"}}'
              refused "a key for another account" "the key is for 'agent@p.iam.gserviceaccount.com', not other@p" trusted \
                "$(jq -c '.serviceAccount = "other@p"' <<< "$(binding '{}')")"
              RENEW_RC=2 refused "a key Google refuses" "Google refused" trusted "$(binding '{}')"
              RENEW_RC=3 refused "a key the renewer finds is not the account's" "is not $sa's" trusted "$(binding '{}')"
              said=$(RENEW_RC=1 prepare trusted "$(binding '{}')" 2>&1 >/dev/null) || fail "Google out of reach ended the launch"
              case $said in *"renewer keeps trying"*) ;; *) fail "Google out of reach was not said: $said" ;; esac

              # The session's end stops the renewer, before its directory goes.
              poststop=$(cat ${lib.head (lib.findFirst (c: lib.hasInfix "chase-agent-trusted-poststop" (lib.head c)) [ "/nonexistent" ] config.flong.agent-trusted.postStop)})
              stop=$(grep -n chase-gcloud-stop <<< "$poststop" | cut -d: -f1 || true)
              rm=$(grep -n 'rm -rf' <<< "$poststop" | cut -d: -f1 || true)
              [ -n "$stop" ] && [ "$stop" -lt "$rm" ] || fail "postStop does not stop the renewer first: $poststop"
              grep -q 'stop "chase-gcloud-renew@$1.service"' ${config.chase.internal.projectApps.gcloud.stop} || fail "the stop names another unit"
              : ${toString (lib.filter (p: lib.getName p == "chase-envelope") config.flong.agent-trusted.path)}

              # A tier without gcloud says so, and keeps no secret.
              [ "$(prepare strict "$(binding '{}')" 2>/dev/null)" = '{}' ] && [ ! -e "$run/secrets/gcloud" ] \
                || fail "a tier without gcloud prepared it"
              touch $out
            '';

          # GOOGLE CLOUD'S GENERATOR (docs/gcloud.md, decision 8), run on a
          # small API of each kind: Discovery and protos, a proto-only API, a
          # mixin. Every way the classification can be wrong is refused.
          gcloud = pkgs.runCommand "gcloud"
            { nativeBuildInputs = [ pkgs.jq pkgs.protobuf (pkgs.python3.withPackages (p: [ p.protobuf p.pyyaml ])) ]; }
            ''
              cp -r ${./tests/gcloud} t && chmod -R u+w t && cd t
              fail() { echo "gcloud: $*" >&2; exit 1; }
              entries=$TMPDIR/entries
              printf '%s\n' demo/v1/demo.proto other/v1/other.proto other/v1beta1/other.proto whole/v1/whole.proto google/longrunning/operations.proto > "$entries"
              (cd googleapis && xargs protoc -I . --include_imports --include_source_info --descriptor_set_out=$TMPDIR/d.pb < "$entries")
              generate() { python3 ${./scripts/gcloud.py} generate app discoveries googleapis $TMPDIR/d.pb "$entries"; }
              rule() { jq -c --arg m "$2" --arg p "$3" '.[] | select(.methods[0] == $m and (.path // .prefix) == $p)' "app/apis/$1.json"; }
              class() { rule "$@" | jq -r .operation.class; }

              generate
              [ "$(class demo GET '/v1/projects/*/secrets/*/versions/*:access')" = guarded ] || fail "an exception did not decide"
              [ "$(class demo GET '/v1/projects/*/secrets/*/versions/*')" = read ] || fail "*:verb was not its own template"
              [ "$(class demo POST '/v1/projects/*/secrets/*:getIamPolicy')" = read ] || fail "a pattern did not decide"
              [ "$(class demo POST '/v1/projects/*/secrets/*:setIamPolicy')" = guarded ] || fail "setIamPolicy is not guarded"
              [ "$(class demo DELETE '/v1/projects/*/secrets/*')" = guarded ] || fail "a DELETE is not guarded"
              [ "$(class demo POST '/batch')" = guarded ] || fail "the batch path is not guarded"
              [ "$(class demo POST '/demo.v1.Secrets/AccessSecretVersion')" = guarded ] || fail "gRPC was not classed as the REST it maps to"
              [ "$(class demo POST '/demo.v1.Secrets/DeleteThing')" = guarded ] || fail "an RPC with no HTTP rule was not classed by its name"
              [ "$(rule demo POST '/demo.v1.Secrets/GetSecret' | jq -r .operation.summary)" = "Gets a Secret." ] || fail "a proto's own words were not used"
              [ "$(rule demo POST '/google.longrunning.Operations/GetOperation' | jq -r .operation.category)" = google.longrunning.Operations ] || fail "a mixin is not its own"
              [ "$(rule demo GET '/v1/b/*/o/*' | jq -r .encodedSlashes)" = true ] || fail "an object's name cannot hold a slash"
              [ "$(rule demo GET '/v1/projects/*/secrets/*' | jq -r .encodedSlashes)" = null ] || fail "encodedSlashes where nothing said so"
              [ "$(rule demo PUT '/upload/v1/b/*/o' | jq -r '.operation | .id + " " + .class')" = "demo.objects.insert.continue read" ] \
                || fail "a resumable upload's continuing PUT is not a read of its own"
              [ "$(class demo POST '/upload/v1/b/*/o')" = write ] && [ "$(class demo POST '/resumable/upload/v1/b/*/o')" = write ] \
                || fail "an upload's first request is not its method's class"
              [ "$(rule demo PUT '/upload/v1/b/*/o/*' | jq -r '.operation | .id + " " + .class')" = "demo.objects.update write" ] \
                && [ "$(class demo PUT '/resumable/upload/v1/b/*/o/*')" = write ] || fail "a PUT method's own upload was taken for a continuation"
              [ "$(class demo GET '/download/v1/b/*/o/*')" = read ] || fail "a download has no rule"
              [ "$(class demo GET '/v2/projects/*/secrets/*')" = read ] || fail "a stable version that is not preferred was left out"
              [ "$(rule demo GET '/v1/projects/*/locations/*/secrets/*' | jq -r .operation.id)" = demo.v1.Secrets.GetSecret ] || fail "an HTTP rule Discovery lacks has no REST rule"
              [ "$(rule demo GET '/v1/projects/*/files' | jq -r '.prefix + " " + (.encodedSlashes | tostring)')" = "/v1/projects/*/files true" ] \
                || fail "a name of any depth at the end is not a prefix, or its flatPath's encodedSlashes were missed"
              [ "$(class demo POST '/v1/operations/*/*/*:cancel')" = write ] && [ "$(class demo POST '/v1/operations/*/*/*/*/*/*/*/*/*/*/*/*:cancel')" = write ] \
                || fail "a name of any depth before a verb is not every depth"
              [ "$(class demo POST '/v1/*:setIamPolicy')" = guarded ] && [ -z "$(rule demo POST '/v1/*/*:setIamPolicy')" ] \
                || fail "a name with nothing literal before a verb was taken for every path ending so"
              jq -e 'length == 3 and all(.operation.class == "guarded")' app/apis/whole.json >/dev/null || fail "an API guarded whole has a rule that is not guarded"
              ! grep -q v1beta1 app/apis/demo.json || fail "a beta that is not preferred was generated"
              [ "$(rule other GET '/v1/things' | jq -r .operation.id)" = other.v1.Things.ReadThing ] || fail "a proto-only API's ** is not a prefix"
              ! grep -q v1beta1 app/apis/other.json || fail "a proto-only API's older version was generated"
              [ ! -e app/apis/gone.json ] || fail "an API with no document was generated"
              jq -e '.demo.streaming == ["demo.v1.Secrets.StreamSecrets"] and .demo.hosts == ["demo.europe-west1.rep.googleapis.com", "demo.googleapis.com"]' app/index.json >/dev/null \
                || fail "the index is wrong: $(cat app/index.json)"
              jq -e -s 'all(.[][]; (keys - ["methods", "path", "prefix", "encodedSlashes", "operation"]) == [] and ((.operation | keys) - ["id", "summary", "description", "class", "category"]) == [])' app/apis/*.json >/dev/null \
                || fail "a rule is not frisket's shape"

              refused() { # WHAT JQ NEEDLE [FILE]
                f=''${4:-app/exceptions.json}
                cp "$f" $TMPDIR/e.json
                jq "$2" $TMPDIR/e.json > "$f"
                if said=$(generate 2>&1); then fail "$1 was not refused"; fi
                case $said in *"$3"*) ;; *) fail "$1: expected '$3' in: $said" ;; esac
                cp $TMPDIR/e.json "$f"
              }
              refused "two classes on one template, across APIs" '.write["demo.projects.secrets.get"] = "x"' "one method and template, two classes"
              refused "another API's literal deciding a stricter operation" '.guarded["demo.projects.secrets.get"] = "x"' "is more specific than a stricter one"
              refused "an exception naming nothing" '.read["demo.nothing"] = "x"' "exceptions that name no operation"
              refused "an exception that changes nothing" '.guarded["demo.projects.secrets.delete"] = "x"' "the class it has anyway"
              refused "an exception without a reason" '.guarded["demo.objects.insert"] = ""' "needs a reason"
              refused "one name in two classes" '.read["demo.projects.secrets.versions.access"] = "x"' "in more than one class"
              refused "a pattern matching nothing" '.patterns.nothing = {"class": "read", "reason": "x"}' "patterns that match no operation"
              refused "encodedSlashes naming nothing" '.encodedSlashes.demo.nothing = "x"' "encodedSlashes that name no parameter"
              refused "an API guarded whole that is not generated" '.apis.nothing = "x"' "APIs guarded whole that are not generated"
              refused "an API guarded whole without a reason" '.apis.whole = ""' "needs a reason"
              refused "batch without a reason" 'del(.batch)' "batch has no reason"
              refused "resumable without a reason" 'del(.resumable)' "resumable has no reason"
              refused "one operation, two classes" '.resources.projects.resources.secrets.methods.get.httpMethod = "DELETE"' "one operation, two classes" discoveries/demo.v2.json
              refused "a path frisket could not match" '.resources.projects.resources.secrets.methods.get.flatPath = "v2/pro%20jects/{p}"' "a path frisket could not match" discoveries/demo.v2.json
              refused "a version Discovery does not have" '.discovery.versions["demo:v9"] = "x"' "versions not in Discovery's index" app/source.json
              refused "a version with no document" '.discovery.versions["gone:v1"] = "x"' "versions without a document" app/source.json

              # What returns or mints a credential is guarded, in the table as committed.
              jq -e -s --argjson ids '["apikeys.projects.locations.keys.create", "google.api.apikeys.v2.ApiKeys.CreateKey",
                  "androidenterprise.enterprises.getServiceAccount", "androidenterprise.serviceaccountkeys.insert",
                  "notebooks.projects.locations.runtimes.refreshRuntimeTokenInternal", "agentidentitycredentials.projects.locations.authProviders.credentials.retrieve",
                  "redis.projects.locations.clusters.tokenAuthUsers.authTokens.get", "redis.projects.locations.clusters.tokenAuthUsers.authTokens.list",
                  "google.cloud.alloydb.v1.AlloyDBAdmin.GenerateClientCertificate", "iap.setIamPolicy", "compute.instances.update"]' \
                '[.[][] | select(.operation.id as $i | $ids | index($i))] | (map(.operation.id) | unique | length) == ($ids | length) and all(.operation.class == "guarded")' \
                ${./apps/gcloud/apis}/*.json >/dev/null || fail "the committed table does not guard what returns a credential"
              jq -e -s 'all(.[][]; .operation.class == "guarded")' ${./apps/gcloud/apis}/iamcredentials.json ${./apps/gcloud/apis}/sts.json >/dev/null \
                || fail "the committed table does not guard iamcredentials and sts whole"
              [ "$(jq -r '.[] | select(.path == "/v1/projects/*/locations/*/clusters/*:generateClientCertificate") | .operation.class' ${./apps/gcloud/apis}/alloydb.json)" = guarded ] \
                || fail "AlloyDB's REST GenerateClientCertificate is not guarded"
              # An upload's continuing PUT reads; its first request is decided as its method.
              jq -e -s '[.[][] | select(.operation.id | endswith(".continue"))] | length > 0 and all(.methods == ["PUT"] and .operation.class == "read")' \
                ${./apps/gcloud/apis}/*.json >/dev/null || fail "an upload's continuing PUT is not a read"
              [ "$(jq -r '[.[] | select(.path == "/upload/storage/v1/b/*/o") | .methods[0] + " " + .operation.id + " " + .operation.class] | join(", ")' ${./apps/gcloud/apis}/storage.json)" \
                = "POST storage.objects.insert write, PUT storage.objects.insert.continue read" ] || fail "storage's upload is not a write and its continuation a read"
              [ "$(jq -r '.[] | select(.path == "/upload/youtube/v3/captions" and .methods == ["PUT"]) | .operation.id + " " + .operation.class' ${./apps/gcloud/apis}/youtube.json)" \
                = "youtube.captions.update write" ] || fail "a method's own PUT was taken for another's continuation"
              # A bucket's patch and update ask: they can set its ACLs, and a person is asked.
              jq -e -s --argjson ids '["storage.buckets.patch", "storage.buckets.update", "google.storage.v2.Storage.UpdateBucket"]' \
                '[.[][] | select(.operation.id as $i | $ids | index($i))] | (map(.operation.id) | unique | length) == ($ids | length) and all(.operation.class == "write")' \
                ${./apps/gcloud/apis}/*.json >/dev/null || fail "a bucket's patch or update is not a write"
              touch $out
            '';

          # Google Cloud's renewer, against a fake token endpoint that
          # verifies each grant against the key's public half.
          gcloud-renew =
            let
              renew = tokenURL: import ./lib/gcloud-renew.nix { inherit pkgs tokenURL; };
            in
            pkgs.runCommand "gcloud-renew"
              { nativeBuildInputs = [ pkgs.jq pkgs.openssl pkgs.python3 (renew "http://127.0.0.1:18080/token") ]; }
              ''
                fail() { echo "gcloud-renew: $*" >&2; exit 1; }
                within() { local n=$(( $1 * 10 )); shift; while ! "$@"; do n=$((n - 1)); [ $n -gt 0 ] || return 1; sleep 0.1; done; }
                sa=renew@demo.iam.gserviceaccount.com
                f=$TMPDIR/fake said=$TMPDIR/said
                mkdir $f && : > $said && : > $f/log
                for k in sa other; do openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $f/$k.pem 2>/dev/null; done
                openssl pkey -in $f/sa.pem -pubout -out $f/sa.pub
                session() {
                  mkdir -m 0700 "$1" "$1/secrets"
                  jq -n --rawfile k "$f/''${2:-sa}.pem" --arg e "''${3:-$sa}" \
                    '{type: "service_account", project_id: "demo", private_key_id: "x", private_key: $k, client_email: $e}' > "$1/secrets/gcloud"
                }
                python3 ${./tests/gcloud-renew/fakegoogle.py} 18080 $f/sa.pub $sa $f &
                within 10 bash -c 'exec 3<>/dev/tcp/127.0.0.1/18080' 2>/dev/null || fail "the fake did not start"
                requests() { wc -l < $f/log; }
                mint() { # EXIT RUN [SA]
                  local rc=0
                  CHASE_GCLOUD_SA=''${3-} chase-gcloud-renew mint "$2" >>$said 2>&1 || rc=$?
                  [ $rc = "$1" ] || fail "mint $2 exited $rc, not $1: $(tail -n 3 $said)"
                }

                run=$TMPDIR/run && session $run
                before=$(date +%s%3N); mint 0 $run $sa; after=$(date +%s%3N)
                [ "$(stat -c %a $run/gcloud-token.json)" = 600 ] || fail "the token file is not 0600"
                jq -e --arg t "$(tail -n 1 $f/log | jq -r .token)" --argjson lo $((before + 3599000)) --argjson hi $((after + 3599000)) \
                  'keys == ["access_token", "expiry"] and .access_token == $t and .expiry >= $lo and .expiry <= $hi' $run/gcloud-token.json >/dev/null \
                  || fail "the token file is wrong: expiry $(jq .expiry $run/gcloud-token.json), sent $before..$after"
                inode=$(stat -c %i $run/gcloud-token.json)
                mint 0 $run
                [ "$(stat -c %i $run/gcloud-token.json)" != "$inode" ] || fail "the token was not replaced by rename"
                [ "$(ls -A $run | tr '\n' ' ')" = "gcloud-token.json secrets " ] || fail "the run directory holds more: $(ls -A $run)"

                kept=$(cat $run/gcloud-token.json) n=$(requests)
                mint 3 $run other@demo.iam.gserviceaccount.com
                [ "$(requests)" = "$n" ] || fail "a key of another account was sent"
                for code in 400 401 403; do echo $code >> $f/codes; mint 2 $run; done
                echo 500 >> $f/codes; mint 1 $run
                [ "$(cat $run/gcloud-token.json)" = "$kept" ] || fail "a failed mint touched the token"

                session $TMPDIR/forged other && mint 2 $TMPDIR/forged
                [ "$(tail -n 1 $f/log | jq -r .wrong)" = signature ] || fail "the fake took a JWT another key signed"
                session $TMPDIR/stranger sa stranger@demo.iam.gserviceaccount.com && mint 2 $TMPDIR/stranger
                [ "$(tail -n 1 $f/log | jq -r .wrong)" = iss ] || fail "the fake took a JWT from another issuer"
                mkdir -p $TMPDIR/junk/secrets && echo '{}' > $TMPDIR/junk/secrets/gcloud && mint 3 $TMPDIR/junk
                rc=0; ${pkgs.lib.getExe (renew "http://127.0.0.1:1/token")} mint $run >>$said 2>&1 || rc=$?
                [ $rc = 1 ] || fail "an unreachable endpoint exited $rc, not 1"

                # Renewed with ten minutes left, and not before.
                session $TMPDIR/soon
                jq -n --argjson e $(( $(date +%s%3N) + 605000 )) '{access_token: "old", expiry: $e}' > $TMPDIR/soon/gcloud-token.json
                n=$(requests) start=$(date +%s)
                (chase-gcloud-renew loop $TMPDIR/soon >>$said 2>&1; touch $f/soon.done) &
                more() { [ "$(requests)" -gt "$n" ]; }
                within 20 more || fail "the loop did not renew"
                [ $(( $(date +%s) - start )) -ge 4 ] || fail "the loop renewed with more than ten minutes left"
                [ "$(jq -r .access_token $TMPDIR/soon/gcloud-token.json)" != old ] || fail "the loop did not write its token"
                rm -rf $TMPDIR/soon
                within 15 [ -e $f/soon.done ] || fail "the loop outlived its run directory"

                # A failure is tried again a minute later.
                session $TMPDIR/retry
                echo 500 >> $f/codes
                start=$(date +%s)
                (chase-gcloud-renew loop $TMPDIR/retry >>$said 2>&1; touch $f/retry.done) &
                within 90 [ -e $TMPDIR/retry/gcloud-token.json ] || fail "the loop did not try again"
                [ $(( $(date +%s) - start )) -ge 55 ] || fail "the loop tried again too soon"
                rm -rf $TMPDIR/retry
                within 15 [ -e $f/retry.done ] || fail "the loop outlived its run directory"

                grep -vF -- ----- $f/sa.pem $f/other.pem | cut -d: -f2 > $f/secret
                jq -r '(.token // empty), (.assertion | split(".") | .[2] // empty)' $f/log >> $f/secret
                [ "$(wc -l < $f/secret)" -gt 20 ] || fail "nothing to look for"
                ! grep -qFf $f/secret $said || fail "a secret was printed: $(grep -Ff $f/secret $said | head -c 80)"
                cat $said
                touch $out
              '';

          # THE GENERATOR ON A SWAGGER 2.0 SPEC (docs/docker.md, decision 4),
          # offline, on a small spec shaped like the Engine API's: its
          # basePath, its own HEAD, its bodies walked into known.json, and an
          # app admitted rather than classed. What would make it generate for
          # a spec it was not pinned to is refused.
          #
          # Then Docker's own: the Engine API spec its source.json pins,
          # fetched by that hash rather than vendored (it is 470 KB of YAML),
          # which makes it a fixed-output input and so as reproducible as a
          # vendored one. What it generates must be what is committed, so
          # the operations.json and known.json a person reviews are the
          # spec's and admit.json's and nothing else.
          operations = pkgs.runCommand "operations"
            { nativeBuildInputs = [ pkgs.jq (pkgs.python3.withPackages (p: [ p.pyyaml ])) ]; }
            ''
              fail() { echo "operations: $*" >&2; exit 1; }
              app=t/apps/demo
              fresh() {
                rm -rf t && mkdir -p t/scripts t/apps
                cp ${./scripts/operations.sh} t/scripts/operations.sh
                cp -r ${./tests/operations/demo} t/apps/demo
                cp -r ${./tests/operations/legacy} t/apps/legacy
                cp -r ${./apps/docker} t/apps/docker && chmod -R u+w t
              }
              repin() { edit source.json ".sha256 = \"$(sha256sum "$app/$1" | cut -d' ' -f1)\""; }
              generate() { bash t/scripts/operations.sh demo 2>$TMPDIR/err; }
              rule() { jq -c --arg m "$1" --arg p "$2" '.[] | select(.methods == ($m | split(",")) and .path == $p)' $app/operations.json; }
              edit() { jq "$2" "$app/$1" > $TMPDIR/edit && mv $TMPDIR/edit "$app/$1"; }
              refuses() {
                local why=$1; shift
                ! generate || fail "generated anyway: $why"
                grep -qF -- "$1" $TMPDIR/err || fail "$why, refused otherwise: $(cat $TMPDIR/err)"
              }

              fresh
              generate || fail "the fixture did not generate: $(cat $TMPDIR/err)"
              jq -e 'all(.[]; .path | startswith("/v1.2") | not)' $app/operations.json >/dev/null && [ -n "$(rule GET '/things/*/json')" ] \
                || fail "the basePath was not stripped from the templates"
              [ "$(rule HEAD /_ping | jq -r '.operation.id + " " + (.refuse | tostring)')" = "PingHead null" ] \
                || fail "an explicit HEAD is not its own rule: $(rule HEAD /_ping)"
              [ "$(rule GET /_ping | jq -r '.operation.id + " " + (.refuse | tostring)')" = "Ping true" ] \
                || fail "a GET beside an explicit HEAD took HEAD too: $(rule GET /_ping)"
              [ "$(rule GET,HEAD /things/json | jq -r .operation.id)" = ThingList ] \
                || fail "a refused GET with no HEAD of its own does not refuse HEAD too"
              [ "$(rule GET /version | jq -r '.docker.owned')" = none ] && [ -z "$(rule GET,HEAD /version)" ] \
                || fail "an admitted operation does not have exactly the methods admit.json lists"
              [ "$(rule DELETE '/things/*' | jq -c '[.refuse, .operation.id, .operation.summary, .operation.class, .docker]')" = '[true,"ThingDelete","Remove a thing","guarded",null]' ] \
                || fail "an operation admit.json does not name is not refused, with its operation: $(rule DELETE '/things/*')"
              jq -e 'all(.[]; (.operation.id | type) == "string" and (.operation.summary | type) == "string"
                  and (.operation.class | IN("read", "write", "guarded")) and ((.refuse == true) != (.docker != null)))' \
                $app/operations.json >/dev/null || fail "a rule is neither refused nor admitted, or has no operation or class"
              [ "$(rule POST /things/create | jq -c .docker)" = "$(jq -c .ThingCreate.docker $app/admit.json)" ] \
                || fail "an admitted operation does not carry its docker block"

              # A body's fields: through #/parameters, $ref and allOf, and not
              # into an array, a map, or a scalar's allOf.
              want='{"ThingCreate":["Name","Labels","Mounts","Kind","Health","Health.Test","Host","Host.Memory","Host.Binds"]}'
              [ "$(jq -c . $app/known.json)" = "$want" ] || fail "known.json is not the body's fields: $(jq -c . $app/known.json)"
              [ "$(wc -l < $app/known.json)" = 13 ] || fail "known.json is not one field per line"
              cp $app/operations.json $TMPDIR/admitted.json

              # The format from the url, where source.json does not say it.
              edit source.json 'del(.format)'
              generate || fail "a .yaml url was not read as YAML: $(cat $TMPDIR/err)"
              cmp -s $app/operations.json $TMPDIR/admitted.json || fail "the format from the url generated something else"

              # Without admit.json, an app is classed, as every app before
              # Docker is, with no exceptions.json and a HEAD where a GET has
              # none of its own.
              fresh
              rm $app/admit.json
              generate || fail "an app with no admit.json did not generate: $(cat $TMPDIR/err)"
              jq -e 'all(.[]; .refuse == null and .docker == null)' $app/operations.json >/dev/null || fail "an app that is not admitted refused"
              [ "$(rule GET,HEAD /version | jq -r .operation.class)" = read ] || fail "a GET with no HEAD of its own does not take HEAD"
              [ "$(rule GET /_ping | jq -r .operation.id)" = Ping ] && [ "$(rule HEAD /_ping | jq -r .operation.id)" = PingHead ] \
                || fail "a GET beside an explicit HEAD took HEAD too"
              [ ! -e $app/known.json ] || fail "known.json was written for an app that is not admitted"

              fresh; edit admit.json '. + {"NoSuchThing": {"methods": ["GET"], "docker": {"owned": "none"}}}'
              refuses "an admitted operation the spec does not have" "not in the pinned spec: [\"NoSuchThing\"]"
              fresh; edit admit.json '. + {"Ping": {"methods": ["GET", "HEAD"], "docker": {"owned": "none"}}}'
              refuses "HEAD admitted as a GET's where the spec has its own" "admit.json gives Ping"
              fresh; edit admit.json '.Version = {"docker": {"owned": "none"}}'
              refuses "an admitted operation with no methods" "needs its methods and a docker block"
              # A key given twice is refused wherever a person writes it: jq
              # would keep the last, and a reviewer may read the first.
              fresh; sed -i 's/^}$/,"Version": {"methods": ["GET"], "docker": {"owned": "list", "query": {"all": "any"}}}\n}/' $app/admit.json
              refuses "an operation admitted twice, the later one winning" "admit.json gives a key twice"
              fresh; sed -i 's/"owned": "container", "param": 1/"owned": "container", "param": 1, "owned": "none"/' $app/admit.json
              refuses "a docker block that gives a field twice" "admit.json gives a key twice"
              fresh; sed -i '0,/{/s//{"basePath": "\/v1.3",/' $app/source.json
              refuses "a pin that gives a field twice" "source.json gives a key twice"
              fresh; edit admit.json '.ThingInspect.docker.body = "ThingInspect"'
              refuses "a body table for an operation with no body" "the spec gives it 0 bodies"
              fresh; edit source.json '.apiVersions.max = "1.3"'
              refuses "a pin whose version is not the top of the range" "info.version is 1.2, not 1.3"
              fresh; edit source.json '.basePath = "/v1.3"'
              refuses "a spec whose basePath is not the one pinned" "basePath is /v1.2, not /v1.3"
              fresh; edit source.json '.format = "openapi3-yaml"'
              refuses "a format that is not what source.json pins" "format openapi3-yaml, but a swagger2 spec"
              fresh; edit source.json '.sha256 = "0000000000000000000000000000000000000000000000000000000000000000"'
              refuses "a spec that does not hash as pinned" "is not the pinned spec"
              fresh; echo 'x: 1' >> $app/spec.yaml
              refuses "YAML changed after it was pinned" "is not the pinned spec"
              fresh; sed -i 's/^swagger: "2.0"$/swagger: "1.2"/' $app/spec.yaml; repin spec.yaml
              refuses "a basePath spec that is not Swagger 2.0" "swagger is 1.2, not 2.0"

              # In an admitted app, admit.json is all that admits: nothing
              # exceptions.json could add would carry a docker block.
              fresh; echo '{"rules": [{"methods": ["POST"], "prefix": "/things/*", "reason": "x", "class": "write", "operation": {"id": "Hand", "summary": "hand"}}]}' > $app/exceptions.json
              refuses "a hand-written rule in an admitted app" "an admitted app takes no hand-written rules"
              fresh; echo '{"graphql": [{"path": "/graphql", "reason": "x", "operation": {"id": "Q", "summary": "q"}}]}' > $app/exceptions.json
              refuses "a GraphQL endpoint in an admitted app" "an admitted app takes no hand-written rules"
              fresh; echo '{"write": {"Ping": "x"}}' > $app/exceptions.json
              refuses "a reclassification in an admitted app" "an admitted app takes no hand-written rules"

              # OpenAPI 3, as the apps before Docker are: its spec vendored as
              # openapi.json and nowhere else (its url does not resolve), and
              # its templates under the servers url's path, whatever scheme.
              app=t/apps/legacy
              fresh
              bash t/scripts/operations.sh legacy 2>$TMPDIR/err || fail "the OpenAPI 3 fixture did not generate from openapi.json: $(cat $TMPDIR/err)"
              [ "$(rule GET,HEAD /api/v3/items | jq -r '.operation.id + " " + .operation.class')" = "listItems read" ] \
                || fail "an OpenAPI 3 GET is not [GET,HEAD] under the server's path: $(jq -c . $app/operations.json)"
              [ "$(rule POST /api/v3/items | jq -r .operation.class)" = write ] && [ "$(rule DELETE '/api/v3/items/*' | jq -r .operation.class)" = guarded ] \
                || fail "an OpenAPI 3 operation is not under the server's path, as its class: $(jq -c . $app/operations.json)"
              jq -e 'length == 3 and all(.[]; .refuse == null and .docker == null)' $app/operations.json >/dev/null \
                || fail "the OpenAPI 3 fixture generated other rules: $(jq -c . $app/operations.json)"
              cp $app/operations.json $TMPDIR/legacy.json
              fresh
              sed -i 's|https://api.example.invalid/api/v3|http://api.example.invalid/api/v3|' $app/openapi.json $app/source.json; repin openapi.json
              bash t/scripts/operations.sh legacy 2>$TMPDIR/err || fail "an http server did not generate: $(cat $TMPDIR/err)"
              cmp -s $app/operations.json $TMPDIR/legacy.json || fail "an http server's path was not stripped as an https one's"
              fresh; edit source.json '.server = "https://api.example.invalid/api/v4"'
              ! bash t/scripts/operations.sh legacy 2>$TMPDIR/err && grep -qF 'servers is ["https://api.example.invalid/api/v3"], not https://api.example.invalid/api/v4' $TMPDIR/err \
                || fail "a server that is not the spec's was not refused: $(cat $TMPDIR/err)"

              # Docker, from the pinned Engine API spec: what is committed is
              # what it generates, byte for byte.
              app=t/apps/docker
              fresh
              bash t/scripts/operations.sh docker ${pkgs.fetchurl { inherit (builtins.fromJSON (builtins.readFile ./apps/docker/source.json)) url sha256; }} 2>$TMPDIR/err || fail "Docker did not generate from its pinned spec: $(cat $TMPDIR/err)"
              cmp -s $app/operations.json ${./apps/docker/operations.json} \
                || fail "apps/docker/operations.json is not what the pinned spec generates: run scripts/operations.sh docker"
              cmp -s $app/known.json ${./apps/docker/known.json} \
                || fail "apps/docker/known.json is not what the pinned spec generates: run scripts/operations.sh docker"

              # Each admitted operation is one rule, with exactly the methods
              # and docker block admit.json gives it; every other operation is
              # a refusal that names what it refused.
              jq -e --slurpfile admit $app/admit.json '
                  ([.[] | select(.docker != null) | .operation.id] | sort) == ($admit[0] | keys)
                  and all(.[] | select(.docker != null); $admit[0][.operation.id] == { methods, docker })' \
                $app/operations.json >/dev/null || fail "an operation admit.json names is not exactly one rule with its methods and docker block"
              jq -e 'all(.[] | select(.docker == null); .refuse == true and (.operation.id | type) == "string" and .operation.id != "")' \
                $app/operations.json >/dev/null || fail "an operation admit.json does not name is not refused with its operation id"
              [ "$(rule HEAD /_ping | jq -r .operation.id)" = SystemPingHead ] && [ "$(rule GET /_ping | jq -r .operation.id)" = SystemPing ] \
                && [ "$(jq '[.[] | select(.path == "/_ping")] | length' $app/operations.json)" = 2 ] \
                || fail "/_ping is not a HEAD rule and a GET rule of their own: $(jq -c '.[] | select(.path == "/_ping")' $app/operations.json)"
              jq -e 'all(.[]; .path // .prefix | startswith("/v1.") | not)' $app/operations.json >/dev/null \
                || fail "a template still carries the API version"
              [ "$(jq -c 'keys' $app/known.json)" = '["ContainerCreate","ExecCreate","ExecStart","NetworkCreate","VolumeCreate"]' ] \
                || fail "known.json does not hold exactly the admitted body tables: $(jq -c keys $app/known.json)"
              # What was compared above is admit.json as jq parsed it, which
              # keeps the last of a repeated key: so, apart from the
              # generator's own refusal, the text itself names each admitted
              # operation once, and no pinned or admitted field twice.
              for f in admit.json source.json; do
                [ "$(jq -c --stream . $app/$f | wc -l)" = "$(jq -c tostream $app/$f | wc -l)" ] \
                  || fail "apps/docker/$f gives a key twice in one object"
              done
              [ "$(grep -cE '^"[A-Za-z]+": ' $app/admit.json)" = "$(jq 'keys | length' $app/admit.json)" ] \
                && [ "$(jq 'keys | length' $app/admit.json)" = 31 ] \
                || fail "admit.json does not name 31 operations, each once on its own line"
              touch $out
            '';

          # The address and names frisket derives again and refuses a route
          # over, and nix-config derives for /etc/hosts. Every vector in
          # frisket's TestTheDerivationGivesTheContractsVectors
          # (internal/docker/docker_test.go, at the frisket this flake locks)
          # is here, with the same address and names; the rest are chase's
          # own. frisket exports only its reserved list, not the vectors, so
          # this check holds lib.docker to that list itself as well. The
          # script is the module's own chase.internal.dockerAddress, the one a
          # project's prepare step runs, so the vectors test the reserved
          # list the module passes it, not one this check chose.
          docker-address =
            let
              address = (harnessConfig { }).chase.internal.dockerAddress;
              docker = self.lib.docker;
              as = n: nixpkgs.lib.concatStrings (nixpkgs.lib.replicate n "a");
              # Every slug below that is given an address, with what lib.docker
              # makes of it, for the script to be compared against.
              slugs = [
                "triptease/data-lab" "triptease/finance-api" "danielbodart/frisket"
                "test/repo-66" "TripTease/Data-Lab" "bodar/bodar.ts" "bodar/bodar-ts"
                "test/${as 63}" "test/${as 64}" "test/___" "test/..." "test/-x.-" "test/_.._"
                "frisket/docker" "google/metadata" "google/data-lab" "frisket/foo"
                "frisket/frisket" "google/google" "x/frisket"
              ];
              fromNix = map (slug: { inherit slug; address = docker.address slug; names = docker.names slug; }) slugs;
              # Slugs frisket refuses, each of which lib.docker must refuse
              # too; those it gives an address or names to are listed.
              refused = [
                "triptease" "triptease/data-lab/x" "" "${nixpkgs.lib.concatStrings (nixpkgs.lib.replicate 40 "o")}/repo"
                "test/.." "test/." "-test/repo" "test/${nixpkgs.lib.concatStrings (nixpkgs.lib.replicate 101 "r")}"
                "test/a b" "test/repo\nx" "test/ré" "a/b/c" "evil/../data-lab" "a/rép" "/x"
              ];
              acceptedByNix = builtins.filter
                (slug: (builtins.tryEval (docker.address slug)).success
                  || (builtins.tryEval (builtins.deepSeq (docker.names slug) true)).success)
                refused;
            in
            assert nixpkgs.lib.assertMsg (docker.reserved == frisket.lib.docker.reserved)
              "lib.docker reserves ${builtins.toJSON docker.reserved}, but frisket reserves ${builtins.toJSON frisket.lib.docker.reserved}";
            pkgs.runCommand "docker-address" {
              nativeBuildInputs = [ address pkgs.jq ];
              fromNix = builtins.toJSON fromNix;
              acceptedByNix = builtins.toJSON acceptedByNix;
              passAsFile = [ "fromNix" "acceptedByNix" ];
            } ''
              fail() { echo "docker-address: $*" >&2; exit 1; }
              as() { printf 'a%.0s' $(seq "$1"); }
              gives() {
                local got
                got=$(chase-docker-address "$1") || fail "$1 was refused"
                [ "$(jq -r .address <<< "$got")" = "$2" ] || fail "$1 is not at $2: $got"
                [ "$(jq -c .names <<< "$got")" = "$3" ] || fail "$1 is not named $3: $got"
                [ "$(jq -r .project <<< "$got")" = "''${1,,}" ] || fail "$1 is not its own project: $got"
              }
              refuses() {
                ! chase-docker-address "$1" 2>$TMPDIR/err || fail "$1 was given an address"
                [ -s $TMPDIR/err ] || fail "$1 was refused without a reason"
              }

              gives triptease/data-lab 127.1.191.78 '["data-lab.internal","data-lab.triptease.internal"]'
              gives triptease/finance-api 127.6.18.253 '["finance-api.internal","finance-api.triptease.internal"]'
              gives danielbodart/frisket 127.103.202.234 '["frisket.danielbodart.internal"]'
              gives test/repo-66 127.211.18.75 '["repo-66.internal","repo-66.test.internal"]'
              gives TripTease/Data-Lab 127.1.191.78 '["data-lab.internal","data-lab.triptease.internal"]'

              # The label folds "." to "-", so two repos of one owner can
              # share both names, at different addresses.
              gives bodar/bodar.ts 127.100.84.99 '["bodar-ts.internal","bodar-ts.bodar.internal"]'
              gives bodar/bodar-ts 127.113.253.232 '["bodar-ts.internal","bodar-ts.bodar.internal"]'

              # A DNS label is at most 63 characters, and a repo that folds
              # to nothing leaves no label at all.
              gives "test/$(as 63)" 127.9.96.222 "[\"$(as 63).internal\",\"$(as 63).test.internal\"]"
              gives "test/$(as 64)" 127.60.34.62 '[]'
              [ "$(chase-docker-address test/___ | jq -c .names)" = '[]' ] || fail "a repo of only underscores was named"
              [ "$(chase-docker-address test/... | jq -c .names)" = '[]' ] || fail "a repo of only dots was named"
              [ "$(chase-docker-address test/-x.- | jq -c .names)" = '["x.internal","x.test.internal"]' ] \
                || fail "the label's ends were not trimmed"

              # A name that is already something else's is never generated.
              [ "$(chase-docker-address frisket/docker | jq -c .names)" = '["docker.internal"]' ] \
                || fail "frisket/docker was given frisket's own route host"
              [ "$(chase-docker-address google/metadata | jq -c .names)" = '["metadata.internal"]' ] \
                || fail "google/metadata was given GCE's metadata server"

              # All of frisket.internal and google.internal is reserved, as
              # frisket and nix-config hold it: an owner frisket or google
              # keeps only its short name, and repo "frisket" or "google" has
              # no short name either.
              [ "$(chase-docker-address google/data-lab | jq -c .names)" = '["data-lab.internal"]' ] \
                || fail "google/data-lab was given a name under google.internal"
              [ "$(chase-docker-address frisket/foo | jq -c .names)" = '["foo.internal"]' ] \
                || fail "frisket/foo was given a name under frisket.internal"
              [ "$(chase-docker-address frisket/frisket | jq -c .names)" = '[]' ] \
                || fail "frisket/frisket was given a name under frisket.internal"
              [ "$(chase-docker-address google/google | jq -c .names)" = '[]' ] \
                || fail "google/google was given a name under google.internal"
              [ "$(chase-docker-address x/frisket | jq -c .names)" = '["frisket.x.internal"]' ] \
                || fail "x/frisket was given frisket.internal"
              [ "$(chase-docker-address test/_.._ | jq -c .names)" = '[]' ] \
                || fail "a repo of only punctuation was named"

              # What frisket would refuse as a route's project is refused here.
              refuses triptease
              refuses triptease/data-lab/x
              refuses ""
              refuses "$(printf 'o%.0s' $(seq 40))/repo"
              refuses test/..
              refuses test/.
              refuses -test/repo
              refuses "test/$(printf 'r%.0s' $(seq 101))"
              refuses "test/a b"
              refuses "$(printf 'test/repo\nx')"
              refuses test/ré
              chase-docker-address "$(printf 'o%.0s' $(seq 39))/repo" >/dev/null || fail "a 39-character owner was refused"
              chase-docker-address "test/$(printf 'r%.0s' $(seq 100))" >/dev/null || fail "a 100-character repo was refused"

              # lib.docker, which a consumer writing /etc/hosts uses, gives
              # every slug above the address and names this script does.
              [ "$(jq length "$fromNixPath")" -eq ${toString (builtins.length slugs)} ] || fail "the slugs from Nix did not arrive"
              while IFS= read -r want; do
                slug=$(jq -r .slug <<< "$want")
                got=$(chase-docker-address "$slug") || fail "$slug was refused"
                [ "$(jq -c '{address, names}' <<< "$got")" = "$(jq -c '{address, names}' <<< "$want")" ] \
                  || fail "lib.docker gives $slug $want, but chase-docker-address gives $got"
              done < <(jq -c '.[]' "$fromNixPath")

              # And lib.docker refuses what the script refuses, rather than
              # naming a project frisket could never route.
              [ "$(jq -c . "$acceptedByNixPath")" = '[]' ] \
                || fail "lib.docker gave an address or names to $(jq -c . "$acceptedByNixPath")"
              for slug in a/b/c evil/../data-lab a/rép /x; do refuses "$slug"; done

              touch $out
            '';

          # WHAT A DOCKER BODY MAY HOLD (docs/docker.md): the hand-written
          # tables in apps/docker/fields.json, one per body admit.json names,
          # each judging every field the pinned spec knows. A field the spec
          # gained on a bump, and the table does not name, would be refused
          # at the first request that sets it, so a bump that leaves one out
          # fails here instead, where a person reads the new row.
          #
          # A known path is either a row, or lies under a row whose spec
          # has no fields of its own -- a zero, such as NetworkCreate's IPAM
          # -- which judges everything beneath it at once. frisket refuses a
          # row under such a spec, so those paths cannot be rows; the rows
          # left, less the `*` rows under a map, which the spec never names,
          # are exactly the known paths.
          #
          # The tables are frisket's internal/docker/testdata/fields.json,
          # byte for byte, at the frisket this flake locks. frisket's own
          # tests judge the bodies Compose really sent, and every refusal its
          # floor makes, against that copy, so the tables chase serves are
          # the ones those tests passed; a change is made there first and
          # reaches chase with the input.
          #
          # Last, frisket itself loads a session's document built from the
          # files, with the address and names chase-docker-address gives, so
          # a table weaker than frisket's floor, or names frisket would not
          # derive, fails here rather than when a session will not start.
          docker-fields =
            let
              address = (harnessConfig { }).chase.internal.dockerAddress;
              frisketPackage = frisket.packages.${system}.default;
            in
            pkgs.runCommand "docker-fields" { nativeBuildInputs = [ address frisketPackage pkgs.jq ]; } ''
              fail() { echo "docker-fields: $*" >&2; exit 1; }
              app=t/apps/docker
              fresh() { rm -rf t && mkdir -p t/apps && cp -r ${./apps/docker} $app && chmod -R u+w t; }
              edit() { jq "$2" "$app/$1" > $TMPDIR/edit && mv $TMPDIR/edit "$app/$1"; }

              # What a jq judgement prints is why it refused. A jq that could
              # not run prints nothing too, so it ends the build rather than
              # passing as a judgement with nothing to say.
              said() { [ -z "$1" ] || { echo "$1" >&2; return 1; }; }

              # Each admitted body has a table, and each table is a body
              # admit.json names: a table nobody names is one nobody reviews
              # as in use.
              tables() {
                local msg
                msg=$(jq -r -n --slurpfile admit $app/admit.json --slurpfile fields $app/fields.json '
                  ([$admit[0][] | .docker.body // empty] | unique) as $bodies
                  | ($bodies - ($fields[0] | keys)) as $none
                  | (($fields[0] | keys) - $bodies) as $spare
                  | if $none != [] then "admitted with no table: \($none | join(", "))"
                    elif $spare != [] then "a table no admitted operation names: \($spare | join(", "))"
                    else empty end') || fail "admit.json and fields.json could not be read"
                said "$msg"
              }

              # Per table, the known paths not under a leaf row are exactly
              # the rows that are not under a map's `*`.
              total() {
                local msg
                msg=$(jq -r -n --slurpfile known $app/known.json --slurpfile fields $app/fields.json '
                  [ ($fields[0] | keys[]) as $t
                    | ($fields[0][$t]) as $rows
                    | [$rows | to_entries[] | select(.value != "struct" and ((.value | type) != "string" or (.value | startswith("map/") | not))) | .key] as $leaves
                    | [($known[0][$t] // [])[] | . as $p | select(any($leaves[]; . as $l | $p | startswith($l + ".")) | not)] as $judged
                    | [$rows | keys[] | select(split(".") | index("*") | not)] as $named
                    | ($judged - $named | sort) as $missing
                    | ($named - $judged | sort) as $unknown
                    | if $missing != [] then "\($t) has no row for \($missing | join(", "))"
                      elif $unknown != [] then "\($t) has a row the pinned spec does not know: \($unknown | join(", "))"
                      else empty end
                  ] | if . == [] then empty else join("; ") end') || fail "known.json and fields.json could not be read"
                said "$msg"
              }

              # The route chase-docker-prepare will write, for one project,
              # with every rule operations.json generates and the table for
              # each body admit.json names.
              sample() {
                local who
                who=$(chase-docker-address triptease/data-lab) || fail "data-lab was given no address"
                jq -n --argjson who "$who" \
                  --slurpfile ops $app/operations.json --slurpfile admit $app/admit.json \
                  --slurpfile fields $app/fields.json --slurpfile source $app/source.json '{
                    name: "trusted",
                    allow: ["docker.frisket.internal"],
                    routes: [{
                      name: "docker",
                      host: "docker.frisket.internal",
                      upstream: "unix:///run/user/1000/docker.sock",
                      unmatched: "refuse",
                      refusal: {contentType: "application/json", body: "{\"message\":\"{{message}}\"}"},
                      paths: $ops[0],
                      docker: {
                        project: $who.project,
                        apiVersions: $source[0].apiVersions,
                        images: ["postgres:18", "library/postgres:18", "docker.io/postgres:18", "docker.io/library/postgres:18"],
                        address: $who.address,
                        ports: [64320, 64321],
                        names: $who.names,
                        maxBody: 262144,
                        bodies: ([$admit[0][] | .docker.body // empty] | unique | map({key: ., value: $fields[0][.]}) | from_entries)
                      }
                    }]
                  }'
              }
              loads() { frisket check "$1" 2>$TMPDIR/err; }

              judge() {
                tables 2>$TMPDIR/err && total 2>$TMPDIR/err && sample > $TMPDIR/sample.json && loads $TMPDIR/sample.json
              }
              refuses() {
                local why=$1; shift
                ! judge || fail "judged anyway: $why"
                grep -qF -- "$1" $TMPDIR/err || fail "$why, refused otherwise: $(cat $TMPDIR/err)"
              }

              cmp -s ${./apps/docker/fields.json} ${frisket}/internal/docker/testdata/fields.json \
                || fail "apps/docker/fields.json is not frisket's internal/docker/testdata/fields.json: change it there, and take the input"
              # A key given twice would be read as its last by jq and by
              # frisket's decoder of the route, while a reviewer may read the
              # first; and one row per line is what a bump's diff shows.
              f=${./apps/docker/fields.json}
              [ "$(jq -c --stream . $f | wc -l)" = "$(jq -c tostream $f | wc -l)" ] || fail "fields.json gives a key twice in one object"
              [ "$(grep -cE '^    "[^"]+": ' $f)" = "$(jq '[.[] | length] | add' $f)" ] || fail "fields.json is not one row per line"

              fresh
              judge || fail "the tables were not judged whole: $(cat $TMPDIR/err)"
              [ "$(jq -c '.routes[0].docker | [.address, .names]' $TMPDIR/sample.json)" = '["127.1.191.78",["data-lab.internal","data-lab.triptease.internal"]]' ] \
                || fail "the sample is not data-lab's address and names: $(jq -c '.routes[0].docker' $TMPDIR/sample.json | head -c 300)"
              [ "$(jq -c '.routes[0].docker.bodies | keys' $TMPDIR/sample.json)" = '["ContainerCreate","ExecCreate","ExecStart","NetworkCreate","VolumeCreate"]' ] \
                || fail "the sample does not carry every admitted body's table"

              fresh; edit fields.json 'del(.ContainerCreate["HostConfig.Memory"])'
              refuses "a table missing a field the spec knows" "ContainerCreate has no row for HostConfig.Memory"
              fresh; edit fields.json 'del(.NetworkCreate.IPAM)'
              refuses "a table missing the zero that judged the fields under it" "NetworkCreate has no row for IPAM, IPAM.Config, IPAM.Driver, IPAM.Options"
              fresh; edit fields.json '.ExecStart.Stream = "zero"'
              refuses "a row the spec does not know" "ExecStart has a row the pinned spec does not know: Stream"
              fresh; edit known.json '.VolumeCreate += ["Status"]'
              refuses "a field a bump added that no row judges" "VolumeCreate has no row for Status"
              fresh; edit fields.json 'del(.ExecStart)'
              refuses "an admitted body with no table" "admitted with no table: ExecStart"
              fresh; edit admit.json '.ExecStart.docker.body = "ExecStartConfig"'
              refuses "an admitted body named for no table" "admitted with no table: ExecStartConfig"
              fresh; edit fields.json '.ContainerUpdate = {"Memory": "any"}'
              refuses "a table no admitted operation names" "a table no admitted operation names: ContainerUpdate"

              # frisket loads what chase would write, and not what is weaker
              # than its floor, or at another project's address or names.
              fresh; edit fields.json '.VolumeCreate.Name = "any"'
              refuses "a table weaker than frisket's floor" "table VolumeCreate is weaker than frisket's floor"
              fresh
              sample > $TMPDIR/good.json
              unloaded() {
                local why=$1 edit=$2 said=$3
                jq "$edit" $TMPDIR/good.json > $TMPDIR/bad.json
                ! loads $TMPDIR/bad.json || fail "frisket loaded $why"
                grep -qF -- "$said" $TMPDIR/err || fail "$why, refused otherwise: $(cat $TMPDIR/err)"
              }
              own="are not [\"data-lab.internal\" \"data-lab.triptease.internal\"], the project's own"
              unloaded "names in another order than it derives" '.routes[0].docker.names |= reverse' "$own"
              unloaded "names short of what it derives" '.routes[0].docker.names = ["data-lab.internal"]' "$own"
              unloaded "another project's names" '.routes[0].docker.names = ["finance-api.internal", "finance-api.triptease.internal"]' "$own"
              unloaded "an address it does not derive" '.routes[0].docker.address = "127.1.191.79"' "is not 127.1.191.78, the project's own"

              touch $out
            '';

          # WHAT AN ENVELOPE MAY NAME FOR DOCKER (docs/docker.md): each
          # image in the one form frisket compares against, never at a
          # registry the host's loopback or an address would answer for, and
          # ports frisket can listen on in the session. options.nix is
          # evaluated alone, as chase-envelope evaluates it, so a bad value
          # has to fail the evaluation itself.
          docker-envelope =
            let
              lib = nixpkgs.lib;
              # A binding is either the value of chase.bindings.docker or a
              # project module of its own, evaluated beside options.nix as
              # chase-envelope evaluates a project's chaseModules.default.
              docker = binding: (lib.evalModules {
                modules = [ ./project/options.nix (if binding ? module then binding.module else { chase.bindings.docker = binding; }) ];
              }).config.chase.bindings.docker;
              evaluates = binding: (builtins.tryEval (builtins.deepSeq (docker binding) true)).success;
              digest = lib.concatStrings (lib.replicate 8 "0123abcd");
              refused = [
                { images = [ "docker.io/postgres:18" ]; }
                { images = [ "index.docker.io/x:1" ]; }
                { images = [ "library/postgres:18" ]; }
                { images = [ "postgres" ]; }
                { images = [ "127.0.0.1:5000/x:1" ]; }
                { images = [ "10.0.0.1/x:1" ]; }
                { images = [ "localhost/x:1" ]; }
                # Names and spellings that resolve to the host's loopback.
                { images = [ "registry.localhost/x:1" ]; }
                { images = [ "localhost.localdomain/x:1" ]; }
                { images = [ "0x7f.1/x:1" ]; }
                { images = [ "127.1/x:1" ]; }
                { images = [ "a.internal/x:1" ]; }
                { images = [ "127.0.0.1.nip.io/x:1" ]; }
                { images = [ "evil.eu.gcr.io.example/x:1" ]; }
                { images = [ "a.b-docker.pkg.dev/x:1" ]; }
                # A project module that declares the option again, to put
                # its own value past the check.
                {
                  name = "a module that redeclares images with an apply";
                  module = { lib, ... }: {
                    options.chase.bindings.docker.images = lib.mkOption { apply = _: [ "127.0.0.1:5000/x:1" ]; };
                  };
                }
                {
                  name = "a module that redeclares ports as any int, for port 80";
                  module = { lib, ... }: {
                    options.chase.bindings.docker.ports = lib.mkOption { type = lib.types.listOf lib.types.int; };
                    config.chase.bindings.docker.ports = [ 80 ];
                  };
                }
                {
                  name = "a module that redeclares ports as 0 to 70000, for ports 0 and 99999";
                  module = { lib, ... }: {
                    options.chase.bindings.docker.ports = lib.mkOption { type = lib.types.listOf (lib.types.ints.between 0 70000); };
                    config.chase.bindings.docker.ports = [ 0 99999 ];
                  };
                }
                { ports = [ 80 ]; }
                { ports = [ 15001 ]; }
                { ports = [ 5432 5432 ]; }
                { ports = lib.range 2000 2064; }
              ];
              accepted = [
                { images = [ "postgres:18" "bitnami/postgresql:16" "ghcr.io/o/x:1" "postgres@sha256:${digest}" "eu.gcr.io/p/x:1" "europe-west2-docker.pkg.dev/p/r/x:1" ]; ports = [ 5432 ]; }
                { ports = lib.range 2000 2063; }
                { }
              ];
              wrong = builtins.filter evaluates refused ++ builtins.filter (b: ! evaluates b) accepted;
            in
            pkgs.runCommand "docker-envelope" { wrong = builtins.toJSON (map (b: b.name or b) wrong); passAsFile = [ "wrong" ]; } ''
              [ "$(cat "$wrongPath")" = "[]" ] || { echo "docker-envelope: evaluated wrongly: $(cat "$wrongPath")" >&2; exit 1; }
              touch $out
            '';

          # A SNAPSHOT FOLLOWS NO LINK. What is evaluated and decrypted is
          # the checkout's tracked files, copied; a session writes the
          # checkout, and can make a directory above a tracked file a link
          # to one of the host's -- another project's sops directory -- so
          # a copy through it would put the host's file where the project's
          # was. Refused, naming the link, with nothing staged and no host
          # byte anywhere chase keeps things; the tracked link a project
          # has is copied as a link, never read through. And which files
          # are tracked is read from the index alone, so nothing the
          # checkout's git config names is run on the host to find out.
          envelope-snapshot = pkgs.runCommand "envelope-snapshot" { nativeBuildInputs = [ pkgs.git pkgs.jq ]; } ''
            export HOME=$TMPDIR
            fail() { echo "envelope-snapshot: $*" >&2; exit 1; }
            ${envelopeHarness { }}
            git config --global user.name x
            git config --global user.email x@example.com
            r=$(cd "$TMPDIR" && pwd -P)/root
            mkdir -p "$r" hostsecret
            echo TOPSECRET > hostsecret/secrets.yaml
            printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > hostflake.nix
            copy=$(grep -o '/nix/store/[^:"]*-chase-copy-tracked[^:"]*/bin' chase-envelope)/chase-copy-tracked
            [ -x "$copy" ] || fail "chase-copy-tracked is not on chase-envelope's PATH"

            checkout() { # DIR TRACKED...: a checkout with a flake, and each TRACKED a file
              local d=$1 f
              shift
              git init -q "$d"
              printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > "$d/flake.nix"
              for f in "$@"; do
                mkdir -p "$(dirname -- "$d/$f")"
                echo "the project's own" > "$d/$f"
              done
              git -C "$d" add -A
            }
            approve() { # DIR MACHINE ENVELOPE
              ENVELOPE=$3 bash ./chase-envelope approve "$1" "$2" trusted >/dev/null 2>err
            }
            leaked() { grep -rqsF TOPSECRET home state run; }
            # DIR MACHINE PREFIX: refused, naming the link, with nothing
            # staged and no host byte kept.
            refused() {
              if approve "$1" "$2" "{\"secrets\": \"$3/secrets.yaml\", \"bindings\": {}}"; then fail "$1 was approved with $3 a link"; fi
              grep -qF "chase: $1: $3 is a link, so what is tracked under it would be copied from wherever it points" err \
                || fail "$1: the link $3 was not said: $(cat err)"
              [ ! -e "run/chase/.envelope/$2.json" ] || fail "$1 was staged with $3 a link"
              ! leaked || fail "$1: the host's file was copied: $(grep -rlF TOPSECRET home state run)"
            }
            # DIR OUT PREFIX: the copier itself, into OUT, which the test
            # keeps (approve's snapshot is gone before leaked() could look):
            # it refuses at the link, and no host byte is in OUT, so it did
            # not copy through the link and check afterwards.
            copyRefused() {
              mkdir "$2"
              if printf 'flake.nix\0%s/secrets.yaml\0' "$3" | "$copy" "$1" "$2" >copy.err; then
                fail "$1: the copier copied through $3"
              fi
              grep -qF "$3 is a link, so what is tracked under it would be copied from wherever it points" copy.err \
                || fail "$1: the copier did not name the link $3: $(cat copy.err)"
              ! grep -rqF TOPSECRET "$2" || fail "$1: a host byte was copied through $3: $(grep -rlF TOPSECRET "$2")"
              [ ! -e "$2/$3/secrets.yaml" ] && [ ! -L "$2/$3" ] || fail "$1: $3 was copied: $(ls -lR "$2")"
            }

            # What is tracked, as it is, is copied and staged.
            checkout "$r/plain" link/secrets.yaml
            approve "$r/plain" m0 '{"secrets": "link/secrets.yaml", "bindings": {}}' || fail "a plain checkout was refused: $(cat err)"
            [ "$(jq -r .secrets.text run/chase/.envelope/m0.json)" = "the project's own" ] || fail "the project's sops file was not staged"

            # (a) A tracked link/f, link then made a link to a host
            # directory: the project's own name for its sops file, and the
            # host's in its place.
            checkout "$r/a" link/secrets.yaml
            rm -rf "$r/a/link"
            ln -s "$PWD/hostsecret" "$r/a/link"
            refused "$r/a" m1 link
            copyRefused "$r/a" out-a link

            # (b) The same, a directory deeper.
            checkout "$r/b" a/b/secrets.yaml
            rm -rf "$r/b/a/b"
            ln -s "$PWD/hostsecret" "$r/b/a/b"
            refused "$r/b" m2 a/b
            copyRefused "$r/b" out-b a/b

            # A directory made a file is refused, and is not called a link.
            checkout "$r/file" d/secrets.yaml
            rm -rf "$r/file/d"
            echo x > "$r/file/d"
            if approve "$r/file" m3 '{"bindings": {}}'; then fail "a tracked directory made a file was approved"; fi
            grep -qF "chase: $r/file: its tracked files could not be copied: d: it is not a directory" err || fail "a directory made a file was not said: $(cat err)"

            # A tracked file missing from the work tree is refused, as tar
            # refused it.
            checkout "$r/gone" gone
            rm "$r/gone/gone"
            if approve "$r/gone" m4 '{"bindings": {}}'; then fail "a checkout missing a tracked file was approved"; fi
            grep -qF "chase: $r/gone: its tracked files could not be copied: gone: " err || fail "a missing file was not said: $(cat err)"

            # (c) A tracked file that is a link to a host file is a link in
            # the snapshot, pointing where it did, and never its target's
            # bytes: named as the sops file, it is outside the checkout.
            checkout "$r/c" tool
            ln -s "$PWD/hostsecret/secrets.yaml" "$r/c/secrets.yaml"
            chmod +x "$r/c/tool"
            git -C "$r/c" add -A
            if approve "$r/c" m5 '{"secrets": "secrets.yaml", "bindings": {}}'; then fail "a sops file linked to the host's was approved"; fi
            grep -qF "chase: $r/c: secrets.yaml is outside the checkout" err || fail "a linked sops file was not said: $(cat err)"
            ! leaked || fail "a tracked link was read through"
            mkdir out-c
            git -C "$r/c" ls-files -z --cached | "$copy" "$r/c" out-c || fail "a checkout with a tracked link was not copied"
            [ -L out-c/secrets.yaml ] && [ "$(readlink out-c/secrets.yaml)" = "$PWD/hostsecret/secrets.yaml" ] \
              || fail "a tracked link was not copied as itself: $(ls -l out-c)"
            [ -f out-c/tool ] && [ ! -L out-c/tool ] && [ -x out-c/tool ] && [ "$(cat out-c/tool)" = "the project's own" ] \
              || fail "a tracked file was not copied with its exec bit: $(ls -l out-c)"
            [ -f out-c/flake.nix ] && [ ! -x out-c/flake.nix ] || fail "a plain file was copied executable"

            # (d) A flake.nix made a link, to a flake that says chaseModules,
            # is not the checkout's.
            checkout "$r/d"
            ln -sf "$PWD/hostflake.nix" "$r/d/flake.nix"
            if approve "$r/d" m6 '{"bindings": {}}'; then fail "a flake.nix made a link was approved"; fi
            grep -qF "chase: $r/d: flake.nix is not a tracked file" err || fail "a linked flake.nix was not said: $(cat err)"
            [ ! -e run/chase/.envelope/m6.json ] || fail "a linked flake.nix was staged"

            # (e) What a session named is said with its control bytes made
            # plain, never sent to the terminal.
            esc=$(printf 'x\033]0;TITLE\007y')
            checkout "$r/e" "$esc/secrets.yaml"
            rm -rf "$r/e/$esc"
            ln -s "$PWD/hostsecret" "$r/e/$esc"
            refused "$r/e" m7 'x?]0;TITLE?y'
            ! LC_ALL=C grep -q "$(printf '[\033\007]')" err || fail "a control byte reached the terminal: $(od -c err)"
            # And C1: CSI as UTF-8, and as the raw byte.
            c1=$(printf 'x\302\2331my\233z')
            checkout "$r/e1" "$c1/secrets.yaml"
            rm -rf "$r/e1/$c1"
            ln -s "$PWD/hostsecret" "$r/e1/$c1"
            refused "$r/e1" m8 'x?1my?z'
            ! LC_ALL=C grep -q "$(printf '[\200-\237]')" err || fail "a C1 control reached the terminal: $(od -c err)"

            # (f) The checkout's git config is the session's: a command it
            # names, as core.fsmonitor or a hook under core.hooksPath, is
            # never run by approve. The same config does run each when git
            # is asked plainly, so the test would see it.
            checkout "$r/f" tracked root-only
            git -C "$r/f" config core.fsmonitor "touch $TMPDIR/PWNED; false"
            git -C "$r/f" ls-files >/dev/null 2>&1 || true
            [ -e "$TMPDIR/PWNED" ] || fail "core.fsmonitor is not run by a plain git ls-files, so (f) proves nothing"
            rm "$TMPDIR/PWNED"
            mkdir -p hooks
            printf '#!/bin/sh\ntouch %s/PWNED\n' "$TMPDIR" > hooks/post-index-change
            chmod +x hooks/post-index-change
            git -C "$r/f" config core.hooksPath "$PWD/hooks"
            # A stat that no longer matches the index has git status write
            # it, which runs post-index-change from core.hooksPath.
            touch -d 2020-01-01 "$r/f/tracked"
            git -C "$r/f" -c core.fsmonitor=false status >/dev/null 2>&1 || true
            [ -e "$TMPDIR/PWNED" ] || fail "core.hooksPath is not run by a git status that refreshes the index, so (f) proves nothing of hooks"
            rm "$TMPDIR/PWNED"
            touch -d 2021-01-01 "$r/f/tracked"
            approve "$r/f" m9 '{"secrets": "tracked", "bindings": {}}' || fail "a checkout with core.fsmonitor set was refused: $(cat err)"
            [ ! -e "$TMPDIR/PWNED" ] || fail "approve ran the checkout's core.fsmonitor or core.hooksPath"
            [ "$(jq -r .secrets.text run/chase/.envelope/m9.json)" = "the project's own" ] \
              || fail "the checkout with core.fsmonitor set was not staged: $(cat run/chase/.envelope/m9.json)"

            # An untracked flake.nix is not the checkout's: the index, not
            # the directory, says what is tracked.
            git init -q "$r/untracked"
            printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > "$r/untracked/flake.nix"
            git -C "$r/untracked" config core.fsmonitor "touch $TMPDIR/PWNED; false"
            if approve "$r/untracked" m10 '{"bindings": {}}'; then fail "an untracked flake.nix was approved"; fi
            grep -qF "chase: $r/untracked: flake.nix is not a tracked file" err || fail "an untracked flake.nix was not said: $(cat err)"
            [ ! -e "$TMPDIR/PWNED" ] || fail "approve ran the untracked checkout's core.fsmonitor"
            [ ! -e run/chase/.envelope/m10.json ] || fail "an untracked flake.nix was staged"

            # A workspace below its checkout's root copies what is tracked
            # there, relative to itself, and nothing of the root's.
            mkdir -p "$r/f/sub"
            printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > "$r/f/sub/flake.nix"
            echo "the sub's own" > "$r/f/sub/tracked"
            git -C "$r/f" -c core.fsmonitor=false -c core.hooksPath=/dev/null add sub
            rm -f "$TMPDIR/PWNED"
            approve "$r/f/sub" m11 '{"secrets": "tracked", "bindings": {}}' || fail "a workspace below its root was refused: $(cat err)"
            [ ! -e "$TMPDIR/PWNED" ] || fail "approve ran core.fsmonitor for a workspace below its root"
            [ "$(jq -r .secrets.text run/chase/.envelope/m11.json)" = "the sub's own" ] \
              || fail "a workspace below its root did not copy its own tracked files: $(cat run/chase/.envelope/m11.json)"

            # A directory in no git checkout has nothing tracked to snapshot.
            mkdir -p "$r/nogit"
            printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > "$r/nogit/flake.nix"
            if approve "$r/nogit" m12 '{"bindings": {}}'; then fail "a directory outside git was approved"; fi
            grep -qF "chase: $r/nogit: an envelope needs a git checkout" err || fail "a directory outside git was not said: $(cat err)"
            [ ! -e run/chase/.envelope/m12.json ] || fail "a directory outside git was staged"

            # An index that needs more than itself is not read: a split
            # index's shared part would be read from beside the index, which
            # the session writes, and a sparse index would leave out what is
            # under its sparse directories without a word.
            checkout "$r/split" f
            git -C "$r/split" update-index --split-index
            ls "$r/split/.git" | grep -q '^sharedindex\.' || fail "the split index has no shared part, so it proves nothing"
            if approve "$r/split" m13 '{"bindings": {}}'; then fail "a split index was approved"; fi
            grep -qF "chase: $r/split: an envelope needs a git checkout, so what is evaluated is what git tracks: the index of $r/split cannot be read on its own" err \
              || fail "a split index was not said: $(cat err)"
            checkout "$r/sparse" keep/f away/f
            git -C "$r/sparse" commit -qm x
            git -C "$r/sparse" sparse-checkout set --cone --sparse-index keep
            if approve "$r/sparse" m14 '{"bindings": {}}'; then fail "a sparse index was approved"; fi
            grep -qF "chase: $r/sparse: an envelope needs a git checkout, so what is evaluated is what git tracks: the index of $r/sparse is sparse, or cannot be read on its own" err \
              || fail "a sparse index was not said: $(cat err)"

            # WHAT THE INDEX LISTS is the session's to write, so a path
            # that would leave the checkout is refused, whatever it is.
            mkdir out-x
            for p in /etc/passwd ../hostsecret/secrets.yaml a/../../x a//b ./flake.nix a/. ""; do
              if why=$(printf '%s\0' "$p" | "$copy" "$r/plain" out-x); then fail "the copier took '$p'"; fi
              [ "$why" = "its index lists $p, which is not a path below it" ] || fail "'$p' was refused for something else: $why"
            done
            [ -z "$(ls -A out-x)" ] || fail "a path that leaves the checkout was copied: $(ls -A out-x)"
            # An unmerged path, listed once for each stage, is copied once.
            mkdir out-u
            printf 'flake.nix\0flake.nix\0flake.nix\0' | "$copy" "$r/plain" out-u || fail "a path listed three times was refused"

            touch $out
          '';

          # A CHECKOUT'S DOCKER PROJECT (docs/docker.md, decision 9), named
          # by its origin on real repositories, held both ways to the paths
          # the tiers pin, and approved: with its address and names in front
          # of the person approving, and never at an address another project
          # holds. chase-envelope is envelopeHarness's, with the host's map
          # of names under the build directory too, and the tiers' pins at
          # paths under a sentinel, put where the build directory is, as the
          # selector's are.
          docker-identity =
            let root = "/chase-docker-identity-test"; in
            pkgs.runCommand "docker-identity" { nativeBuildInputs = [ pkgs.git pkgs.jq ]; } ''
              export HOME=$TMPDIR
              fail() { echo "docker-identity: $*" >&2; exit 1; }
              ${envelopeHarness {
                chase = {
                  tiers.trusted.match = [ { checkouts."triptease/data-lab" = "${root}/p/data-lab"; } ];
                  tiers.strict.match = [ { checkouts."TripTease/Finance-API" = "${root}/p/finance-api"; } ];
                };
                rewrite.hosts = "$PWD/docker-hosts.json";
              }}
              r=$(cd "$TMPDIR" && pwd -P)/root
              mkdir -p "$r"

              # Every tier's pins, lower-cased, in one file, put where the
              # build directory is.
              baked=$(sed -n 's/^checkouts=//p' chase-envelope)
              sed "s|${root}|$r|g" "$baked" > checkouts.json
              jq -e --arg r "$r" '.["triptease/data-lab"] == [$r + "/p/data-lab"] and .["triptease/finance-api"] == [$r + "/p/finance-api"]
                and .["alice/nix-config"] == ["/home/alice/Projects/nix-config"]' checkouts.json >/dev/null \
                || fail "the tiers' checkouts were not baked: $(cat checkouts.json)"
              sed -i "s|^checkouts=.*|checkouts=$PWD/checkouts.json|" chase-envelope
              grep -q "^checkouts=$PWD/checkouts.json$" chase-envelope || fail "checkouts is not one line of chase-envelope's"

              repo() { # DIR URL...
                local d=$1 u
                shift
                mkdir -p "$d"
                git -C "$d" init -q
                for u in "$@"; do git -C "$d" config --add remote.origin.url "$u"; done
              }
              names() { # DIR SLUG
                local got
                got=$(bash ./chase-envelope project "$1" trusted 2>err) || fail "$1 was not named $2: $(cat err)"
                [ "$got" = "$2" ] || fail "$1 is named $got, not $2"
              }
              refused() { # DIR NEEDLE
                local got
                if got=$(bash ./chase-envelope project "$1" trusted 2>err); then fail "$1 was named $got"; fi
                grep -qF -- "$2" err || fail "$1: expected '$2' in: $(cat err)"
              }

              # EACH FORM OF A GITHUB URL names owner/repo, lower-cased.
              repo "$r/w/scp" git@github.com:acme/app.git
              names "$r/w/scp" acme/app
              repo "$r/w/https" https://github.com/acme/app
              names "$r/w/https" acme/app
              repo "$r/w/ssh" ssh://git@github.com/acme/app.git/
              names "$r/w/ssh" acme/app
              repo "$r/w/upper" git@github.com:AcMe/App.Name.git
              names "$r/w/upper" acme/app.name
              mkdir -p "$r/w/scp/deep/er"
              names "$r/w/scp/deep/er" acme/app

              # A pinned project, at its path, anywhere under it, and from a
              # worktree of it kept there.
              repo "$r/p/data-lab" git@github.com:TripTease/Data-Lab.git
              git -C "$r/p/data-lab" -c user.name=x -c user.email=x@example.com commit -q --allow-empty -m first
              names "$r/p/data-lab" triptease/data-lab
              mkdir -p "$r/p/data-lab/sub"
              names "$r/p/data-lab/sub" triptease/data-lab
              git -C "$r/p/data-lab" worktree add -q "$r/p/data-lab/.claude/worktrees/feat"
              names "$r/p/data-lab/.claude/worktrees/feat" triptease/data-lab

              # A pinned project kept bare, in the path's .bare, with its
              # worktrees beside it, as the selector's in_checkout holds it;
              # but not a bare repository elsewhere with a worktree under
              # the pinned path.
              jq --arg p "$r/p/bare" '. + {"acme/bare": [$p]}' checkouts.json > checkouts.json.new
              mv checkouts.json.new checkouts.json
              bared() { # GITDIR URL
                git init -q --bare "$1"
                git --git-dir="$1" config remote.origin.url "$2"
                git --git-dir="$1" update-ref refs/heads/main \
                  "$(git --git-dir="$1" -c user.name=x -c user.email=x@example.com commit-tree -m first "$(git --git-dir="$1" mktree </dev/null)")"
              }
              bared "$r/p/bare/.bare" git@github.com:acme/bare.git
              git --git-dir="$r/p/bare/.bare" worktree add -q "$r/p/bare/main" main
              names "$r/p/bare/main" acme/bare
              bared "$r/elsewhere/bare.git" git@github.com:acme/bare.git
              git --git-dir="$r/elsewhere/bare.git" worktree add -q "$r/p/bare/other" main
              refused "$r/p/bare/other" "is under $r/p/bare, where acme/bare is pinned, but is a "

              # NO NAME: two URLs, not GitHub, none, and no repository.
              repo "$r/w/two" git@github.com:acme/app.git git@github.com:triptease/data-lab.git
              refused "$r/w/two" "exactly one origin URL"
              repo "$r/w/gitlab" git@gitlab.com:acme/app.git
              refused "$r/w/gitlab" "is not github.com/owner/repo"
              repo "$r/w/lookalike" https://github.com.example/acme/app
              refused "$r/w/lookalike" "is not github.com/owner/repo"
              repo "$r/w/none"
              refused "$r/w/none" "exactly one origin URL, so its project has a name, and it has 0"
              repo "$r/w/dot" git@github.com:acme/..git
              refused "$r/w/dot" "origin git@github.com:acme/. names no repository"
              # GitHub's shape, but not a project frisket routes: an owner
              # may not begin with a hyphen.
              repo "$r/w/hyphen" git@github.com:-acme/app.git
              refused "$r/w/hyphen" "-acme/app is not a project frisket can route"
              # What a session wrote is said with its control bytes made
              # plain, never sent to the terminal.
              repo "$r/w/escape" "$(printf 'x\033]0;TITLE\007y')"
              refused "$r/w/escape" "origin x?]0;TITLE?y is not github.com/owner/repo"
              ! LC_ALL=C grep -q "$(printf '[\033\007]')" err || fail "a control byte reached the terminal: $(od -c err)"
              mkdir -p "$r/w/plain"
              refused "$r/w/plain" "not a git repository"

              # BOTH WAYS: a pinned project anywhere but its path, and a
              # pinned path claiming anything but its project.
              repo "$r/elsewhere/data-lab" git@github.com:triptease/data-lab.git
              refused "$r/elsewhere/data-lab" "its origin says triptease/data-lab, which is pinned at $r/p/data-lab, not $r/elsewhere/data-lab"
              repo "$r/p/finance-api" git@github.com:acme/app.git
              refused "$r/p/finance-api" "is under $r/p/finance-api, where triptease/finance-api is pinned, but its origin says acme/app"

              # WHAT A SESSION COULD WRITE to take the pinned project's name:
              # its own config's core.worktree, a .git file into the pinned
              # repository, and a clone of its own inside the pinned path,
              # whose session writes its origin.
              repo "$r/forge" git@github.com:triptease/data-lab.git
              git -C "$r/forge" config core.worktree "$r/p/data-lab"
              refused "$r/forge" "core.worktree sends git to $r/p/data-lab"
              mkdir -p "$r/evil"
              echo "gitdir: $r/p/data-lab/.git" > "$r/evil/.git"
              refused "$r/evil" "which is not a worktree's"
              repo "$r/p/data-lab/nested" git@github.com:triptease/data-lab.git
              refused "$r/p/data-lab/nested" "is a checkout of $r/p/data-lab/nested, not of $r/p/data-lab"

              # APPROVAL. An envelope that binds Docker, as nix would print it.
              docker='{"bindings": {"docker": {"images": ["postgres:18"], "ports": [64320, 64321]}}}'
              flake() { # DIR
                printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > "$1/flake.nix"
                git -C "$1" add flake.nix
              }
              approve() { # DIR MACHINE ENVELOPE
                ENVELOPE=$3 bash ./chase-envelope approve "$1" "$2" trusted >/dev/null 2>err
              }
              asked() { jq -s '[.[] | select(.kind == "envelope")] | length' approvals.jsonl; }
              staged() { jq -r "$2" "run/chase/.envelope/$1.json"; }
              line='Docker as triptease/data-lab at 127.1.191.78 (data-lab.internal, data-lab.triptease.internal), ports 64320 64321'
              said() { grep -F "chase: $r/p/data-lab: $line" err; }
              ws=$r/p/data-lab
              flake "$ws"

              # No hosts file: the names are the session's, and the host has
              # only the address.
              approve "$ws" m1 "$docker" || fail "data-lab was not approved: $(cat err)"
              [ "$(said)" = "chase: $ws: $line; on this host, 127.1.191.78 only" ] || fail "the approval did not say where Docker is: $(cat err)"
              [ "$(staged m1 .result.dockerProject)" = triptease/data-lab ] || fail "the project was not staged: $(cat run/chase/.envelope/m1.json)"
              [ "$(asked)" = 1 ] || fail "the envelope was not asked about"
              jq -s -e '[.[] | select(.kind == "envelope")][0].diff | contains("\"dockerProject\": \"triptease/data-lab\"")' approvals.jsonl >/dev/null \
                || fail "the approval's diff does not show the project: $(cat approvals.jsonl)"
              [ "$(jq -c . state/docker/addresses.json)" = '{"triptease/data-lab":"127.1.191.78"}' ] \
                || fail "the address was not recorded: $(cat state/docker/addresses.json)"

              # The host's names, where the hosts file gives this project
              # them at this address; the address alone where it gives them
              # elsewhere, and only those it gives. Approved again, the same
              # project passes, is not asked about, and is held once.
              printf '{"triptease/data-lab": {"address": "127.1.191.78", "names": ["data-lab.internal", "data-lab.triptease.internal"]}}' > docker-hosts.json
              approve "$ws" m2 "$docker" || fail "data-lab was not approved again: $(cat err)"
              [ "$(said)" = "chase: $ws: $line" ] || fail "the host's names were not recognised: $(cat err)"
              [ "$(asked)" = 1 ] || fail "an unchanged envelope was asked about again"
              [ "$(jq -c . state/docker/addresses.json)" = '{"triptease/data-lab":"127.1.191.78"}' ] \
                || fail "the address is not held once: $(cat state/docker/addresses.json)"
              [ "$(grep -o triptease/data-lab state/docker/addresses.json | wc -l)" = 1 ] || fail "the project is recorded twice"
              printf '{"triptease/data-lab": {"address": "127.9.9.9", "names": ["data-lab.internal", "data-lab.triptease.internal"]}}' > docker-hosts.json
              approve "$ws" m3 "$docker" || fail "data-lab was not approved: $(cat err)"
              [ "$(said)" = "chase: $ws: $line; on this host, 127.1.191.78 only" ] || fail "names at another address were taken as the host's: $(cat err)"
              printf '{"triptease/data-lab": {"address": "127.1.191.78", "names": ["data-lab.triptease.internal"]}}' > docker-hosts.json
              approve "$ws" m4 "$docker" || fail "data-lab was not approved: $(cat err)"
              [ "$(said)" = "chase: $ws: $line; on this host, 127.1.191.78 and data-lab.triptease.internal only" ] \
                || fail "a name the host lacks was taken as the host's: $(cat err)"
              rm docker-hosts.json

              # A changed origin is a changed envelope, asked about again.
              app=$r/w/scp
              flake "$app"
              approve "$app" m5 "$docker" || fail "acme/app was not approved: $(cat err)"
              [ "$(asked)" = 2 ] || fail "acme/app was not asked about"
              grep -qF "chase: $app: Docker as acme/app at " err || fail "the approval did not say acme/app: $(cat err)"
              git -C "$app" remote set-url origin git@github.com:acme/app2.git
              approve "$app" m6 "$docker" || fail "acme/app2 was not approved: $(cat err)"
              [ "$(asked)" = 3 ] || fail "a changed origin was not asked about"
              jq -s -e '[.[] | select(.kind == "envelope")][2].diff | contains("-  \"dockerProject\": \"acme/app\"") and contains("+  \"dockerProject\": \"acme/app2\"")' approvals.jsonl >/dev/null \
                || fail "the diff does not show the origin's change: $(jq -s '.[-1].diff' approvals.jsonl)"
              [ "$(staged m6 .result.dockerProject)" = acme/app2 ] || fail "the new project was not staged"

              # The workspace is a path a session can name: the line beside
              # the approval says it with its control bytes made plain.
              esc=$ws/$(printf 'x\033]0;PWNED\007\033[8m')
              mkdir -p "$esc"
              flake "$esc"
              approve "$esc" m13 "$docker" || fail "a workspace with an escape in its path was not approved: $(cat err)"
              grep -qF "chase: $ws/x?]0;PWNED??[8m: Docker as triptease/data-lab at 127.1.191.78" err \
                || fail "the approval did not say where Docker is: $(od -c err)"
              ! LC_ALL=C grep -q "$(printf '[\033\007]')" err || fail "a control byte reached the terminal: $(od -c err)"

              # A declined approval holds no address, and stages nothing.
              repo "$r/w/declined" git@github.com:acme/declined.git
              flake "$r/w/declined"
              cp bin/approver approver.ok
              # Its source is approved, so what is declined is the envelope,
              # the approval the address is recorded after.
              printf '#!%s\n%s -e %s >/dev/null\n' "$(command -v bash)" "$(command -v jq)" "'.kind != \"envelope\"'" > bin/approver
              if approve "$r/w/declined" m14 "$docker"; then fail "a declined envelope was applied"; fi
              grep -qF "chase: $r/w/declined: its envelope was not approved" err || fail "the decline was not said: $(cat err)"
              [ ! -e run/chase/.envelope/m14.json ] || fail "a declined envelope was staged"
              jq -e 'has("acme/declined") | not' state/docker/addresses.json >/dev/null \
                || fail "a declined project holds its address: $(cat state/docker/addresses.json)"
              mv approver.ok bin/approver

              # AN ADDRESS ANOTHER PROJECT HOLDS: in the approved addresses,
              # or only in the host's map. Refused, naming both, with nothing
              # staged or recorded.
              rm -rf state/docker
              mkdir -p state/docker
              printf '{"evil/x": "127.1.191.78"}' > state/docker/addresses.json
              if approve "$ws" m7 "$docker"; then fail "data-lab was approved at an address evil/x holds"; fi
              grep -qF "chase: $ws: triptease/data-lab would be at 127.1.191.78, which evil/x already holds" err \
                || fail "the collision was not said: $(cat err)"
              [ ! -e run/chase/.envelope/m7.json ] || fail "a collision was staged"
              [ "$(jq -c . state/docker/addresses.json)" = '{"evil/x":"127.1.191.78"}' ] || fail "a collision was recorded"
              rm -rf state/docker
              printf '{"evil/x": {"address": "127.1.191.78", "names": ["x.internal"]}}' > docker-hosts.json
              if approve "$ws" m8 "$docker"; then fail "data-lab was approved at an address the host gives evil/x"; fi
              grep -qF "chase: $ws: triptease/data-lab would be at 127.1.191.78, which evil/x already holds" err \
                || fail "the host's collision was not said: $(cat err)"
              [ ! -e run/chase/.envelope/m8.json ] || fail "the host's collision was staged"
              [ "$(jq -c . state/docker/addresses.json)" = '{}' ] || fail "the host's collision was recorded"
              rm docker-hosts.json

              # No usable origin, and Docker: nothing is applied.
              flake "$r/w/none"
              if approve "$r/w/none" m9 "$docker"; then fail "a checkout with no origin was given Docker"; fi
              grep -qF "exactly one origin URL" err || fail "no origin was not said: $(cat err)"
              [ ! -e run/chase/.envelope/m9.json ] || fail "a checkout with no origin was staged"

              # Without Docker, no project is named, or needed.
              approve "$r/w/none" m10 '{"bindings": {"github": {"allow": ["x"]}}}' || fail "an envelope without Docker was refused: $(cat err)"
              [ "$(staged m10 '.result | has("dockerProject")')" = false ] || fail "an envelope without Docker gained a project"
              ! grep -q "Docker as" err || fail "an envelope without Docker printed one: $(cat err)"

              # What chase derives is not the envelope's to say: a module's
              # own dockerProject or secretsSHA256 is dropped, not staged.
              approve "$r/w/none" m11 '{"dockerProject": "triptease/data-lab", "secretsSHA256": "0", "bindings": {"github": {"allow": ["x"]}}}' \
                || fail "an envelope naming its own project was refused: $(cat err)"
              [ "$(staged m11 '.result | has("dockerProject") or has("secretsSHA256")')" = false ] \
                || fail "an envelope's own dockerProject was staged: $(cat run/chase/.envelope/m11.json)"

              # A PINNED PROJECT HOLDS ITS ADDRESS before it is ever approved:
              # collide/x33613042, pinned, hashes to acme/app's address
              # (found once, offline), so acme/app is refused.
              jq '. + {"collide/x33613042": ["/nowhere/collide"]}' checkouts.json > checkouts.json.new
              mv checkouts.json.new checkouts.json
              git -C "$app" remote set-url origin git@github.com:acme/app.git
              rm -rf state/docker
              if approve "$app" m12 "$docker"; then fail "acme/app was approved at an address a pinned project holds"; fi
              grep -qF "chase: $app: acme/app would be at 127.95.137.218, which collide/x33613042 already holds" err \
                || fail "the pinned project's collision was not said: $(cat err)"
              [ ! -e run/chase/.envelope/m12.json ] || fail "the pinned project's collision was staged"

              touch $out
            '';

          # AN APP WITH NO CREDENTIAL (docs/docker.md), launched: its
          # prepare is run from the binding alone, whenever the binding says
          # anything, with nothing decrypted, and given the Docker project
          # that approve staged -- never one derived again at launch, nor one
          # the session has. probe stands in for such an app, and is only
          # this test's. An app with a credential is still bound only with
          # one, and an app with neither is refused when the system is built.
          project-launch =
            let
              lib = nixpkgs.lib;
              root = "/chase-project-launch-test";
              probe = pkgs.writeShellScript "chase-probe-prepare" ''
                cat > "$3/probe.stdin"
                printf '%s:%s' "''${chase_project+set}" "''${chase_project-}" > "$3/probe.project"
                printf '%s\n' '{"routes": [], "allow": ["probe.example"], "env": {"PROBE": "1"}}'
              '';
              bad = harnessEnvelope (harnessConfig { internal.projectApps.bad.credential = false; });
            in
            assert ! (builtins.tryEval (builtins.deepSeq bad.drvPath true)).success
              || throw "project-launch: an app with no credential and no prepare was built";
            pkgs.runCommand "project-launch" { nativeBuildInputs = [ pkgs.git pkgs.jq ]; } ''
              export HOME=$TMPDIR
              fail() { echo "project-launch: $*" >&2; exit 1; }
              ${envelopeHarness {
                chase = {
                  tiers.trusted.match = [ { checkouts."triptease/data-lab" = "${root}/p/data-lab"; } ];
                  internal.projectApps.probe = { credential = false; prepare = "${probe}"; };
                };
                rewrite = { hosts = "$PWD/docker-hosts.json"; policies = "$PWD/policies"; };
              }}
              r=$(cd "$TMPDIR" && pwd -P)/root
              baked=$(sed -n 's/^checkouts=//p' chase-envelope)
              sed "s|${root}|$r|g" "$baked" > checkouts.json
              sed -i "s|^checkouts=.*|checkouts=$PWD/checkouts.json|" chase-envelope
              grep -q "^checkouts=$PWD/checkouts.json$" chase-envelope || fail "checkouts is not one line of chase-envelope's"
              jq -e '.probe.credential == false' "$(sed -n 's/^apps=//p' chase-envelope)" >/dev/null || fail "probe is not an app with no credential"

              # Any decryption is logged, and fails.
              cat > bin/sops <<'SH'
              #!${pkgs.runtimeShell}
              echo "$*" >> "$TMPDIR/sops.log"
              exit 1
              SH
              chmod +x bin/sops
              mkdir policies
              printf '{"name": "trusted", "allow": [], "routes": []}\n' > policies/trusted.json

              ws=$r/p/data-lab
              git init -q "$ws"
              git -C "$ws" config remote.origin.url git@github.com:triptease/data-lab.git
              printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > "$ws/flake.nix"
              git -C "$ws" add flake.nix
              envfile=state/env/$(printf '%s' "$ws" | sha256sum | cut -c1-32)/env

              launched() { # MACHINE ENVELOPE
                ENVELOPE=$2 bash ./chase-envelope approve "$ws" "$1" trusted >/dev/null 2>err || fail "$1 was not approved: $(cat err)"
                bash ./chase-envelope launch trusted "$ws" "$1" 2>err || fail "$1 was not launched: $(cat err)"
              }

              # Docker and probe: probe is prepared from its binding, as the
              # project approve named, and a gcloud binding with no secret is
              # not bound at all.
              launched m1 '{"bindings": {"docker": {"images": ["postgres:18"], "ports": [64320]}, "probe": {"x": 1}, "gcloud": {"serviceAccount": "a@p.iam.gserviceaccount.com"}}}'
              m=run/chase/m1
              [ "$(jq -c . "$m/probe.stdin")" = '{"x":1}' ] || fail "prepare was not given the binding: $(cat "$m/probe.stdin")"
              [ "$(cat "$m/probe.project")" = set:triptease/data-lab ] || fail "prepare was not given the approved project: $(cat "$m/probe.project")"
              jq -e '.allow == ["probe.example"] and .routes == []' "$m/policy.json" >/dev/null || fail "probe's patch was not merged: $(cat "$m/policy.json")"
              grep -qx "export PROBE='1'" "$envfile" || fail "probe's env was not exported: $(cat "$envfile")"
              ! grep -q chase_project "$envfile" || fail "the session was given chase_project: $(cat "$envfile")"
              grep -qxF "chase: $ws: probe from no credential" err || fail "where probe came from was not said: $(cat err)"
              ! grep -q "gcloud from" err || fail "gcloud was bound with no secret: $(cat err)"
              [ ! -e sops.log ] && [ -z "$(ls -A "$m/secrets")" ] || fail "a secret was decrypted: $(cat sops.log 2>/dev/null)"

              # Without probe, its prepare is never run.
              launched m2 '{"bindings": {"docker": {"images": ["postgres:18"], "ports": [64320]}}}'
              [ ! -e run/chase/m2/probe.stdin ] && [ ! -e run/chase/m2/probe.project ] || fail "probe was prepared with no binding"
              ! grep -q "probe from" err || fail "probe was said with no binding: $(cat err)"
              jq -e '.allow == []' run/chase/m2/policy.json >/dev/null || fail "probe's names were allowed with no binding"

              # Without Docker, there is no project to give, and it is empty.
              launched m3 '{"bindings": {"probe": {"x": 2}}}'
              [ "$(cat run/chase/m3/probe.project)" = set: ] || fail "prepare was given a project with no Docker: $(cat run/chase/m3/probe.project)"
              [ "$(jq -c . run/chase/m3/probe.stdin)" = '{"x":2}' ] || fail "prepare was not given the binding"
              [ ! -e sops.log ] || fail "a secret was decrypted: $(cat sops.log)"

              touch $out
            '';

          gcloud-session = pkgs.testers.runNixOSTest (import ./tests/gcloud-session.nix { inherit self home-manager; });

          # The version script decides what every release is called, so it is
          # gated by the same check that gates the release.
          shellcheck = pkgs.runCommand "shellcheck"
            { nativeBuildInputs = [ pkgs.shellcheck ]; }
            ''
              shellcheck ${./scripts/version.sh} ${./scripts/operations.sh} ${./scripts/gcloud.sh} ${./scripts/gcloud-renew.sh}
              touch $out
            '';
        });

      # What ./scripts/operations.sh needs: jq and curl for every app, and
      # graphql-core for a GraphQL schema. ./scripts/gcloud.sh needs git,
      # protoc, protobuf to read what protoc compiles, and pyyaml.
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.jq pkgs.curl pkgs.git pkgs.protobuf pkgs.shellcheck (pkgs.python3.withPackages (p: [ p.graphql-core p.protobuf p.pyyaml ])) ];
          };
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
