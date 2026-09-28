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

  outputs = { self, nixpkgs, home-manager, ... }:
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

      checks = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
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
            pkgs.runCommand "selector" { nativeBuildInputs = [ pkgs.git ]; } ''
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
              expect "$r/p/nix-config/nested" host "alice/nix-config at"
              # Its remote, anywhere else: strict, because strict is asked
              # before trusted and lists it.
              expect "$r/elsewhere/nix-config" strict "repo alice/nix-config"
              expect "$r/p/mine" trusted "owner alice, first commit by a@Example.com"
              expect "$r/p/fork" strict "first commit by x@upstream.org"
              expect "$r/p/other" strict "owner bob is not listed"
              expect "$r/plain" strict "not a git repository"
              git -C "$r/p/shallow" remote set-url origin git@github.com:alice/mine.git
              expect "$r/p/shallow" strict "shallow clone"
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
                        apps.gcloud = { enable = true; apis = [ "bigquery" ]; };
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
              [ "$(jq -c '[.paths[].operation.category] | unique' <<< "$route")" = '["bigquery","google.iam.v1.IAMPolicy","pubsub"]' ] \
                || fail "the APIs are not the tier's with the project's changes: $(jq -c '[.paths[].operation.category] | unique' <<< "$route")"
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

              # The session's key: the service account and its project, a key
              # of its own, and its public half in the route.
              key=env/gcloud-key.json
              [ "$(jq -r '.env.GOOGLE_APPLICATION_CREDENTIALS, .env.CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE' <<< "$patch" | sort -u)" = "$PWD/$key" ] \
                || fail "the environment does not name the key"
              jq -e --arg e "$sa" '.type == "service_account" and .client_email == $e and .project_id == "p" and .private_key_id != "real" and (has("client_id") | not)' "$key" >/dev/null \
                || fail "the session's key is not the service account's shape"
              [ "$(jq -r .sessionKey.publicKey <<< "$route")" = "$(jq -r .private_key "$key" | openssl pkey -pubout)" ] || fail "the route does not hold the session key's public half"
              [ "$(jq -r .sessionKey.publicKey <<< "$route")" != "$(jq -r .private_key real.json | openssl pkey -pubout)" ] || fail "the session holds the real key"
              id=$(jq -r .private_key_id "$key")
              prepare trusted "$(binding '{}')" > /dev/null
              [ "$(jq -r .private_key_id "$key")" = "$id" ] || fail "the checkout's key was made again"
              grep -qx "$sa mint $run" renew.log || fail "no first token was minted: $(cat renew.log)"
              grep -qx "/run/user/1000 --user start chase-gcloud-renew@agent-trusted-1-2.service" systemctl.log || fail "the renewer was not started: $(cat systemctl.log)"

              # Merged into the tier's document, with a project's lists.
              doc=$(jq -c --slurpfile patch <(printf '%s' "$patch") -f ${./project/merge.jq} <<< '{"name": "trusted", "allow": ["github.com"], "routes": [{"name": "gcloud", "host": "x"}]}')
              jq -e '.allow == ["*.googleapis.com", "github.com"] and ([.routes[].name] == ["gcloud", "gcloud-mtls"])' <<< "$doc" >/dev/null \
                || fail "the routes were not merged: $(jq -c '{allow, names: [.routes[].name]}' <<< "$doc")"
              listed=$(jq -c --arg app gcloud --argjson lists '{"allow": ["category:bigquery"], "ask": ["pubsub.projects.topics.delete"], "refuse": []}' -f ${./project/lists.jq} <<< "$doc")
              [ "$(answer bigquery.datasets.insert <<< "$listed")" = allow ] || fail "category:bigquery did not decide"
              [ "$(answer pubsub.projects.topics.delete <<< "$listed")" = ask ] || fail "a name did not decide"
              ! jq -c --arg app gcloud --argjson lists '{"allow": ["category:storage"], "ask": [], "refuse": []}' -f ${./project/lists.jq} <<< "$doc" 2>/dev/null \
                || fail "a category of an API the session does not carry was applied"
              printf '%s' '{"access_token": "t", "expiry": 1}' > "$run/gcloud-token.json"
              printf '%s\n' "$listed" > policy.json
              frisket check policy.json || fail "frisket refused the document"

              # What is unmatched is allowed where the tier says so.
              jq -e '.routes[0].paths[-1] == {methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], prefix: "/"} and .routes[0].unmatched == "refuse"' \
                <<< "$(prepare loose "$(binding '{}')")" >/dev/null || fail "an unmatched allow has no catch-all"

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
              [ "$(class demo PUT '/upload/v1/b/*/o')" = write ] || fail "a resumable upload's PUT has no rule"
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
              touch $out
            '';

          # The version script decides what every release is called, so it is
          # gated by the same check that gates the release.
          shellcheck = pkgs.runCommand "shellcheck"
            { nativeBuildInputs = [ pkgs.shellcheck ]; }
            ''
              shellcheck ${./scripts/version.sh} ${./scripts/operations.sh} ${./scripts/gcloud.sh}
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
