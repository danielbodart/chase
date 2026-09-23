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
            # strict says refuse for all three, and an app in it that sets
            # nothing asks about nothing.
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
            # The tiers' filters: trusted can debug, strict cannot; only a tier
            # that takes envelopes asks the checkout for more.
            assert
              (let config = configWith { }; in
              config.flong.agent-trusted.seccomp.debug
              && config.flong.agent-trusted.seccompPolicy != ""
              && config.flong.agent-strict.seccomp.tier == "strict"
              && ! config.flong.agent-strict.seccomp.debug
              && config.flong.agent-strict.seccompPolicy == "")
              || throw "assertions: the tiers' seccomp is not what they say";
            pkgs.runCommand "assertions" { } "touch $out";

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

          # The version script decides what every release is called, so it is
          # gated by the same check that gates the release.
          shellcheck = pkgs.runCommand "shellcheck"
            { nativeBuildInputs = [ pkgs.shellcheck ]; }
            ''
              shellcheck ${./scripts/version.sh} ${./scripts/operations.sh}
              touch $out
            '';
        });

      # What ./scripts/operations.sh needs: jq and curl for every app, and
      # graphql-core for a GraphQL schema.
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.jq pkgs.curl pkgs.shellcheck (pkgs.python3.withPackages (p: [ p.graphql-core ])) ];
          };
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
