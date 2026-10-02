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

      # ./VERSION is the major version alone. The package is named by it;
      # `chase-generate version` derives what CI publishes.
      version = nixpkgs.lib.fileContents ./VERSION;

      # THE BINARY. Everything the module runs rather than evaluates: every
      # hook flong is given and every unit systemd is. Only the Go sources
      # are its source, so a change to a doc or a check does not rebuild it.
      mkChase = pkgs: pkgs.buildGoModule {
        pname = "chase";
        inherit version;
        src = nixpkgs.lib.fileset.toSource {
          root = ./.;
          # apps/ too: the generated tables the tests regenerate and the
          # apps' tests read.
          fileset = nixpkgs.lib.fileset.unions [ ./go.mod ./go.sum ./cmd ./internal ./apps ];
        };

        # The binary is chase alone: chase-generate is its own package below.
        # Excluded, not subPackages, so every package's tests still run here.
        excludedPackages = [ "cmd/chase-generate" ];

        # Pinned rather than null, because there are dependencies: frisket's
        # public packages, the address and names a project is known by and the
        # policy document's types, so chase builds what frisket reads with
        # frisket's own code; and golang.org/x/crypto's ssh, which reads an SSH
        # grant's host keys as frisket does. The frisket-pin check holds
        # go.mod's frisket to the one flake.lock pins.
        vendorHash = "sha256-vSNXEoQh2bSnBxhm0SsRgsBtW+OB0j00XqNmv8iS+ak=";

        # A static binary, as frisket's is: cgo would bring glibc's NSS, which
        # resolves names by whatever the host's nsswitch.conf says.
        env.CGO_ENABLED = 0;

        ldflags = [ "-s" "-w" "-X" "main.version=${version}" ];

        # The unit tests are checks.test rather than this build's checkPhase:
        # every VM test and every check that runs the binary waits on this
        # derivation, and buildGoModule's checkPhase tests one package after
        # another. What they need stays here for the checks that turn them
        # on: real git for the checkouts they build, sqlite3 for the codex
        # thread indexes a move repoints, protoc for the gcloud
        # generator's fixtures, and frisket's `check` for the documents chase
        # writes, required rather than skipped. With doCheck off, none of it
        # is an input of the binary.
        doCheck = false;
        nativeCheckInputs = [ pkgs.git pkgs.protobuf (nixpkgs.lib.getBin pkgs.sqlite) frisket.packages.${pkgs.stdenv.hostPlatform.system}.default ];
        env.CHASE_REQUIRE_FRISKET = "1";

        meta = {
          description = "Which sandbox a checkout gets, and which credential each app is given";
          homepage = "https://github.com/danielbodart/chase";
          license = nixpkgs.lib.licenses.mit;
          mainProgram = "chase";
          platforms = nixpkgs.lib.platforms.linux;
        };
      };
    in
    {
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        rec {
          chase = mkChase pkgs;
          default = chase;
          # For a person regenerating, and for CI's version: never the
          # module's, and never on a host.
          chase-generate = chase.overrideAttrs (old: {
            pname = "chase-generate";
            # The binary's modules, not a download of its own under its name.
            inherit (chase) goModules;
            subPackages = [ "cmd/chase-generate" ];
            excludedPackages = [ ];
            doCheck = false;
            meta = old.meta // {
              description = "Regenerates what chase reads from what its providers publish";
              mainProgram = "chase-generate";
            };
          });
        });

      # Curried on `self` so the module can reach the flake's own inputs --
      # flong's and frisket's modules -- without a consumer having to pass
      # them in or import them first. See ./module.nix.
      nixosModules.chase = import ./module.nix self;
      nixosModules.default = self.nixosModules.chase;

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          # A system with ./examples/tiers.nix and CHASE (more of the chase
          # section), for what a check needs of its configuration.
          exampleConfig = chase:
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
                    apps = {
                      claude.package = pkgs.hello;
                      codex.package = pkgs.hello;
                      github.credentialFile = "/run/secrets/gh_token";
                    };
                  } chase;
                }
              ];
            }).config;

          # A Go command run as a check, inside the package's build where the
          # module's dependencies already are. It builds no binary -- the
          # command compiles what it needs, and a test's compile, without
          # -trimpath, would not reuse the binary's anyway -- and it takes the
          # package's goModules rather than downloading its own under its own
          # name.
          goCheck = pname: env: command:
            let chase = self.packages.${system}.chase; in
            chase.overrideAttrs (old: {
              inherit pname;
              inherit (chase) goModules;
              env = (old.env or { }) // env;
              dontBuild = true;
              doCheck = true;
              checkPhase = ''
                runHook preCheck
                export GOFLAGS=''${GOFLAGS//-trimpath/}
                ${command}
                runHook postCheck
              '';
              installPhase = "touch $out";
              dontFixup = true;
            });
        in
        {
          # The binary's build.
          inherit (self.packages.${system}) chase;

          # The unit tests, every package at once as `go test ./...` runs
          # them.
          test = goCheck "chase-test" { } "go test ./...";

          # THE MODULE AND THE BINARY AGREE: the configuration the module
          # writes for the example tiers is one the binary loads, strictly,
          # and answers from -- every section, the grant's included. The
          # binary's own tests cover what it does with one; this covers the
          # module writing it.
          module-config =
            let
              config = exampleConfig { };
              file = config.environment.etc."chase/config.json".source;
            in
            pkgs.runCommand "module-config" { nativeBuildInputs = [ self.packages.${system}.chase pkgs.jq ]; } ''
              fail() { echo "module-config: $*" >&2; exit 1; }
              chase -config ${file} tier --dry-run / > out || fail "the tier could not be decided: $(cat out)"
              grep -q ' strict ' out || fail "/ is not the fallback's: $(cat out)"
              # The payload strict's exec prints, from the session section the
              # apps wrote: Claude Code with the tier's settings and the one
              # writable bind, an isolated codex's home, and the placeholder
              # login and trust seeded into the home.
              workspace=/w binds=$'/p:rw\n/q:ro' chase -config ${file} hook exec strict claude -p hi > payload \
                || fail "strict's exec printed no payload"
              tr '\0' '\n' < payload > fields
              settings=$(jq -r .session.tiers.strict.claude.settings ${file})
              [[ $settings == /nix/store/*-claude-strict-settings.json ]] || fail "strict's settings are $settings"
              want=$(printf 'arg:%s\n' claude --add-dir /p --settings "$settings" --allow-dangerously-skip-permissions -p hi)
              [ "$(grep '^arg:' fields)" = "$want" ] || fail "strict runs $(grep '^arg:' fields)"
              grep -qx 'env:CODEX_HOME=/home/alice/.local/state/chase/codex/strict/-w' fields || fail "strict's codex has no home: $(cat fields)"
              ! grep -q '^env:XDG_CACHE_HOME=' fields || fail "strict keeps caches: $(cat fields)"
              # trusted keeps them, for the tier, its tools pointed there.
              jq -e '.session.tiers.trusted.stores.caches | .scope == "tier" and .root == "/home/alice/.cache/chase/caches" and .env.XDG_CACHE_HOME == "cache"' ${file} > /dev/null \
                || fail "trusted keeps no caches: $(jq -c .session.tiers.trusted.stores ${file})"
              grep -qx 'file:0600:/home/alice/.claude/.credentials.json' fields || fail "strict's Claude Code has no login"
              grep -qx 'file:0600:/home/alice/.claude.json' fields || fail "strict's Claude Code does not trust its workspace"
              # The container's environment is flong's computation of it, a
              # profile's variables and the launch's own references among
              # it, not environment.variables alone.
              jq -e '.session.tiers.strict.environment.XDG_DATA_DIRS | contains("''${HOME}/.nix-profile/share")' ${file} > /dev/null \
                || fail "strict's environment is not flong's: $(jq -c .session.tiers.strict.environment ${file})"
              # A closed list: nothing else on the container's PATH runs.
              ! workspace=/w chase -config ${file} hook exec strict sh -c id > /dev/null 2>&1 || fail "strict ran sh"
              for section in selector session grant wrappers claude codex; do
                jq -e --arg s "$section" 'has($s)' ${file} >/dev/null || fail "no $section section"
              done
              touch $out
            '';

          # Formatting as a gate rather than a habit, as frisket has it.
          gofmt = pkgs.runCommand "gofmt"
            { nativeBuildInputs = [ pkgs.go ]; }
            ''
              cd ${self.packages.${system}.chase.src}
              unformatted=$(gofmt -l .)
              if [ -n "$unformatted" ]; then
                echo "not gofmt'd:" >&2
                echo "$unformatted" >&2
                exit 1
              fi
              touch $out
            '';

          # go vet from inside the package's own build, where the module's
          # dependencies already are.
          govet = goCheck "chase-vet" { } "go vet ./...";

          # The tests again, under the race detector, which needs cgo; the
          # package is still built static and never ships this.
          race = goCheck "chase-race" { CGO_ENABLED = 1; } "go test -race ./...";

          # ONE FRISKET. The module and the checks take frisket from
          # flake.lock, and the binary compiles frisket's public packages from
          # the version go.mod requires. Were they two commits, chase would
          # build documents and name projects with one frisket's code while
          # another serves them. go.mod's pseudo-version ends in the commit's
          # first twelve hex digits, so the two must agree there.
          frisket-pin =
            let
              locked = (builtins.fromJSON (builtins.readFile ./flake.lock)).nodes.frisket.locked.rev;
              required = builtins.head (builtins.match ".*\n[[:space:]]*github.com/danielbodart/frisket (v[^[:space:]]+).*" (builtins.readFile ./go.mod));
              commit = builtins.head (builtins.match ".*-([0-9a-f]{12})" required);
            in
            assert nixpkgs.lib.assertMsg (builtins.match ".*replace[[:space:]].*" (builtins.readFile ./go.mod) == null)
              "go.mod replaces a module, so what it builds is not what it requires";
            assert nixpkgs.lib.assertMsg (nixpkgs.lib.hasPrefix commit locked)
              "go.mod requires frisket ${required}, but flake.lock pins ${locked}";
            pkgs.writeText "frisket-pin" locked;

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
                        apps = {
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
            assert refused "a bare tier with an app" { chase.tiers.host.apps.claude.enable = true; } "is bare";
            # TRUST IS A TIER'S TO SAY, and off unless it does: trusted's
            # sessions trust their checkout, strict's do not, and a bare
            # tier that says so has the wrapper trust it on the host,
            # without becoming a sandbox.
            assert
              (let
                config = configWith { chase.tiers.host.apps = { claude.trust = true; codex.trust = true; mise.trust = true; }; };
                c = config.chase.internal.config;
              in
              lib.all (a: a.assertion) config.assertions
              && c.session.tiers.trusted.claude.trust && c.session.tiers.trusted.codex.trust
              && ! c.session.tiers.strict.claude.trust && ! c.session.tiers.strict.codex.trust
              && c.selector.tiers.host.trust == { claude = true; codex = true; env = [ "MISE_TRUSTED_CONFIG_PATHS" ]; }
              && ! c.selector.tiers.trusted ? trust
              && ! c.session.tiers ? host)
              || throw "assertions: trust was not where the tiers say";
            # Codex's homes are chase's state, and the codex commands move
            # them from where an earlier chase kept them, with sqlite3 to
            # repoint their thread indexes.
            assert
              (let c = (configWith { }).chase.internal.config.codex; in
              c.stateDir == "/home/alice/.local/state/chase/codex"
              && c.placeholder == "/home/alice/.local/state/chase/codex/auth-placeholder.json"
              && c.formerStateDir == "/home/alice/.local/state/agents/codex"
              && nixpkgs.lib.hasSuffix "/bin/sqlite3" c.sqlite)
              || throw "assertions: codex's state is not chase's";
            # A bare tier is no container, launcher or policy; every other is.
            assert
              (let config = configWith { }; in
              ! config.containers ? chase-host && ! config.flong ? chase-host
              && ! config.services.frisket.policies ? host
              && config.containers ? chase-strict && config.flong ? chase-trusted
              && config.services.frisket.policies ? strict)
              || throw "assertions: a bare tier was given a sandbox, or a sandbox was not";
            # RECORDING (record.nix) is a tier's own second launcher: on its
            # container, with its guard, binds and filter, but every
            # connection steered to frisket and chase's record hooks in
            # place of approve and exec; the selector knows it, and only a
            # tier whose seccompPolicy and document chase writes records.
            assert refused "recording a tier that takes no grant" { chase.tiers.strict.record.enable = true; } "strict takes no grant";
            assert refused "recording a bare tier" { chase.tiers.host.record.enable = true; } "host is bare";
            assert
              (let
                config = configWith { chase.tiers.trusted.record.enable = true; };
                l = config.flong.chase-trusted-record;
                t = config.flong.chase-trusted;
                f = config.services.frisket.flong;
                c = config.chase.internal.config;
              in
              lib.all (a: a.assertion) config.assertions
              && l.container == "chase-trusted" && l.network == null && t.network != null
              && l.guard == t.guard && l.binds == t.binds && l.workspace == t.workspace && l.seccomp == t.seccomp
              && lib.elem [ "record-approve" "trusted" ] (map (h: lib.drop 2 h) l.seccompPolicy)
              && lib.drop 1 l.exec == [ "hook" "record-exec" "trusted" ]
              && f.chase-trusted-record.set == "all" && f.chase-trusted.set == "service"
              && f.chase-trusted-record.policyFile == f.chase-trusted.policyFile
              && lib.hasSuffix "/bin/chase-trusted-record" c.selector.tiers.trusted.recordLauncher
              && ! c.selector.tiers.strict ? recordLauncher
              && c.grant.recordDir == "/var/lib/frisket/records"
              && lib.hasSuffix "/bin/flong-seccomp" c.record.seccomp
              && lib.hasSuffix "/bin/journalctl" c.record.journalctl
              && lib.hasPrefix "/nix/store/" c.record.names.trusted
              && ! config.flong ? chase-strict-record)
              || throw "assertions: trusted's record launcher is not the tier's own, steered whole";
            # The old selector options say where their replacement is.
            assert refused "a removed selector option" { chase.trustedOrgs = [ "alice" ]; } "chase.tiers.<name>.match";
            # DECLARED BUT UNBOUND REFUSES (PLAN.md, decision 4). trusted's
            # github is authenticated, so a null credential file is a route
            # frisket would serve with no credential at all.
            assert refused "an unbound github credential"
              { chase.apps.github.credentialFile = lib.mkForce null; }
              "chase.tiers.trusted.apps.github is authenticated, but has no credentialFile";
            # ... and is fine when no tier is authenticated for github or git.
            assert chaseFailures {
              chase.apps.github.credentialFile = lib.mkForce null;
              chase.tiers.trusted.apps = { github.authenticated = lib.mkForce false; git.authenticated = lib.mkForce false; };
            } == [ ]
              || throw "assertions: an unauthenticated github still demanded a credential";
            # git's credential is github's unless it has its own: one that
            # pushes without it is refused just the same ...
            assert refused "an unbound credential for git alone"
              { chase.apps.github.credentialFile = lib.mkForce null; chase.tiers.trusted.apps.github.authenticated = lib.mkForce false; }
              "chase.tiers.trusted.apps.git is authenticated, but has no credentialFile";
            # ... and a tier's own is its own: strict, given one, holds it,
            # and trusted still holds the machine's.
            assert
              (let p = (configWith {
                chase.tiers.strict.apps.github = { authenticated = true; credentialFile = "/run/secrets/strict_gh"; };
              }).services.frisket.policies; in
              p.strict.routes.github.credentialFile == "/run/secrets/strict_gh"
              && p.trusted.routes.github.credentialFile == "/run/secrets/gh_token")
              || throw "assertions: a tier's own credential was not its own";
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
            # one -- and unless it is authenticated the tier has no
            # Cloudflare route, whatever the machine binds.
            assert
              (let config = configWith {
                chase.tiers.trusted.apps.cloudflare.enable = true;
                chase.apps.cloudflare.credentialFile = "/run/secrets/cloudflare-token";
              }; in
              lib.all (a: a.assertion) config.assertions
              && ! (config.services.frisket.policies.trusted.routes ? cloudflare))
              || throw "assertions: cloudflare without a token of the tier's own did not hold together";
            # Authenticated, it holds together: no assertion fails, chase's or
            # frisket's, and frisket's configuration -- every generated
            # operation, through frisket's own option types -- is written.
            # Forcing ExecStart forces the file it names.
            assert
              (let
                config = configWith {
                  chase.tiers.trusted.apps.cloudflare = { enable = true; authenticated = true; };
                  chase.apps.cloudflare.credentialFile = "/run/secrets/cloudflare-token";
                };
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
              in
              failed == [ ] && lib.hasInfix ''"-config" "/nix/store/'' config.systemd.services.frisket.serviceConfig.ExecStart
                || throw "assertions: a bound cloudflare did not hold together: ${builtins.toJSON failed}");
            # Hugging Face as github is: a tier authenticated with a
            # credential it was not given is refused ...
            assert refused "an unbound huggingface credential"
              { chase.tiers.trusted.apps.huggingface = { enable = true; authenticated = true; }; }
              "chase.tiers.trusted.apps.huggingface is authenticated, but has no credentialFile";
            # ... and one that is not needs none, holds none, and refuses
            # the token Xet would write with.
            assert
              (let
                config = configWith { chase.tiers.strict.apps.huggingface.enable = true; };
                route = config.services.frisket.policies.strict.routes.huggingface;
              in
              lib.all (a: a.assertion) config.assertions
              && route.credentialFile == null
              && lib.any (p: p.refuse or false && p.path or "" == "/api/models/*/*/xet-write-token/*") route.paths
              && ! lib.any (p: p.ask or false) route.paths)
              || throw "assertions: an unauthenticated huggingface did not hold together";
            # Its downloads are kept as the tier's caches are unless it says:
            # trusted's for the tier, in a store of its own, and strict's in
            # the session, named so XDG_CACHE_HOME never moves them; `host`
            # binds the host's.
            assert
              (let
                config = configWith {
                  chase.tiers.trusted.apps.huggingface.enable = true;
                  chase.tiers.strict.apps.huggingface.enable = true;
                };
                hostScope = configWith { chase.tiers.trusted.apps.huggingface = { enable = true; scope = "host"; }; };
                session = config.chase.internal.config.session.tiers;
              in
              session.trusted.stores.huggingface.scope == "tier"
              && ! session.strict.stores ? huggingface
              && config.containers.chase-strict.config.environment.variables.HF_HUB_CACHE == "/home/alice/.cache/huggingface/hub"
              && ! config.containers.chase-trusted.config.environment.variables ? HF_HUB_CACHE
              && hostScope.containers.chase-trusted.bindMounts ? "/home/alice/.cache/huggingface/hub"
              && ! hostScope.chase.internal.config.session.tiers.trusted.stores ? huggingface)
              || throw "assertions: huggingface's downloads were not kept where its scope says";
            # mise's installs follow the tier's caches as Hugging Face's do:
            # trusted's for the tier, in a store, with its shims on PATH;
            # strict's overlaid from the host. Its state is the host's,
            # overlaid, in every scope; `host` binds the installs.
            assert
              (let
                config = configWith {
                  chase.tiers.trusted.apps.mise.enable = true;
                  chase.tiers.strict.apps.mise.enable = true;
                };
                hostScope = configWith { chase.tiers.trusted.apps.mise = { enable = true; scope = "host"; }; };
                session = config.chase.internal.config.session.tiers;
                trusted = config.containers.chase-trusted.config.environment;
              in
              lib.all (a: a.assertion) config.assertions
              && session.trusted.stores.mise.env.MISE_DATA_DIR == "data"
              && lib.hasInfix "/home/alice/.cache/chase/mise/trusted/all/data/shims" trusted.extraInit
              && ! trusted.variables ? MISE_DATA_DIR
              && trusted.variables.MISE_STATE_DIR == "/home/alice/.local/state/mise"
              && config.flong.chase-trusted.overlays ? "/home/alice/.local/state/mise"
              && ! config.flong.chase-trusted.overlays ? "/home/alice/.local/share/mise"
              && config.flong.chase-strict.overlays ? "/home/alice/.local/share/mise"
              && config.containers.chase-strict.config.environment.variables.MISE_DATA_DIR == "/home/alice/.local/share/mise"
              && hostScope.containers.chase-trusted.bindMounts ? "/home/alice/.local/share/mise"
              && ! hostScope.containers.chase-trusted.bindMounts ? "/home/alice/.local/state/mise")
              || throw "assertions: mise was not kept where its scope says";
            # Claude Code's managed settings are each sandbox container's,
            # never the host's: the container the only boundary, a key a
            # tier sets kept beside the others, and none at all when forced
            # empty.
            assert
              (let
                managed = config: name:
                  builtins.fromJSON (builtins.readFile
                    config.containers."chase-${name}".config.environment.etc."claude-code/managed-settings.json".source);
                config = configWith { chase.tiers.strict.apps.claude.managedSettings.permissions.defaultMode = "plan"; };
                none = configWith { chase.tiers.trusted.apps.claude.managedSettings = lib.mkForce { }; };
              in
              managed config "trusted" == { allowManagedPermissionRulesOnly = true; permissions.defaultMode = "auto"; }
              && managed config "strict" == { allowManagedPermissionRulesOnly = true; permissions.defaultMode = "plan"; }
              && ! config.environment.etc ? "claude-code/managed-settings.json"
              && ! none.containers.chase-trusted.config.environment.etc ? "claude-code/managed-settings.json")
              || throw "assertions: Claude Code's managed settings were not each container's";
            # Google Cloud is only ever a project's (PLAN.md, decision 9): a
            # tier that takes no grant cannot enable it, an API it names
            # must exist, and a tier that has it gets gcloud and nothing in
            # its own document.
            assert refused "gcloud in a tier that takes no grant"
              { chase.tiers.strict.apps.gcloud.enable = true; } "takes no grant";
            assert refused "an unknown Google API"
              { chase.tiers.trusted.apps.gcloud = { enable = true; apis = [ "bigquery" "nope" ]; }; } "names no Google API: nope";
            assert
              (let
                config = configWith { chase.tiers.trusted.apps.gcloud = { enable = true; apis = [ "bigquery" ]; }; };
                env = config.containers.chase-trusted.config.environment;
                policy = config.services.frisket.policies.trusted;
              in
              lib.all (a: a.assertion) config.assertions
              && lib.any (p: lib.getName p == lib.getName pkgs.google-cloud-sdk) env.systemPackages
              && env.variables.CLOUDSDK_CONFIG == "/run/user/1000/gcloud"
              && env.variables.CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE == "/etc/frisket/ca-bundle.crt"
              && env.variables.GRPC_DEFAULT_SSL_ROOTS_FILE_PATH == "/etc/frisket/ca-bundle.crt"
              && ! lib.any (lib.hasPrefix "gcloud") (lib.attrNames policy.routes)
              && ! lib.elem "*.googleapis.com" policy.allow
              && ! config.containers.chase-strict.config.environment.variables ? CLOUDSDK_CONFIG)
              || throw "assertions: gcloud in trusted did not hold together";
            # Docker is only ever a project's, and only where a session has
            # the network a container on the host's daemon has anyway.
            assert refused "Docker in a tier with no network but frisket"
              { chase.tiers.strict = { grants = true; apps.docker.enable = true; }; } "chase.tiers.strict.apps.docker is enabled, but the tier's egress is not direct";
            assert refused "Docker in a tier that takes no grant"
              { chase.tiers.open = { egress = "direct"; apps.docker.enable = true; }; } "chase.tiers.open.apps.docker is enabled, but the tier takes no grant";
            # trusted publishes what a session listens on ("auto"), which
            # Docker's relay is not refused over: it listens on nothing a
            # session's pasta would see. The tier gets the CLI and the CA it
            # verifies frisket by, and nothing in its own document: the
            # route is made per launch, for a project.
            assert
              (let
                config = configWith { chase.tiers.trusted.apps.docker.enable = true; };
                env = config.containers.chase-trusted.config.environment;
                policy = config.services.frisket.policies.trusted;
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
              in
              failed == [ ]
              && config.chase.tiers.trusted.forwardPorts == "auto"
              && lib.any (p: lib.getName p == "docker") env.systemPackages
              && env.etc."chase/docker/ca.pem".source == "/etc/frisket/ca.crt"
              && ! policy.routes ? docker
              && ! lib.elem "docker.frisket.internal" policy.allow
              && ! lib.any (p: lib.getName p == "docker") config.containers.chase-strict.config.environment.systemPackages
              && ! config.containers.chase-strict.config.environment.etc ? "chase/docker/ca.pem")
              || throw "assertions: Docker in trusted did not hold together";
            # SSH is only ever a project's, through frisket, which holds the
            # one credential the machine names: an agent's socket or a key
            # file, by a path the daemon reaches, never the store's.
            assert refused "SSH in a tier that takes no grant"
              { chase.tiers.strict.apps.ssh.enable = true; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "chase.tiers.strict.apps.ssh is enabled, but the tier takes no grant";
            assert refused "SSH in a bare tier"
              { chase.tiers.host.apps.ssh.enable = true; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "chase.tiers.host.apps.ssh is enabled, but the tier is bare";
            assert refused "SSH with nothing to log in with"
              { chase.tiers.trusted.apps.ssh.enable = true; } "chase.apps.ssh needs exactly one of agentSocket and keyFile";
            assert refused "SSH with two things to log in with"
              { chase.tiers.trusted.apps.ssh.enable = true; chase.apps.ssh = { agentSocket = "/run/user/1000/gcr/ssh"; keyFile = "/home/alice/.ssh/k"; }; } "exactly one of agentSocket and keyFile";
            assert refused "an agent under /tmp, which the daemon's PrivateTmp hides"
              { chase.tiers.trusted.apps.ssh.enable = true; chase.apps.ssh.agentSocket = "/tmp/ssh-XXXX/agent.1"; } "chase.apps.ssh.agentSocket is '/tmp/ssh-XXXX/agent.1', which is under a /tmp";
            assert refused "a key file in the store"
              { chase.tiers.trusted.apps.ssh.enable = true; chase.apps.ssh.keyFile = "${pkgs.hello}/key"; } "is in the store";
            assert refused "a relative key file"
              { chase.tiers.trusted.apps.ssh.enable = true; chase.apps.ssh.keyFile = "home/alice/k"; } "is not an absolute path";
            assert refused "a key file that is not clean"
              { chase.tiers.trusted.apps.ssh.enable = true; chase.apps.ssh.keyFile = "/home/alice/../bob/k"; } "is not a clean path";
            assert refused "an identity with no agent"
              { chase.tiers.trusted.apps.ssh.enable = true; chase.apps.ssh = { keyFile = "/home/alice/.ssh/k"; identity = "SHA256:${lib.fixedWidthString 43 "A" ""}"; }; } "identity names a key of an agent's";
            # A Nix path is no string: it would copy the key into the store.
            assert ! (builtins.tryEval (configWith { chase.apps.ssh.keyFile = ./flake.nix; }).chase.apps.ssh.keyFile).success
              || throw "assertions: a key file given as a Nix path was taken";
            # An env name is a name, or the start of one and a *: never a
            # lone *, which would be every name.
            assert ! (builtins.tryEval (builtins.deepSeq (configWith { chase.tiers.trusted.apps.ssh = { enable = true; env = [ "*" ]; }; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; }).chase.tiers.trusted.apps.ssh.env true)).success
              || throw "assertions: a lone * was taken as an env name";
            # trusted's sessions point ssh at what frisket mounts, ahead of
            # NixOS's own settings and with no store path included; their
            # machines and rules are made per launch, from the grant, so
            # nothing of them is in the tier's document.
            assert
              (let
                config = configWith { chase.tiers.trusted.apps.ssh.enable = true; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; };
                env = config.containers.chase-trusted.config.environment;
                text = env.etc."ssh/ssh_config".text;
                c = config.chase.internal.config.grant;
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
              in
              failed == [ ]
              && lib.hasPrefix "Include /etc/frisket/ssh_config\nGlobalKnownHostsFile /etc/frisket/ssh_known_hosts /etc/ssh/ssh_known_hosts\n" text
              && ! lib.hasInfix "Include ${builtins.storeDir}" text
              && ! lib.hasInfix "/etc/frisket/ssh_config" config.containers.chase-strict.config.environment.etc."ssh/ssh_config".text
              && c.ssh.tiers == { trusted = { writes = "ask"; guarded = "refuse"; unmatched = "ask"; env = [ "LANG" "LC_*" "TZ" "COLUMNS" "LINES" "NO_COLOR" "SYSTEMD_COLORS" ]; }; }
              && c.ssh.agent == "/run/user/1000/gcr/ssh" && ! c.ssh ? keyFile && ! c.ssh ? identity
              && lib.hasPrefix builtins.storeDir c.ssh.catalogue
              && c.apps.ssh.credential == false
              && ! config.services.frisket.policies.trusted ? ssh)
              || throw "assertions: SSH in trusted did not hold together";
            # A TIER'S OWN MACHINES, each logging in with its own credential
            # or the machine's, by a path frisket reads and the session never
            # sees; a tier with them needs no grant, and is launched for them.
            assert
              (let
                key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHp6lanvRi86XJnpME3lUbtyAWnykpE7SwLQXBzaXa/F";
                config = configWith {
                  chase.tiers.strict.apps.ssh = {
                    enable = true;
                    hosts.modem = { address = "192.168.1.1"; user = "admin"; hostKeys = [ key ]; passwordFile = "/run/secrets/modem-password"; shell = true; };
                  };
                };
                c = config.chase.internal.config;
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
                inside = builtins.toJSON config.containers.chase-strict.config.environment.etc;
              in
              failed == [ ]
              && c.grant.ssh.tiers.strict.hosts == { modem = { address = "192.168.1.1"; user = "admin"; hostKeys = [ key ]; passwordFile = "/run/secrets/modem-password"; shell = true; }; }
              && ! c.grant.ssh ? agent
              && c.grant.ungranted == [ "strict" ] && lib.elem "strict" c.grantTiers
              && config.flong.chase-strict.seccompPolicy != [ ]
              && lib.hasInfix "Include /etc/frisket/ssh_config" config.containers.chase-strict.config.environment.etc."ssh/ssh_config".text
              && ! lib.hasInfix "modem-password" inside)
              || throw "assertions: a tier's own machines did not hold together";
            assert refused "tier machines with SSH off"
              { chase.tiers.trusted.apps.ssh.hosts.m = { address = "10.0.0.9"; user = "u"; hostKeys = [ "k" ]; }; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "chase.tiers.trusted.apps.ssh.hosts names machines, and apps.ssh is not enabled";
            assert refused "a tier machine with two credentials"
              { chase.tiers.trusted.apps.ssh = { enable = true; hosts.m = { address = "10.0.0.9"; user = "u"; hostKeys = [ "k" ]; keyFile = "/home/alice/k"; passwordFile = "/run/secrets/p"; }; }; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "chase.tiers.trusted.apps.ssh.hosts.m names keyFile and passwordFile";
            assert refused "a tier machine's password under /tmp"
              { chase.tiers.trusted.apps.ssh = { enable = true; hosts.m = { address = "10.0.0.9"; user = "u"; hostKeys = [ "k" ]; passwordFile = "/tmp/p"; }; }; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "chase.tiers.trusted.apps.ssh.hosts.m.passwordFile is '/tmp/p', which is under a /tmp";
            assert refused "a tier machine's identity with no agent of its own"
              { chase.tiers.trusted.apps.ssh = { enable = true; hosts.m = { address = "10.0.0.9"; user = "u"; hostKeys = [ "k" ]; identity = "SHA256:${lib.fixedWidthString 43 "A" ""}"; }; }; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "hosts.m.identity names a key of the host's own agent";
            assert refused "a tier machine with no key"
              { chase.tiers.trusted.apps.ssh = { enable = true; hosts.m = { address = "10.0.0.9"; user = "u"; hostKeys = [ ]; }; }; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "hosts.m.hostKeys is empty";
            assert refused "a tier machine with an upper-case name"
              { chase.tiers.trusted.apps.ssh = { enable = true; hosts.M = { address = "10.0.0.9"; user = "u"; hostKeys = [ "k" ]; }; }; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "'M' is not a host's name";
            assert refused "a tier machine logging in with the machine's credential, which it has not"
              { chase.tiers.strict.apps.ssh = { enable = true; hosts.m = { address = "10.0.0.9"; user = "u"; hostKeys = [ "k" ]; }; }; } "a tier's that names none of its own";
            # A MACHINE'S OWN CATALOGUE: a name the machine offers, each in
            # the store, and the machine's build checks every one, and every
            # tier's own machines, as a launch would.
            assert
              (let
                key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHp6lanvRi86XJnpME3lUbtyAWnykpE7SwLQXBzaXa/F";
                config = configWith {
                  chase.apps.ssh.catalogues.zyxel = ./apps/ssh/operations.json;
                  chase.tiers.strict.apps.ssh = {
                    enable = true;
                    hosts.modem = { address = "192.168.1.1"; user = "admin"; hostKeys = [ key ]; passwordFile = "/run/secrets/modem-password"; shell = true; catalogue = "zyxel"; expect."cat /etc/passwd" = "allow"; };
                  };
                };
                c = config.chase.internal.config;
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
              in
              failed == [ ]
              && c.grant.ssh.tiers.strict.hosts.modem.catalogue == "zyxel"
              && c.grant.ssh.tiers.strict.hosts.modem.expect == { "cat /etc/passwd" = "allow"; }
              && lib.hasPrefix "${builtins.storeDir}/" c.grant.ssh.catalogues.zyxel
              && lib.any (d: lib.getName d == "chase-ssh-check") config.system.checks)
              || throw "assertions: a machine's own catalogue did not hold together";
            assert refused "a tier machine naming a catalogue the machine does not offer"
              { chase.apps.ssh.catalogues.draytek = ./apps/ssh/operations.json; chase.tiers.trusted.apps.ssh = { enable = true; hosts.m = { address = "10.0.0.9"; user = "u"; hostKeys = [ "k" ]; catalogue = "zyxel"; }; }; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "hosts.m.catalogue is 'zyxel', which is no catalogue chase.apps.ssh.catalogues offers: it offers draytek";
            assert refused "a catalogue named as no machine could name it"
              { chase.apps.ssh.catalogues.Zyxel = ./apps/ssh/operations.json; chase.tiers.trusted.apps.ssh.enable = true; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "chase.apps.ssh.catalogues.Zyxel: a catalogue is named in kebab-case";
            assert refused "a catalogue outside the store"
              { chase.apps.ssh.catalogues.zyxel = "/home/alice/zyxel.json"; chase.tiers.trusted.apps.ssh.enable = true; chase.apps.ssh.agentSocket = "/run/user/1000/gcr/ssh"; } "is a file in the store";
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
                      chase.tiers.trusted.apps.cloudflare = { enable = true; authenticated = true; };
                      chase.apps.cloudflare.credentialFile = "/run/secrets/cloudflare-token";
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
                sandboxes = lib.filterAttrs (n: _: lib.hasPrefix "chase-" n) config.flong;
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
              in
              sandboxes != { }
              && ! lib.any (r: lib.elem "alice" (r.users or [ ])) config.security.sudo.extraRules
              && failed == [ ]
                || throw "assertions: a session is granted sudo, or flong refused them: ${builtins.toJSON failed}");
            # The example tiers' filters: trusted can debug, strict cannot;
            # only a tier that takes grants asks the checkout for more.
            assert
              (let config = configWith { }; in
              config.flong.chase-trusted.seccomp.debug
              && config.flong.chase-trusted.seccompPolicy != [ ]
              && config.flong.chase-strict.seccomp.tier == "strict"
              && ! config.flong.chase-strict.seccomp.debug
              && config.flong.chase-strict.seccompPolicy == [ ])
              || throw "assertions: the tiers' seccomp is not what they say";
            pkgs.runCommand "assertions" { } "touch $out";

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
          # The tables are frisket's internal/dockerapi/testdata/fields.json,
          # byte for byte, at the frisket this flake locks. frisket's own
          # tests judge the bodies Compose really sent, and every refusal its
          # floor makes, against that copy, so the tables chase serves are
          # the ones those tests passed; a change is made there first and
          # reaches chase with the input.
          #
          # Last, frisket itself loads a session's document built from the
          # files, with the address and names `chase docker-address` gives, so
          # a table weaker than frisket's floor, or names frisket would not
          # derive, fails here rather than when a session will not start.
          docker-fields =
            let
              frisketPackage = frisket.packages.${system}.default;
            in
            pkgs.runCommand "docker-fields" { nativeBuildInputs = [ self.packages.${system}.chase frisketPackage pkgs.jq ]; } ''
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
                who=$(chase docker-address example/shop) || fail "shop was given no address"
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

              cmp -s ${./apps/docker/fields.json} ${frisket}/internal/dockerapi/testdata/fields.json \
                || fail "apps/docker/fields.json is not frisket's internal/dockerapi/testdata/fields.json: change it there, and take the input"
              # A key given twice would be read as its last by jq and by
              # frisket's decoder of the route, while a reviewer may read the
              # first; and one row per line is what a bump's diff shows.
              f=${./apps/docker/fields.json}
              [ "$(jq -c --stream . $f | wc -l)" = "$(jq -c tostream $f | wc -l)" ] || fail "fields.json gives a key twice in one object"
              [ "$(grep -cE '^    "[^"]+": ' $f)" = "$(jq '[.[] | length] | add' $f)" ] || fail "fields.json is not one row per line"

              fresh
              judge || fail "the tables were not judged whole: $(cat $TMPDIR/err)"
              [ "$(jq -c '.routes[0].docker | [.address, .names]' $TMPDIR/sample.json)" = '["127.101.170.171",["shop.example.internal"]]' ] \
                || fail "the sample is not shop's address and names: $(jq -c '.routes[0].docker' $TMPDIR/sample.json | head -c 300)"
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
              own="are not [\"shop.example.internal\"], the project's own"
              unloaded "names beyond what it derives" '.routes[0].docker.names += ["shop.internal"]' "$own"
              unloaded "names short of what it derives" '.routes[0].docker.names = []' "$own"
              unloaded "another project's names" '.routes[0].docker.names = ["billing.example.internal"]' "$own"
              unloaded "an address it does not derive" '.routes[0].docker.address = "127.101.170.172"' "is not 127.101.170.171, the project's own"

              touch $out
            '';

          gcloud-session = pkgs.testers.runNixOSTest (import ./tests/gcloud-session.nix { inherit self home-manager; });
          ssh-session = pkgs.testers.runNixOSTest (import ./tests/ssh-session.nix { inherit self home-manager; });
          record-session = pkgs.testers.runNixOSTest (import ./tests/record-session.nix { inherit self home-manager; });
        } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # Only where the pinned postgres:18 runs: the image is amd64's.
          docker-session = pkgs.testers.runNixOSTest (import ./tests/docker-session.nix { inherit self home-manager; });
        });

      # Go for the binary, built as the flake builds it; chase-generate, and
      # the git and protoc `chase-generate gcloud` runs; sqlite3, which the
      # codex tests hold a thread index in; frisket, whose
      # `check` some tests hold what chase writes to.
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.go pkgs.gopls pkgs.git pkgs.protobuf (nixpkgs.lib.getBin pkgs.sqlite) frisket.packages.${system}.default self.packages.${system}.chase-generate ];
            CHASE_REQUIRE_FRISKET = "1";
            # The setting the package builds with, so a `go build` here gives
            # the binary the flake does.
            CGO_ENABLED = "0";
          };
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
