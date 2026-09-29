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

        # Pinned rather than null, because there is a dependency: frisket's
        # public packages, the address and names a project is known by and the
        # policy document's types, so chase builds what frisket reads with
        # frisket's own code. The frisket-pin check holds go.mod's frisket to
        # the one flake.lock pins.
        vendorHash = "sha256-dGdszz303JcidzwThyehlQrSy4NAjO6yB+AEVdSR9Ik=";

        # A static binary, as frisket's is: cgo would bring glibc's NSS, which
        # resolves names by whatever the host's nsswitch.conf says.
        env.CGO_ENABLED = 0;

        ldflags = [ "-s" "-w" "-X" "main.version=${version}" ];

        # buildGoModule runs `go test ./...` here, so the unit tests gate the
        # build itself: real git for the checkouts they build, protoc for the
        # gcloud generator's fixtures, and frisket's `check` for the documents
        # chase writes, required rather than skipped.
        doCheck = true;
        nativeCheckInputs = [ pkgs.git pkgs.protobuf frisket.packages.${pkgs.stdenv.hostPlatform.system}.default ];
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

      # A project's loopback address and names, from its owner/repo, as
      # `chase docker-address` prints them: address, names, reserved and
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
          # The binary's build, which is also its unit tests.
          inherit (self.packages.${system}) chase;

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
          govet = self.packages.${system}.chase.overrideAttrs (_: {
            pname = "chase-vet";
            checkPhase = ''
              runHook preCheck
              go vet ./...
              runHook postCheck
            '';
          });

          # The tests again, under the race detector, which needs cgo; the
          # package is still built static and never ships this.
          race = self.packages.${system}.chase.overrideAttrs (old: {
            pname = "chase-race";
            env = (old.env or { }) // { CGO_ENABLED = 1; };
            checkPhase = ''
              runHook preCheck
              go test -race ./...
              runHook postCheck
            '';
          });

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
            # Docker is only ever a project's, and only where a session has
            # the network a container on the host's daemon has anyway.
            assert refused "Docker in a tier with no network but frisket"
              { chase.tiers.strict = { envelope = true; apps.docker.enable = true; }; } "chase.tiers.strict.apps.docker is enabled, but the tier's egress is not direct";
            assert refused "Docker in a tier that takes no envelope"
              { chase.tiers.open = { egress = "direct"; apps.docker.enable = true; }; } "chase.tiers.open.apps.docker is enabled, but the tier takes no envelope";
            # trusted publishes what a session listens on ("auto"), which
            # Docker's relay is not refused over: it listens on nothing a
            # session's pasta would see. The tier gets the CLI and the CA it
            # verifies frisket by, and nothing in its own document: the
            # route is made per launch, for a project.
            assert
              (let
                config = configWith { chase.tiers.trusted.apps.docker.enable = true; };
                env = config.containers.agent-trusted.config.environment;
                policy = config.services.frisket.policies.trusted;
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
              in
              failed == [ ]
              && config.chase.tiers.trusted.forwardPorts == "auto"
              && lib.any (p: lib.getName p == "docker") env.systemPackages
              && env.etc."chase/docker/ca.pem".source == "/etc/frisket/ca.crt"
              && ! policy.routes ? docker
              && ! lib.elem "docker.frisket.internal" policy.allow
              && ! lib.any (p: lib.getName p == "docker") config.containers.agent-strict.config.environment.systemPackages
              && ! config.containers.agent-strict.config.environment.etc ? "chase/docker/ca.pem")
              || throw "assertions: Docker in trusted did not hold together";
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

          # The address and names frisket derives again and refuses a route
          # over, and nix-config derives for /etc/hosts. chase gives them
          # with frisket's own functions, which frisket's tests and chase's
          # (internal/dockerproject) hold to the contract's vectors. What is
          # left to hold is lib.docker, the one derivation that is not Go
          # because nix-config has only Nix to evaluate: for every slug here
          # it gives what the binary does, and it refuses what the binary
          # refuses rather than naming a project frisket could never route.
          docker-address =
            let
              docker = self.lib.docker;
              lib = nixpkgs.lib;
              as = n: lib.concatStrings (lib.replicate n "a");
              slugs = [
                "example/shop" "example/billing" "danielbodart/frisket"
                "test/repo-66" "Example/Shop" "bodar/bodar.ts" "bodar/bodar-ts"
                "test/${as 63}" "test/${as 64}" "test/___" "test/..." "test/-x.-" "test/_.._"
                "frisket/docker" "google/metadata" "google/shop" "frisket/foo"
                "frisket/frisket" "google/google" "x/frisket"
              ];
              fromNix = map (slug: { inherit slug; address = docker.address slug; names = docker.names slug; }) slugs;
              refused = [
                "example" "example/shop/x" "" "${lib.concatStrings (lib.replicate 40 "o")}/repo"
                "test/.." "test/." "-test/repo" "test/${lib.concatStrings (lib.replicate 101 "r")}"
                "test/a b" "test/repo\nx" "test/ré" "a/b/c" "evil/../shop" "a/rép" "/x"
              ];
              acceptedByNix = builtins.filter
                (slug: (builtins.tryEval (docker.address slug)).success
                  || (builtins.tryEval (builtins.deepSeq (docker.names slug) true)).success)
                refused;
            in
            assert lib.assertMsg (docker.reserved == frisket.lib.docker.reserved)
              "lib.docker reserves ${builtins.toJSON docker.reserved}, but frisket reserves ${builtins.toJSON frisket.lib.docker.reserved}";
            assert lib.assertMsg (acceptedByNix == [ ])
              "lib.docker gave an address or names to ${builtins.toJSON acceptedByNix}";
            pkgs.runCommand "docker-address" {
              nativeBuildInputs = [ self.packages.${system}.chase pkgs.jq ];
              fromNix = builtins.toJSON fromNix;
              refused = builtins.toJSON refused;
              passAsFile = [ "fromNix" "refused" ];
            } ''
              fail() { echo "docker-address: $*" >&2; exit 1; }
              [ "$(jq length "$fromNixPath")" -eq ${toString (builtins.length slugs)} ] || fail "the slugs from Nix did not arrive"
              while IFS= read -r want; do
                slug=$(jq -r .slug <<< "$want")
                got=$(chase docker-address "$slug") || fail "$slug was refused"
                [ "$(jq -c '{address, names}' <<< "$got")" = "$(jq -c '{address, names}' <<< "$want")" ] \
                  || fail "lib.docker gives $slug $want, but chase docker-address gives $got"
              done < <(jq -c '.[]' "$fromNixPath")
              # NUL-separated: one of the refused has a newline in it.
              while IFS= read -r -d "" slug; do
                ! chase docker-address "$slug" >/dev/null 2>&1 || fail "chase docker-address gave $slug an address"
              done < <(jq -j '.[] + "\u0000"' "$refusedPath")
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
              [ "$(jq -c '.routes[0].docker | [.address, .names]' $TMPDIR/sample.json)" = '["127.101.170.171",["shop.internal","shop.example.internal"]]' ] \
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
              own="are not [\"shop.internal\" \"shop.example.internal\"], the project's own"
              unloaded "names in another order than it derives" '.routes[0].docker.names |= reverse' "$own"
              unloaded "names short of what it derives" '.routes[0].docker.names = ["shop.internal"]' "$own"
              unloaded "another project's names" '.routes[0].docker.names = ["billing.internal", "billing.example.internal"]' "$own"
              unloaded "an address it does not derive" '.routes[0].docker.address = "127.101.170.172"' "is not 127.101.170.171, the project's own"

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
                # An image's ID, or a prefix of one, for whatever local image
                # has it.
                { images = [ "sha256:${digest}" ]; }
                { images = [ "sha256:0123abcd" ]; }
                { images = [ "${digest}:1" ]; }
                { images = [ "o/${digest}:1" ]; }
                { images = [ "o/sha256:1" ]; }
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
                  tiers.trusted.match = [ { checkouts."example/shop" = "${root}/p/shop"; } ];
                  tiers.strict.match = [ { checkouts."Example/Billing" = "${root}/p/billing"; } ];
                };
                rewrite.hosts = "$PWD/docker-hosts.json";
              }}
              r=$(cd "$TMPDIR" && pwd -P)/root
              mkdir -p "$r"

              # Every tier's pins, lower-cased, in one file, put where the
              # build directory is.
              baked=$(sed -n 's/^checkouts=//p' chase-envelope)
              sed "s|${root}|$r|g" "$baked" > checkouts.json
              jq -e --arg r "$r" '.["example/shop"] == [$r + "/p/shop"] and .["example/billing"] == [$r + "/p/billing"]
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
              repo "$r/p/shop" git@github.com:Example/Shop.git
              git -C "$r/p/shop" -c user.name=x -c user.email=x@example.com commit -q --allow-empty -m first
              names "$r/p/shop" example/shop
              mkdir -p "$r/p/shop/sub"
              names "$r/p/shop/sub" example/shop
              git -C "$r/p/shop" worktree add -q "$r/p/shop/.claude/worktrees/feat"
              names "$r/p/shop/.claude/worktrees/feat" example/shop

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
              repo "$r/w/two" git@github.com:acme/app.git git@github.com:example/shop.git
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
              repo "$r/elsewhere/shop" git@github.com:example/shop.git
              refused "$r/elsewhere/shop" "its origin says example/shop, which is pinned at $r/p/shop, not $r/elsewhere/shop"
              repo "$r/p/billing" git@github.com:acme/app.git
              refused "$r/p/billing" "is under $r/p/billing, where example/billing is pinned, but its origin says acme/app"

              # WHAT A SESSION COULD WRITE to take the pinned project's name:
              # its own config's core.worktree, a .git file into the pinned
              # repository, and a clone of its own inside the pinned path,
              # whose session writes its origin.
              repo "$r/forge" git@github.com:example/shop.git
              git -C "$r/forge" config core.worktree "$r/p/shop"
              refused "$r/forge" "core.worktree sends git to $r/p/shop"
              mkdir -p "$r/evil"
              echo "gitdir: $r/p/shop/.git" > "$r/evil/.git"
              refused "$r/evil" "which is not a worktree's"
              repo "$r/p/shop/nested" git@github.com:example/shop.git
              refused "$r/p/shop/nested" "is a checkout of $r/p/shop/nested, not of $r/p/shop"

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
              line='Docker as example/shop at 127.101.170.171 (shop.internal, shop.example.internal), ports 64320 64321'
              said() { grep -F "chase: $r/p/shop: $line" err; }
              ws=$r/p/shop
              flake "$ws"

              # No hosts file: the names are the session's, and the host has
              # only the address.
              approve "$ws" m1 "$docker" || fail "shop was not approved: $(cat err)"
              [ "$(said)" = "chase: $ws: $line; on this host, 127.101.170.171 only" ] || fail "the approval did not say where Docker is: $(cat err)"
              [ "$(staged m1 .result.dockerProject)" = example/shop ] || fail "the project was not staged: $(cat run/chase/.envelope/m1.json)"
              [ "$(asked)" = 1 ] || fail "the envelope was not asked about"
              jq -s -e '[.[] | select(.kind == "envelope")][0].diff | contains("\"dockerProject\": \"example/shop\"")' approvals.jsonl >/dev/null \
                || fail "the approval's diff does not show the project: $(cat approvals.jsonl)"
              [ "$(jq -c . state/docker/addresses.json)" = '{"example/shop":"127.101.170.171"}' ] \
                || fail "the address was not recorded: $(cat state/docker/addresses.json)"

              # The host's names, where the hosts file gives this project
              # them at this address; the address alone where it gives them
              # elsewhere, and only those it gives. Approved again, the same
              # project passes, is not asked about, and is held once.
              printf '{"example/shop": {"address": "127.101.170.171", "names": ["shop.internal", "shop.example.internal"]}}' > docker-hosts.json
              approve "$ws" m2 "$docker" || fail "shop was not approved again: $(cat err)"
              [ "$(said)" = "chase: $ws: $line" ] || fail "the host's names were not recognised: $(cat err)"
              [ "$(asked)" = 1 ] || fail "an unchanged envelope was asked about again"
              [ "$(jq -c . state/docker/addresses.json)" = '{"example/shop":"127.101.170.171"}' ] \
                || fail "the address is not held once: $(cat state/docker/addresses.json)"
              [ "$(grep -o example/shop state/docker/addresses.json | wc -l)" = 1 ] || fail "the project is recorded twice"
              printf '{"example/shop": {"address": "127.9.9.9", "names": ["shop.internal", "shop.example.internal"]}}' > docker-hosts.json
              approve "$ws" m3 "$docker" || fail "shop was not approved: $(cat err)"
              [ "$(said)" = "chase: $ws: $line; on this host, 127.101.170.171 only" ] || fail "names at another address were taken as the host's: $(cat err)"
              printf '{"example/shop": {"address": "127.101.170.171", "names": ["shop.example.internal"]}}' > docker-hosts.json
              approve "$ws" m4 "$docker" || fail "shop was not approved: $(cat err)"
              [ "$(said)" = "chase: $ws: $line; on this host, 127.101.170.171 and shop.example.internal only" ] \
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
              grep -qF "chase: $ws/x?]0;PWNED??[8m: Docker as example/shop at 127.101.170.171" err \
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
              printf '{"evil/x": "127.101.170.171"}' > state/docker/addresses.json
              if approve "$ws" m7 "$docker"; then fail "shop was approved at an address evil/x holds"; fi
              grep -qF "chase: $ws: example/shop would be at 127.101.170.171, which evil/x already holds" err \
                || fail "the collision was not said: $(cat err)"
              [ ! -e run/chase/.envelope/m7.json ] || fail "a collision was staged"
              [ "$(jq -c . state/docker/addresses.json)" = '{"evil/x":"127.101.170.171"}' ] || fail "a collision was recorded"
              rm -rf state/docker
              printf '{"evil/x": {"address": "127.101.170.171", "names": ["x.internal"]}}' > docker-hosts.json
              if approve "$ws" m8 "$docker"; then fail "shop was approved at an address the host gives evil/x"; fi
              grep -qF "chase: $ws: example/shop would be at 127.101.170.171, which evil/x already holds" err \
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
              approve "$r/w/none" m11 '{"dockerProject": "example/shop", "secretsSHA256": "0", "bindings": {"github": {"allow": ["x"]}}}' \
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
                  tiers.trusted.match = [ { checkouts."example/shop" = "${root}/p/shop"; } ];
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

              ws=$r/p/shop
              git init -q "$ws"
              git -C "$ws" config remote.origin.url git@github.com:example/shop.git
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
              [ "$(cat "$m/probe.project")" = set:example/shop ] || fail "prepare was not given the approved project: $(cat "$m/probe.project")"
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

          # DOCKER, LAUNCHED (docs/docker.md): a checkout whose envelope binds
          # Docker gets a route to the rootless daemon, as the project approve
          # staged -- its address, its names, every spelling of its images,
          # its ports and the tables its bodies are judged by -- and the
          # variables that point the CLI at it; frisket loads the document.
          # A checkout that binds nothing of Docker's gets no route, and a
          # binding in a tier without Docker is said and adds nothing.
          docker-launch =
            let
              root = "/chase-docker-launch-test";
              frisketPackage = frisket.packages.${system}.default;
            in
            pkgs.runCommand "docker-launch" { nativeBuildInputs = [ pkgs.git pkgs.jq frisketPackage ]; } ''
              export HOME=$TMPDIR
              fail() { echo "docker-launch: $*" >&2; exit 1; }
              ${envelopeHarness {
                chase = {
                  tiers.trusted = {
                    match = [ { checkouts."example/shop" = "${root}/p/shop"; } ];
                    apps.docker.enable = true;
                  };
                  tiers.plain = { egress = "direct"; envelope = true; };
                };
                rewrite = { hosts = "$PWD/docker-hosts.json"; policies = "$PWD/policies"; };
              }}
              r=$(cd "$TMPDIR" && pwd -P)/root
              baked=$(sed -n 's/^checkouts=//p' chase-envelope)
              sed "s|${root}|$r|g" "$baked" > checkouts.json
              sed -i "s|^checkouts=.*|checkouts=$PWD/checkouts.json|" chase-envelope
              grep -q "^checkouts=$PWD/checkouts.json$" chase-envelope || fail "checkouts is not one line of chase-envelope's"
              jq -e '.docker.credential == false and (.docker.prepare | endswith("/bin/chase-docker-prepare"))' "$(sed -n 's/^apps=//p' chase-envelope)" >/dev/null \
                || fail "docker is not an app with no credential and a prepare"

              mkdir policies
              for t in trusted plain; do
                printf '{"name": "%s", "allow": ["github.com"], "routes": []}\n' "$t" > "policies/$t.json"
              done

              ws=$r/p/shop
              git init -q "$ws"
              git -C "$ws" config remote.origin.url git@github.com:Example/Shop.git
              printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > "$ws/flake.nix"
              git -C "$ws" add flake.nix
              envfile=state/env/$(printf '%s' "$ws" | sha256sum | cut -c1-32)/env

              launched() { # TIER MACHINE ENVELOPE
                ENVELOPE=$3 bash ./chase-envelope approve "$ws" "$2" "$1" >/dev/null 2>err || fail "$2 was not approved: $(cat err)"
                jq -r '.result.dockerProject // empty' "run/chase/.envelope/$2.json" > "staged.$2"
                bash ./chase-envelope launch "$1" "$ws" "$2" 2>err || fail "$2 was not launched: $(cat err)"
              }
              docker='{"bindings": {"docker": {"images": ["postgres:18", "bitnami/redis:7", "ghcr.io/o/x:1"], "ports": [64320, 64321]}}}'

              # THE ROUTE, as shop was approved: its address and names
              # are the project's, never the envelope's, and every spelling
              # the CLI could send of each image is there.
              launched trusted m1 "$docker"
              [ "$(cat staged.m1)" = example/shop ] || fail "approve did not stage the project: $(cat staged.m1)"
              grep -qxF "chase: $ws: docker from no credential" err || fail "where docker came from was not said: $(cat err)"
              policy=run/chase/m1/policy.json
              [ "$(jq '[.routes[] | select(.name == "docker")] | length' $policy)" = 1 ] || fail "there is not one docker route: $(jq -c '[.routes[].name]' $policy)"
              route=$(jq -c '.routes[] | select(.name == "docker")' $policy)
              jq -e --argjson admit "$(cat ${./apps/docker/admit.json})" --argjson fields "$(cat ${./apps/docker/fields.json})" '
                .host == "docker.frisket.internal" and .upstream == "unix:///run/user/1000/docker.sock"
                and .unmatched == "refuse" and (has("credentialFile") | not)
                and .docker.project == "example/shop"
                and .docker.address == "127.101.170.171"
                and .docker.names == ["shop.internal", "shop.example.internal"]
                and .docker.images == ["postgres:18", "library/postgres:18", "docker.io/postgres:18", "docker.io/library/postgres:18",
                                       "bitnami/redis:7", "docker.io/bitnami/redis:7", "ghcr.io/o/x:1"]
                and .docker.ports == [64320, 64321]
                and .docker.apiVersions == {min: "1.55", max: "1.56", unversioned: ["/_ping"]}
                and .docker.maxBody == 262144
                and .docker.bodies == ($fields | with_entries(select(.key as $k | [$admit[] | .docker.body // empty] | index($k))))
                and (.docker.bodies | keys) == ["ContainerCreate", "ExecCreate", "ExecStart", "NetworkCreate", "VolumeCreate"]
                and all(.paths[]; has("operation") and (.operation | has("description") | not))
                and ([.paths[] | select(.refuse | not) | {key: .operation.id, value: {methods, docker}}] | from_entries) == $admit
                and ([.paths[] | select(.refuse | not)] | length) == ($admit | length)
                and all(.paths[]; (.ask // false) | not)' <<< "$route" >/dev/null \
                || fail "the route is not shop's: $(jq -c 'del(.paths, .docker.bodies)' <<< "$route")"
              jq -e '.allow == ["docker.frisket.internal", "github.com"]' $policy >/dev/null || fail "docker.frisket.internal was not allowed: $(jq -c .allow $policy)"
              frisket check $policy || fail "frisket refused the document"

              # THE ENVIRONMENT: the CLI pointed at frisket, verifying it by
              # the session's CA, and the project said for a person to read.
              for line in \
                "export DOCKER_HOST='tcp://docker.frisket.internal:2376'" \
                "export DOCKER_TLS_VERIFY='1'" \
                "export DOCKER_CERT_PATH='/etc/chase/docker'" \
                "export CHASE_DOCKER_PROJECT='example/shop'" \
                "export CHASE_DOCKER_ADDRESS='127.101.170.171'" \
                "export CHASE_DOCKER_NAMES='shop.internal shop.example.internal'" \
                "export CHASE_DOCKER_PORTS='64320 64321'"; do
                grep -qxF "$line" "$envfile" || fail "the env file has no $line: $(cat "$envfile")"
              done

              # Images alone, with no ports, still route: no port is
              # published, and nothing relayed.
              launched trusted m2 '{"bindings": {"docker": {"images": ["postgres:18"]}}}'
              jq -e '.routes[] | select(.name == "docker") | .docker.ports == []' run/chase/m2/policy.json >/dev/null || fail "no ports did not route with none"
              grep -qxF "export CHASE_DOCKER_PORTS='''" "$envfile" || fail "no ports was not said as none: $(cat "$envfile")"
              frisket check run/chase/m2/policy.json || fail "frisket refused a route with no ports"

              # Ports alone name nothing a container could run, so the launch
              # ends there rather than frisket refusing the document.
              ENVELOPE='{"bindings": {"docker": {"ports": [64320]}}}' bash ./chase-envelope approve "$ws" m3 trusted >/dev/null 2>err || fail "m3 was not approved: $(cat err)"
              if bash ./chase-envelope launch trusted "$ws" m3 2>err; then fail "Docker with no images was launched"; fi
              grep -qF "chase: $ws: docker: no images" err || fail "no images was not said: $(cat err)"

              # NO BINDING, NO ROUTE, and nothing of Docker's in the session.
              launched trusted m4 '{"bindings": {"gcloud": {"serviceAccount": "a@p.iam.gserviceaccount.com"}}}'
              jq -e '.routes == [] and .allow == ["github.com"]' run/chase/m4/policy.json >/dev/null || fail "a checkout with no binding got a route: $(cat run/chase/m4/policy.json)"
              ! grep -q DOCKER "$envfile" || fail "a checkout with no binding got Docker's variables: $(cat "$envfile")"
              ! grep -q "docker" err || fail "docker was said with no binding: $(cat err)"

              # A TIER WITHOUT DOCKER says so, and adds nothing.
              launched plain m5 "$docker"
              grep -qxF "chase: $ws: docker ignored: plain has no docker" err || fail "the tier without Docker did not say so: $(cat err)"
              jq -e '.routes == [] and .allow == ["github.com"]' run/chase/m5/policy.json >/dev/null || fail "a tier without Docker got a route: $(cat run/chase/m5/policy.json)"

              # NO PROJECT, NO ROUTE: approve always stages one for a Docker
              # binding, so the prepare is run as launch would with none.
              prepare=$(jq -r .docker.prepare "$(sed -n 's/^apps=//p' chase-envelope)")
              if printf '{"images": ["postgres:18"]}' | chase_project= "$prepare" trusted "$ws" run envdir > out 2>err; then
                fail "a route was prepared with no project: $(cat out)"
              fi
              grep -qF "chase: $ws: docker: no project was approved" err || fail "no project was not said: $(cat err)"
              [ ! -s out ] || fail "the refusal printed something for the launch: $(cat out)"

              # AN IMAGE'S ID is refused by the prepare too, though the
              # envelope's options refuse it first: every spelling the route
              # gets is made from what reaches it.
              for img in "sha256:${nixpkgs.lib.concatStrings (nixpkgs.lib.replicate 8 "0123abcd")}" sha256:0123abcd \
                         "${nixpkgs.lib.concatStrings (nixpkgs.lib.replicate 8 "0123ABCD")}:1" o/sha256:1; do
                if printf '{"images": ["%s"]}' "$img" | chase_project=example/shop "$prepare" trusted "$ws" run envdir > out 2>err; then
                  fail "a route was prepared for $img: $(cat out)"
                fi
                grep -qF "chase: $ws: docker: an image named by its ID" err || fail "$img was not refused as an ID: $(cat err)"
              done
              ! grep -q DOCKER "$envfile" || fail "a tier without Docker got Docker's variables: $(cat "$envfile")"

              touch $out
            '';

          # WHERE A PROJECT'S DOCKER IS, SAID (docs/docker.md): `chase docker`
          # prints a checkout's project, address, session names and approved
          # ports, and calls a name the host's only where the host's map gives
          # it this project at this address; `chase shell` says the session's
          # name and ports when the launch exported them, and nothing else
          # otherwise.
          docker-show =
            let
              root = "/chase-docker-show-test";
              chase = {
                tiers.trusted = {
                  match = [ { checkouts."example/shop" = "${root}/p/shop"; } ];
                  apps.docker.enable = true;
                };
                tiers.plain = { egress = "direct"; envelope = true; };
              };
              config = harnessConfig chase;
              command = builtins.head config.flong.agent-plain.command;
              chaseCommand = nixpkgs.lib.findFirst (p: nixpkgs.lib.getName p == "chase")
                (throw "docker-show: alice has no chase") config.home-manager.users.alice.home.packages;
            in
            pkgs.runCommand "docker-show" { nativeBuildInputs = [ pkgs.git pkgs.jq ]; } ''
              export HOME=$TMPDIR
              fail() { echo "docker-show: $*" >&2; exit 1; }
              ${envelopeHarness {
                inherit chase;
                rewrite.hosts = "$PWD/docker-hosts.json";
              }}
              r=$(cd "$TMPDIR" && pwd -P)/root
              baked=$(sed -n 's/^checkouts=//p' chase-envelope)
              sed "s|${root}|$r|g" "$baked" > checkouts.json
              sed -i "s|^checkouts=.*|checkouts=$PWD/checkouts.json|" chase-envelope
              grep -q "^checkouts=$PWD/checkouts.json$" chase-envelope || fail "checkouts is not one line of chase-envelope's"

              ws=$r/p/shop
              git init -q "$ws"
              git -C "$ws" config remote.origin.url git@github.com:Example/Shop.git
              printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > "$ws/flake.nix"
              git -C "$ws" add flake.nix
              mkdir -p "$ws/sub"

              shown() { # DIR TIER EXPECTED
                local got
                got=$(bash ./chase-envelope docker "$1" "$2" 2>err) || fail "$1 in $2 was not shown: $(cat err)"
                [ "$got" = "$3" ] || fail "$1 in $2 was shown as:
              $got
              not:
              $3"
              }
              block() { # HOST PORTS
                printf '%s\n' example/shop \
                  "  address  127.101.170.171" \
                  "  session  shop.internal shop.example.internal" \
                  "  host     $1" \
                  "  ports    $2"
              }
              only="(address only; not in this host's /etc/hosts)"
              both="shop.internal shop.example.internal"
              ports="64320 64321   (approved)"

              # Nothing approved, and no map of the host's names: the names
              # are the session's alone, and no port is the project's yet.
              shown "$ws" trusted "$(block "$only" "(none approved)")"

              # Approved, its ports are the project's, from anywhere in the
              # checkout, which is keyed by its root as the launch keys it.
              ENVELOPE='{"bindings": {"docker": {"images": ["postgres:18"], "ports": [64320, 64321]}}}' \
                bash ./chase-envelope approve "$ws" m1 trusted >/dev/null 2>err || fail "shop was not approved: $(cat err)"
              shown "$ws" trusted "$(block "$only" "$ports")"
              shown "$ws/sub" trusted "$(block "$only" "$ports")"

              # The host's names are those its map gives this project at
              # this address, and no others.
              printf '{"example/shop": {"address": "127.101.170.171", "names": ["shop.internal", "shop.example.internal"]}}' > docker-hosts.json
              shown "$ws" trusted "$(block "$both" "$ports")"
              printf '{"example/shop": {"address": "127.101.170.171", "names": ["shop.example.internal", "other.internal"]}}' > docker-hosts.json
              shown "$ws" trusted "$(block shop.example.internal "$ports")"
              printf '{"example/shop": {"address": "127.9.9.9", "names": ["shop.internal", "shop.example.internal"]}}' > docker-hosts.json
              shown "$ws" trusted "$(block "$only" "$ports")"
              printf '{"example/shop": {"address": "127.101.170.171", "names": []}}' > docker-hosts.json
              shown "$ws" trusted "$(block "$only" "$ports")"
              printf '{"evil/x": {"address": "127.101.170.171", "names": ["shop.internal"]}}' > docker-hosts.json
              shown "$ws" trusted "$(block "$only" "$ports")"
              rm docker-hosts.json
              shown "$ws" trusted "$(block "$only" "$ports")"

              # A tier without Docker still has the address, and says so.
              shown "$ws" plain "$(printf '%s\n' example/shop "  address  127.101.170.171" "  (no Docker on plain)")"

              # An approval of the checkout as another project approved
              # none of this one's ports.
              app=$r/w/app
              git init -q "$app"
              git -C "$app" config remote.origin.url git@github.com:acme/app.git
              printf '{ outputs = _: { chaseModules.default = { }; }; }\n' > "$app/flake.nix"
              git -C "$app" add flake.nix
              ENVELOPE='{"bindings": {"docker": {"images": ["postgres:18"], "ports": [5432]}}}' \
                bash ./chase-envelope approve "$app" m2 trusted >/dev/null 2>err || fail "acme/app was not approved: $(cat err)"
              bash ./chase-envelope docker "$app" trusted > out 2>err || fail "acme/app was not shown: $(cat err)"
              grep -qxF "  ports    5432   (approved)" out || fail "acme/app's ports were not shown: $(cat out)"
              git -C "$app" remote set-url origin git@github.com:acme/app2.git
              bash ./chase-envelope docker "$app" trusted > out 2>err || fail "acme/app2 was not shown: $(cat err)"
              head -n 1 out | grep -qxF acme/app2 || fail "the new origin was not shown: $(cat out)"
              grep -qxF "  ports    (none approved)" out || fail "another project's ports were shown as approved: $(cat out)"

              # NO USABLE ORIGIN: why, and exit 1, with nothing on stdout.
              none=$r/w/none
              git init -q "$none"
              if bash ./chase-envelope docker "$none" trusted > out 2>err; then fail "a checkout with no origin was shown: $(cat out)"; fi
              grep -qF "chase: $none: Docker needs exactly one origin URL" err || fail "no origin was not said: $(cat err)"
              [ ! -s out ] || fail "a checkout with no origin printed: $(cat out)"

              # `chase` knows the subcommand.
              if ${chaseCommand}/bin/chase 2>err; then fail "chase with nothing ran"; fi
              grep -qF "chase docker [DIR]" err || fail "chase's usage does not say docker: $(cat err)"
              if ${chaseCommand}/bin/chase docker a b 2>err; then fail "chase docker took two directories"; fi

              # `chase docker DIR` sorts DIR, not where it is run from: with
              # its agent-tier and chase-envelope those of this build
              # directory, DIR's tier is the one shown from anywhere else.
              mkdir -p tbin "$r/elsewhere"
              sed "s|${root}|$r|g" ${nixpkgs.lib.getExe config.chase.internal.agentTier} > tbin/agent-tier
              cp chase-envelope tbin/chase-envelope
              sed "s|^export PATH=\"|export PATH=\"$PWD/tbin:|" ${chaseCommand}/bin/chase > tbin/chase
              grep -q "^export PATH=\"$PWD/tbin:" tbin/chase || fail "PATH is not one line of chase's"
              chmod +x tbin/*
              [ "$(bash ./tbin/agent-tier "$ws")" = trusted ] || fail "shop is not trusted to agent-tier"
              [ "$(bash ./tbin/agent-tier "$r/elsewhere")" = strict ] || fail "elsewhere is not strict to agent-tier"
              got=$(cd "$r/elsewhere" && bash "$OLDPWD/tbin/chase" docker "$ws" 2>err) || fail "chase docker $ws failed: $(cat err)"
              [ "$got" = "$(block "$only" "$ports")" ] || fail "chase docker $ws from elsewhere said: $got"
              (cd "$ws" && bash "$OLDPWD/tbin/chase" docker "$app") > out 2>err || fail "chase docker $app from shop failed: $(cat err)"
              grep -qxF "  (no Docker on strict)" out || fail "chase docker $app from shop said: $(cat out)"
              got=$(cd "$ws/sub" && bash "$OLDPWD/tbin/chase" docker 2>err) || fail "chase docker with no DIR failed: $(cat err)"
              [ "$got" = "$(block "$only" "$ports")" ] || fail "chase docker in shop said: $got"

              # THE SHELL'S BANNER, only when the launch exported Docker.
              banner() { env -u CHASE_DOCKER_ADDRESS -u CHASE_DOCKER_NAMES -u CHASE_DOCKER_PORTS "$@" ${command} shell -c 'echo ran' 2>err; }
              [ "$(banner)" = ran ] || fail "the shell did not run"
              ! grep -q docker err || fail "a shell without Docker said: $(cat err)"
              [ "$(banner CHASE_DOCKER_ADDRESS=127.101.170.171 CHASE_DOCKER_NAMES="$both" CHASE_DOCKER_PORTS="64320 64321")" = ran ] || fail "the shell did not run with Docker"
              grep -qxF "docker: shop.internal → 127.101.170.171, ports 64320 64321; localhost works too" err || fail "the banner was not said: $(cat err)"
              [ "$(banner CHASE_DOCKER_ADDRESS=127.101.170.171 CHASE_DOCKER_NAMES="" CHASE_DOCKER_PORTS="")" = ran ] || fail "the shell did not run with no ports"
              grep -qxF "docker: 127.101.170.171, no ports" err || fail "the banner with no names or ports was not said: $(cat err)"

              touch $out
            '';

          gcloud-session = pkgs.testers.runNixOSTest (import ./tests/gcloud-session.nix { inherit self home-manager; });
        } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # Only where the pinned postgres:18 runs: the image is amd64's.
          docker-session = pkgs.testers.runNixOSTest (import ./tests/docker-session.nix { inherit self home-manager; });
        });

      # Go for the binary, built as the flake builds it; chase-generate, and
      # the git and protoc `chase-generate gcloud` runs; frisket, whose
      # `check` some tests hold what chase writes to.
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.go pkgs.gopls pkgs.git pkgs.protobuf frisket.packages.${system}.default self.packages.${system}.chase-generate ];
            CHASE_REQUIRE_FRISKET = "1";
            # The setting the package builds with, so a `go build` here gives
            # the binary the flake does.
            CGO_ENABLED = "0";
          };
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
