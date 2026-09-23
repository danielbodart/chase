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
            # ... and is fine when no tier asks for a credentialled github.
            assert chaseFailures {
              chase.bindings.github.credentialFile = lib.mkForce null;
              chase.tiers.trusted.apps.github.anonymous = true;
            } == [ ]
              || throw "assertions: an anonymous-only github still demanded a credential";
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
            # NO PRIVILEGE ANYWHERE (PLAN.md, decision 2). Every session is
            # rootless, nothing is granted through sudo, and flong accepts
            # what chase declares: none of flong's own assertions fail.
            assert
              (let
                config = configWith { };
                agents = lib.filterAttrs (n: _: lib.hasPrefix "agent-" n) config.flong;
                failed = map (a: a.message) (lib.filter (a: ! a.assertion) config.assertions);
              in
              agents != { }
              && lib.all (d: d.engine == "rootless") (lib.attrValues agents)
              && ! lib.any (r: lib.elem "alice" (r.users or [ ])) config.security.sudo.extraRules
              && failed == [ ]
                || throw "assertions: the sessions are not rootless, or flong refused them: ${builtins.toJSON failed}");
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

          # The version script decides what every release is called, so it is
          # gated by the same check that gates the release.
          shellcheck = pkgs.runCommand "shellcheck"
            { nativeBuildInputs = [ pkgs.shellcheck ]; }
            ''
              shellcheck ${./scripts/version.sh} ${./scripts/operations.sh}
              touch $out
            '';
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
