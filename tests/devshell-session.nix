# A checkout's devShell end to end (PLAN.md, decision 21): realised by the
# launcher, confined, and given to the session as nix develop would give it.
#
# Two tiers, as a desk has them: `own`, direct egress, a devShell whenever
# the checkout has one, with mise; and `others`, the fallback, frisket's
# alone, an empty allowlist, a devShell only when the checkout's approved
# grant asks for one. The machine has no binary cache, and has everything
# a shell.nix of `import <nixpkgs> { }` needs already, so a miss fails
# fast and nothing is fetched. A flake needs no nixpkgs: its devShell is a
# derivation whose builder is a static bash in a relative path: input.
#
# alice's mise and chase directories are made by the test itself, and
# home-manager is not waited on: its activation service fails in this VM,
# and nothing it would write is what is tested here.
{ self, home-manager }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  system = pkgs.stdenv.hostPlatform.system;
  home = "/home/alice";
  port = 8123;

  # The checkout's shell.nix, and the devShell it is, as the host evaluates
  # it against the same nixpkgs: what it needs is in the machine's store.
  shellNix = ./devshell/shell.nix;
  shellDrv = import shellNix { pkgs = import pkgs.path { inherit system; }; };

  # What may not be read, or reached, from an evaluation.
  bashrcNix = pkgs.writeText "shell.nix" ''
    { ... }: builtins.trace (builtins.readFile ${home}/.bashrc) (import <nixpkgs> { }).mkShell { }
  '';
  # https, which a direct tier's allowed-uris lets through: only the
  # network pasta gives the evaluation can keep it from the host's loopback.
  loopbackNix = pkgs.writeText "shell.nix" ''
    { ... }: builtins.trace (builtins.readFile (builtins.fetchurl { url = "https://127.0.0.1:${toString port}/x"; name = "x"; })) (import <nixpkgs> { }).mkShell { }
  '';

  # A devShell with something of its own to build, which no cache holds:
  # refused in a filtered tier, which builds nothing of its inputs
  # (--max-jobs 0).
  buildsNix = pkgs.writeText "shell.nix" ''
    { pkgs ? import <nixpkgs> { } }: pkgs.mkShell { packages = [ (pkgs.writeShellScriptBin "own-tool" "echo own") ]; }
  '';

  # A flake with a relative path: input, sub, holding a static bash, which
  # is the devShell's builder: nothing to fetch, and nothing of nixpkgs.
  flakeNix = pkgs.writeText "flake.nix" ''
    {
      inputs.sub.url = "path:./sub";
      outputs = { self, sub }: {
        devShells.${system}.default = derivation {
          name = "flake-shell";
          system = "${system}";
          builder = "''${sub}/bash";
          args = [ "-c" "echo > $out" ];
          # Said, as mkDerivation says it: nix develop dumps the
          # environment into each output $outputs names.
          outputs = [ "out" ];
          FROM_FLAKE = "yes";
        };
      };
    }
  '';
  subFlake = pkgs.writeText "flake.nix" "{ outputs = _: { }; }";

  # A grant that asks for the checkout's devShell.
  grantNix = pkgs.writeText "chase.jsonc" ''
    { "apps": { "nix": { "devShell": true } } }
  '';

  # A lock whose GitHub node names another host: fetched by nothing in a
  # filtered tier.
  hostLock = pkgs.writeText "flake.lock" (builtins.toJSON {
    nodes = {
      root.inputs.n = "n";
      n.locked = {
        type = "github";
        owner = "o";
        repo = "r";
        host = "example.org";
        rev = "0123456789abcdef0123456789abcdef01234567";
        narHash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
      };
    };
    root = "root";
    version = 7;
  });

  # A checkout at DIR, with each FILE copied from SOURCE, committed.
  mkCheckout = pkgs.writeShellScript "mk-checkout" ''
    set -euo pipefail
    export PATH=${lib.makeBinPath (with pkgs; [ coreutils git ])}
    dir=$1; shift
    mkdir -p "$dir"
    cd "$dir"
    [ -d .git ] || git init -q -b main
    printf 'out/\n' > .gitignore
    while [ $# -gt 0 ]; do
      mkdir -p "$(dirname "$2")"
      cp -f "$1" "$2"
      chmod u+w "$2"
      shift 2
    done
    git add -A
    git -c user.name=alice -c user.email=alice@example.com commit -qm checkout --allow-empty
  '';

  # What the session reports of itself, each a line of out/<name>.
  report = pkgs.writeText "report.sh" ''
    mkdir -p "$PWD/out"
    {
      echo "PATH=$PATH"
      echo "HELLO=$(command -v hello)"
      echo "GREETING=''${HELLO_FROM_SHELL-}"
      echo "FLAKE=''${FROM_FLAKE-}"
      echo "BASH=$2"
      echo "SSL=''${SSL_CERT_FILE-}"
    } > "$PWD/out/$1"
  '';
in
{
  name = "chase-devshell-session";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ self.nixosModules.default home-manager.nixosModules.home-manager ];

    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 8192;
    virtualisation.cores = 2;

    security.sudo.enable = false;
    nix.settings = {
      experimental-features = [ "nix-command" "flakes" ];
      # No cache: a miss fails at once rather than waiting on a network
      # the machine does not have.
      substituters = lib.mkForce [ ];
    };
    environment.systemPackages = with pkgs; [ git jq util-linux ];
    # What the shell.nix needs, and nixpkgs itself, already here.
    system.extraDependencies = [ pkgs.path shellDrv.inputDerivation pkgs.pkgsStatic.bash ];

    # Something on the host's loopback an evaluation must not reach.
    systemd.services.loopback = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server ${toString port} --bind 127.0.0.1 --directory /var/empty";
    };

    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      group = "users";
      linger = true;
      autoSubUidGidRange = false;
      subUidRanges = [{ startUid = 100000; count = 65536; }];
      subGidRanges = [{ startGid = 100000; count = 65536; }];
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
      order = [ "own" ];
      fallback = "others";
      approver = "${pkgs.writeShellScript "approver" ''
        ${pkgs.coreutils}/bin/cat | ${pkgs.util-linux}/bin/logger -t chase-test-approver
      ''}";
      apps = {
        claude.package = pkgs.hello;
        codex.package = pkgs.hello;
      };
      tiers.own = {
        match = [{ paths = map (d: "${home}/${d}") [ "mine" "mine-flake" "bashrc" "loopback" "gone" ]; }];
        egress = "direct";
        allow = [ "*" ];
        apps.mise.enable = true;
        apps.nix = { enable = true; devShell = "automatic"; };
      };
      tiers.others = {
        egress = "frisket";
        grants = true;
        writes = "refuse";
        guarded = "refuse";
        unmatched = "refuse";
        apps.nix.enable = true;
      };
    };
  };

  testScript = { nodes, ... }:
    let
      own = lib.getExe nodes.machine.flong.chase-own.launcher;
      others = lib.getExe nodes.machine.flong.chase-others.launcher;
    in
    ''
      import shlex

      def as_user(script):
          inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; " + script
          return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                  f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

      def checkout(name, *files):
          machine.succeed(f"runuser -u alice -- ${mkCheckout} ${home}/{name} " + " ".join(files))

      def launch(launcher, name, run="ran"):
          """The session's report and what the launch said, or None for a refusal."""
          # The program chase shell's own bash is, not the report's, which
          # is whichever bash is first on its PATH; nor $BASH, which bash
          # finds on PATH too.
          cmd = f"cd ${home}/{name} && {launcher} shell -c {shlex.quote('bash ${report} ' + run + ' \"$(readlink /proc/$$/exe)\"')} > /tmp/out 2> /tmp/err; echo $? > /tmp/rc"
          machine.succeed(as_user(cmd), timeout=900)
          said = machine.succeed("cat /tmp/err")
          print(said)
          if machine.succeed("cat /tmp/rc").strip() != "0":
              return None, said
          lines = machine.succeed(f"cat ${home}/{name}/out/{run}").splitlines()
          return dict(l.split("=", 1) for l in lines), said

      start_all()
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      machine.wait_for_unit("loopback.service")
      machine.wait_for_unit("user@1000.service")
      machine.succeed("runuser -u alice -- sh -c 'echo the-users-bashrc > ${home}/.bashrc'")
      # mise's directories and chase's state, alice's own, as on a desk:
      # tmpfiles makes none of them in a home that is hers.
      machine.succeed("mkdir -p ${home}/.config/mise ${home}/.local/share/mise ${home}/.local/state/mise ${home}/.cache/mise ${home}/.local/state/chase"
                      " && chown -R alice:users ${home}")

      with subtest("a shell.nix's devShell is the session's, behind the wrappers and mise's shims"):
          checkout("mine", "${shellNix}", "shell.nix")
          s, said = launch("${own}", "mine")
          assert s is not None, said
          path = s["PATH"].split(":")
          assert path[0] == "/run/wrappers/bin", path
          assert path[1] == "${home}/.local/share/mise/shims", path
          assert path[2] == "${home}/mine/bin", path
          assert path[3].startswith("/nix/store/"), path
          assert s["HELLO"].startswith("/nix/store/") and s["HELLO"].endswith("/bin/hello"), s
          assert s["GREETING"] == "hi", s
          # chase shell's bash is the container's, with readline, never the
          # devShell's.
          assert s["BASH"] == machine.succeed("readlink -f /run/current-system/sw/bin/bash").strip(), s
          assert "bash-interactive" in s["BASH"], s
          assert s["SSL"] == "/etc/frisket/ca-bundle.crt", s
          assert "the hook ran in ${home}/mine" in said, said
          assert "the hook ran" not in machine.succeed("cat /tmp/out")
          assert "realising the devShell of shell.nix" in said, said
          machine.succeed("test -e \"$(echo ${home}/.local/state/chase/checkouts/*/devshell/profile)\"")

      with subtest("a second launch realises nothing, and a change is the next launch's"):
          s, said = launch("${own}", "mine", "again")
          assert s is not None and s["GREETING"] == "hi", said
          assert "realising" not in said, said
          machine.succeed("runuser -u alice -- sed -i 's/HELLO_FROM_SHELL = \"hi\"/HELLO_FROM_SHELL = \"changed\"/' ${home}/mine/shell.nix")
          checkout("mine")
          s, said = launch("${own}", "mine", "changed")
          assert s is not None and s["GREETING"] == "changed", said

      with subtest("an evaluation reads no file of the user's, and reaches nothing on the host's loopback"):
          checkout("bashrc", "${bashrcNix}", "shell.nix")
          s, said = launch("${own}", "bashrc")
          assert s is not None and "could not be realised" in said, said
          assert "the-users-bashrc" not in said, said
          checkout("loopback", "${loopbackNix}", "shell.nix")
          s, said = launch("${own}", "loopback")
          assert s is not None and "could not be realised" in said, said
          # Past restrict-eval, so what kept it out is the namespace.
          assert "forbidden in restricted mode" not in said and "connect" in said.lower(), said
          assert "127.0.0.1 - -" not in machine.succeed("journalctl -u loopback.service -o cat --no-pager"), "the evaluation reached the host's loopback"

      with subtest("someone else's checkout has a devShell only when its approved grant asks"):
          checkout("theirs", "${shellNix}", "shell.nix")
          s, said = launch("${others}", "theirs")
          assert s is not None and s["GREETING"] == "", (s, said)
          checkout("theirs", "${grantNix}", "chase.jsonc")
          s, said = launch("${others}", "theirs", "granted")
          assert s is not None and s["GREETING"] == "hi", said
          assert "devShell" in machine.succeed("journalctl -t chase-test-approver -o cat --no-pager")

      with subtest("a devShell a grant asks for that cannot be realised refuses the launch"):
          checkout("theirs-bashrc", "${bashrcNix}", "shell.nix", "${grantNix}", "chase.jsonc")
          s, said = launch("${others}", "theirs-bashrc")
          assert s is None and "the devShell the grant asks for could not be realised" in said, said

      with subtest("a filtered tier builds nothing of a devShell's inputs"):
          checkout("theirs-builds", "${buildsNix}", "shell.nix", "${grantNix}", "chase.jsonc")
          s, said = launch("${others}", "theirs-builds")
          assert s is None and "local builds are disabled" in said, said

      with subtest("a flake with a relative path: input is realised in either tier"):
          for name, launcher in [("mine-flake", "${own}"), ("theirs-flake", "${others}")]:
              checkout(name, "${flakeNix}", "flake.nix", "${subFlake}", "sub/flake.nix", "${pkgs.pkgsStatic.bash}/bin/bash", "sub/bash")
              machine.succeed(as_user(f"cd ${home}/{name} && nix --extra-experimental-features 'nix-command flakes' flake lock"))
              checkout(name, *(["${grantNix}", "chase.jsonc"] if name == "theirs-flake" else []))
              s, said = launch(launcher, name)
              assert s is not None and s["FLAKE"] == "yes", (name, said)

      with subtest("a lock node that names another host is fetched by nothing in a filtered tier"):
          checkout("theirs-host", "${flakeNix}", "flake.nix", "${hostLock}", "flake.lock", "${grantNix}", "chase.jsonc")
          s, said = launch("${others}", "theirs-host")
          assert s is None and "is fetched by nothing in a filtered tier" in said, said

      with subtest("a checkout that is gone has its devShell let go of"):
          checkout("gone", "${shellNix}", "shell.nix")
          s, said = launch("${own}", "gone")
          assert s is not None and s["GREETING"] == "hi", said
          machine.succeed("grep -l '\"workspace\":\"${home}/gone\"' ${home}/.local/state/chase/checkouts/*/devshell/state.json")
          machine.succeed("rm -rf ${home}/gone")
          launch("${own}", "mine", "after")
          machine.fail("grep -l '\"workspace\":\"${home}/gone\"' ${home}/.local/state/chase/checkouts/*/devshell/state.json")
    '';
}
