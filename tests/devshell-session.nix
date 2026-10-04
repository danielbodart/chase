# A checkout's devShell end to end (PLAN.md, decision 21): realised by the
# launcher, as the caller, and given to the session as nix develop would
# give it.
#
# Two tiers, as a desk has them: `own`, direct egress, a devShell whenever
# the checkout has one, with mise; and `others`, the fallback, frisket's
# alone, with no nix, which no tier of that egress may have. The machine
# has no binary cache, and has everything a shell.nix of
# `import <nixpkgs> { }` needs already, so a miss fails fast and nothing is
# fetched. A flake needs no nixpkgs: its devShell is a derivation whose
# builder is a static bash in a relative path: input.
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

  # The checkout's shell.nix, and the devShell it is, as the host evaluates
  # it against the same nixpkgs: what it needs is in the machine's store.
  shellNix = ./devshell/shell.nix;
  shellDrv = import shellNix { pkgs = import pkgs.path { inherit system; }; };

  # What restrict-eval keeps from a shell.nix: a file of the user's
  # outside the checkout.
  bashrcNix = pkgs.writeText "shell.nix" ''
    { ... }: builtins.trace (builtins.readFile ${home}/.bashrc) (import <nixpkgs> { }).mkShell { }
  '';

  # What nix's own restrictions let through, and the bubblewrap nix runs in
  # does not: a shell.nix's builtins.getFlake, and a flake's path: input,
  # each of a directory of the user's outside the checkout.
  getFlakeNix = pkgs.writeText "shell.nix" ''
    { ... }: builtins.trace (builtins.readFile ((builtins.getFlake "path:${home}?dir=secrets").sourceInfo.outPath + "/secrets/token")) (import <nixpkgs> { }).mkShell { }
  '';
  pathInputNix = pkgs.writeText "flake.nix" ''
    {
      inputs.secrets = { url = "path:${home}/secrets"; flake = false; };
      outputs = { self, secrets }: {
        devShells.${system}.default = builtins.trace (builtins.readFile "''${secrets}/token") (derivation {
          name = "leak"; system = "${system}"; builder = "/bin/sh";
        });
      };
    }
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
      apps = {
        claude.package = pkgs.hello;
        codex.package = pkgs.hello;
      };
      tiers.own = {
        match = [{ paths = map (d: "${home}/${d}") [ "mine" "mine-flake" "bashrc" "getflake" "pathinput" "gone" ]; }];
        egress = "direct";
        allow = [ "*" ];
        apps.mise.enable = true;
        apps.nix.enable = true;
      };
      tiers.others = {
        egress = "frisket";
        writes = "refuse";
        guarded = "refuse";
        unmatched = "refuse";
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
          s, said = launch("${own}", "mine", "changed")
          assert s is not None and s["GREETING"] == "changed", said

      with subtest("a shell.nix is evaluated restricted: a file of the user's outside the checkout is not read"):
          checkout("bashrc", "${bashrcNix}", "shell.nix")
          s, said = launch("${own}", "bashrc")
          assert s is not None and "could not be realised" in said, said
          assert "the-users-bashrc" not in said, said
          assert "restricted mode" in said, said

      with subtest("nix sees nothing of the user's outside the checkout: not through getFlake, nor a flake's path: input"):
          machine.succeed("runuser -u alice -- sh -c 'mkdir -p ${home}/secrets && echo the-users-token > ${home}/secrets/token && echo \"{ outputs = _: { }; }\" > ${home}/secrets/flake.nix'")
          checkout("getflake", "${getFlakeNix}", "shell.nix")
          s, said = launch("${own}", "getflake")
          assert s is not None and "could not be realised" in said, said
          assert "the-users-token" not in said, said
          checkout("pathinput", "${pathInputNix}", "flake.nix")
          s, said = launch("${own}", "pathinput")
          assert s is not None and "could not be realised" in said, said
          assert "the-users-token" not in said, said
          machine.fail("grep -rl the-users-token /nix/store/*-nix-shell-env 2>/dev/null")

      with subtest("a flake with a relative path: input is realised from the checkout itself"):
          checkout("mine-flake", "${flakeNix}", "flake.nix", "${subFlake}", "sub/flake.nix", "${pkgs.pkgsStatic.bash}/bin/bash", "sub/bash")
          machine.succeed(as_user("cd ${home}/mine-flake && nix --extra-experimental-features 'nix-command flakes' flake lock"))
          checkout("mine-flake")
          s, said = launch("${own}", "mine-flake")
          assert s is not None and s["FLAKE"] == "yes", said
          assert "realising the devShell of flake.nix" in said, said

      with subtest("a tier without nix gives no devShell"):
          checkout("theirs", "${shellNix}", "shell.nix")
          s, said = launch("${others}", "theirs")
          assert s is not None and s["GREETING"] == "", (s, said)
          assert "realising" not in said, said

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
