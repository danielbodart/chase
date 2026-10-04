# A store of the session's own, end to end (flong's PLAN §3): a tier of other
# people's code, its egress frisket's, whose approved grant asks for the
# checkout's devShell, which the session evaluates itself -- nothing of it
# on the host -- over a local-overlay store of its own, kept for the one
# launch and gone after it.
#
# One tier, `strict`, as a desk has it for someone else's code: frisket's
# egress, grants, nothing allowed beyond what a grant adds, a devShell only
# when the grant asks, mise. The machine has no binary cache, and has
# everything the checkouts need already in its store -- the session's lower
# -- so a miss fails fast and nothing is fetched: what is evaluated, built
# and written is the session's, into its upper. A shell.nix shaped as
# pokeranker's, its libraries and its shellHook's exports; and a flake
# whose devShell is a derivation whose builder is a static bash in a
# relative path: input, which needs nothing of nixpkgs.
#
# alice's mise directories are made by the test itself, and home-manager is
# not waited on: its activation service fails in this VM, and nothing it
# would write is what is tested here.
{ self, home-manager }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  system = pkgs.stdenv.hostPlatform.system;
  home = "/home/alice";
  sessions = "${home}/.cache/chase/nix/sessions";

  # The checkout's shell.nix, and the devShell it is, as the host would
  # evaluate it against the same nixpkgs: what it needs is in the machine's
  # store, the session's lower.
  shellNix = ./nixstore/shell.nix;
  shellDrv = import shellNix { pkgs = import pkgs.path { inherit system; }; };

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
          outputs = [ "out" ];
          FROM_FLAKE = "yes";
          shellHook = "export FROM_FLAKE_HOOK=yes";
        };
      };
    }
  '';
  subFlake = pkgs.writeText "flake.nix" "{ outputs = _: { }; }";

  # The grant that asks for the devShell, and so for the store.
  grant = pkgs.writeText "chase.jsonc" ''
    // The checkout's devShell, evaluated in its sessions.
    { "apps": { "nix": { "devShell": true } } }
  '';

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

  # What the session reports of itself, each a line of out/<name>: the
  # agent's environment, what its nix is told, and what nix makes of its
  # store.
  report = pkgs.writeText "report.sh" ''
    mkdir -p "$PWD/out"
    {
      echo "PATH=$PATH"
      echo "HELLO=$(command -v hello)"
      echo "GREETING=''${HELLO_FROM_SHELL-}"
      echo "LD_LIBRARY_PATH=''${LD_LIBRARY_PATH-}"
      echo "GIO_MODULE_DIR=''${GIO_MODULE_DIR-}"
      echo "XDG_DATA_DIRS=''${XDG_DATA_DIRS-}"
      echo "FLAKE=''${FROM_FLAKE-}"
      echo "FLAKE_HOOK=''${FROM_FLAKE_HOOK-}"
      echo "NIX_REMOTE=''${NIX_REMOTE-}"
      echo "STORE=$(nix store info 2>&1 | tr '\n' ' ')"
      echo "NIX=$(readlink -f "$(command -v nix)")"
    } > "$PWD/out/$1"
  '';

  # What the session does once it has reported: whatever the test asks,
  # each a script of its own, run by the agent's bash.
  steps = {
    # A file of the host's store -- this script itself -- unlinked: the
    # upper's root is shaped as the lower's, so the session may not.
    unlink = pkgs.writeText "unlink.sh" ''
      f=$0
      rm -f "$f" 2>"$PWD/out/unlink.err"; echo $? > "$PWD/out/unlink.rc"
      if [ -e "$f" ]; then echo kept > "$PWD/out/unlink.kept"; fi
    '';
    # A name off the allowlist, fetched by the session's nix: frisket
    # answers it as no name.
    fetch = pkgs.writeText "fetch.sh" ''
      nix store prefetch-file https://off-allowlist.test/x > "$PWD/out/fetch.out" 2>&1; echo $? > "$PWD/out/fetch.rc"
    '';
    # A build of the session's own that refers to a path of the host's no
    # root of the host's holds -- the one the test added, named in
    # out/lower -- and then a wait, while the host collects its garbage,
    # until out/go: the path is still there, rooted by the session.
    hold = pkgs.writeText "hold.sh" ''
      lower=$(cat "$PWD/lower")
      bash=$(readlink -f "$(command -v bash)")
      nix build --impure --no-link --print-out-paths --expr \
        "derivation { name = \"refers\"; system = builtins.currentSystem; builder = \"$bash\"; args = [ \"-c\" \"echo \''${builtins.storePath \"$lower\"} > \$out\" ]; }" \
        > "$PWD/out/built" 2>"$PWD/out/built.err"
      until [ -e "$PWD/go" ]; do sleep 1; done
      cat "$lower" > "$PWD/out/lower.read" 2>&1
      cat "$(cat "$PWD/out/built")" > "$PWD/out/built.read" 2>&1
    '';
    # More than the tier's maxBytes, into the store: the session is
    # stopped for it.
    flood = pkgs.writeText "flood.sh" ''
      head -c 300M /dev/zero > /nix/store/flood
      sleep 60
      echo survived > "$PWD/out/flood.survived"
    '';
  };
in
{
  name = "chase-nix-store-session";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ self.nixosModules.default home-manager.nixosModules.home-manager ];

    virtualisation.memorySize = 4096;
    virtualisation.diskSize = 12288;
    virtualisation.cores = 2;

    security.sudo.enable = false;
    nix.settings = {
      experimental-features = [ "nix-command" "flakes" ];
      # No cache: a miss fails at once rather than waiting on a network
      # the machine does not have.
      substituters = lib.mkForce [ ];
    };
    environment.systemPackages = with pkgs; [ git jq util-linux ];
    # What the shell.nix needs, and nixpkgs itself, already here; and the
    # test's own scripts, rooted, since it collects the store's garbage.
    system.extraDependencies = [ pkgs.path shellDrv.inputDerivation pkgs.pkgsStatic.bash mkCheckout report shellNix flakeNix subFlake grant ]
      ++ lib.attrValues steps;

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
      fallback = "strict";
      approver = "${pkgs.writeShellScript "approver" ''
        ${pkgs.coreutils}/bin/cat | ${pkgs.util-linux}/bin/logger -t chase-test-approver
      ''}";
      apps = {
        claude.package = pkgs.hello;
        codex.package = pkgs.hello;
      };
      tiers.strict = {
        egress = "frisket";
        grants = true;
        writes = "refuse";
        guarded = "refuse";
        unmatched = "refuse";
        apps.mise.enable = true;
        apps.nix = {
          enable = true;
          devShell = "granted";
          store = "session";
          maxBytes = 256 * 1024 * 1024;
        };
      };
    };
  };

  testScript = { nodes, ... }:
    let
      launcher = lib.getExe nodes.machine.flong.chase-strict.launcher;
    in
    ''
      import shlex

      def as_user(script):
          inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; " + script
          return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                  f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

      def checkout(name, *files):
          machine.succeed(f"runuser -u alice -- ${mkCheckout} ${home}/{name} " + " ".join(files))

      def command(name, run, step):
          inner = "bash ${report} " + run + (f" && bash {step}" if step else "")
          return f"cd ${home}/{name} && ${launcher} shell -c {shlex.quote(inner)}"

      def launch(name, run="ran", step=None):
          """The session's report and what the launch said, or None for a refusal."""
          machine.succeed(as_user(command(name, run, step) + " > /tmp/out 2> /tmp/err; echo $? > /tmp/rc"), timeout=900)
          said = machine.succeed("cat /tmp/err")
          print(said)
          if machine.succeed("cat /tmp/rc").strip() != "0":
              return None, said
          lines = machine.succeed(f"cat ${home}/{name}/out/{run}").splitlines()
          return dict(l.split("=", 1) for l in lines), said

      def start(name, run, step, tag):
          machine.succeed(f"rm -f /tmp/rc-{tag}; {as_user(command(name, run, step) + f' > /tmp/out-{tag} 2> /tmp/err-{tag}; echo $? > /tmp/rc-{tag}')} >/dev/null 2>&1 &")

      def no_stores():
          machine.wait_until_succeeds("test -z \"$(ls -A ${sessions})\"", timeout=60)

      start_all()
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      machine.wait_for_unit("user@1000.service")
      machine.succeed("mkdir -p ${home}/.config/mise ${home}/.local/share/mise ${home}/.local/state/mise ${home}/.cache/mise ${home}/.local/state/chase"
                      " && chown -R alice:users ${home}")

      with subtest("the session's nix is the container's, patched, its schema the host's"):
          nix = "${lib.getExe nodes.machine.chase.tiers.strict.apps.nix.sessionPackage}"
          host = machine.succeed("cat /nix/var/nix/db/schema").strip()
          assert host == "10", host
          machine.succeed(f"{nix} --version")

      with subtest("a shell.nix the grant asks for is evaluated in the session, and the agent is given it"):
          checkout("theirs", "${shellNix}", "shell.nix", "${grant}", "chase.jsonc")
          s, said = launch("theirs")
          assert s is not None, said
          assert "evaluating the devShell of shell.nix in the session" in said, said
          assert "the hook ran in ${home}/theirs" in said, said
          path = s["PATH"].split(":")
          assert path[0] == "/run/wrappers/bin", path
          assert path[1].endswith("/shims"), path
          assert path[2].startswith("/nix/store/"), path
          assert s["HELLO"].startswith("/nix/store/") and s["HELLO"].endswith("/bin/hello"), s
          assert s["GREETING"] == "hi", s
          assert "-zlib-" in s["LD_LIBRARY_PATH"] and "-libffi-" in s["LD_LIBRARY_PATH"], s
          assert s["GIO_MODULE_DIR"].endswith("/lib/gio/modules/"), s
          assert "-glib-" in s["XDG_DATA_DIRS"], s
          assert s["NIX_REMOTE"].startswith("local-overlay://?real=/nix/store&state=${sessions}/"), s
          assert "local-overlay://" in s["STORE"], s
          assert s["NIX"] == machine.succeed(f"readlink -f {nix}").strip(), s
          # Nothing of the checkout's was evaluated on the host: no nix of
          # chase's ran there, and nothing was rooted for it in chase's state.
          machine.fail("ls ${home}/.local/state/chase/checkouts/*/devshell 2>/dev/null | grep -q .")
          # What the session built is gone with it.
          no_stores()

      with subtest("a flake the grant asks for is evaluated in the session, purely"):
          checkout("theirs-flake", "${flakeNix}", "flake.nix", "${subFlake}", "sub/flake.nix", "${pkgs.pkgsStatic.bash}/bin/bash", "sub/bash", "${grant}", "chase.jsonc")
          machine.succeed(as_user("cd ${home}/theirs-flake && nix --extra-experimental-features 'nix-command flakes' flake lock"))
          checkout("theirs-flake")
          s, said = launch("theirs-flake")
          assert s is not None and s["FLAKE"] == "yes" and s["FLAKE_HOOK"] == "yes", said
          assert "evaluating the devShell of flake.nix in the session" in said, said
          no_stores()

      with subtest("the session may not unlink a path of the host's store"):
          s, said = launch("theirs", "unlink", "${steps.unlink}")
          assert s is not None, said
          assert machine.succeed("cat ${home}/theirs/out/unlink.rc").strip() != "0"
          assert "Operation not permitted" in machine.succeed("cat ${home}/theirs/out/unlink.err")
          machine.succeed("test -e ${home}/theirs/out/unlink.kept")

      with subtest("a fetch from a name off the allowlist fails in the session, refused by frisket"):
          s, said = launch("theirs", "fetch", "${steps.fetch}")
          assert s is not None, said
          assert machine.succeed("cat ${home}/theirs/out/fetch.rc").strip() != "0"
          machine.wait_until_succeeds("journalctl -u frisket.service -o cat --no-pager | grep off-allowlist.test | grep -q 'not allowed'", timeout=30)

      with subtest("what the session's store looks at of the host's is rooted while it runs, and let go after"):
          lower = machine.succeed("echo chase-test-lower > /tmp/lower && nix-store --add /tmp/lower").strip()
          machine.succeed(f"runuser -u alice -- sh -c 'echo {lower} > ${home}/theirs/lower; rm -f ${home}/theirs/go'")
          start("theirs", "hold", "${steps.hold}", "hold")
          machine.wait_until_succeeds("test -s ${home}/theirs/out/built", timeout=600)
          built = machine.succeed("cat ${home}/theirs/out/built").strip()
          machine.wait_until_succeeds(f"grep -qx {lower} \"$(readlink ${sessions}/*/roots)\"", timeout=60)
          machine.succeed("nix-collect-garbage >&2")
          machine.succeed(f"test -e {lower}")
          machine.succeed("runuser -u alice -- touch ${home}/theirs/go")
          machine.wait_until_succeeds("test -s /tmp/rc-hold", timeout=120)
          assert machine.succeed("cat /tmp/rc-hold").strip() == "0", machine.succeed("cat /tmp/err-hold")
          assert machine.succeed("cat ${home}/theirs/out/lower.read").strip() == "chase-test-lower"
          assert machine.succeed("cat ${home}/theirs/out/built.read").strip() == lower
          # The session's own build never reaches the host's store, and
          # once the session is gone its root is too.
          machine.fail(f"nix-store --check-validity {built}")
          no_stores()
          machine.succeed("nix-collect-garbage >&2")
          machine.fail(f"test -e {lower}")

      with subtest("a session whose store grows past the tier's bytes is stopped, and said"):
          start("theirs", "flood", "${steps.flood}", "flood")
          machine.wait_until_succeeds("test -s /tmp/rc-flood", timeout=300)
          said = machine.succeed("cat /tmp/err-flood")
          print(said)
          assert machine.succeed("cat /tmp/rc-flood").strip() != "0", said
          assert "the session's nix store is over its limit" in said, said
          machine.fail("test -e ${home}/theirs/out/flood.survived")
          no_stores()

      with subtest("a checkout whose grant does not ask has no store, and no devShell"):
          checkout("plain", "${shellNix}", "shell.nix")
          s, said = launch("plain")
          assert s is not None and s["GREETING"] == "" and s["NIX_REMOTE"] == "", (s, said)
          assert "evaluating" not in said, said
          no_stores()
    '';
}
