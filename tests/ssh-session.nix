# An SSH session end to end: chase's launch, flong's session and frisket's
# SSH route on one machine, and an sshd on another, reached by its private
# VLAN address. The project's grant names the machine, its user and its
# host key; the key that logs in is alice's, a file only frisket reads. The
# session's ssh reaches the machine by its name through what the tier's ssh
# config includes -- frisket's ssh_config and its CA, in a namespace whose
# root is not the host's, which is what ssh's ownership check on an
# included file is about -- and each command is decided by the catalogue.
# The tier names a machine of its own too, the same sshd on another port
# taking only a password, which frisket reads from a file of alice's and
# the session never sees.
{ self, home-manager }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  ws = "/home/alice/proj";
  password = "open sesame 2222";
  passwordFile = "/home/alice/.ssh/box-password";

  # Test keys, so in the store: the machine's host key, nixpkgs' snakeoil,
  # which the tier's own machine pins when the module is evaluated, and
  # alice's.
  snakeoil = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;
  sshKeys = pkgs.runCommand "chase-test-ssh-keys" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir $out
    cp ${snakeoil.snakeOilEd25519PrivateKey} $out/host
    echo '${snakeoil.snakeOilEd25519PublicKey}' > $out/host.pub
    ssh-keygen -q -t ed25519 -N "" -C alice -f $out/client
  '';

  # The session runs what the test hands it, one numbered file at a time,
  # and leaves each one's output and exit status beside it, as
  # docker-session's does.
  runner = pkgs.writeText "runner.sh" ''
    mkdir -p cmd
    touch cmd/ready
    n=0
    while [ ! -e release ]; do
      if [ -e "cmd/$n" ]; then
        bash "cmd/$n" > "cmd/$n.out" 2>&1
        echo $? > "cmd/$n.rc.tmp" && mv "cmd/$n.rc.tmp" "cmd/$n.rc"
        n=$((n + 1))
      else
        sleep 0.1
      fi
    done
  '';

  # The project: a chase.jsonc naming the machine, made while the test runs,
  # since the machine's address and key are the test's to give.
  mkProject = pkgs.writeShellScript "mk-project" ''
    set -euo pipefail
    export PATH=${lib.makeBinPath (with pkgs; [ coreutils git jq ])}
    address=$1 hostKey=$2
    mkdir -p ${ws}
    cd ${ws}
    git init -q -b main
    jq -n --arg address "$address" --arg hostKey "$hostKey" \
      '{apps: {ssh: {hosts: {server: {address: $address, user: "ops", hostKeys: [$hostKey]}}}}}' > chase.jsonc
    printf 'cmd/\nrelease\n' > .gitignore
    git add chase.jsonc .gitignore
    git -c user.name=alice -c user.email=alice@example.com commit -qm project
  '';
in
{
  name = "chase-ssh-session";

  # The machine, by its VLAN address: its host key from the store, a copy
  # only root reads, as sshd insists, and a user whose one authorized key is
  # alice's.
  # On 2222 it takes a password and no key, as a device with no key support
  # does.
  nodes.server = { lib, pkgs, ... }: {
    services.openssh = {
      enable = true;
      ports = [ 22 2222 ];
      hostKeys = [{ path = "/etc/ssh/ssh_host_ed25519_key"; type = "ed25519"; }];
      settings.PasswordAuthentication = false;
      settings.KbdInteractiveAuthentication = false;
      extraConfig = ''
        Match LocalPort 2222
          PasswordAuthentication yes
          PubkeyAuthentication no
      '';
    };
    environment.etc."ssh/ssh_host_ed25519_key" = { source = "${sshKeys}/host"; mode = "0600"; };
    environment.etc."ssh/authorized_keys.d/ops" = { source = "${sshKeys}/client.pub"; mode = "0444"; };
    users.users.ops = { isNormalUser = true; inherit password; };
    # NixOS gives sshd's PAM a password check only when PasswordAuthentication
    # is on everywhere; here it is on for 2222 alone.
    security.pam.services.sshd.unixAuth = lib.mkForce true;
  };

  nodes.machine = { config, nodes, pkgs, ... }: {
    imports = [ self.nixosModules.default home-manager.nixosModules.home-manager ];

    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 8192;
    virtualisation.cores = 2;

    security.sudo.enable = false;
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
    environment.systemPackages = with pkgs; [ git jq netcat util-linux ];

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

    # Says what it was asked, and lets through only what carries approve-me.
    services.frisket.asker = "${pkgs.writeShellScript "asker" ''
      q=$(${pkgs.coreutils}/bin/cat)
      printf '%s\n' "$q" | ${pkgs.util-linux}/bin/logger -t chase-test-asker
      case $q in *approve-me*) exit 0 ;; esac
      exit 1
    ''}";

    chase = {
      user = "alice";
      uid = 1000;
      gid = 100;
      fallback = "trusted";
      approver = "${pkgs.writeShellScript "approver" ''
        ${pkgs.coreutils}/bin/cat | ${pkgs.util-linux}/bin/logger -t chase-test-approver
      ''}";
      apps = {
        claude.package = pkgs.hello;
        codex.package = pkgs.hello;
        # Put there by the test, alice's and 0600, as a key on a desk is.
        ssh.keyFile = "/home/alice/.ssh/frisket";
      };
      tiers.trusted = {
        egress = "direct";
        allow = [ "*" ];
        grants = true;
        apps.ssh.enable = true;
        apps.ssh.hosts.box = {
          address = "${nodes.server.networking.primaryIPAddress}:2222";
          user = "ops";
          hostKeys = [ snakeoil.snakeOilEd25519PublicKey ];
          inherit passwordFile;
        };
      };
    };

    # Ahead of chase's steps: where the test finds the session.
    flong.chase-trusted.postStart = lib.mkOrder 100 [ [ "${pkgs.writeShellScript "mark" ''
      echo "$machine" > /tmp/last-session
      echo "$leader" > /tmp/last-leader
    ''}" ] ];
  };

  testScript = { nodes, ... }:
    let
      launcher = lib.getExe nodes.machine.flong.chase-trusted.launcher;
      address = nodes.server.networking.primaryIPAddress;
    in
    ''
      import json
      import shlex
      from datetime import timedelta

      def as_user(script):
          inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; " + script
          return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                  f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

      # One command in the session, as the session: its output and status.
      step = 0
      def session(script, timeout=120):
          global step
          n = step
          step += 1
          machine.succeed(f"runuser -u alice -- sh -c {shlex.quote(f'cat > ${ws}/cmd/{n}.tmp && mv ${ws}/cmd/{n}.tmp ${ws}/cmd/{n}')} "
                          f"<<'CHASE_TEST_EOF'\n{script}\nCHASE_TEST_EOF")
          machine.wait_until_succeeds(f"test -e ${ws}/cmd/{n}.rc", timeout=timeout)
          rc = int(machine.succeed(f"cat ${ws}/cmd/{n}.rc").strip())
          out = machine.succeed(f"cat ${ws}/cmd/{n}.out")
          print(f"session[{n}] {script!r} -> {rc}\n{out}")
          return rc, out

      # ssh as an agent runs it, by the machine's name and nothing else:
      # BatchMode only so that a prompt fails the test rather than hangs it.
      def ssh(command):
          return session(f"ssh -o BatchMode=yes server {shlex.quote(command)}")

      def asked():
          out = machine.succeed("journalctl -t chase-test-asker -o cat --no-pager")
          return [json.loads(l) for l in out.splitlines() if l.startswith("{")]

      # How many times the machine's sshd let alice's key in.
      def logins():
          return int(server.succeed("journalctl -u sshd -o cat | grep -c 'Accepted publickey for ops' || true").strip())

      start_all()
      server.wait_for_unit("sshd.service")
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      machine.wait_for_unit("user@1000.service")
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_until_succeeds("nc -z -w 2 ${address} 22")
      machine.succeed("install -d -m 0700 -o alice -g users /home/alice/.ssh && install -m 0600 -o alice -g users ${sshKeys}/client /home/alice/.ssh/frisket")
      machine.succeed("printf '%s\\n' '${password}' > ${passwordFile} && chown alice:users ${passwordFile} && chmod 0400 ${passwordFile}")

      with subtest("the launch approves the machine the grant names, and routes it"):
          host_key = machine.succeed("cat ${sshKeys}/host.pub").strip()
          machine.succeed(f"runuser -l alice -c {shlex.quote(f'${mkProject} ${address} {shlex.quote(host_key)}')}")
          machine.succeed(as_user("cd ${ws} && ${launcher} shell -c 'bash ${runner}'") + " >/tmp/session.out 2>&1 &")
          machine.wait_until_succeeds("test -e ${ws}/cmd/ready", timeout=timedelta(minutes=5))
          print(machine.succeed("cat /tmp/session.out"))
          name = machine.succeed("cat /tmp/last-session").strip()
          approvals = machine.succeed("journalctl -t chase-test-approver -o cat --no-pager")
          assert "${address}" in approvals, approvals
          policy = json.loads(machine.succeed(f"cat /run/user/1000/chase/{name}/policy.json"))
          routes = {r["name"]: r for r in policy["ssh"]}
          assert sorted(routes) == ["box", "server"], routes
          route = routes["server"]
          assert (route["name"], route["address"], route["user"], route["hostKeys"], route["keyFile"]) == \
              ("server", "${address}", "ops", [host_key], "/home/alice/.ssh/frisket"), route

      with subtest("the session's ssh reads frisket's files through the tier's config, its CA first"):
          rc, out = session("ssh -G server")
          assert rc == 0, out
          said = dict(l.split(" ", 1) for l in out.splitlines() if " " in l)
          assert (said["hostname"], said["port"], said["user"]) == ("${address}", "22", "ops"), said
          assert said["globalknownhostsfile"] == "/etc/frisket/ssh_known_hosts /etc/ssh/ssh_known_hosts", said

      with subtest("a read runs on the machine as the grant's user, with no key in the session"):
          before = logins()
          rc, out = ssh("uptime && id -un")
          assert rc == 0 and "load average" in out and out.splitlines()[-1] == "ops", (rc, out)
          assert logins() == before + 1, (logins(), before)
          rc, out = session("ls -A ~/.ssh 2>/dev/null; test -z \"$SSH_AUTH_SOCK\"")
          assert rc == 0 and "frisket" not in out and "id_" not in out, out

      with subtest("a write is asked about, and runs only when approved"):
          rc, out = ssh("touch /home/ops/approve-me")
          assert rc == 0, (rc, out)
          server.succeed("test -e /home/ops/approve-me")
          rc, out = ssh("touch /home/ops/deny-me")
          assert rc == 126 and "declined" in out, (rc, out)
          server.fail("test -e /home/ops/deny-me")
          commands = [q["command"] for q in asked() if q.get("kind") == "ssh"]
          assert commands == ["touch /home/ops/approve-me", "touch /home/ops/deny-me"], asked()

      with subtest("a guarded command and a secret are refused unasked, and never reach the machine"):
          before, questions = logins(), len(asked())
          for command in ["rm /home/ops/approve-me", "cat /home/ops/.ssh/authorized_keys", "cat /etc/shadow"]:
              rc, out = ssh(command)
              assert rc == 126 and "refused" in out, (command, rc, out)
          server.succeed("test -e /home/ops/approve-me")
          assert logins() == before and len(asked()) == questions, (logins(), before, asked())

      with subtest("the tier's own machine is logged in to with its password file, which the session never sees"):
          rc, out = session("ssh -o BatchMode=yes box id -un")
          assert rc == 0 and out.splitlines()[-1] == "ops", (rc, out)
          server.succeed("journalctl -u sshd -o cat | grep -q 'Accepted password for ops'")
          box = routes["box"]
          assert (box["passwordFile"], box["address"]) == ("${passwordFile}", "${address}:2222") and "agent" not in box and "keyFile" not in box, box
          # The password in two halves, so that this command's own file,
          # which the session reads, does not hold it.
          rc, out = session("p=$(printf %s 'open ses' 'ame 2222'); grep -rlF -D skip \"$p\" /etc /home /tmp 2>/dev/null; "
                            "env | grep -cF \"$p\"; cat ${passwordFile} 2>/dev/null | grep -cF \"$p\"")
          assert out.split() == ["0", "0"], out
          machine.fail(f"grep -qF '${password}' /run/user/1000/chase/{name}/policy.json")
          machine.fail("journalctl -o cat --no-pager | grep -qF '${password}'")

      with subtest("the session's end ends its route"):
          machine.succeed("runuser -u alice -- touch ${ws}/release")
          machine.wait_until_succeeds(f"test ! -e /run/user/1000/flong/sessions/{name}", timeout=timedelta(minutes=1))
    '';
}
