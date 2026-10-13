# A recording end to end: `chase record --default allow` in a checkout of
# a tier that refuses what the session is about to do, on one machine, and
# an upstream on another standing in for GitHub's API and for a host no
# route serves, and, at a private address, for a host on the local
# network. The session deletes a ref -- a write the tier refuses --
# fetches from a name off the allowlist and from the host on the local
# network, and runs strace, whose ptrace the tier's filter refuses; each
# goes through while recording, and is written down: the request and the connection by frisket, in its sink; the call
# by the kernel's audit, which `chase record` follows and puts down to the
# session by its cgroup. What is left is a report and a proposal, which
# `chase record apply` adds to the checkout's chase.json and has signed,
# by quoin's signer over a software TPM, through galley -- a stand-in
# that allows it; signed, it lets the next launch of the same session do
# the same things with nothing recording and nobody asked. A hand edit
# that nobody signed is put to the signer by the launch itself.
{ self, home-manager }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  system = pkgs.stdenv.hostPlatform.system;
  fakegalley = lib.getExe self.inputs.quoin.packages.${system}.fakegalley;
  upstream4 = "203.0.113.20";
  upstream6 = "2001:db8:113::20";
  # The same machine on the local network: a private address, which
  # frisket dials only for a name in a document's lan.
  lan4 = "192.168.1.20";
  ws = "/home/alice/proj";
  token = "ghp_the-real-token";

  certs = pkgs.runCommand "chase-test-record-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -keyout ca.key -out ca.crt -subj /CN=chase-test-record-ca \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout server.key -out server.csr -subj /CN=api.github.com
    printf '%s\n' 'subjectAltName=DNS:api.github.com' 'extendedKeyUsage=serverAuth' > ext
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 3650 -extfile ext -out server.crt
  '';

  # GitHub's API as far as a ref's deletion goes, saying what it was sent;
  # and a plain page on 80, for a name no route serves and for the host on
  # the local network.
  upstream = pkgs.writeText "upstream.py" ''
    import json, socket, ssl, sys, threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *a):
            pass
        def any(self):
            print(json.dumps({"method": self.command, "host": self.headers.get("Host", ""), "path": self.path,
                              "auth": self.headers.get("Authorization", "")}), flush=True)
            body = b"plain page\n"
            self.send_response(204 if self.command == "DELETE" else 200)
            self.send_header("Content-Length", "0" if self.command == "DELETE" else str(len(body)))
            self.end_headers()
            if self.command != "DELETE":
                self.wfile.write(body)
        do_GET = do_POST = do_DELETE = any

    # Both families on one socket: :: takes v4 too.
    class Dual(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[1], sys.argv[2])
    tls = Dual(("::", 443), H)
    tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
    threading.Thread(target=tls.serve_forever, daemon=True).start()
    Dual(("::", 80), H).serve_forever()
  '';

  # What the session does, each result a file in the workspace: the
  # ref's deletion, the page, and strace, which lives a second so that its
  # calls are read while it does.
  session = pkgs.writeText "session.sh" ''
    out=$PWD/out/$1
    mkdir -p "$out"
    curl -sS -m 20 -o /dev/null -w '%{http_code}' -X DELETE -H 'Authorization: Bearer proxy-injected' \
      https://api.github.com/repos/o/r/git/refs/heads/x > "$out/delete" 2>&1
    curl -sS -m 20 http://plain.test/ > "$out/plain" 2>&1
    curl -sS -m 20 http://nas.test/ > "$out/nas" 2>&1
    strace -f -o /dev/null sleep 1 > "$out/strace" 2>&1
    echo $? >> "$out/strace"
  '';

  mkProject = pkgs.writeShellScript "mk-project" ''
    set -euo pipefail
    export PATH=${lib.makeBinPath (with pkgs; [ coreutils git ])}
    mkdir -p ${ws}
    cd ${ws}
    git init -q -b main
    printf 'out/\n' > .gitignore
    git add .gitignore
    git -c user.name=alice -c user.email=alice@example.com commit -qm project
  '';
in
{
  name = "chase-record-session";

  nodes.upstream = { pkgs, ... }: {
    networking.interfaces.eth1.ipv4.addresses = [{ address = upstream4; prefixLength = 24; } { address = lan4; prefixLength = 24; }];
    networking.interfaces.eth1.ipv6.addresses = [{ address = upstream6; prefixLength = 64; }];
    networking.firewall.enable = false;
    services.dnsmasq = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        listen-address = [ upstream4 ];
        bind-dynamic = true;
        no-resolv = true;
        # Both families, as a resolver asks for both and takes a refusal
        # of either as a server's failure.
        address = [
          "/api.github.com/${upstream4}"
          "/api.github.com/${upstream6}"
          "/plain.test/${upstream4}"
          "/plain.test/${upstream6}"
          "/nas.test/${lan4}"
        ];
      };
    };
    systemd.services.upstream = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 ${upstream} ${certs}/server.crt ${certs}/server.key";
        Restart = "on-failure";
        RestartSec = 1;
      };
    };
  };

  nodes.machine = { config, pkgs, ... }: {
    imports = [ self.nixosModules.default home-manager.nixosModules.home-manager self.inputs.quoin.nixosModules.signer ];

    # quoin's signer, alice's agent, over a software TPM: the key is made
    # in it as the test runs, so the allowed signers are written then. It
    # asks alice's galley, a stand-in answering from a script.
    virtualisation.tpm.enable = true;
    services.quoin.signer = { enable = true; forUser = "alice"; };
    services.quoin.policy = {
      fileName = "chase.json";
      courier = { enable = true; forUser = "alice"; };
    };
    environment.etc."quoin/allowed_signers".source = lib.mkForce "/run/allowed_signers";
    systemd.tmpfiles.rules = [ "d /run/galley-ask 0755 alice users -" "d /run/fakegalley 0755 alice users -" ];
    systemd.user.services.galley.serviceConfig = {
      ExecStart = "${fakegalley} -socket /run/galley-ask/alice.sock -script /run/fakegalley/script -log /run/fakegalley/log";
      Slice = "app.slice";
    };

    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 8192;
    virtualisation.cores = 2;

    networking.interfaces.eth1.ipv4.addresses = [{ address = "203.0.113.10"; prefixLength = 24; } { address = "192.168.1.10"; prefixLength = 24; }];
    networking.interfaces.eth1.ipv6.addresses = [{ address = "2001:db8:113::10"; prefixLength = 64; }];
    networking.nameservers = [ upstream4 ];
    security.pki.certificateFiles = [ "${certs}/ca.crt" ];
    security.sudo.enable = false;
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
    environment.systemPackages = with pkgs; [ git jq curl util-linux ssh-tpm-agent openssh ];

    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      group = "users";
      # The audit records of logged calls are in the system journal.
      extraGroups = [ "systemd-journal" ];
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
      fallback = "recorded";
      # Never asked: chase.json is signed, by the signer.
      approver = "${pkgs.writeShellScript "approver" ''
        ${pkgs.coreutils}/bin/cat | ${pkgs.util-linux}/bin/logger -t chase-test-approver
      ''}";
      signer.agentSocket = "/run/quoin-signer/agent";
      apps = {
        claude.package = pkgs.hello;
        codex.package = pkgs.hello;
        # Put there by the test, alice's and 0600.
        github.credentialFile = "/home/alice/gh-token";
      };
      # Everything through frisket, nothing allowed but GitHub's API, its
      # writes refused, and flong's strict filter, which has no ptrace.
      tiers.recorded = {
        egress = "frisket";
        grants = true;
        writes = "refuse";
        guarded = "refuse";
        unmatched = "refuse";
        record.enable = true;
        apps.github = { enable = true; authenticated = true; };
      };
    };

    containers.chase-recorded.config = { pkgs, ... }: {
      environment.systemPackages = [ pkgs.strace pkgs.curl ];
    };

    # Ahead of chase's steps: the ordinary launcher's session, for the test.
    flong.chase-recorded.postStart = lib.mkOrder 100 [ [ "${pkgs.writeShellScript "mark" ''
      echo "$machine" > /tmp/last-session
    ''}" ] ];
  };

  testScript = { nodes, ... }:
    let
      chase = lib.getExe nodes.machine.chase.package;
      launcher = lib.getExe nodes.machine.flong.chase-recorded.launcher;
    in
    ''
      import json
      import shlex

      ${builtins.readFile ./vm-read.py}
      def as_user(script):
          inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; " + script
          return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                  f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

      def upstream_saw():
          out = upstream.succeed("journalctl -u upstream.service -o cat --no-pager")
          return [json.loads(l) for l in out.splitlines() if l.startswith("{")]

      def result(run, name):
          return vm_read(machine, f"${ws}/out/{run}/{name}")

      def galley(*script):
          machine.succeed(f"printf '%s\\n' {' '.join(map(shlex.quote, script))} > /run/fakegalley/script")
          machine.succeed("rm -f /run/galley-ask/alice.sock")
          machine.succeed("systemctl -M alice@ --user restart galley.service")
          machine.wait_until_succeeds("test -S /run/galley-ask/alice.sock")

      def questions():
          out = machine.succeed("cat /run/fakegalley/log 2>/dev/null || true")
          return [e for e in map(json.loads, out.splitlines()) if e["event"] == "question"]

      def verifies():
          machine.succeed("ssh-keygen -Y verify -f /etc/quoin/allowed_signers -I alice -n 'quoin-policy:~/proj' "
                          "-s ${ws}/chase.json.sig < ${ws}/chase.json")

      start_all()
      upstream.wait_for_unit("upstream.service")
      upstream.wait_for_unit("dnsmasq.service")
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      machine.wait_for_unit("user@1000.service")
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_until_succeeds("curl -sS -m 2 -o /dev/null http://plain.test/")
      machine.wait_until_succeeds("curl -sS -m 2 -6 -o /dev/null http://plain.test/")
      machine.wait_until_succeeds("curl -sS -m 2 -o /dev/null http://nas.test/")
      machine.wait_until_succeeds("curl -sS -m 2 -o /dev/null -X DELETE https://api.github.com/")
      machine.succeed("printf '%s' '${token}' > /home/alice/gh-token && chown alice:users /home/alice/gh-token && chmod 0600 /home/alice/gh-token")
      machine.succeed("runuser -l alice -c ${mkProject}")

      # alice's signing key, made in the TPM, and the allowed signers that
      # allow it in every quoin-policy namespace.
      machine.wait_for_unit("quoin-signer.socket")
      machine.succeed("systemctl start quoin-signer.service")
      machine.succeed("SSH_ASKPASS_REQUIRE=never ssh-tpm-keygen -f /root/id_ecdsa -C alice@machine </dev/null")
      machine.succeed("install -o ssh-signer -g ssh-signer -m 0600 /root/id_ecdsa.tpm /var/lib/quoin-signer/")
      machine.succeed("systemctl restart quoin-signer.service")
      key = " ".join(machine.succeed("cat /root/id_ecdsa.pub").split()[:2])
      machine.succeed(f"echo 'alice namespaces=\"quoin-policy:*\" {key}' > /run/allowed_signers")
      galley("answer 0")

      with subtest("the tier refuses all four, with nothing recording"):
          machine.succeed(as_user(f"cd ${ws} && ${launcher} shell -c {shlex.quote('bash ${session} before')}"), timeout=300)
          assert result("before", "delete").strip() == "403", result("before", "delete")
          assert "plain page" not in result("before", "plain"), result("before", "plain")
          assert "plain page" not in result("before", "nas"), result("before", "nas")
          assert result("before", "strace").splitlines()[-1] != "0", result("before", "strace")
          assert not [l for l in upstream_saw() if l["path"].startswith("/repos/")], upstream_saw()

      with subtest("chase record --default allow lets each through, and writes each down"):
          report = machine.succeed(as_user(f"cd ${ws} && ${chase} record --default allow -- shell -c {shlex.quote('bash ${session} recording')}"), timeout=300)
          print(report)
          assert result("recording", "delete").strip() == "204", result("recording", "delete")
          assert result("recording", "plain") == "plain page\n", result("recording", "plain")
          assert result("recording", "nas") == "plain page\n", result("recording", "nas")
          assert result("recording", "strace").splitlines()[-1] == "0", result("recording", "strace")
          deletes = [l for l in upstream_saw() if l["path"].startswith("/repos/")]
          assert len(deletes) == 1 and deletes[0]["auth"] == "Bearer ${token}", deletes
          for needle in ["HTTP on routes", "git/delete-ref", "plain.test:80", "nas.test:80", "(local network)", "ptrace", "chase record apply"]:
              assert needle in report, (needle, report)

          [kept] = machine.succeed("ls /home/alice/.local/state/chase/records").split()
          at = f"/home/alice/.local/state/chase/records/{kept}"
          meta = vm_json(machine, f"{at}/meta.json")
          assert (meta["tier"], meta["workspace"], meta["options"]) == ("recorded", "${ws}", {"default": "allow", "base": "tier"}), meta
          lines = [json.loads(l) for l in vm_read(machine, f"{at}/record.jsonl").splitlines()]
          http = [l for l in lines if l["kind"] == "http"]
          assert [(l["route"], l["method"], l.get("operation"), l["answer"], l["source"]) for l in http] == \
              [("github", "DELETE", "git/delete-ref", "allow", "default")], http
          egress = {(l["name"], l["port"], l.get("lan", False), l["answer"]) for l in lines if l["kind"] == "egress" and l["source"] == "default"}
          assert egress == {("plain.test", 80, False, "allow"), ("nas.test", 80, True, "allow")}, egress
          calls = {l["name"]: l for l in lines if l["kind"] == "syscall"}
          assert "ptrace" in calls and not calls["ptrace"].get("probable"), calls
          # frisket's copy is the user's own record now, and goes.
          machine.succeed(f"test ! -e /var/lib/frisket/records/{kept}.jsonl")
          machine.fail("ls /run/user/1000/chase/.record/* 2>/dev/null | grep .")

          proposal = vm_json(machine, f"{at}/proposal.json")
          print(json.dumps(proposal, indent=2))
          frisket = proposal["propose"]["frisket"]
          assert frisket["routes"]["github"]["operations"] == {"git/delete-ref": "allow"}, frisket
          assert frisket["allow"] == {"plain.test": True, "nas.test": True}, frisket
          assert frisket["lan"] == {"nas.test": {"ports": [80]}}, frisket
          assert proposal["propose"]["flong"]["seccomp"]["syscalls"]["ptrace"] == "allow", proposal
          assert "loosens" in proposal["notes"]["/frisket/routes/github/operations/git~1delete-ref"], proposal["notes"]
          machine.fail("test -e ${ws}/chase.json")

      with subtest("from scratch, flong takes the lines, and what the tier allows is reported, not proposed"):
          report = machine.succeed(as_user(f"cd ${ws} && ${chase} record --default allow --base none -- shell -c {shlex.quote('bash ${session} scratch')}"), timeout=300)
          print(report)
          assert result("scratch", "strace").splitlines()[-1] == "0", result("scratch", "strace")
          at = machine.succeed("ls -td /home/alice/.local/state/chase/records/* | head -1").strip()
          assert vm_json(machine, f"{at}/meta.json")["options"] == {"default": "allow", "base": "none"}
          calls = {json.loads(l)["name"] for l in vm_read(machine, f"{at}/record.jsonl").splitlines() if '"syscall"' in l}
          # The tier's own calls are seen, its filter's exceptions proposed.
          assert {"execve", "ptrace"} <= calls, calls
          proposal = vm_read(machine, f"{at}/proposal.json")
          assert '"ptrace"' in proposal and '"execve"' not in proposal, proposal

      with subtest("chase record apply adds the proposal to the checkout's chase.json, and the signer signs it"):
          asked = len(questions())
          out = machine.succeed(as_user(f"cd ${ws} && ${chase} record apply {kept}"))
          print(out)
          grant = vm_read(machine, "${ws}/chase.json")
          print(grant)
          for needle in ['"git/delete-ref"', '"plain.test"', '"nas.test"', '"lan"', '"ptrace"']:
              assert needle in grant, (needle, grant)
          qs = questions()[asked:]
          assert len(qs) == 1 and qs[0]["title"] == "sign ~/proj/chase.json", qs
          assert qs[0]["diff"]["new"] == grant and qs[0]["diff"]["old"] == "", qs[0]["diff"]
          assert "signed, chase.json.sig written" in out, out
          verifies()
          assert "nothing to add" in machine.succeed(as_user(f"cd ${ws} && ${chase} record apply {kept}"))

      with subtest("signed, the next launch lets the session do it all, with nothing recording and nobody asked"):
          machine.succeed("runuser -l alice -c 'cd ${ws} && git add chase.json chase.json.sig && git -c user.name=alice -c user.email=alice@example.com commit -qm grant'")
          asked = len(questions())
          machine.succeed(as_user(f"cd ${ws} && ${launcher} shell -c {shlex.quote('bash ${session} after')}"), timeout=300)
          assert len(questions()) == asked, questions()[asked:]
          machine.fail("journalctl -q -t chase-test-approver -o cat --no-pager | grep -q .")
          assert result("after", "delete").strip() == "204", result("after", "delete")
          assert result("after", "plain") == "plain page\n", result("after", "plain")
          assert result("after", "nas") == "plain page\n", result("after", "nas")
          assert result("after", "strace").splitlines()[-1] == "0", result("after", "strace")
          name = machine.succeed("cat /tmp/last-session").strip()
          machine.wait_until_succeeds(f"test ! -e /run/user/1000/chase/{name}", timeout=60)

      with subtest("a hand edit nobody signed is put to the signer by the launch, against what HEAD signed"):
          signed = vm_read(machine, "${ws}/chase.json")
          machine.succeed(as_user("cd ${ws} && jq '.frisket.allow[\"extra.test\"] = true' chase.json > c && mv c chase.json && ${chase} fmt chase.json"))
          machine.fail("ssh-keygen -Y verify -f /etc/quoin/allowed_signers -I alice -n 'quoin-policy:~/proj' -s ${ws}/chase.json.sig < ${ws}/chase.json")
          asked = len(questions())
          machine.succeed(as_user(f"cd ${ws} && ${launcher} shell -c {shlex.quote('bash ${session} edited')}"), timeout=300)
          qs = questions()[asked:]
          assert len(qs) == 1 and qs[0]["title"] == "sign ~/proj/chase.json", qs
          assert qs[0]["diff"]["old"] == signed and '"extra.test": true' in qs[0]["diff"]["new"], qs[0]["diff"]
          verifies()
          assert result("edited", "delete").strip() == "204", result("edited", "delete")

      with subtest("refused, the launch ends"):
          galley("cancel")
          machine.succeed(as_user("cd ${ws} && jq '.frisket.allow[\"refused.test\"] = true' chase.json > c && mv c chase.json && ${chase} fmt chase.json"))
          rc, _ = machine.execute(as_user(f"cd ${ws} && ${launcher} shell -c {shlex.quote('bash ${session} refused')}"), timeout=300)
          assert rc != 0, rc
          machine.fail("test -e ${ws}/out/refused")
    '';
}
