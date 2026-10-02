# A recording end to end: `chase record --default allow` in a checkout of
# a tier that refuses what the session is about to do, on one machine, and
# an upstream on another standing in for GitHub's API and for a host no
# route serves. The session deletes a ref -- a write the tier refuses --
# fetches from a name off the allowlist, and runs strace, whose ptrace the
# tier's filter refuses; each goes through while recording, and is written
# down: the request and the connection by frisket, in its sink; the call
# by the kernel's audit, which `chase record` follows and puts down to the
# session by its cgroup. What is left is a report and a proposal, which
# `chase record apply` adds to the checkout's chase.jsonc; approved at the
# next launch, it lets the same session do the same things with nothing
# recording.
{ self, home-manager }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  upstream4 = "203.0.113.20";
  upstream6 = "2001:db8:113::20";
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
  # and a plain page on 80, for a name no route serves.
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
    networking.interfaces.eth1.ipv4.addresses = [{ address = upstream4; prefixLength = 24; }];
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
    imports = [ self.nixosModules.default home-manager.nixosModules.home-manager ];

    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 8192;
    virtualisation.cores = 2;

    networking.interfaces.eth1.ipv4.addresses = [{ address = "203.0.113.10"; prefixLength = 24; }];
    networking.interfaces.eth1.ipv6.addresses = [{ address = "2001:db8:113::10"; prefixLength = 64; }];
    networking.nameservers = [ upstream4 ];
    security.pki.certificateFiles = [ "${certs}/ca.crt" ];
    security.sudo.enable = false;
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
    environment.systemPackages = with pkgs; [ git jq curl util-linux ];

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
      approver = "${pkgs.writeShellScript "approver" ''
        ${pkgs.coreutils}/bin/cat | ${pkgs.util-linux}/bin/logger -t chase-test-approver
      ''}";
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

      def as_user(script):
          inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; " + script
          return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                  f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

      def upstream_saw():
          out = upstream.succeed("journalctl -u upstream.service -o cat --no-pager")
          return [json.loads(l) for l in out.splitlines() if l.startswith("{")]

      def result(run, name):
          return machine.succeed(f"cat ${ws}/out/{run}/{name}")

      start_all()
      upstream.wait_for_unit("upstream.service")
      upstream.wait_for_unit("dnsmasq.service")
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      machine.wait_for_unit("user@1000.service")
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_until_succeeds("curl -sS -m 2 -o /dev/null http://plain.test/")
      machine.wait_until_succeeds("curl -sS -m 2 -6 -o /dev/null http://plain.test/")
      machine.wait_until_succeeds("curl -sS -m 2 -o /dev/null -X DELETE https://api.github.com/")
      machine.succeed("printf '%s' '${token}' > /home/alice/gh-token && chown alice:users /home/alice/gh-token && chmod 0600 /home/alice/gh-token")
      machine.succeed("runuser -l alice -c ${mkProject}")

      with subtest("the tier refuses all three, with nothing recording"):
          machine.succeed(as_user(f"cd ${ws} && ${launcher} shell -c {shlex.quote('bash ${session} before')}"), timeout=300)
          assert result("before", "delete").strip() == "403", result("before", "delete")
          assert "plain page" not in result("before", "plain"), result("before", "plain")
          assert result("before", "strace").splitlines()[-1] != "0", result("before", "strace")
          assert not [l for l in upstream_saw() if l["path"].startswith("/repos/")], upstream_saw()

      with subtest("chase record --default allow lets each through, and writes each down"):
          report = machine.succeed(as_user(f"cd ${ws} && ${chase} record --default allow -- shell -c {shlex.quote('bash ${session} recording')}"), timeout=300)
          print(report)
          assert result("recording", "delete").strip() == "204", result("recording", "delete")
          assert result("recording", "plain") == "plain page\n", result("recording", "plain")
          assert result("recording", "strace").splitlines()[-1] == "0", result("recording", "strace")
          deletes = [l for l in upstream_saw() if l["path"].startswith("/repos/")]
          assert len(deletes) == 1 and deletes[0]["auth"] == "Bearer ${token}", deletes
          for needle in ["HTTP on routes", "git/delete-ref", "plain.test:80", "ptrace", "chase record apply"]:
              assert needle in report, (needle, report)

          [kept] = machine.succeed("ls /home/alice/.local/state/chase/records").split()
          at = f"/home/alice/.local/state/chase/records/{kept}"
          meta = json.loads(machine.succeed(f"cat {at}/meta.json"))
          assert (meta["tier"], meta["workspace"], meta["options"]) == ("recorded", "${ws}", {"default": "allow", "base": "tier"}), meta
          lines = [json.loads(l) for l in machine.succeed(f"cat {at}/record.jsonl").splitlines()]
          http = [l for l in lines if l["kind"] == "http"]
          assert [(l["route"], l["method"], l.get("operation"), l["answer"], l["source"]) for l in http] == \
              [("github", "DELETE", "git/delete-ref", "allow", "default")], http
          egress = {(l["name"], l["port"], l["answer"]) for l in lines if l["kind"] == "egress" and l["source"] == "default"}
          assert egress == {("plain.test", 80, "allow")}, egress
          calls = {l["name"]: l for l in lines if l["kind"] == "syscall"}
          assert "ptrace" in calls and not calls["ptrace"].get("probable"), calls
          # frisket's copy is the user's own record now, and goes.
          machine.succeed(f"test ! -e /var/lib/frisket/records/{kept}.jsonl")
          machine.fail("ls /run/user/1000/chase/.record/* 2>/dev/null | grep .")

          proposal = machine.succeed(f"cat {at}/proposal.jsonc")
          print(proposal)
          for needle in ['"git/delete-ref"', '"plain.test"', '"ptrace"', "loosens"]:
              assert needle in proposal, (needle, proposal)
          machine.fail("test -e ${ws}/chase.jsonc")

      with subtest("from scratch, flong takes the lines, and what the tier allows is reported, not proposed"):
          report = machine.succeed(as_user(f"cd ${ws} && ${chase} record --default allow --base none -- shell -c {shlex.quote('bash ${session} scratch')}"), timeout=300)
          print(report)
          assert result("scratch", "strace").splitlines()[-1] == "0", result("scratch", "strace")
          at = machine.succeed("ls -td /home/alice/.local/state/chase/records/* | head -1").strip()
          assert json.loads(machine.succeed(f"cat {at}/meta.json"))["options"] == {"default": "allow", "base": "none"}
          calls = {json.loads(l)["name"] for l in machine.succeed(f"cat {at}/record.jsonl").splitlines() if '"syscall"' in l}
          # The tier's own calls are seen, its filter's exceptions proposed.
          assert {"execve", "ptrace"} <= calls, calls
          proposal = machine.succeed(f"cat {at}/proposal.jsonc")
          assert '"ptrace"' in proposal and '"execve"' not in proposal, proposal

      with subtest("chase record apply adds the proposal to the checkout's grant"):
          out = machine.succeed(as_user(f"cd ${ws} && ${chase} record apply {kept}"))
          print(out)
          grant = machine.succeed("cat ${ws}/chase.jsonc")
          print(grant)
          for needle in ['"git/delete-ref"', '"plain.test"', '"ptrace"']:
              assert needle in grant, (needle, grant)
          assert "nothing to add" in machine.succeed(as_user(f"cd ${ws} && ${chase} record apply {kept}"))

      with subtest("approved at the next launch, the grant lets the session do it all, with nothing recording"):
          machine.succeed("runuser -l alice -c 'cd ${ws} && git add chase.jsonc && git -c user.name=alice -c user.email=alice@example.com commit -qm grant'")
          machine.succeed(as_user(f"cd ${ws} && ${launcher} shell -c {shlex.quote('bash ${session} after')}"), timeout=300)
          approvals = machine.succeed("journalctl -t chase-test-approver -o cat --no-pager")
          assert "git/delete-ref" in approvals and "ptrace" in approvals and "plain.test" in approvals, approvals
          assert result("after", "delete").strip() == "204", result("after", "delete")
          assert result("after", "plain") == "plain page\n", result("after", "plain")
          assert result("after", "strace").splitlines()[-1] == "0", result("after", "strace")
          name = machine.succeed("cat /tmp/last-session").strip()
          machine.wait_until_succeeds(f"test ! -e /run/user/1000/chase/{name}", timeout=60)
    '';
}
