# A Docker session end to end: chase's launch, flong's session, frisket's
# route and relay, and alice's rootless Docker daemon, all on one machine.
# The checkout is shop as the machine knows it -- its origin, pinned at
# its path -- with a flake binding postgres:18 on 64320, and a one-service
# Compose file shaped like shop's own. The session runs Compose as its
# scripts do, reaches the database as localhost and by its .internal name,
# and is refused whatever would reach the host.
{ self, home-manager }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  project = "example/shop";
  address = "127.101.170.171";
  ws = "/home/alice/shop";

  # The real postgres:18, pinned, so the daemon runs what shop runs.
  # Loaded before the session starts: the VM has no registry to pull from,
  # and a pull through the route is frisket's own VM test's to show.
  postgres = pkgs.dockerTools.pullImage {
    imageName = "postgres";
    imageDigest = "sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722";
    hash = "sha256-XpXCSH7vYyt6K99YNN86ibvG/TdZITtUSJyIoJveuyA=";
    finalImageName = "postgres";
    finalImageTag = "18";
    os = "linux";
    arch = "amd64";
  };

  compose = pkgs.writeText "compose.yaml" ''
    services:
      db:
        image: 'postgres:18'
        environment:
          - POSTGRES_USER=data_lab
          - POSTGRES_PASSWORD=data_lab
          - POSTGRES_DB=data_lab
        ports:
          - '64320:5432'
        volumes:
          - pgdata:/var/lib/postgresql

    volumes:
      pgdata:
  '';

  # The session runs what the test hands it, one numbered file at a time, in
  # the checkout with the session's own environment, and leaves each one's
  # output and exit status beside it: so the test can read frisket's log
  # between one command and the next.
  runner = pkgs.writeText "runner.sh" ''
    mkdir -p cmd
    until ip route show default | grep -q .; do sleep 0.2; done
    env > cmd/env
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

  # shop as a developer has it: its GitHub origin, a flake giving the
  # envelope its image and port, and the Compose file its scripts run.
  mkProject = pkgs.writeShellScript "mk-project" ''
    set -euo pipefail
    export PATH=${lib.makeBinPath (with pkgs; [ coreutils git ])}
    mkdir -p ${ws}
    cd ${ws}
    git init -q -b main
    git remote add origin git@github.com:example/shop.git
    cat > flake.nix <<'EOF'
    {
      outputs = { self }: {
        chaseModules.default = {
          chase.bindings.docker.images = [ "postgres:18" ];
          chase.bindings.docker.ports = [ 64320 ];
        };
      };
    }
    EOF
    install -m 0644 ${compose} compose.yaml
    printf 'cmd/\n' > .gitignore
    git add flake.nix compose.yaml .gitignore
    git -c user.name=alice -c user.email=alice@example.com commit -qm project
  '';
in
{
  name = "chase-docker-session";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ self.nixosModules.default home-manager.nixosModules.home-manager ];

    virtualisation.memorySize = 4096;
    virtualisation.diskSize = 8192;
    virtualisation.cores = 2;

    security.sudo.enable = false;
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
    environment.systemPackages = with pkgs; [ git jq postgresql util-linux ];

    # As nix-config's modules/docker.nix runs it: alice's own daemon under
    # her user manager, which frisket, running as her, reaches at
    # /run/user/1000/docker.sock.
    virtualisation.docker.rootless = {
      enable = true;
      setSocketVariable = true;
      daemon.settings.storage-driver = "overlay2";
    };
    # The port driver is left at dockerd-rootless.sh's default, as the desk
    # leaves it: builtin, while slirp4netns is the network driver. builtin
    # binds a published port in the host's namespace at the HostIp the
    # daemon is given, which is what puts the project's port at its own
    # loopback address and nowhere else. Not pinning it is the point: a
    # default that moved to a driver binding elsewhere would fail the
    # address checks below rather than go unnoticed on a desk.

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
      order = [ "trusted" ];
      fallback = "trusted";
      approver = "${pkgs.writeShellScript "approver" ''
        ${pkgs.coreutils}/bin/cat | ${pkgs.util-linux}/bin/logger -t chase-test-approver
      ''}";
      bindings = {
        claude.package = pkgs.hello;
        codex.package = pkgs.hello;
      };
      # As trusted is on a desk: direct egress, envelopes, dev servers
      # forwarded with `auto`, and shop pinned where it lives.
      tiers.trusted = {
        match = [ { checkouts.${project} = ws; } ];
        egress = "direct";
        allow = [ "*" ];
        envelope = true;
        forwardPorts = "auto";
        apps.docker.enable = true;
      };
    };

    containers.agent-trusted.config = { pkgs, ... }: {
      environment.systemPackages = [ pkgs.postgresql pkgs.iproute2 ];
    };

    # Ahead of chase's steps: where the test finds the session.
    flong.agent-trusted.postStart = lib.mkOrder 100 [ [ "${pkgs.writeShellScript "mark" ''
      echo "$machine" > /tmp/last-session
      echo "$leader" > /tmp/last-leader
    ''}" ] ];
  };

  testScript = { nodes, ... }:
    let
      launcher = lib.getExe nodes.machine.flong.agent-trusted.launcher;
      compose = nodes.machine.chase.bindings.docker.package;
    in
    ''
      import json
      import shlex
      from datetime import timedelta

      def as_user(script):
          inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; " + script
          return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                  f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

      # The daemon, from the host, as alice: what a person at the desk
      # sees, never through frisket.
      def host_docker(args):
          return machine.succeed(f"runuser -u alice -- env DOCKER_HOST=unix:///run/user/1000/docker.sock docker {args}")

      def frisket_lines(msg):
          out = machine.succeed("journalctl -u frisket.service -o cat --no-pager")
          lines = []
          for l in out.splitlines():
              try:
                  m = json.loads(l)
              except ValueError:
                  continue
              if m.get("msg") == msg and m.get("session") == name:
                  lines.append(m)
          return lines

      def requests():
          return [m for m in frisket_lines("request") if m.get("route") == "docker"]

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

      def session_ok(script, timeout=120):
          rc, out = session(script, timeout)
          assert rc == 0, (script, rc, out)
          return out

      # What frisket may say of a request in the flows Compose runs: admitted,
      # or the daemon's own 404 for an object that is not there yet, and
      # either way the operation it was judged as.
      def flow_line(m):
          return m.get("operation") and (
              m["decision"] == "allowed"
              or (m["decision"] == "refused" and m.get("reason") == "no such object" and m["status"] == 404))

      start_all()
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      machine.wait_for_unit("user@1000.service")
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_until_succeeds("test -S /run/user/1000/docker.sock", timeout=120)
      machine.wait_until_succeeds("runuser -u alice -- env DOCKER_HOST=unix:///run/user/1000/docker.sock docker version", timeout=120)

      with subtest("the daemon is alice's, rootless, with the image shop runs and a container of nobody's"):
          info = json.loads(host_docker("info --format '{{json .}}'"))
          assert "name=rootless" in info["SecurityOptions"], info["SecurityOptions"]
          assert info["Driver"] == "overlay2", info["Driver"]
          host_docker("load -i ${postgres}")
          host_docker("image inspect postgres:18 --format '{{.Id}}'")
          # Made on the host, without frisket, so it carries no project's label.
          host_docker("create --name stray postgres:18")

      with subtest("the launch approves shop as its origin names it, and routes its Docker"):
          machine.succeed("runuser -l alice -c ${mkProject}")
          machine.succeed(as_user("cd ${ws} && ${launcher} shell -c 'bash ${runner}'") + " >/tmp/session.out 2>&1 &")
          machine.wait_until_succeeds("test -e ${ws}/cmd/ready", timeout=timedelta(minutes=5))
          print(machine.succeed("cat /tmp/session.out"))
          name = machine.succeed("cat /tmp/last-session").strip()
          run = f"/run/user/1000/chase/{name}"
          approvals = machine.succeed("journalctl -t chase-test-approver -o cat --no-pager")
          assert '"kind": "envelope"' in approvals and '\\"dockerProject\\": \\"${project}\\"' in approvals, approvals
          policy = json.loads(machine.succeed(f"cat {run}/policy.json"))
          [route] = [r for r in policy["routes"] if r["name"] == "docker"]
          d = route["docker"]
          assert d["project"] == "${project}" and d["address"] == "${address}" and d["ports"] == [64320], d
          assert d["names"] == ["shop.internal", "shop.example.internal"], d["names"]
          env = dict(l.split("=", 1) for l in machine.succeed("cat ${ws}/cmd/env").splitlines() if "=" in l)
          assert env["DOCKER_HOST"] == "tcp://docker.frisket.internal:2376" and env["DOCKER_TLS_VERIFY"] == "1", env
          assert env["CHASE_DOCKER_ADDRESS"] == "${address}" and env["CHASE_DOCKER_PORTS"] == "64320", env

      with subtest("the session's Docker is the binding's package, with Compose ${pkgs.docker-compose.version}"):
          out = session_ok("readlink -f \"$(command -v docker)\"; docker compose version --short")
          assert out.splitlines()[0].startswith("${compose}/"), out
          assert out.splitlines()[1].lstrip("v") == "${pkgs.docker-compose.version}", out

      with subtest("Compose brings the database up, and runs pg_isready and psql in it as shop's scripts do"):
          session_ok("docker compose up -d", timeout=300)
          session_ok("for i in $(seq 120); do docker compose exec -T db pg_isready -U data_lab && exit 0; sleep 1; done; exit 1", timeout=300)
          out = session_ok("printf '%s\\n' 'CREATE TABLE seen (what text);' \"INSERT INTO seen VALUES ('through frisket');\" 'SELECT what FROM seen;' "
                           "| docker compose exec -T db psql -v ON_ERROR_STOP=1 -U data_lab -d data_lab")
          assert "through frisket" in out, out

      with subtest("the container's network went to the daemon as its ID, and a second up with nothing changed recreates nothing"):
          # frisket names a network by the ID it checked, never by its name,
          # which the daemon would resolve again at every start. Compose
          # judges drift by its config hash and each network's ID, so the ID
          # where it sent a name moves nothing.
          netid = host_docker("network inspect shop_default --format '{{.Id}}'").strip()
          assert host_docker("inspect shop-db-1 --format '{{.HostConfig.NetworkMode}}'").strip() == netid
          before = host_docker("ps -q --no-trunc --filter name=shop-db-1").strip()
          out = session_ok("docker compose up -d", timeout=300)
          assert "Recreate" not in out and "Created" not in out, out
          assert host_docker("ps -q --no-trunc --filter name=shop-db-1").strip() == before, out
          assert host_docker("network inspect shop_default --format '{{.Id}}'").strip() == netid

      with subtest("the session reaches the database as localhost, ::1, its .internal name and its address"):
          # pg_isready inside the container can answer before the server
          # listens on TCP: the image's first start runs one on its socket alone.
          session_ok("for i in $(seq 120); do pg_isready -h 127.0.0.1 -p 64320 && exit 0; sleep 1; done; exit 1", timeout=300)
          for host in ["localhost", "::1", "shop.internal", "shop.example.internal", "${address}"]:
              out = session_ok(f"PGPASSWORD=data_lab psql -h {host} -p 64320 -U data_lab -d data_lab -tAc 'SELECT what FROM seen'")
              assert out.strip() == "through frisket", (host, out)
          relays = frisket_lines("relay")
          assert relays, "no relay line"
          assert all(m["decision"] == "relayed" and m["to"] == "${address}:64320" and m["project"] == "${project}" for m in relays), relays
          origs = {m["orig"] for m in relays}
          assert {"127.0.0.1:64320", "[::1]:64320", "${address}:64320"} <= origs, origs

      with subtest("another project's .internal name is not answered locally, but goes where the tier's allowlist sends it"):
          # frisket answers only the session's own names; any other .internal
          # name is an ordinary name, and trusted allows every name, so it is
          # looked up upstream. The VM has no upstream, so it answers nothing.
          session("getent ahosts billing.internal")
          dns = frisket_lines("dns")
          own = [m for m in dns if m.get("name") == "shop.internal"]
          assert own and all(m["decision"] == "local" and m.get("answers") == ["${address}"] for m in own if m["type"] == "A"), own
          other = [m for m in dns if m.get("name") == "billing.internal"]
          assert other, "no dns line for billing.internal"
          assert all(m["decision"] in ("resolved", "failed") and "127.10.146.214" not in m.get("answers", []) for m in other), other

      with subtest("on the host, the database is at the project's address and not at 127.0.0.1"):
          ps = host_docker("ps --filter label=frisket.project=${project} --format '{{.Names}} {{.Ports}}'")
          assert "shop-db-1 ${address}:64320->5432/tcp" in ps, ps
          machine.succeed("pg_isready -h ${address} -p 64320")
          machine.fail("pg_isready -t 3 -h 127.0.0.1 -p 64320")
          # One listener on the port, at the project's address: pasta's
          # `auto` has nothing of the session's to republish on it.
          held = machine.succeed("ss -Htln 'sport = :64320'").strip().splitlines()
          assert len(held) == 1 and "${address}:64320" in held[0], held

      with subtest("Compose's logs, and a recreate after the file changes, keep the database"):
          out = session_ok("docker compose logs db")
          assert "database system is ready to accept connections" in out, out
          before = host_docker("ps -q --filter name=shop-db-1").strip()
          session_ok("sed -i 's/POSTGRES_DB=data_lab/POSTGRES_DB=data_lab\\n      - CHASE_TEST=recreated/' compose.yaml && docker compose up -d", timeout=300)
          after = host_docker("ps -q --filter name=shop-db-1").strip()
          assert after and after != before, (before, after)
          assert "CHASE_TEST=recreated" in host_docker("inspect shop-db-1 --format '{{json .Config.Env}}'")
          session_ok("for i in $(seq 120); do PGPASSWORD=data_lab psql -h localhost -p 64320 -U data_lab -d data_lab -tAc 'SELECT what FROM seen' "
                     "| grep -qx 'through frisket' && exit 0; sleep 1; done; exit 1", timeout=300)

      with subtest("an attached up, stopped with Ctrl-C, stops the database"):
          session_ok("docker compose stop")
          session_ok("""
            docker compose up > cmd/attached.log 2>&1 &
            pid=$!
            for i in $(seq 120); do grep -q 'ready to accept connections' cmd/attached.log && break; sleep 1; done
            grep -q 'ready to accept connections' cmd/attached.log || exit 1
            kill -INT $pid
            wait $pid
            docker compose ps --all --format '{{.State}}'
          """, timeout=300)
          assert host_docker("inspect shop-db-1 --format '{{.State.Status}}'").strip() == "exited"

      flows = requests()

      with subtest("frisket admitted every request of the flows as an operation, or gave the daemon's own 404"):
          assert flows, "no request lines"
          wrong = [m for m in flows if not flow_line(m)]
          assert wrong == [], wrong
          ops = {m["operation"] for m in flows}
          print(f"frisket's lines for the flows: {len(flows)}, as {sorted(ops)}")
          for op in ["ContainerCreate", "ContainerStart", "ContainerExec", "ExecStart", "VolumeCreate", "NetworkCreate",
                     "ContainerLogs", "ContainerStop"]:
              assert op in ops, (op, sorted(ops))

      # What would reach the host, each tried from the session: refused
      # before the daemon, with the operation it was judged as and why. A
      # body is tried as Compose sends it, since Compose is the client this
      # is for, each as a service of its own in a project of its own that
      # is taken down after: the docker CLI's own create sends a
      # MemorySwappiness of -1, which is refused before anything a row adds.
      def service(extra):
          return (f"cat > cmd/refused.yaml <<'EOF'\nservices:\n  x:\n    image: 'postgres:18'\n{extra}\nEOF\n"
                  "docker compose -p refused -f cmd/refused.yaml up -d; rc=$?\n"
                  "docker compose -p refused -f cmd/refused.yaml down -v\nexit $rc")
      refusals = [
          ("a bind mount of a host path", service("    volumes:\n      - /etc:/host"), {"ContainerCreate"}, "Binds"),
          ("privileged", service("    privileged: true"), {"ContainerCreate"}, "Privileged"),
          ("the host's network", service("    network_mode: host"), {"ContainerCreate"}, "NetworkMode"),
          ("an explicit HostIp", service("    ports:\n      - '10.0.2.15:64320:5432'"), {"ContainerCreate"}, "hostip not allowed"),
          ("another project's address", service("    ports:\n      - '127.10.146.214:64320:5432'"), {"ContainerCreate"}, "hostip not allowed"),
          ("a port the project does not declare", service("    ports:\n      - '64399:5432'"), {"ContainerCreate"}, "host port this project does not list"),
          ("a label only frisket may set", service("    labels:\n      frisket.project: ${project}"), {"ContainerCreate"}, "only frisket may set"),
          ("an image the project does not declare", service("    image: 'busybox:1.37'").replace("    image: 'postgres:18'\n", ""),
           {"ImageInspect"}, "image not listed"),
          ("a pull of an image the project does not declare", "docker pull busybox:1.37", {"ImageCreate"}, "image not listed"),
          ("inspecting a container of nobody's", "docker container inspect stray", {"ContainerInspect"}, "not this project's"),
          ("deleting a container of nobody's", "docker rm -f stray", {"ContainerDelete"}, "not this project's"),
      ]
      for what, cmd, ops, why in refusals:
          with subtest(f"refused: {what}"):
              before = len(requests())
              rc, out = session(cmd)
              assert rc != 0, (what, out)
              assert "frisket: refused" in out, (what, out)
              new = requests()[before:]
              refused = [m for m in new if not flow_line(m)]
              assert refused, (what, new)
              assert all(m["decision"] == "refused" and m["status"] == 403 and m.get("operation") in ops for m in refused), (what, refused)
              assert any(why in m.get("reason", "") + " " + m.get("docker", "") for m in refused), (what, refused)

      with subtest("a container whose network is deleted before it starts never joins another of that name"):
          # The project makes a network and a container on it, not started,
          # then deletes the network, which has no endpoint yet; someone
          # else -- another project, or here the host -- makes one of the
          # same name. The create named the network by its ID, so the start
          # finds no such network rather than joining theirs.
          session_ok("printf 'services:\n  x:\n    image: postgres:18\n' > cmd/attack.yaml && docker compose -p attack -f cmd/attack.yaml create", timeout=300)
          ours = host_docker("network inspect attack_default --format '{{.Id}}'").strip()
          assert host_docker("inspect attack-x-1 --format '{{.HostConfig.NetworkMode}}'").strip() == ours
          session_ok("docker network rm attack_default")
          theirs = host_docker("network create attack_default").strip()
          assert theirs != ours
          rc, out = session("docker start attack-x-1")
          assert rc != 0 and ours in out, out
          assert host_docker("network inspect attack_default --format '{{len .Containers}}'").strip() == "0"
          assert host_docker("inspect attack-x-1 --format '{{.State.Status}}'").strip() == "created"
          session_ok("docker rm attack-x-1")
          host_docker("network rm attack_default")

      with subtest("nothing refused was made, and the container of nobody's is still there"):
          names = host_docker("ps -a --format '{{.Names}}'").split()
          assert sorted(names) == ["shop-db-1", "stray"], names
          assert host_docker("inspect stray --format '{{index .Config.Labels \"frisket.project\"}}'").strip() == ""

      with subtest("down -v takes the project's containers, network and volume, and nothing else"):
          before = len(requests())
          session_ok("docker compose down -v", timeout=300)
          new = requests()[before:]
          assert new and all(flow_line(m) for m in new), new
          assert host_docker("ps -a --format '{{.Names}}'").split() == ["stray"]
          assert "shop" not in host_docker("volume ls --format '{{.Name}}'")
          assert "shop" not in host_docker("network ls --format '{{.Name}}'")

      with subtest("every database connection was relayed to the project's address, and no request went unmatched"):
          relays = frisket_lines("relay")
          assert relays and all(m["decision"] == "relayed" and m["to"] == "${address}:64320" for m in relays), relays
          assert all(m.get("operation") for m in requests()), [m for m in requests() if not m.get("operation")]
          assert not [m for m in requests() if "unmatched" in json.dumps(m)], requests()

      with subtest("the session ends"):
          machine.succeed("touch ${ws}/release")
          machine.wait_until_succeeds(f"test ! -e /run/user/1000/flong/sessions/{name}", timeout=timedelta(minutes=1))
    '';
}
