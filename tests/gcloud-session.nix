# A Google Cloud session end to end: chase's launch, flong's session and
# frisket's routes on one machine, and a fake Google on another. The
# project's service-account key is made while the test runs, sops-encrypted
# to an age key alice holds, and decrypted by the launch as it would be on a
# desk; the fake token endpoint checks every grant against that key's public
# half, and every API call against the tokens it issued.
{ self, home-manager }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  google4 = "203.0.113.20";
  grpc4 = "203.0.113.22";
  google6 = "2001:db8:113::20";
  grpc6 = "2001:db8:113::22";
  sa = "agent@chase-test.iam.gserviceaccount.com";

  certs = pkgs.runCommand "chase-test-google-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -keyout ca.key -out ca.crt -subj /CN=chase-test-google-ca \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout server.key -out server.csr -subj /CN=googleapis.com
    printf '%s\n' 'subjectAltName=DNS:googleapis.com,DNS:*.googleapis.com,DNS:*.mtls.googleapis.com' 'extendedKeyUsage=serverAuth' > ext
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 3650 -extfile ext -out server.crt
  '';

  fakeGoogle = pkgs.writeText "fakegoogle.py" ''
    import base64, hashlib, json, os, re, subprocess, sys, tempfile, threading, time, urllib.parse
    from concurrent import futures
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import grpc, socket, ssl

    REST, REST6, GRPC, GRPC6, CERT, KEY, PUB, EMAIL = sys.argv[1:9]
    issued = set()
    objects = {("chase-test", "hello.txt"): b"hello from fake storage\n"}

    def say(**kw):
        print(json.dumps(kw), flush=True)

    def b64d(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    def b64(b):
        return base64.b64encode(b).decode()

    def verify(form):
        if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"]:
            return "grant_type"
        if not os.path.exists(PUB):
            return "no key yet"
        h, c, s = form["assertion"][0].split(".")
        if json.loads(b64d(h)).get("alg") != "RS256":
            return "header"
        with tempfile.NamedTemporaryFile() as sig:
            sig.write(b64d(s))
            sig.flush()
            r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", PUB, "-signature", sig.name],
                               input=f"{h}.{c}".encode(), capture_output=True)
        if r.returncode != 0:
            return "signature"
        claims = json.loads(b64d(c))
        now = time.time()
        if claims.get("iss") != EMAIL:
            return "iss"
        if claims.get("aud") != "https://oauth2.googleapis.com/token":
            return "aud"
        if claims.get("scope") != "https://www.googleapis.com/auth/cloud-platform":
            return "scope"
        if not (now - 60 <= claims["iat"] <= now + 5) or not (0 < claims["exp"] - claims["iat"] <= 3600):
            return "times"
        return None

    def authorized(header):
        return header.startswith("Bearer ") and header[7:] in issued

    def crc32c(data):
        crc = 0xFFFFFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
        return crc ^ 0xFFFFFFFF

    def meta(host, bucket, name, data):
        path = f"/b/{bucket}/o/{urllib.parse.quote(name, safe="")}"
        return {
            "selfLink": f"https://{host}/storage/v1{path}",
            "mediaLink": f"https://{host}/download/storage/v1{path}?generation=1&alt=media",
            "kind": "storage#object", "id": f"{bucket}/{name}/1", "bucket": bucket, "name": name,
            "generation": "1", "metageneration": "1", "contentType": "text/plain",
            "size": str(len(data)), "storageClass": "STANDARD",
            "md5Hash": b64(hashlib.md5(data).digest()), "crc32c": b64(crc32c(data).to_bytes(4, "big")),
            "timeCreated": "2026-01-01T00:00:00.000Z", "updated": "2026-01-01T00:00:00.000Z",
        }

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def reply(self, code, body, ctype="application/json"):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def any(self):
            host = self.headers.get("Host", "")
            u = urllib.parse.urlsplit(self.path)
            q = urllib.parse.parse_qs(u.query)
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if host.startswith("oauth2.googleapis.com") and u.path == "/token":
                wrong = verify(urllib.parse.parse_qs(body.decode()))
                if wrong:
                    say(token="refused", why=wrong)
                    return self.reply(400, {"error": "invalid_grant", "error_description": wrong})
                token = "ya29.real-" + os.urandom(16).hex()
                issued.add(token)
                say(issued=token)
                return self.reply(200, {"access_token": token, "expires_in": 3599, "token_type": "Bearer"})
            auth = self.headers.get("Authorization", "")
            ok = authorized(auth)
            say(api=self.command, host=host, path=self.path, authorized=ok, auth=auth, body=body.decode(errors="replace"))
            if not ok:
                return self.reply(401, {"error": {"code": 401, "message": "unauthenticated", "status": "UNAUTHENTICATED"}})
            m = re.match(r"^(?:/download)?/storage/v1/b/([^/]+)/o/([^/]+)$", u.path)
            if m and self.command in ("GET", "HEAD"):
                key = (m[1], urllib.parse.unquote(m[2]))
                if key not in objects:
                    return self.reply(404, {"error": {"code": 404, "message": "No such object", "status": "NOT_FOUND"}})
                if q.get("alt") == ["media"]:
                    return self.reply(200, objects[key], "text/plain")
                return self.reply(200, meta(host, *key, objects[key]))
            m = re.match(r"^/storage/v1/b/([^/]+)/storageLayout$", u.path)
            if m and self.command == "GET":
                return self.reply(200, {"kind": "storage#storageLayout", "bucket": m[1], "location": "US",
                                        "locationType": "multi-region", "hierarchicalNamespace": {"enabled": False}})
            m = re.match(r"^/upload/storage/v1/b/([^/]+)/o$", u.path)
            if m and self.command == "POST":
                key = (m[1], q["name"][0])
                objects[key] = body
                say(stored=key[1])
                return self.reply(200, meta(host, *key, body))
            return self.reply(404, {"error": {"code": 404, "message": "not here", "status": "NOT_FOUND"}})

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = any

    class G(grpc.GenericRpcHandler):
        def service(self, details):
            method = details.method
            def call(request, context):
                auth = dict(context.invocation_metadata()).get("authorization", "")
                ok = authorized(auth)
                say(grpc=method, authorized=ok, auth=auth, request=b64(request))
                if not ok:
                    context.abort(grpc.StatusCode.UNAUTHENTICATED, "unauthenticated")
                if method == "/google.pubsub.v1.Publisher/GetTopic":
                    return request
                if method == "/google.pubsub.v1.Publisher/Publish":
                    return b"\x0a\x03m-1"
                context.abort(grpc.StatusCode.UNIMPLEMENTED, method)
            return grpc.unary_unary_rpc_method_handler(call)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8), handlers=[G()])
    for a in [GRPC, f"[{GRPC6}]"]:
        server.add_secure_port(f"{a}:443", grpc.ssl_server_credentials([(open(KEY, "rb").read(), open(CERT, "rb").read())]))
    server.start()

    class V6(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    servers = [ThreadingHTTPServer((REST, 443), H), V6((REST6, 443), H)]
    for rest in servers:
        rest.socket = ctx.wrap_socket(rest.socket, server_side=True)
        threading.Thread(target=rest.serve_forever, daemon=True).start()
    threading.Event().wait()
  '';

  # A Pub/Sub call with no generated code: its messages are a field or two,
  # written by hand. The bearer is the placeholder, or a JWT the session's key
  # signs for the API, as Google's gRPC clients send by default.
  grpcClient = pkgs.writeText "grpc-client.py" ''
    import base64, json, os, subprocess, sys, tempfile, time
    import grpc

    mode, method = sys.argv[1], sys.argv[2]
    data = sys.argv[3] if len(sys.argv) > 3 else ""

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def field(n, b):
        return bytes([n << 3 | 2, len(b)]) + b

    if mode == "jwt":
        key = json.load(open(os.environ["GOOGLE_APPLICATION_CREDENTIALS"]))
        now = int(time.time())
        h = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": key["private_key_id"]}).encode())
        c = b64(json.dumps({"iss": key["client_email"], "sub": key["client_email"],
                            "aud": "https://pubsub.googleapis.com/", "iat": now, "exp": now + 3600}).encode())
        with tempfile.NamedTemporaryFile("w") as k:
            k.write(key["private_key"])
            k.flush()
            s = subprocess.run(["openssl", "dgst", "-sha256", "-sign", k.name], input=f"{h}.{c}".encode(),
                               capture_output=True, check=True).stdout
        bearer = f"{h}.{c}.{b64(s)}"
    else:
        bearer = "proxy-injected"

    topic = b"projects/chase-test/topics/t"
    req = field(1, topic) if method == "GetTopic" else field(1, topic) + field(2, field(1, data.encode()))
    channel = grpc.secure_channel("pubsub.googleapis.com:443", grpc.ssl_channel_credentials())
    try:
        resp = channel.unary_unary(f"/google.pubsub.v1.Publisher/{method}")(
            req, metadata=[("authorization", "Bearer " + bearer)], timeout=30)
        print("ok", base64.b64encode(resp).decode())
    except grpc.RpcError as e:
        print("error", e.code().name, e.details())
        sys.exit(1)
  '';

  # What the session does, each result a file in the workspace for the test
  # to read, and then it waits to be released.
  session = pkgs.writeText "session.sh" ''
    out=$PWD/out
    mkdir -p "$out"
    env > "$out/env"
    cp "$GOOGLE_APPLICATION_CREDENTIALS" "$out/key.json"
    stat -c %a "$GOOGLE_APPLICATION_CREDENTIALS" > "$out/key-mode"
    gcloud auth print-access-token > "$out/token" 2> "$out/token.err"
    gcloud storage cat gs://chase-test/hello.txt > "$out/cat" 2> "$out/cat.err"
    python3 ${grpcClient} placeholder GetTopic > "$out/grpc-placeholder" 2>&1
    python3 ${grpcClient} jwt GetTopic > "$out/grpc-jwt" 2>&1
    python3 ${grpcClient} placeholder Publish approve-me > "$out/publish-yes" 2>&1
    python3 ${grpcClient} placeholder Publish deny-me > "$out/publish-no" 2>&1
    upload() {
      curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer proxy-injected' \
        -H 'Content-Type: text/plain' --data-binary "$1" \
        "https://storage.googleapis.com/upload/storage/v1/b/chase-test/o?uploadType=media&name=$2"
    }
    upload approve-me yes.txt > "$out/write-yes" 2>&1
    upload deny-me no.txt > "$out/write-no" 2>&1
    curl -sS -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer proxy-injected' \
      https://storage.mtls.googleapis.com/storage/v1/b/chase-test/o/hello.txt > "$out/mtls" 2>&1
    curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer proxy-injected' \
      -H 'Content-Type: application/json' -d '{"scope": ["https://www.googleapis.com/auth/cloud-platform"], "x": "approve-me"}' \
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${sa}:generateAccessToken" > "$out/mint" 2>&1
    curl -sS -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer proxy-injected' \
      "https://secretmanager.googleapis.com/v1/projects/chase-test/secrets/s/versions/latest:access?x=approve-me" > "$out/secret" 2>&1
    touch "$out/done"
    while [ ! -e release ]; do sleep 0.2; done
  '';

  # The project as a developer would set it up: its key in sops, to her age
  # key, and a chase.jsonc binding it.
  mkProject = pkgs.writeShellScript "mk-project" ''
    set -euo pipefail
    export PATH=${lib.makeBinPath (with pkgs; [ coreutils git sops jq ])}
    recipient=$1
    mkdir -p ~/proj
    cd ~/proj
    git init -q -b main
    cat > chase.jsonc <<'EOF'
    {
      "secrets": "secrets.yaml",
      "apps": {
        "gcloud": {
          "credential": { "secret": "gcloud-key" },
          "serviceAccount": "${sa}",
          "apis": { "add": ["pubsub"] },
        },
      },
    }
    EOF
    tmp=$(mktemp)
    jq -Rs '{"gcloud-key": .}' > "$tmp"
    sops --encrypt --age "$recipient" --input-type json --output-type yaml "$tmp" > secrets.yaml
    rm -f "$tmp"
    printf 'out/\n' > .gitignore
    git add chase.jsonc secrets.yaml .gitignore
    git -c user.name=alice -c user.email=alice@example.com commit -qm project
  '';
in
{
  name = "chase-gcloud-session";

  nodes.google = { pkgs, ... }: {
    networking.interfaces.eth1.ipv4.addresses = [
      { address = google4; prefixLength = 24; }
      { address = grpc4; prefixLength = 24; }
    ];
    networking.interfaces.eth1.ipv6.addresses = [
      { address = google6; prefixLength = 64; }
      { address = grpc6; prefixLength = 64; }
    ];
    networking.firewall.enable = false;
    services.dnsmasq = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        listen-address = [ google4 ];
        bind-dynamic = true;
        no-resolv = true;
        address = [
          "/googleapis.com/${google4}"
          "/googleapis.com/${google6}"
          "/pubsub.googleapis.com/${grpc4}"
          "/pubsub.googleapis.com/${grpc6}"
        ];
      };
    };
    systemd.services.fakegoogle = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      path = [ pkgs.openssl ];
      serviceConfig = {
        ExecStart = "${pkgs.python3.withPackages (p: [ p.grpcio ])}/bin/python3 ${fakeGoogle} ${google4} ${google6} ${grpc4} ${grpc6} ${certs}/server.crt ${certs}/server.key /run/fakegoogle/sa.pub ${sa}";
        Restart = "on-failure";
        RestartSec = 1;
      };
    };
  };

  nodes.machine = { config, pkgs, ... }: {
    imports = [ self.nixosModules.default home-manager.nixosModules.home-manager ];

    virtualisation.memorySize = 4096;
    virtualisation.diskSize = 8192;
    virtualisation.cores = 2;

    networking.interfaces.eth1.ipv4.addresses = [{ address = "203.0.113.10"; prefixLength = 24; }];
    networking.interfaces.eth1.ipv6.addresses = [{ address = "2001:db8:113::10"; prefixLength = 64; }];
    networking.nameservers = [ google4 ];
    security.pki.certificateFiles = [ "${certs}/ca.crt" ];
    security.sudo.enable = false;
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
    environment.systemPackages = with pkgs; [ age sops git jq openssl curl util-linux ];

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
      bindings = {
        claude.package = pkgs.hello;
        codex.package = pkgs.hello;
      };
      tiers.trusted = {
        egress = "direct";
        allow = [ "*" ];
        grants = true;
        apps.gcloud = { enable = true; apis = [ "storage" ]; };
      };
    };

    containers.agent-trusted.config = { pkgs, ... }: {
      environment.systemPackages = [ (pkgs.python3.withPackages (p: [ p.grpcio ])) pkgs.openssl ];
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
    in
    ''
      import json
      import secrets
      import shlex
      from datetime import timedelta

      def as_user(script):
          inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; " + script
          return ("systemd-run -M alice@ --user --wait --pipe --quiet --collect "
                  f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

      def user_unit(verb, unit):
          return machine.execute(f"systemctl -M alice@ --user {verb} {unit}")[1].strip()

      def google_log():
          out = google.succeed("journalctl -u fakegoogle.service -o cat --no-pager")
          lines = []
          for l in out.splitlines():
              try:
                  lines.append(json.loads(l))
              except ValueError:
                  pass
          return lines

      def asked():
          out = machine.succeed("journalctl -t chase-test-asker -o cat --no-pager")
          return [json.loads(l) for l in out.splitlines() if l.startswith("{")]

      def found(root, patterns):
          args = " ".join(f"-e {shlex.quote(p)}" for p in patterns)
          return machine.succeed(f"grep -rsFl {args} {root} || true").split()

      start_all()
      google.wait_for_unit("fakegoogle.service")
      google.wait_for_unit("dnsmasq.service")
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      machine.wait_for_unit("user@1000.service")
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_until_succeeds("curl -sS -m 2 -o /dev/null https://storage.googleapis.com/")
      machine.wait_until_succeeds("curl -sSk -m 2 -g -o /dev/null 'https://[${google6}]/'")

      with subtest("a project binds a service-account key from its sops"):
          machine.succeed("runuser -l alice -c 'mkdir -p ~/.config/sops/age && age-keygen -o ~/.config/sops/age/keys.txt 2>/dev/null'")
          recipient = machine.succeed("runuser -l alice -c 'age-keygen -y ~/.config/sops/age/keys.txt'").strip()
          key_id = secrets.token_hex(20)
          machine.succeed(
              "umask 077; mkdir -p /root/real && cd /root/real"
              " && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem 2>/dev/null"
              " && openssl pkey -in key.pem -pubout -out pub.pem"
              f" && jq -Rs --arg id {key_id} '{{type: \"service_account\", project_id: \"chase-test\", private_key_id: $id,"
              " private_key: ., client_email: \"${sa}\", client_id: \"1234567890\","
              " token_uri: \"https://oauth2.googleapis.com/token\"}' key.pem > key.json")
          pub = machine.succeed("cat /root/real/pub.pem")
          google.succeed(f"mkdir -p /run/fakegoogle && printf '%s' {shlex.quote(pub)} > /run/fakegoogle/sa.pub")
          machine.succeed(f"runuser -l alice -c '${mkProject} {recipient}' < /root/real/key.json")
          real_lines = machine.succeed("sed -n '2,5p' /root/real/key.pem").split()
          assert len(real_lines) == 4 and all(len(l) == 64 for l in real_lines), real_lines
          machine.succeed("grep -q ENC /home/alice/proj/secrets.yaml")
          assert machine.succeed(f"grep -cF {real_lines[0]} /home/alice/proj/secrets.yaml || true").strip() == "0"

      with subtest("the launch approves, decrypts, mints and starts the renewer"):
          machine.succeed(as_user(f"cd /home/alice/proj && ${launcher} shell -c {shlex.quote('bash ${session}')}") + " >/tmp/session.out 2>&1 &")
          machine.wait_until_succeeds("test -e /home/alice/proj/out/done", timeout=timedelta(minutes=5))
          name = machine.succeed("cat /tmp/last-session").strip()
          leader = machine.succeed("cat /tmp/last-leader").strip()
          run = f"/run/user/1000/chase/{name}"
          print(machine.succeed("cat /tmp/session.out"))
          approvals = machine.succeed("journalctl -t chase-test-approver -o cat --no-pager")
          assert '"workspace": "/home/alice/proj"' in approvals and '\\"serviceAccount\\": \\"${sa}\\"' in approvals, approvals
          assert user_unit("is-active", f"chase-gcloud-renew@{name}.service") == "active"
          issued = [l["issued"] for l in google_log() if "issued" in l]
          assert len(issued) >= 1, google_log()
          token_file = json.loads(machine.succeed(f"cat {run}/gcloud-token.json"))
          assert token_file["access_token"] in issued, token_file
          machine.succeed(f"test \"$(stat -c %a {run}/secrets/gcloud)\" = 600")
          policy = json.loads(machine.succeed(f"cat {run}/policy.json"))
          routes = {r["name"]: r for r in policy["routes"]}
          ids = {p["operation"]["id"] for p in routes["gcloud"]["paths"] if "operation" in p}
          assert {"storage.objects.get", "pubsub.projects.topics.get"} <= ids and "bigquery.datasets.get" not in ids, sorted(ids)[:40]
          assert routes["gcloud"]["sessionKey"]["issuer"] == "${sa}"
          assert "*.googleapis.com" in policy["allow"] or "*" in policy["allow"], policy["allow"]

      out = "/home/alice/proj/out"

      with subtest("the session holds a fake key for the service account, and its environment points at it"):
          env = dict(l.split("=", 1) for l in machine.succeed(f"cat {out}/env").splitlines() if "=" in l)
          # Seeded into the session's home by flong init, the user's alone;
          # the checkout's own copy is kept on the host, bound into no session.
          key_path = env["GOOGLE_APPLICATION_CREDENTIALS"]
          assert key_path.startswith("/home/alice/.config/chase/gcloud-key-") and key_path.endswith(".json"), key_path
          kept = machine.succeed(f"ls /home/alice/.local/state/chase/checkouts/*/{key_path.rsplit('/', 1)[1]}").strip()
          assert machine.succeed(f"cat {kept}") == machine.succeed(f"cat {out}/key.json"), kept
          assert machine.succeed(f"cat {out}/key-mode").strip() == "600", machine.succeed(f"cat {out}/key-mode")
          machine.fail(f"test -e {key_path}")
          assert env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"] == key_path, env
          assert env["CLOUDSDK_CONFIG"] == "/run/user/1000/gcloud", env
          assert env["CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK"] == "1", env
          for v in ["CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE", "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"]:
              assert env[v] == "/etc/frisket/ca-bundle.crt", (v, env)
          assert not [k for k in env if k in ("GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT")], env
          fake = json.loads(machine.succeed(f"cat {out}/key.json"))
          real = json.loads(machine.succeed("cat /root/real/key.json"))
          assert fake["type"] == "service_account" and fake["client_email"] == "${sa}" and fake["project_id"] == "chase-test", fake
          assert fake["private_key_id"] != real["private_key_id"] and fake["private_key"] != real["private_key"]
          assert "client_id" not in fake, fake
          fake_pub = machine.succeed(f"jq -r .private_key {out}/key.json | openssl pkey -pubout")
          assert fake_pub.strip() == routes["gcloud"]["sessionKey"]["publicKey"].strip()
          assert fake_pub.strip() != pub.strip()

      with subtest("gcloud reads as the service account, with a token it never sees"):
          assert machine.succeed(f"cat {out}/token").strip() == "proxy-injected", machine.succeed(f"cat {out}/token {out}/token.err")
          assert machine.succeed(f"cat {out}/cat") == "hello from fake storage\n", machine.succeed(f"cat {out}/cat.err")
          reads = [l for l in google_log() if l.get("api") and "/o/hello.txt" in l["path"]]
          assert reads and all(l["authorized"] and l["auth"][7:] in issued for l in reads), reads

      with subtest("gRPC, with the placeholder and with a JWT the fake key signed"):
          for f in ["grpc-placeholder", "grpc-jwt"]:
              assert machine.succeed(f"cat {out}/{f}").startswith("ok "), machine.succeed(f"cat {out}/{f}")
          calls = [l for l in google_log() if l.get("grpc") == "/google.pubsub.v1.Publisher/GetTopic"]
          assert len(calls) == 2 and all(l["authorized"] for l in calls), calls

      with subtest("a write asks, and goes only when approved"):
          assert machine.succeed(f"cat {out}/write-yes").strip() == "200", machine.succeed(f"cat {out}/write-yes")
          assert machine.succeed(f"cat {out}/write-no").strip() == "403", machine.succeed(f"cat {out}/write-no")
          assert machine.succeed(f"cat {out}/publish-yes").startswith("ok "), machine.succeed(f"cat {out}/publish-yes")
          assert machine.succeed(f"cat {out}/publish-no").startswith("error "), machine.succeed(f"cat {out}/publish-no")
          stored = [l["stored"] for l in google_log() if "stored" in l]
          assert stored == ["yes.txt"], stored
          published = [l for l in google_log() if l.get("grpc") == "/google.pubsub.v1.Publisher/Publish"]
          assert len(published) == 1 and published[0]["authorized"], published
          ops = [(q.get("operation") or {}).get("id") for q in asked()]
          assert ops.count("storage.objects.insert") == 2, asked()
          assert ops.count("google.pubsub.v1.Publisher.Publish") == 2, asked()
          assert set(ops) == {"storage.objects.insert", "google.pubsub.v1.Publisher.Publish"}, asked()

      with subtest("what returns a credential is guarded, refused unasked, from an API the session does not carry"):
          for f in ["mint", "secret"]:
              assert machine.succeed(f"cat {out}/{f}").strip() == "403", (f, machine.succeed(f"cat {out}/{f}"))
          assert not [l for l in google_log() if l.get("host", "").startswith(("iamcredentials.", "secretmanager."))], google_log()
          assert not [q for q in asked() if "iamcredentials" in json.dumps(q) or "secretmanager" in json.dumps(q)], asked()

      with subtest("an mTLS host is refused, and never reached"):
          assert machine.succeed(f"cat {out}/mtls").strip() == "403", machine.succeed(f"cat {out}/mtls")
          assert not [l for l in google_log() if "mtls" in l.get("host", "")], google_log()

      with subtest("the real key and tokens are nowhere in the session"):
          issued = [l["issued"] for l in google_log() if "issued" in l]
          patterns = real_lines + [key_id] + issued
          # The search finds them where they are: on the host, outside it.
          assert len(found(run, patterns)) >= 2, found(run, patterns)
          roots = machine.succeed(
              f"nsenter --target={leader} --mount -- sh -c "
              "'for d in /* /nix/*; do case $d in /proc|/sys|/dev|/nix|/nix/store) ;; *) echo $d ;; esac; done'").split()
          assert "/home" in roots and "/run" in roots and "/etc" in roots, roots
          args = " ".join(f"-e {shlex.quote(p)}" for p in patterns)
          hits = machine.succeed(
              f"nsenter --target={leader} --mount -- sh -c {shlex.quote(f'grep -rsFl {args} ' + ' '.join(roots) + ' || true')}").split()
          print(f"session files holding the real key or a real token: {len(hits)}")
          assert hits == [], hits
          environs = machine.succeed(
              f"ns=$(readlink /proc/{leader}/ns/pid); for p in /proc/[0-9]*; do [ \"$(readlink $p/ns/pid)\" = \"$ns\" ] && cat $p/environ; done 2>/dev/null"
              f" | tr '\\0' '\\n' | grep -cF {args} || true").strip()
          assert environs == "0", environs

      with subtest("the session's end stops the renewer and removes the secret"):
          machine.succeed("touch /home/alice/proj/release")
          machine.wait_until_succeeds(f"test ! -e /run/user/1000/flong/sessions/{name}", timeout=timedelta(minutes=1))
          machine.wait_until_succeeds(f"test ! -e {run}")
          assert user_unit("is-active", f"chase-gcloud-renew@{name}.service") != "active"
          machine.succeed(f"test ! -e /run/user/1000/chase/.grant/{name}.json")
          assert found("/run/user/1000", patterns) == [], found("/run/user/1000", patterns)
          machine.succeed(f"test -e {kept}")
    '';
}
