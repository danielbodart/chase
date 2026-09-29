# What a project's envelope may say (PLAN.md, decisions 10 and 17).
#
# Evaluated on its own with lib.evalModules -- not as part of any NixOS
# system -- against the project's `chaseModules.default`, so an option that is
# not here is refused rather than quietly applied somewhere else. What it
# evaluates to is the document a person approves: small, and every field in it
# means one thing.
#
#   chaseModules.default = {
#     chase.secrets = "secrets.yaml";
#     chase.bindings.cloudflare = {
#       credential.secret = "cloudflare-token";
#       accountId = "023e105f4ecef8ad9ca31a8372d0c353";
#     };
#     chase.seccomp.allow = [ "io_uring_setup" "io_uring_enter" "io_uring_register" ];
#   };
{ lib, ... }:

let
  inherit (lib) mkOption types;
  secretKey = types.nullOr (types.strMatching "[A-Za-z0-9_.-]+");
  apiName = types.strMatching "[A-Za-z0-9_-]+";

  # A syscall's name or a systemd group's, as flong takes them. flong refuses
  # a name systemd does not list, at launch.
  syscallName = types.strMatching "@?[a-z0-9_-]+";

  # What a project names in an app's lists: an operation id from the API's
  # own description, a whole category of them as "category:<name>", or --
  # for an endpoint the description does not name -- methods and an exact
  # path template.
  named = types.either (types.strMatching "category:.+|[A-Za-z0-9_./:-]+") (types.submodule {
    options = {
      methods = mkOption { type = types.nonEmptyListOf (types.enum [ "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" ]); };
      path = mkOption { type = types.strMatching "/[^[:space:]]*"; };
    };
  });

  # An image as `docker pull` would be given it, in the one form that names
  # it: the familiar name, a tag or a digest always, and a registry only by
  # a dotted domain. frisket admits a pull or a run only of a name in this
  # list, compared as a string, so a second spelling of the same image
  # would be a second thing to approve: docker.io/, index.docker.io/ and
  # library/ are the familiar name spelled out, and are refused.
  #
  # The daemon runs in the host's network and treats a loopback registry as
  # insecure, so a registry judged by its spelling would let a listed image
  # pull from the host's own loopback: by a name that resolves there
  # (registry.localhost, localhost.localdomain, anything.nip.io, a project's
  # .internal name in /etc/hosts), or by an address as inet_aton reads it
  # (127.1, 0x7f.1). So a registry is one of frisket's fixed public ones
  # (docker/image.go), whose names no project controls, and nothing
  # else; frisket refuses any other when a session opens. `localhost` with
  # no dot, which the pattern reads as a Docker Hub user, the daemon reads
  # as a registry, and it is refused too.
  #
  # The daemon takes sha256:<hex>, and a bare 64-hex string, for an image's
  # ID, and sha256:<prefix> for any image whose ID begins so, and would run
  # whatever local image has it, made or loaded by anyone. So no part of an
  # image's name may be sha256 or 64 hex, as frisket's ValidImage has it.
  image =
    let
      pattern = "([a-z0-9-]+(\\.[a-z0-9-]+)+/)?[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[0-9a-f]{64})";
      registries = [ "ghcr.io" "quay.io" "gcr.io" "mcr.microsoft.com" "public.ecr.aws" "registry.k8s.io" ];
      # One DNS label under a suffix no project controls: gcr.io's regions
      # (eu.gcr.io) and Artifact Registry's (europe-west2-docker.pkg.dev).
      label = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";
      underSuffix = r:
        builtins.match "${label}\\.gcr\\.io" r != null
        || builtins.match "${label}-docker\\.pkg\\.dev" r != null;
      first = s: builtins.head (lib.splitString "/" s);
      registry = s:
        let f = first s; in
        if builtins.length (lib.splitString "/" s) > 1 && lib.hasInfix "." f then f else null;
      # Each /-separated part's name, before its :tag or @digest.
      names = s: map (c: builtins.head (lib.splitString ":" (builtins.head (lib.splitString "@" c)))) (lib.splitString "/" s);
      isID = n: n == "sha256" || builtins.match "[0-9a-f]{64}" n != null;
      problem = s:
        if builtins.match pattern s == null then "is not a familiar name with a :tag or @sha256:<64 hex>"
        else if lib.any isID (names s) then "names an image by its ID, which runs whatever local image has it; name it by its repository"
        else if lib.elem (first s) [ "docker.io" "index.docker.io" "registry-1.docker.io" "library" ] then "spells out Docker Hub; name it as `docker pull` shortens it"
        else if first s == "localhost" && lib.hasInfix "/" s then "is from a registry on the host's own loopback"
        else if registry s != null && !(lib.elem (registry s) registries || underSuffix (registry s))
        then "is from registry ${registry s}, which is not Docker Hub or one of ${lib.concatStringsSep ", " registries}, *.gcr.io or *-docker.pkg.dev"
        else null;
    in
    {
      type = types.addCheck types.str (s: problem s == null) // {
        description = "image in its familiar form, with a tag or digest, from Docker Hub or a known public registry";
      };
      # Checked again after the merge, and as an `apply` so that a project
      # module cannot declare one of its own: the module system refuses a
      # second `apply`, where it would let one replace the checked list.
      apply = images:
        map (s: if problem s == null then s else throw "chase.bindings.docker.images: ${s} ${problem s}") images;
    };

  # A port the session's own loopback steers to frisket, which relays it to
  # the project's address, where the project's containers publish it. It is
  # steered, not listened on, so pasta's `-t auto` has nothing of it to
  # republish. frisket refuses the whole document if the list breaks any
  # of this, so it is refused here first, when the envelope is evaluated.
  dockerPorts = ports:
    let
      steering = 15001;
      duplicates = lib.unique (lib.filter (p: lib.count (q: q == p) ports > 1) ports);
      # The type says this too, but a project module may declare the option
      # again with a wider type, which the module system merges with this
      # one; it may not bring a second `apply`, so the range is kept here.
      outside = lib.filter (p: ! builtins.isInt p || p < 1024 || p > 65535) ports;
    in
    if outside != [ ] then throw "chase.bindings.docker.ports: not a port from 1024 to 65535: ${lib.concatMapStringsSep " " builtins.toJSON outside}"
    else if builtins.length ports > 64 then throw "chase.bindings.docker.ports: at most 64 ports, not ${toString (builtins.length ports)}"
    else if lib.elem steering ports then throw "chase.bindings.docker.ports: ${toString steering} is frisket's own steering listener"
    else if duplicates != [ ] then throw "chase.bindings.docker.ports: named twice: ${toString duplicates}"
    else ports;

  # An app's lists (PLAN.md, decision 18). What a project names decides
  # before what its tier says: a name before a category, and either before
  # the tier's `writes`, `guarded` and `unmatched`. Part of what is approved,
  # like everything here, and ignored in an app that is anonymous.
  lists = app: {
    allow = mkOption {
      type = types.listOf named;
      default = [ ];
      example = [ "category:pulls" ];
      description = ''
        What ${app} lets through without a dialog: writes this project makes
        often enough that asking every time would only train a person to
        click through. A rule equally specific to one that asks still asks.
      '';
    };
    ask = mkOption {
      type = types.listOf named;
      default = [ ];
      description = "What ${app} puts to a person, whatever its tier would do.";
    };
    refuse = mkOption {
      type = types.listOf named;
      default = [ ];
      description = "What ${app} refuses, whatever its tier would do.";
    };
  };
in
{
  options.chase = {
    secrets = mkOption {
      type = types.nullOr (types.strMatching "[^/].*");
      default = null;
      example = "secrets.yaml";
      description = ''
        The project's sops file, relative to the checkout: one file, many
        secrets, each under its own key, encrypted to admin keys. A string and
        not a path, so what is approved is where the file is and not whatever
        it happens to hold -- the ciphertext is the project's to rotate.
      '';
    };

    # Applied before the session starts, since a filter is installed before
    # anything in it runs: evaluated and approved with the rest, in flong's
    # seccompPolicy, and handed to flong as allow and deny lines.
    seccomp = {
      allow = mkOption {
        type = types.listOf syscallName;
        default = [ ];
        example = [ "io_uring_setup" "io_uring_enter" "io_uring_register" ];
        description = ''
          Syscalls, or systemd `@groups`, this project's sessions need beyond
          the tier's filter. Each one is kernel surface the session gains, and
          part of what is approved. The fixed filters stay whatever this says:
          no terminal injection, no audit socket, no namespaces of its own.
        '';
      };
      deny = mkOption {
        type = types.listOf syscallName;
        default = [ ];
        example = [ "ptrace" ];
        description = ''
          Syscalls, or `@groups`, taken away from the tier's filter, after
          `allow`, which this overrides.
        '';
      };
    };

    bindings.huggingface = lists "Hugging Face";
    bindings.github = lists "GitHub's API";
    # Its push is the operation `git-receive-pack`.
    bindings.git = lists "git";

    bindings.cloudflare = lists "Cloudflare" // {
      credential.secret = mkOption {
        type = secretKey;
        default = null;
        example = "cloudflare-token";
        description = ''
          The key in `secrets` holding the project's Cloudflare API token.
          Decrypted at launch outside the session, and added on the wire by
          frisket; the session holds the placeholder.
        '';
      };
      accountId = mkOption {
        type = types.nullOr (types.strMatching "[0-9a-f]{32}");
        default = null;
        example = "023e105f4ecef8ad9ca31a8372d0c353";
        description = ''
          The Cloudflare account, set as CLOUDFLARE_ACCOUNT_ID in the session.
          Not a secret -- it names the account, it does not open it -- so it
          is written here, where it is approved, rather than in `secrets`.
        '';
      };
    };

    # Docker, through frisket, on the host's rootless daemon. No lists: what
    # a session may ask the daemon is fixed, and what the project names is
    # which images, and which ports its containers publish.
    bindings.docker = {
      images = mkOption {
        type = types.listOf image.type;
        default = [ ];
        apply = image.apply;
        example = [ "postgres:18" "ghcr.io/owner/tool@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ];
        description = ''
          The images this project's sessions may pull and run, each exactly
          as it will be written: `postgres:18`, not `docker.io/library/postgres:18`,
          and never without a tag or digest.
        '';
      };
      ports = mkOption {
        type = types.listOf (types.ints.between 1024 65535);
        default = [ ];
        apply = dockerPorts;
        example = [ 5432 ];
        description = ''
          The host ports this project's containers publish, at most 64, each
          once. They are published on the project's own loopback address,
          and a session reaches them on its 127.0.0.1 through frisket.
        '';
      };
    };

    bindings.gcloud = lists "Google Cloud" // {
      credential.secret = mkOption {
        type = secretKey;
        default = null;
        example = "gcloud-key";
        description = ''
          The key in `secrets` holding the project's service-account key, the
          JSON Google issues, as one string. Decrypted at launch outside the
          session, where only the renewer reads it; the session holds a key of
          the same shape that Google has never seen.
        '';
      };
      serviceAccount = mkOption {
        type = types.nullOr (types.strMatching "[^@[:space:]]+@[^@[:space:]]+");
        default = null;
        example = "agent@my-project.iam.gserviceaccount.com";
        description = ''
          The service account the key must be for. A key naming another is
          refused at launch.
        '';
      };
      apis = {
        add = mkOption {
          type = types.listOf apiName;
          default = [ ];
          example = [ "secretmanager" ];
          description = "Google APIs, by Discovery name, carried beside the tier's.";
        };
        remove = mkOption {
          type = types.listOf apiName;
          default = [ ];
          example = [ "pubsub" ];
          description = "The tier's Google APIs this project's sessions do without.";
        };
      };
    };
  };
}
