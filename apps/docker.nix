{ config, lib, pkgs, ... }:

# Docker through frisket (docs/docker.md): a project's containers, on the
# rootless daemon of the tier's user, reached by the session only through a
# route frisket judges request by request, and published only on the
# project's own loopback address. What the project is was approved with its
# envelope, from its checkout's origin; the route is made at launch, from
# that and the binding's images and ports.

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.chase;
  bindings = cfg.bindings.docker;
  read = f: builtins.fromJSON (builtins.readFile f);

  # Generated from the pinned Engine API spec by ../scripts/operations.sh:
  # every operation, the admitted ones with their docker block and the rest
  # refused. admit.json and fields.json are hand-written and reviewed.
  operations = read ./docker/operations.json;
  admit = read ./docker/admit.json;
  fields = read ./docker/fields.json;
  source = read ./docker/source.json;

  # Each admitted rule already carries exactly admit.json's methods: the
  # generator writes them in place of the spec's (and refuses any the spec
  # does not give), and the docker check and docker-launch hold it to that.
  # The descriptions are for a person reading the generated file, and would
  # only swell every session's document.
  paths = map (rule: rule // { operation = removeAttrs rule.operation [ "description" ]; }) operations;

  # Only on direct egress: a container on the rootless daemon reaches
  # whatever the host does, which a tier with no network but frisket could
  # not otherwise.
  enabled = lib.filterAttrs (_: t: !t.bare && t.apps.docker.enable && t.egress == "direct") cfg.tiers;

  # Everything of a tier's route that the launch does not decide. No
  # operation-less rule, as `writes` and `unmatched` would add for another
  # app: frisket refuses one on a Docker route, and nothing here ever asks.
  route = {
    name = "docker";
    host = "docker.frisket.internal";
    upstream = "unix:///run/user/${toString cfg.uid}/docker.sock";
    unmatched = "refuse";
    # Docker's own error shape, which its CLI prints.
    refusal = { contentType = "application/json"; body = builtins.toJSON { message = "{{message}}"; }; };
    inherit paths;
    docker = {
      inherit (source) apiVersions;
      # The largest body Compose sends is a ContainerCreate, a few KiB.
      maxBody = 262144;
      bodies = lib.genAttrs (lib.unique (lib.concatMap (a: lib.optional (a.docker ? body) a.docker.body) (lib.attrValues admit)))
        (body: fields.${body});
    };
  };
  routeTemplates = pkgs.writeText "chase-docker-routes.json" (builtins.toJSON (lib.mapAttrs (_: _: route) enabled));

  prepare = pkgs.writeShellApplication {
    name = "chase-docker-prepare";
    runtimeInputs = [ pkgs.jq cfg.internal.dockerAddress ];
    # RUN and ENVDIR are not needed: Docker has no secret, and nothing of
    # the checkout's to keep.
    text = ''
      tier=$1 ws=$2
      binding=$(cat)
      die() { echo "chase: $ws: docker: $*" >&2; exit 1; }

      route=$(jq -c --arg t "$tier" '.[$t] // empty' ${routeTemplates})
      if [ -z "$route" ]; then
        echo "chase: $ws: docker ignored: $tier has no docker" >&2
        echo '{}'
        exit 0
      fi

      # The project approve derived from the checkout's origin, and was
      # approved as: never anything the envelope says, which would let a
      # project name another's containers as its own.
      [ -n "''${chase_project:-}" ] || die "no project was approved for it, so its containers could be nobody's"
      jq -e '(.images // []) != []' <<< "$binding" >/dev/null \
        || die "no images: say which the project's containers may run"
      who=$(chase-docker-address "$chase_project") || die "$chase_project has no address"

      # frisket compares an image as the string a client sends, and the CLI
      # sends what it was given: every spelling that names the same image
      # on Docker Hub. The envelope allows only the shortest, so each is
      # given all of its own here.
      jq -c <<< "$binding" --argjson route "$route" --argjson who "$who" '
        def spellings:
          if (contains("/") | not) then [., "library/" + ., "docker.io/" + ., "docker.io/library/" + .]
          elif (split("/")[0] | test("[.:]") or . == "localhost") then [.]
          else [., "docker.io/" + .] end;
        (reduce (.images[] | spellings[]) as $i ([]; if index([$i]) then . else . + [$i] end)) as $images
        | (.ports // []) as $ports
        | {
            routes: [$route | .docker += {project: $who.project, images: $images, ports: $ports, address: $who.address, names: $who.names}],
            allow: ["docker.frisket.internal"],
            env: {
              DOCKER_HOST: "tcp://docker.frisket.internal:2376",
              DOCKER_TLS_VERIFY: "1",
              DOCKER_CERT_PATH: "/etc/chase/docker",
              CHASE_DOCKER_PROJECT: $who.project,
              CHASE_DOCKER_ADDRESS: $who.address,
              CHASE_DOCKER_NAMES: ($who.names | join(" ")),
              CHASE_DOCKER_PORTS: ($ports | map(tostring) | join(" "))
            }
          }'
    '';
  };
in
{
  options.chase.bindings.docker.package = mkOption {
    type = types.package;
    default = pkgs.docker-client;
    defaultText = lib.literalExpression "pkgs.docker-client";
    description = ''
      The Docker CLI a session gets, Compose with it: nixpkgs' docker-client
      carries it as a plugin.
    '';
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.docker.enable = mkEnableOption ''
        Docker in this tier, for a project whose envelope binds it: its
        containers run on `chase.user`'s rootless daemon, reached through
        frisket, which admits only what is the project's own, and publish
        their ports on the project's own loopback address. Only for a tier
        that takes envelopes, with direct egress, since a container reaches
        whatever the host does. chase runs no daemon: the machine runs
        rootless Docker for `chase.user`, its socket at
        /run/user/<uid>/docker.sock, as NixOS's
        `virtualisation.docker.rootless` does'';
    });
  };

  config = {
    assertions = lib.concatLists (lib.mapAttrsToList (name: tier: [
      {
        assertion = !tier.apps.docker.enable || tier.egress == "direct";
        message = "chase.tiers.${name}.apps.docker is enabled, but the tier's egress is not direct: a container on the host's daemon reaches whatever the host does.";
      }
      {
        assertion = !tier.apps.docker.enable || tier.envelope;
        message = "chase.tiers.${name}.apps.docker is enabled, but the tier takes no envelope: Docker is only ever a project's.";
      }
    ]) cfg.tiers);

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" (mkIf tier.apps.docker.enable {
      config.environment = {
        systemPackages = [ bindings.package ];
        # The session's CA, which frisket mounts in its namespace, is what
        # docker.frisket.internal's certificate is signed by. No cert.pem or
        # key.pem: the CLI goes without them, and frisket asks for none.
        etc."chase/docker/ca.pem".source = "/etc/frisket/ca.crt";
      };
    })) cfg.tiers;

    chase.internal.projectApps.docker = {
      credential = false;
      prepare = lib.getExe prepare;
    };
  };
}
