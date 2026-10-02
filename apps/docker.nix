{ config, options, lib, pkgs, ... }:

# Docker through frisket (docs/docker.md): a project's containers, on the
# rootless daemon of the tier's user, reached by the session only through a
# route frisket judges request by request, and published only on the
# project's own loopback address. What the project is was approved with its
# grant, from its checkout's origin; the route is made at launch, from
# that and the images and ports its grant names.

let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.chase;
  apps = import ../lib/apps.nix { inherit lib; };
  machine = options.chase.apps.docker;
  read = f: builtins.fromJSON (builtins.readFile f);

  # Generated from the pinned Engine API spec by chase-generate operations
  # (../internal/generate): every operation, the admitted ones with their
  # docker block and the rest refused. admit.json and fields.json are
  # hand-written and reviewed.
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
in
{
  options.chase.apps.docker.package = mkOption {
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
      options.apps.docker = apps.overrides machine [ "package" ] // {
        enable = mkEnableOption ''
          Docker in this tier, for a project whose grant names it: its
          containers run on `chase.user`'s rootless daemon, reached through
          frisket, which admits only what is the project's own, and publish
          their ports on the project's own loopback address. Only for a tier
          that takes grants, with direct egress, since a container reaches
          whatever the host does. chase runs no daemon: the machine runs
          rootless Docker for `chase.user`, its socket at
          /run/user/<uid>/docker.sock, as NixOS's
          `virtualisation.docker.rootless` does'';
      };
    });
  };

  config = {
    assertions = lib.concatLists (lib.mapAttrsToList (name: tier: [
      {
        assertion = !tier.apps.docker.enable || tier.egress == "direct";
        message = "chase.tiers.${name}.apps.docker is enabled, but the tier's egress is not direct: a container on the host's daemon reaches whatever the host does.";
      }
      {
        assertion = !tier.apps.docker.enable || tier.grants;
        message = "chase.tiers.${name}.apps.docker is enabled, but the tier takes no grant: Docker is only ever a project's.";
      }
    ]) cfg.tiers);

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "chase-${name}" (mkIf tier.apps.docker.enable {
      config.environment = {
        systemPackages = [ tier.apps.docker.package ];
        # The session's CA, which frisket mounts in its namespace, is what
        # docker.frisket.internal's certificate is signed by. No cert.pem or
        # key.pem: the CLI goes without them, and frisket asks for none.
        etc."chase/docker/ca.pem".source = "/etc/frisket/ca.crt";
      };
    })) cfg.tiers;

    # Made at launch, for the project approved and its images and ports
    # (internal/apps/docker), from each tier's route as it is here.
    chase.internal.projectApps = lib.mkIf (enabled != { }) { docker.credential = false; };
    chase.internal.config = lib.mkIf (enabled != { }) { grant.docker.routes = lib.mapAttrs (_: _: route) enabled; };
  };
}
