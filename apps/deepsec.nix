{ config, options, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkMerge mkOption types;
  cfg = config.chase;
  apps = import ../lib/apps.nix { inherit lib; };
  machine = options.chase.apps.deepsec;
  base = cfg.apps.deepsec.package;

  # deepsec on the host, with the host's own logins: its Claude backend is
  # pointed at Claude Code itself, since the `claude` on the host's PATH is
  # the chase binary, which would start a session of its own in the
  # checkout's tier. A default, so a person's own CLAUDE_CODE_EXECUTABLE
  # wins. Its codex backend runs the codex it carries, never the PATH's.
  raw = pkgs.runCommand "deepsec-raw" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
    makeWrapper ${base}/bin/deepsec $out/bin/deepsec \
      --set-default CLAUDE_CODE_EXECUTABLE ${cfg.apps.claude.package}/bin/claude
  '';

  # `deepsec` on the host is the chase binary, which picks the checkout's
  # tier and runs deepsec there; `deepsec-raw` is deepsec itself.
  deepsecLinks = pkgs.runCommand "deepsec-links" { } ''
    mkdir -p $out/bin
    ln -s ${lib.getExe cfg.package} $out/bin/deepsec
    ln -s ${raw}/bin/deepsec $out/bin/deepsec-raw
  '';
in
{
  options.chase.apps.deepsec.package = mkOption {
    type = types.package;
    description = ''
      deepsec, Vercel's vulnerability scanner, with its `deepsec` program.
      Declared rather than pinned by chase, for the reason
      `chase.apps.claude.package` is, and with no default: what npm
      publishes reads the variables and paths a session has wrong, and the
      machine's package is the one that carries its fixes (see
      ../docs/apps/deepsec.md). Without one, there is no `deepsec` on the
      host, and a tier that enables it is refused.
    '';
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule {
      options.apps.deepsec = apps.overrides machine [ "package" ] // {
        enable = mkEnableOption ''
          deepsec in this tier, run as an agent of its own, its models
          reached through the tier's Claude Code or codex with the
          session's placeholder login, as `deepsec init --model-auth local`
          sets a checkout's up to use'';
      };
    });
  };

  config = mkMerge [
    {
      assertions = lib.concatLists (lib.mapAttrsToList (name: tier:
        let a = tier.apps.deepsec; in [
          {
            assertion = !a.enable || tier.apps.claude.enable || tier.apps.codex.enable;
            message = "chase.tiers.${name}.apps.deepsec is enabled, and neither claude nor codex is: deepsec reaches its models through one of them.";
          }
          {
            assertion = !(a.enable && tier.bare);
            message = "chase.tiers.${name}.apps.deepsec is enabled, and the tier is bare: a bare tier runs the host's deepsec, `deepsec-raw`, without it.";
          }
          {
            # The package has no default, and an undefined one throws only
            # where the container is built, naming the option and no more.
            assertion = !a.enable || (builtins.tryEval a.package).success;
            message = "chase.tiers.${name}.apps.deepsec is enabled, and there is no deepsec to run: set chase.apps.deepsec.package, the machine's, which carries the fixes a session needs.";
          }
        ]) cfg.tiers);

      # Its own agent in the launcher's closed list (internal/session), run
      # with nothing added but, where the tier has Claude Code, the backend
      # `deepsec init` is given when it is given none: the one choice deepsec
      # keeps in a checkout's own deepsec.config.ts, which every later run
      # reads, rather than a flag added to each run over what that file says.
      # Its logins are the session's own placeholders, which the tier's
      # Claude Code and codex are seeded with whatever the agent.
      chase.internal.config.session.tiers = lib.mapAttrs (_: tier: {
        deepsec = lib.optionalAttrs tier.apps.claude.enable { agent = "claude"; };
      }) (lib.filterAttrs (_: t: !t.bare && t.apps.deepsec.enable) cfg.tiers);

      containers = lib.mapAttrs' (name: tier: lib.nameValuePair "chase-${name}"
        (mkIf tier.apps.deepsec.enable {
          config.environment.systemPackages = [ tier.apps.deepsec.package ];
          # Inside a sandbox deepsec drops its agents' own sandboxes --
          # Claude Code's bubblewrap, codex's read-only one -- which cannot
          # nest in the container, the boundary anyway. Its Claude backend
          # runs the tier's Claude Code rather than one it carries.
          config.environment.variables = {
            DEEPSEC_INSIDE_SANDBOX = "1";
          } // lib.optionalAttrs tier.apps.claude.enable {
            CLAUDE_CODE_EXECUTABLE = "${tier.apps.claude.package}/bin/claude";
          };
        })) cfg.tiers;
    }
    (mkIf machine.package.isDefined {
      chase.internal.config.wrappers.deepsec.hostCommand = [ "${raw}/bin/deepsec" ];
      home-manager.users.${cfg.user}.home.packages = [ deepsecLinks ];
    })
  ];
}
