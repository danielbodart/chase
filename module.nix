# chase's entry point. Curried on `self` so it can import flong's and
# frisket's modules from its own inputs: a consumer imports chase and gets
# all three, rather than having to know that frisket's adapter goes in and
# frisket's own module does not.
self:
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption types;
  cfg = config.chase;
  lines = builtins.concatStringsSep "\n";
  chomp = lib.removeSuffix "\n";
  indent = s: lines (map (l: if l == "" then l else "  " + l) (lib.splitString "\n" s));

  # flong's `binds`: the other members of every group the workspace is in, one
  # PATH:rw per line (a bare PATH would be read-only). Not transitive.
  groupBinds = ''
    # Not GROUPS: bash reserves that name and silently ignores assignment.
    GROUP_TABLE=${lib.escapeShellArg (lines (
      map (g: builtins.concatStringsSep "\t" g) cfg.workspaceGroups
    ))}
    out=
    while IFS= read -r group; do
      [ -n "$group" ] || continue
      IFS=$'\t' read -ra members <<< "$group"
      mine=
      for m in "''${members[@]}"; do
        if [ "$m" = "$workspace" ]; then mine=1; fi
      done
      [ -n "$mine" ] || continue
      for m in "''${members[@]}"; do
        if [ "$m" != "$workspace" ] && [ -d "$m" ]; then
          out=$out$m:rw$'\n'
        fi
      done
    done <<< "$GROUP_TABLE"
    # Printed after the loop so the exit status is printf's (this runs under set -e).
    printf '%s' "$out" | sort -u
  '';

  # The checkout's root, so all of it is mounted wherever you start; otherwise
  # the directory itself, which agent-tier can only ever call strict.
  workspaceSnippet = ''
    ${lib.getExe pkgs.git} -C "$PWD" rev-parse --show-toplevel 2>/dev/null || pwd
  '';

  # flong's `command`: runs in the container as the user, in the workspace,
  # and execs the agent named by the first argument.
  mkCommand = tier: contributions: pkgs.writeShellApplication {
    name = "agent-command-${tier}";
    text = ''
      workspace=$PWD

      ${lines (map chomp contributions.setupLines)}

      if [ $# -eq 0 ]; then
        echo "agent-container: no agent named" >&2
        exit 1
      fi
      agent=$1
      shift

      # Group mounts are passed to the agent as --add-dir. Only :rw ones:
      # codex's --add-dir means writable. Not ~/.claude, which is storage.
      add_dirs=()
      while IFS= read -r bind; do
        case $bind in
          ${cfg.home}/.claude/*) ;;
          *:rw) add_dirs+=("''${bind%:rw}") ;;
        esac
      done <<< "''${FLONG_BINDS:-}"

      # A closed list, so this cannot exec anything else on the container's PATH.
      case $agent in
      ${indent (lines (map chomp (lib.attrValues contributions.launchers)))}
        *)
          echo "agent-container: unknown agent '$agent'" >&2
          exit 1
          ;;
      esac

      exec "$@"
    '';
  };

  tierType = types.submodule {
    options = {
      egress = mkOption {
        type = types.enum [ "direct" "frisket" ];
        description = ''
          `direct`: the container's own network (pasta), with frisket answering
          DNS. `frisket`: no network but frisket.
        '';
      };
      allow = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Names frisket lets this tier resolve.";
      };
      apps = mkOption {
        type = types.submodule { };
        default = { };
        description = "Applications enabled in this tier; each app module declares its own.";
      };
    };
  };
in
{
  imports = [
    self.inputs.flong.nixosModules.default
    # Imports frisket's daemon module too.
    self.inputs.frisket.nixosModules.flong
    ./selector.nix
    # The two tiers chase is opinionated about. A consumer sets their values
    # and an envelope overlays `trusted`; nothing overlays `strict`.
    ./tiers/trusted.nix
    ./tiers/strict.nix
    ./apps/github.nix
    ./apps/claude.nix
    ./apps/codex.nix
    ./apps/dragoman.nix
    ./apps/audio.nix
    ./apps/mise.nix
  ];

  options.chase = {
    user = mkOption { type = types.str; };
    uid = mkOption { type = types.int; };
    gid = mkOption { type = types.int; };
    home = mkOption {
      type = types.str;
      default = "/home/${cfg.user}";
    };
    # What a container holds in place of every credential; frisket replaces
    # exactly this value. Claude Code keeps a variable set to it when it
    # scrubs credentials from subprocesses.
    placeholder = mkOption {
      type = types.str;
      default = "proxy-injected";
    };
    # The nixpkgs release the container guests are built against. Not the
    # host's: a container's stateVersion is a fact about the guest closure.
    stateVersion = mkOption {
      type = types.str;
      default = "26.05";
      example = "25.11";
      description = ''
        `system.stateVersion` for every tier's container. Separate from the
        host's, which is a fact about the machine rather than about these
        throwaway guests.
      '';
    };
    strictRepos = mkOption { type = types.listOf types.str; default = [ ]; };
    trustedRepos = mkOption { type = types.attrsOf types.str; default = { }; };
    hostRepos = mkOption { type = types.attrsOf types.str; default = { }; };
    hostPaths = mkOption { type = types.listOf types.str; default = [ ]; };
    trustedOrgs = mkOption { type = types.listOf types.str; default = [ ]; };
    trustedAuthorDomains = mkOption { type = types.listOf types.str; default = [ ]; };
    workspaceGroups = mkOption { type = types.listOf (types.listOf types.str); default = [ ]; };
    tiers = mkOption { type = types.attrsOf tierType; default = { }; };
    # What apps add to each tier's command and binds. Separate from `tiers`,
    # which apps read, so contributing to it does not recurse.
    internal.tiers = mkOption {
      internal = true;
      default = { };
      type = types.attrsOf (types.submodule {
        options = {
          setupLines = mkOption { type = types.listOf types.lines; default = [ ]; };
          bindLines = mkOption { type = types.listOf types.lines; default = [ ]; };
          launchers = mkOption { type = types.attrsOf types.lines; default = { }; };
        };
      });
    };
  };

  config = {
    # The user whose credential files the routes read.
    services.frisket = {
      enable = true;
      user = cfg.user;
      policies = lib.mapAttrs (_: tier: { allow = tier.allow; }) cfg.tiers;
      flong = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" {
        policy = name;
        set = if tier.egress == "direct" then "service" else "all";
      }) cfg.tiers;
    };

    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" {
      autoStart = false;
      privateNetwork = true;
      config = { pkgs, ... }: {
        system.stateVersion = cfg.stateVersion;
        # The host's uid, so bind-mounted files have the right owner.
        users.users.${cfg.user} = {
          isNormalUser = true;
          uid = cfg.uid;
          group = "users";
          home = cfg.home;
        };
        users.groups.users.gid = cfg.gid;
        services.openssh.enable = false;
        environment.systemPackages = with pkgs; [ bun git coreutils gnugrep curl jq ];
      };
    }) cfg.tiers;

    flong = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" ({
      user = cfg.user;
      command = [ (lib.getExe (mkCommand name cfg.internal.tiers.${name})) ];
      workspace = workspaceSnippet;
      binds = groupBinds + lines cfg.internal.tiers.${name}.bindLines;
    } // lib.optionalAttrs (tier.egress == "direct") { network = { }; })) cfg.tiers;
  };
}
