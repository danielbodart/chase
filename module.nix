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

  # "owner/name", as a remote URL carries it. Narrow because selector.nix
  # parses every entry as one, and a malformed slug would otherwise sit in the
  # configuration matching nothing until the day you wondered why.
  slug = types.strMatching "[^/[:space:]]+/[^/[:space:]]+";
  absPath = types.strMatching "/.*";

  # WHERE THE BUNDLE IS is frisket's to say; which variables point at it is
  # not. frisket puts the session's CA at /etc/frisket/ca-bundle.crt and stops
  # there, because the list below is a fact about the TOOLS a sandbox runs --
  # it drifts as they come and go, and chase is what chose to run them.
  #
  # Each of these REPLACES a runtime's roots, bar NODE_EXTRA_CA_CERTS, which
  # adds to Node's own and takes the bundle as readily as the CA alone.
  caVariables =
    lib.genAttrs [
      "AWS_CA_BUNDLE"
      "CARGO_HTTP_CAINFO"
      "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"
      "CURL_CA_BUNDLE"
      "DENO_CERT"
      "GIT_SSL_CAINFO"
      "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"
      "HEX_CACERTS_PATH"
      "HTTPLIB2_CA_CERTS"
      "NIX_SSL_CERT_FILE"
      "NODE_EXTRA_CA_CERTS"
      "PIP_CERT"
      "REQUESTS_CA_BUNDLE"
      "SSL_CERT_FILE"
    ]
      (_: "/etc/frisket/ca-bundle.crt")
    // {
      DENO_TLS_CA_STORE = "system,mozilla";
      # uv's roots are compiled in; this makes it read the system's, which
      # SSL_CERT_FILE names.
      UV_NATIVE_TLS = "true";
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
    user = mkOption {
      type = types.str;
      example = "alice";
      description = ''
        Whose agents these are. The account the wrappers go on the PATH of,
        the account a session runs as inside its container, and the account
        frisket reads the credential files of -- the same name on both sides
        of the boundary, because a bind-mounted file has one owner.
      '';
    };
    uid = mkOption {
      type = types.ints.unsigned;
      example = 1000;
      description = ''
        `user`'s uid on the HOST, reused inside the container. There is no uid
        namespace, so a file bind-mounted in has to be owned by the same
        number on both sides or the session cannot read what it was given.
      '';
    };
    gid = mkOption {
      type = types.ints.unsigned;
      example = 100;
      description = "`user`'s primary gid on the host, reused inside the container, for the reason `uid` is.";
    };
    home = mkOption {
      type = types.strMatching "/.*";
      default = "/home/${cfg.user}";
      defaultText = lib.literalExpression ''"/home/''${config.chase.user}"'';
      description = ''
        `user`'s home, at the same path inside a session as outside: the
        agents' own state directories are bound through by absolute path, and
        a tool that writes one would otherwise write it somewhere else.
      '';
    };
    placeholder = mkOption {
      type = types.str;
      default = "proxy-injected";
      description = ''
        What a container holds in place of every credential, and the ONLY
        value frisket replaces: a request carrying anything else goes upstream
        as it was sent. Claude Code keeps a variable set to exactly this when
        it scrubs credentials from a subprocess's environment.
      '';
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
    # HOW A CHECKOUT IS SORTED. The options below are the selector's inputs,
    # in the order it consults them: explicit paths, then explicit slugs, then
    # the heuristic. See ./selector.nix, which is where the order is enforced.
    #
    # A repository is named "owner/name", matched against `origin`'s URL. A
    # slug ALONE is never enough to raise a tier: where the checkout sits has
    # to agree, because a remote is a string any checkout can claim and a path
    # is not.
    strictRepos = mkOption {
      type = types.listOf slug;
      default = [ ];
      example = [ "danielbodart/something-i-do-not-trust" ];
      description = ''
        Repositories forced to the strict tier, whatever else would have said.
        Checked before every other rule, including the paths, so this is how
        an exception is written down.
      '';
    };
    trustedRepos = mkOption {
      type = types.attrsOf absPath;
      default = { };
      example = { "someorg/a-fork-we-work-on" = "/home/alice/Projects/a-fork-we-work-on"; };
      description = ''
        Repositories raised to the trusted tier that the heuristic would not
        reach -- a fork, whose first commit is upstream's, or a repository in
        an organisation that is not yours.

        Keyed by "owner/name", valued by where that checkout must live. BOTH
        have to match: a checkout claiming the slug from anywhere else is
        sorted strict and told why.
      '';
    };
    hostRepos = mkOption {
      type = types.attrsOf absPath;
      default = { };
      example = { "alice/nix-config" = "/home/alice/Projects/nix-config"; };
      description = ''
        Repositories that run with no container at all, for work a container
        cannot do: real sudo, /dev/input, KVM, or the network namespaces these
        sessions are made of.

        Keyed and matched exactly as `trustedRepos` is, and for the stronger
        reason -- this tier has no boundary, so the path agreeing is the whole
        of what is checked.
      '';
    };
    hostPaths = mkOption {
      type = types.listOf absPath;
      default = [ ];
      example = [ "/home/alice" ];
      description = ''
        Directories that run bare, matched EXACTLY and never as a prefix, and
        consulted before anything asks git a question. The one signal a
        checkout cannot forge, which is why it is first.
      '';
    };
    trustedOrgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "alice" "her-employer" ];
      description = ''
        Repository owners whose work is yours. An unlisted owner is strict
        without further questions; a listed one still has to pass
        `trustedAuthorDomains` before the tier is raised.
      '';
    };
    trustedAuthorDomains = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "example.com" ];
      description = ''
        Email domains of the author of a repository's FIRST commit. A fork's
        root commit is upstream's, so the domain there is what gives a fork
        away when the slug and the owner both look like yours.
      '';
    };
    workspaceGroups = mkOption {
      type = types.listOf (types.listOf absPath);
      default = [ ];
      example = [ [ "/home/alice/Projects/api" "/home/alice/Projects/web" ] ];
      description = ''
        Checkouts worked on together. Opening any member binds the others
        beside it, read-write, at the session's own tier -- for a service and
        the client generated from it, say.

        Not transitive, and the members are reported at launch rather than
        re-sorted: a group is a statement that these are one piece of work.
      '';
    };
    tiers = mkOption {
      type = types.attrsOf tierType;
      default = { };
      description = ''
        The sandboxes a checkout can be sorted into, by name. chase ships two
        -- `trusted` and `strict` -- and each becomes a container, a flong
        launcher and a frisket policy of the same name.

        `host` is deliberately absent: it is the ABSENCE of a tier, not one of
        them, and a checkout sorted there runs bare.
      '';
    };
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
        # Defaults: a container that wants one runtime pointed elsewhere says
        # so in its own declaration.
        environment.variables = lib.mapAttrs (_: lib.mkDefault) caVariables;
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
