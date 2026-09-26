# git over HTTPS: clone, fetch and push, and what github.com serves beside
# them -- release downloads, archives, Git LFS. An app apart from github, which
# is GitHub's API and gh, so the two can be answered differently: a tier can
# let git push while gh's writes still ask (PLAN.md, decision 18). They share
# GitHub's credential, `chase.bindings.github.credentialFile`.
#
# Its operations are the protocol's, not GitHub's: a fetch is a read, a push
# is a write, and frisket's git rule tells them apart by the request line. A
# push asked about is asked about once, showing the refs it would update.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkMerge mkOption types;
  cfg = config.chase;
  ops = import ../lib/operations.nix { inherit lib; };
  host = "github.com";

  # A checkout's remotes stay git@github.com: git rewrites them to HTTPS, so
  # they go through frisket, and no key is needed.
  https = {
    url."https://${host}/".insteadOf = [ "git@${host}:" "ssh://git@${host}/" ];
  };

  # What github.com serves besides git's own requests, which frisket's git
  # rule decides before any of these. Written by hand: there is no
  # description to generate them from.
  operations = [
    {
      methods = [ "GET" "HEAD" ];
      prefix = "/";
      operation = {
        id = "github-download";
        summary = "Download from github.com";
        description = "A release asset, an archive, a raw file or a page: whatever github.com serves to a GET.";
        class = "read";
      };
    }
    # Git LFS's batch API says in its body whether it is a download or an
    # upload, and frisket does not yet look: until it does, both are writes.
    {
      methods = [ "POST" ];
      path = "/*/*/info/lfs/objects/batch";
      operation = {
        id = "lfs-batch";
        summary = "Transfer Git LFS objects";
        description = "Asks for URLs to download or upload the listed LFS objects; which, the body says.";
        class = "write";
        category = "lfs";
      };
    }
    {
      methods = [ "POST" ];
      prefix = "/*/*/info/lfs/locks";
      operation = {
        id = "lfs-locks";
        summary = "Lock, unlock or list Git LFS file locks";
        class = "write";
        category = "lfs";
      };
    }
  ];

  # Where a clone's other bytes come from: archives, raw files, release
  # assets and LFS objects. Allowed by name and spliced, never intercepted.
  hosts = [ host "codeload.github.com" "*.githubusercontent.com" ];
in
{
  imports = [
    (lib.mkRenamedOptionModule [ "chase" "bindings" "github" "gitConfig" ] [ "chase" "bindings" "git" "config" ])
  ];

  options.chase.bindings.git.config = mkOption {
    type = types.listOf (types.strMatching "/.*");
    default = [ "${cfg.home}/.gitconfig" "${cfg.home}/.config/git" ];
    defaultText = lib.literalExpression ''[ "''${config.chase.home}/.gitconfig" "''${config.chase.home}/.config/git" ]'';
    description = ''
      The user's own git configuration -- files or directories, each of which
      must exist on the host -- bound read-only at the same paths into a tier
      whose git is not anonymous, so git in a session is the git the user
      set up: who commits, aliases, filters, defaults. Not into an anonymous
      one: a git config can carry a credential in a URL, and those tiers run
      other people's code. Empty: none.
    '';
  };

  options.chase.tiers = mkOption {
    type = types.attrsOf (types.submodule ({ config, ... }: {
      options.apps.git = ops.appOptions config // {
        enable = mkEnableOption ''
          git over HTTPS to github.com in this tier, with GitHub's credential:
          a clone or fetch goes straight through, and a push -- a write -- is
          answered as `writes` says'';
        anonymous = mkEnableOption ''
          read-only git with no credential of yours: public clones and fetches,
          and no push'';
      };
    }));
  };

  config = {
    containers = lib.mapAttrs' (name: tier: lib.nameValuePair "agent-${name}" (mkIf tier.apps.git.enable {
      # Read-only: a session uses the user's configuration and cannot change
      # it.
      bindMounts = mkIf (!tier.apps.git.anonymous) (lib.listToAttrs (map
        (p: lib.nameValuePair p { hostPath = p; isReadOnly = true; })
        cfg.bindings.git.config));
      config = mkMerge [
        # git-lfs on the PATH: a repository's LFS hooks look for it there.
        { programs.git = { enable = true; config = https; }; environment.systemPackages = [ pkgs.git-lfs ]; }
        # git hands the placeholder over as Basic auth's password, which is
        # where frisket puts the token.
        (mkIf (!tier.apps.git.anonymous) {
          programs.git.config.credential."https://${host}".helper =
            "!f() { if [ \"$1\" = get ]; then printf 'username=x-access-token\\npassword=%s\\n' ${lib.escapeShellArg cfg.placeholder}; fi; }; f";
        })
      ];
    })) cfg.tiers;

    services.frisket.policies = lib.mapAttrs (name: tier: mkIf tier.apps.git.enable (
      let s = ops.settings tier.apps.git; in
      {
        # For a tier with an allowlist of names; one allowing `*` has it already.
        allow = lib.mkAfter hosts;
        routes.git = {
          inherit host;
          upstream = "https://${host}";
          # Any repository: which ones a session may reach is the token's to
          # say. A push is a write, answered as the tier and the app say.
          git = { repos = [ "*" ]; push = s.writes; };
          paths = ops.paths s operations;
          unmatched = ops.unmatched s;
        } // lib.optionalAttrs (!tier.apps.git.anonymous) {
          # Anonymous, intercepted with no credential, so the scope holds: a
          # token the session brings still reaches GitHub, but only to read.
          # Otherwise GitHub's own token, which git takes only as Basic
          # auth's password.
          credentialFile = cfg.bindings.github.credentialFile;
          placeholder = cfg.placeholder;
          basicUser = "x-access-token";
        };
      })) cfg.tiers;
  };
}
