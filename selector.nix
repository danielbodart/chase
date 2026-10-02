{ config, lib, pkgs, ... }:

# WHICH TIER A CHECKOUT IS: the selector's part of the configuration, and
# where it is run. The sorting itself -- reading a checkout's .git without
# running anything its config names, the rules, the guard -- is the chase
# binary's (internal/checkout, internal/selector, and internal/gitsafe for
# how git is run on a repository a session wrote). The module says which
# tiers there are and what puts a checkout in each, and puts the binary on
# the person's PATH under the names they run.

let
  cfg = config.chase;
  sandboxes = lib.filterAttrs (_: t: !t.bare) cfg.tiers;
  chase = lib.getExe cfg.package;

  # The empty repositories every git call is given as its GIT_DIR and HOME,
  # one of each object format, read-only in the store so nothing of the
  # user's can write them.
  emptyGit = format: pkgs.runCommand "chase-empty-git-${format}" { } ''
    mkdir -p $out/objects $out/refs
    echo 'ref: refs/heads/none' > $out/HEAD
    printf '[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tobjectFormat = %s\n' ${format} > $out/config
  '';

  # `chase` itself. A link, not a wrapper script: the binary picks what to
  # be from the name it was run as. The agents' own names are their apps'
  # (apps/claude.nix, apps/codex.nix).
  links = pkgs.runCommand "chase-links" { } ''
    mkdir -p $out/bin
    ln -s ${chase} $out/bin/chase
  '';
in
{
  config = {
    chase.internal.config.selector = {
      git = "${pkgs.git}/bin/git";
      emptySha1 = "${emptyGit "sha1"}";
      emptySha256 = "${emptyGit "sha256"}";
      inherit (cfg) order fallback;
      tiers = lib.mapAttrs (name: t: {
        inherit (t) bare match;
      } // lib.optionalAttrs (!t.bare) {
        launcher = lib.getExe config.flong."chase-${name}".launcher;
      }) cfg.tiers;
    };

    # A consistency check and, for every sandbox, one gate: see
    # internal/selector's Guard. A command, never shell.
    flong = lib.mapAttrs' (name: _: lib.nameValuePair "chase-${name}" {
      guard = [ [ chase "guard" name ] ];
    }) sandboxes;

    home-manager.users.${cfg.user}.home.packages = [ links ];
  };
}
