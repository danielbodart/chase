# RFC 7396's JSON Merge Patch, as frisket's projpolicy.MergePatch merges a
# project's section over a tier's: `patch` over `target`, objects merged
# key by key, a null deleting the key it is under, and anything else --
# a list among them -- replacing what was there whole. A tier's own
# sections (module.nix) are merged over what its other options make this
# way, as a project's are merged over the tier's at launch.
{ lib }:

let
  mergePatch = target: patch:
    if builtins.isAttrs patch then
      let t = if builtins.isAttrs target then target else { }; in
      removeAttrs
        (t // builtins.mapAttrs (k: v: mergePatch (t.${k} or null) v) patch)
        (lib.filter (k: patch.${k} == null) (builtins.attrNames patch))
    else
      patch;
in
mergePatch
