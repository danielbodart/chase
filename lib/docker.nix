# A project's loopback address and its names, from its owner/repo slug
# (docs/docker.md, with names under .internal), in Nix. chase's
# chase-docker-address prints what these give, and the flake exports them as
# lib.docker, so a consumer naming projects in /etc/hosts derives them from
# this one source rather than from a copy. frisket derives both again from the
# route's project and refuses a route whose address or names differ; the
# docker-address check holds this, and chase-docker-address, to the vectors
# frisket asserts.
{ lib }:

rec {
  # Names that already mean something else under .internal, which a project's
  # name must never equal or fall under. The whole of frisket.internal is
  # frisket's, for its route hosts, docker.frisket.internal among them and any
  # it adds later: repo "docker" of owner "frisket" would otherwise be
  # docker.frisket.internal, and repo "frisket" would be frisket.internal. The
  # whole of google.internal is the cloud's, metadata.google.internal among
  # it. So owner frisket or google keeps only its short name.
  #
  # frisket owns this list (internal/docker/address.go, the reserved its
  # docker.Names uses), and refuses a route whose names differ from its own.
  # chase keeps the same literal here until its frisket input is new enough
  # to export the list; then it takes the list from frisket's flake, and the
  # docker-address check holds the vectors of both to agree.
  reserved = [
    "frisket.internal"
    "google.internal"
  ];

  isReserved = name:
    lib.any (r: name == r || lib.hasSuffix ".${r}" name) reserved;

  # Whether the slug is a project as frisket accepts one, and
  # chase-docker-address with it: owner/repo, of this shape once lower-cased,
  # and a repo that is neither "." nor "..". address and names refuse any
  # other slug, since frisket could never route it, and a name made from it
  # could only stand in /etc/hosts for nothing, or crowd out a real one.
  isProject = slug:
    let s = lib.toLower slug; in
    builtins.match "[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}" s != null
    && !(lib.elem (lib.last (lib.splitString "/" s)) [ "." ".." ]);

  project = slug:
    if isProject slug then lib.toLower slug
    else throw "lib.docker: ${builtins.toJSON slug} is not owner/repo as frisket accepts it";

  # sha256 of the lower-cased slug, three bytes from its first six hex digits.
  # A b1 of 0 would land in 127.0.0.0/16, where 127.0.0.1 and 127.0.0.53
  # live, and 255.255.255 is the broadcast address, so either re-hashes the
  # 64 hex characters and tries again.
  address = slug:
    let
      byte = h: i: lib.fromHexString (builtins.substring (2 * i) 2 h);
      go = h:
        let b = map (byte h) [ 0 1 2 ]; in
        if builtins.head b == 0 || b == [ 255 255 255 ]
        then go (builtins.hashString "sha256" h)
        else "127.${lib.concatMapStringsSep "." toString b}";
    in
    go (builtins.hashString "sha256" (project slug));

  # The short name, then the long one, less any that is reserved. The repo
  # folds to one DNS label: anything but [a-z0-9-] becomes "-", and the ends
  # are trimmed. A label over 63 characters is not a DNS label, and frisket
  # refuses such a query before it could answer it, so that repo has no names
  # at all.
  names = slug:
    let
      parts = lib.splitString "/" (project slug);
      owner = builtins.elemAt parts 0;
      repo = builtins.elemAt parts 1;
      folded = lib.concatMapStrings
        (c: if builtins.match "[a-z0-9-]" c != null then c else "-")
        (lib.stringToCharacters repo);
      label = lib.pipe folded [
        (s: builtins.match "-*(.*[^-])?-*" s)
        builtins.head
        (s: if s == null then "" else s)
      ];
    in
    if label == "" || builtins.stringLength label > 63
    then [ ]
    else lib.filter (n: !isReserved n) [ "${label}.internal" "${label}.${owner}.internal" ];
}
