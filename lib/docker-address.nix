# chase-docker-address OWNER/REPO: a project's loopback address and its
# names, printed as {project,address,names} (docs/docker.md, with names
# under .internal). It computes them as ./docker.nix does, with the
# reserved names frisket exports, which the caller passes in; the
# docker-address check holds the two to the same vectors, and to those frisket
# asserts, since frisket derives both again from the route's project and
# refuses a route whose address or names differ.
#
# It is a script of its own, with nothing but coreutils and jq, so that
# chase-envelope, the Docker prepare step and chase itself can all run it
# without any of them depending on another.
{ pkgs, reserved }:

pkgs.writeShellApplication {
  name = "chase-docker-address";
  runtimeInputs = with pkgs; [ coreutils jq ];
  text = ''
    # The C locale keeps lower-casing and the character classes below to
    # ASCII, as frisket's and nix-config's are.
    export LC_ALL=C
    die() {
      printf 'chase-docker-address: %s\n' "$1" >&2
      exit 1
    }
    [ $# -eq 1 ] || die "usage: chase-docker-address OWNER/REPO"

    # frisket refuses a route whose project is not a slug of this shape, so
    # a bad one is refused here, when it is approved, rather than when a
    # session fails to start.
    slug=''${1,,}
    [[ $slug =~ ^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$ ]] \
      || die "$1 is not owner/repo as frisket accepts it"
    owner=''${slug%%/*}
    repo=''${slug#*/}
    case $repo in
      . | ..) die "$1 names no repository" ;;
    esac

    # Three bytes of the slug's sha256. A b1 of 0 would land in
    # 127.0.0.0/16, where 127.0.0.1 and 127.0.0.53 live, and 255.255.255 is
    # the broadcast address, so either hashes the 64 hex characters again.
    h=$(printf '%s' "$slug" | sha256sum | cut -c1-64)
    while :; do
      b1=$((16#''${h:0:2})) b2=$((16#''${h:2:2})) b3=$((16#''${h:4:2}))
      if [ "$b1" -ne 0 ] && [ "$b1.$b2.$b3" != 255.255.255 ]; then break; fi
      h=$(printf '%s' "$h" | sha256sum | cut -c1-64)
    done

    # The repo as one DNS label: anything but [a-z0-9-] folds to "-", and
    # the ends are trimmed. A label over 63 characters is not a DNS label,
    # and frisket refuses such a query, so that repo has no names at all.
    label=''${repo//[^a-z0-9-]/-}
    while [[ $label == -* ]]; do label=''${label#-}; done
    while [[ $label == *- ]]; do label=''${label%-}; done

    jq -cn \
      --arg project "$slug" \
      --arg address "127.$b1.$b2.$b3" \
      --arg label "$label" \
      --arg owner "$owner" \
      --argjson reserved ${pkgs.lib.escapeShellArg (builtins.toJSON reserved)} \
      '{project: $project, address: $address,
        names: (if $label == "" or ($label | length) > 63 then []
                else [$label + ".internal", $label + "." + $owner + ".internal"]
                  | map(select(. as $n | $reserved | any(. as $r | $n == $r or ($n | endswith("." + $r))) | not))
                end)}'
  '';
}
