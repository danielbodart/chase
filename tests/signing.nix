# A key of the test's own that signs a project's chase.json, as `ssh-keygen
# -Y sign` would by hand (quoin's docs/policy.md), and the allowed signers
# that allow it in every quoin-policy namespace: what the session tests
# give chase.signer.allowedSigners. quoin's signer, which signs through
# galley, is record-session's.
{ pkgs, lib, chase }:

rec {
  keys = pkgs.runCommand "chase-test-signing-key" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir $out
    ssh-keygen -q -t ed25519 -N "" -C chase-test -f $out/key
    echo "alice namespaces=\"quoin-policy:*\" $(cut -d' ' -f1,2 $out/key.pub)" > $out/allowed_signers
  '';

  allowedSigners = "${keys}/allowed_signers";

  # `sign WS [HOME]`, as the user whose home WS is in, $HOME unless it is
  # given: WS's chase.json in its canonical form, and chase.json.sig beside
  # it, in the namespace of WS.
  sign = pkgs.writeShellScript "sign-chase-json" ''
    set -euo pipefail
    export PATH=${lib.makeBinPath [ pkgs.coreutils pkgs.openssh ]}
    ws=$(realpath "$1")
    home=$(realpath "''${2:-$HOME}")
    ${lib.getExe chase} fmt "$ws/chase.json" > /dev/null
    key=$(mktemp)
    trap 'rm -f "$key"' EXIT
    install -m 0600 ${keys}/key "$key"
    rm -f "$ws/chase.json.sig"
    ssh-keygen -q -Y sign -f "$key" -n "quoin-policy:~/''${ws#"$home"/}" "$ws/chase.json"
  '';
}
