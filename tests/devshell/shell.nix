# The checkout's shell.nix in tests/devshell-session.nix: hello and a bash of
# its own, a variable, and a hook that says where it ran and puts the
# checkout's bin ahead of its PATH.
{ pkgs ? import <nixpkgs> { }, ... }:
pkgs.mkShell {
  packages = [ pkgs.hello pkgs.bash ];
  HELLO_FROM_SHELL = "hi";
  shellHook = ''
    echo "the hook ran in $PWD"
    export PATH=$PWD/bin:$PATH
  '';
}
