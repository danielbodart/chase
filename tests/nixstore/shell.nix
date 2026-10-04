# The checkout's shell.nix in tests/nix-store-session.nix, shaped as
# pokeranker's: libraries a GUI build links against, and a shellHook that
# exports where they are -- LD_LIBRARY_PATH, XDG_DATA_DIRS and
# GIO_MODULE_DIR -- and says where it ran.
{ pkgs ? import <nixpkgs> { }, ... }:
let
  libraries = [ pkgs.zlib pkgs.libffi pkgs.glib ];
in
pkgs.mkShell {
  nativeBuildInputs = [ pkgs.pkg-config ];
  buildInputs = libraries;
  packages = [ pkgs.hello ];
  HELLO_FROM_SHELL = "hi";
  shellHook = ''
    export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath libraries}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
    export XDG_DATA_DIRS=${pkgs.glib}/share''${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}
    export GIO_MODULE_DIR=${pkgs.glib.out}/lib/gio/modules/
    echo "the hook ran in $PWD" >&2
  '';
}
