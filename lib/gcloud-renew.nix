# tokenURL is for the flake's check alone: nothing at run time can move it.
{ pkgs, tokenURL ? "https://oauth2.googleapis.com/token" }:

pkgs.writeShellApplication {
  name = "chase-gcloud-renew";
  runtimeInputs = [ pkgs.openssl pkgs.curl pkgs.jq pkgs.coreutils ];
  text = builtins.replaceStrings
    [ "token_url=https://oauth2.googleapis.com/token" ]
    [ "token_url=${pkgs.lib.escapeShellArg tokenURL}" ]
    (builtins.readFile ../scripts/gcloud-renew.sh);
}
