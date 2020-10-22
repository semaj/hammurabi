# This imports the nix package collection,
# so we can access the `pkgs` and `stdenv` variables
let
  unstable = import (fetchTarball https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz) { };
in
{ nixpkgs ? import <nixpkgs> {} }:
with nixpkgs; mkShell {
  buildInputs = with pkgs; [ cargo rustc carnix autoconf libtool texinfo automake115x ];
}
