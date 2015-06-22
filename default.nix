{ mkDerivation, base, bindings-posix, c-storable-deriving
, containers, filepath, ghc-prim, mtl, stdenv, unix
}:
mkDerivation {
  pname = "ptrace";
  version = "0.2";
  src = ./.;
  buildDepends = [
    base bindings-posix c-storable-deriving containers filepath
    ghc-prim mtl unix
  ];
  license = stdenv.lib.licenses.bsd3;
}
