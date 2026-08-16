{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
  pname,
  src,
  blurb ? "",
}:

rustPlatform.buildRustPackage {
  inherit pname src;
  version = "0.1.0";
  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];

  cargoBuildFlags = [
    "-p"
    pname
  ];
  cargoTestFlags = [
    "-p"
    "idrac6-kvm"
  ];

  meta = {
    description = "Modern KVM console proxy for Dell iDRAC 6 " + blurb;
    mainProgram = pname;
  };
}
