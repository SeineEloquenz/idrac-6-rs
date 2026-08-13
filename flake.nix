{
  description = "idrac6-kvm: modern KVM console proxy for Dell iDRAC 6 (APCP to RFB/VNC)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "idrac6-kvm";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
          meta = {
            description = "Modern KVM console proxy for Dell iDRAC 6";
            mainProgram = "idrac6-kvm";
          };
        };
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.default}/bin/idrac6-kvm";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          # pkg-config's setup hook adds buildInputs' .dev outputs to PKG_CONFIG_PATH,
          # and stdenv provides `cc`, so openssl-sys links the nixpkgs OpenSSL cleanly.
          nativeBuildInputs = with pkgs; [
            pkg-config
            rustc
            cargo
            rustfmt
            clippy
            rust-analyzer
          ];
          buildInputs = [ pkgs.openssl ];
          env = {
            RUST_LOG = "idrac6_kvm=debug,info";
            # Link the system (nixpkgs) OpenSSL rather than vendoring/building it.
            OPENSSL_NO_VENDOR = "1";
          };
        };

        # Opt-in shell with the heavy tooling for the M0 capture spike against the R710.
        capture = pkgs.mkShell {
          packages = with pkgs; [ tigervnc wireshark-cli ];
        };
      });

      nixosModules.default = import ./nix/module.nix self;
    };
}
