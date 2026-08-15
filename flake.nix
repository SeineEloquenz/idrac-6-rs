{
  description = "idrac6-kvm: modern KVM console proxy for Dell iDRAC 6 (APCP to RFB/VNC)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));

      # The two paths are one binary gated by the `web` feature: `serve` is the lean RFB/VNC proxy,
      # `web` adds the self-serve noVNC app (axum/tower/serde).
      mkBin = pkgs: { pname, withWeb }: pkgs.rustPlatform.buildRustPackage {
        inherit pname;
        version = "0.1.0";
        src = self;
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.openssl ];
        buildNoDefaultFeatures = !withWeb;
        cargoBuildFlags = [ "-p" "idrac6-kvm" ];
        cargoTestFlags = [ "-p" "idrac6-kvm" ];
        meta = {
          description = "Modern KVM console proxy for Dell iDRAC 6"
            + (if withWeb then " (self-serve noVNC web app)" else " (RFB/VNC proxy)");
          mainProgram = "idrac6-kvm";
        };
      };
    in
    {
      packages = forAllSystems (pkgs:
        let
          serve = mkBin pkgs { pname = "idrac6-kvm-serve"; withWeb = false; };
          web = mkBin pkgs { pname = "idrac6-kvm-web"; withWeb = true; };
        in
        {
          inherit serve web;
          default = web;

          # OCI images built purely with nix (dockerTools). Listen addresses default to all
          # interfaces for containers; `IDRAC_HOST`/`IDRAC_USER`/`IDRAC_PASSWORD` (and `IDRAC_LISTEN`)
          # configure a running container, so no flags are baked into the entrypoint.
          serve-image = pkgs.dockerTools.buildLayeredImage {
            name = "idrac6-kvm-serve";
            tag = "latest";
            config = {
              Entrypoint = [ (pkgs.lib.getExe serve) "serve" ];
              Env = [ "IDRAC_LISTEN=0.0.0.0:5900" ];
              ExposedPorts = { "5900/tcp" = { }; };
            };
          };

          web-image = pkgs.dockerTools.buildLayeredImage {
            name = "idrac6-kvm-web";
            tag = "latest";
            contents = [ pkgs.novnc ];
            config = {
              Entrypoint = [ (pkgs.lib.getExe web) "web" ];
              Env = [
                "IDRAC_LISTEN=0.0.0.0:8080"
                "IDRAC_NOVNC_ROOT=${pkgs.novnc}/share/webapps/novnc"
              ];
              ExposedPorts = { "8080/tcp" = { }; };
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

      nixosModules = {
        serve = import ./nix/serve.nix self;
        web = import ./nix/web.nix self;
        default = { imports = [ (import ./nix/serve.nix self) (import ./nix/web.nix self) ]; };
      };
    };
}
