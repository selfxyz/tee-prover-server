{
  nixConfig = {
    # extra-substituters = ["https://oyster.cachix.org"];
    # extra-trusted-public-keys = ["oyster.cachix.org-1:QEXLEQvMA7jPLn4VZWVk9vbtypkXhwZknX+kFgDpYQY="];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.11";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nitro-util = {
      url = "github:monzo/aws-nitro-util";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    fenix,
    naersk,
    nitro-util,
  }: let
    systemBuilder = systemConfig: rec {
      external.dnsproxy = import ./external/dnsproxy.nix {
        inherit nixpkgs systemConfig;
      };
      external.supervisord = import ./external/supervisord.nix {
        inherit nixpkgs systemConfig;
      };
      attestation-server = import ./attestation-server { 
        inherit nixpkgs systemConfig fenix naersk;
      };
      initialization.vet = import ./initialization/vet {
        inherit nixpkgs systemConfig fenix naersk;
      };
      kernels.tuna = import ./kernels/tuna.nix {
        inherit nixpkgs systemConfig;
      };
      networking.raw-proxy = import ./networking/raw-proxy {
        inherit nixpkgs systemConfig fenix naersk;
      };
      enclave = import ./enclave {
        inherit nixpkgs systemConfig nitro-util;
        supervisord = external.supervisord.compressed;
        dnsproxy = external.dnsproxy.compressed;
        raw-proxy = networking.raw-proxy.compressed;
        attestation-server = attestation-server.compressed;
        vet = initialization.vet.compressed;
        kernels = kernels.tuna;
      };
    };
  in {
    formatter = {
      "x86_64-linux" = nixpkgs.legacyPackages."x86_64-linux".alejandra;
      "aarch64-linux" = nixpkgs.legacyPackages."aarch64-linux".alejandra;
    };
    packages = {
      "x86_64-linux" = rec {
        gnu = systemBuilder {
          system = "x86_64-linux";
          rust_target = "x86_64-unknown-linux-gnu";
          eif_arch = "x86_64";
          static = false;
        };
        musl = systemBuilder {
          system = "x86_64-linux";
          rust_target = "x86_64-unknown-linux-musl";
          eif_arch = "x86_64";
          static = true;
        };
        default = musl;
      };
      "aarch64-linux" = rec {
        gnu = systemBuilder {
          system = "aarch64-linux";
          rust_target = "aarch64-unknown-linux-gnu";
          eif_arch = "aarch64";
          static = false;
        };
        musl = systemBuilder {
          system = "aarch64-linux";
          rust_target = "aarch64-unknown-linux-musl";
          eif_arch = "aarch64";
          static = true;
        };
        default = musl;
      };
      "aarch64-darwin" = rec {
        gnu = systemBuilder {
          system = "aarch64-darwin";
          rust_target = "aarch64-apple-darwin";
          eif_arch = "aarch64";
          static = false;
        };
        # TODO: Figure out how to organize this properly
        musl = systemBuilder {
          system = "aarch64-darwin";
          rust_target = "aarch64-apple-darwin";
          eif_arch = "aarch64";
          static = false;
        };
        default = musl;
      };
    };
  };
}
