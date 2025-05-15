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
    tee-monorepo = { 
      url = "github:selfxyz/tee-monorepo";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    fenix,
    naersk,
    nitro-util,
    tee-monorepo,
  }: let
    systemBuilder = systemConfig: rec {
      enclave = import ./enclave {
        inherit nixpkgs systemConfig nitro-util;
        # TODO: use systemConfig.system later
        supervisord = tee-monorepo.packages.x86_64-linux.supervisord;
        dnsproxy = tee-monorepo.packages.x86_64-linux.dnsproxy;
        raw-proxy = tee-monorepo.packages.x86_64-linux.raw-proxy;
        attestation-server = tee-monorepo.packages.x86_64-linux.attestation-server;
        vet = tee-monorepo.packages.x86_64-linux.vet;
        kernels = tee-monorepo.packages.x86_64-linux.tuna;
      };
    };
  in {
    formatter = {
      "x86_64-linux" = nixpkgs.legacyPackages."x86_64-linux".alejandra;
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
    };
  };
}
