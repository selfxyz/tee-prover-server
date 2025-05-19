{
  nixConfig = {};
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
    systemBuilder = systemConfig: let
      enclaveBaseArgs = {
        inherit nixpkgs systemConfig nitro-util;
        # TODO: use systemConfig.system later instead of x86_64-linux
        supervisord = tee-monorepo.packages.x86_64-linux.supervisord;
        dnsproxy = tee-monorepo.packages.x86_64-linux.dnsproxy;
        raw-proxy = tee-monorepo.packages.x86_64-linux.raw-proxy;
        attestation-server = tee-monorepo.packages.x86_64-linux.attestation-server;
        vet = tee-monorepo.packages.x86_64-linux.vet;
        kernels = tee-monorepo.packages.x86_64-linux.tuna;
        dockerOrganization = "selfdotxyz";
      };

      dockerVariants = [
        { dockerType = "register-small"; tag = "staging"; }
        { dockerType = "register-small"; tag = "latest"; }
        { dockerType = "register-medium"; tag = "staging"; }
        { dockerType = "register-medium"; tag = "latest"; }
        { dockerType = "register-large"; tag = "staging"; }
        { dockerType = "register-large"; tag = "latest"; }
        { dockerType = "dsc-small"; tag = "staging"; }
        { dockerType = "dsc-small"; tag = "latest"; }
        { dockerType = "dsc-medium"; tag = "staging"; }
        { dockerType = "dsc-medium"; tag = "latest"; }
        { dockerType = "dsc-large"; tag = "staging"; }
        { dockerType = "dsc-large"; tag = "latest"; }
        { dockerType = "disclose-small"; tag = "staging"; }
        { dockerType = "disclose-small"; tag = "latest"; }
      ];

      enclaves = builtins.listToAttrs (builtins.map (variant:
        let
          name = "enclave-${variant.dockerType}-${variant.tag}";
          args = enclaveBaseArgs // {
            dockerType = variant.dockerType;
            dockerTag = variant.tag;
          };
        in {
          inherit name;
          value = import ./enclave args;
        }
      ) dockerVariants);
    in enclaves;

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
