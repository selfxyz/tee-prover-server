{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  src = pkgs.fetchFromGitHub {
    owner = "AdguardTeam";
    repo = "dnsproxy";
    rev = "v0.71.2";
    sha256 = "sha256-fsJWyb3YFmTeLf1qbO42RTldiEv3MeXyrySywGmIg5A=";
  };
in rec {
  # static by default since CGO is disabled
  uncompressed = pkgs.buildGoModule {
    src = src;
    name = "dnsproxy";
    vendorHash = "sha256-oINdRXLtfoCOpZ+n4HAkPtXyKen4m9VaDz1ggiEzehc=";
    ldflags = ["-s" "-w"];
    trimpath = true;
    buildMode = "pie";
    tags = ["netgo" "osusergo"];
    subPackages = ["."];
  };

  compressed =
    pkgs.runCommand "compressed" {
      nativeBuildInputs = [pkgs.upx];
    } ''
      mkdir -p $out/bin
      cp ${uncompressed}/bin/* $out/bin/
      chmod +w $out/bin/*
      upx $out/bin/*
    '';

  default = compressed;
}
