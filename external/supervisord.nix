{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  src = pkgs.fetchFromGitHub {
    owner = "ochinchina";
    repo = "supervisord";
    rev = "c2cae38b7454d444f4cb8281d5367d50a55c0011";
    sha256 = "sha256-aJ+/hyh6MxYQgnk+cE75TpQbMDYvOHHE6cntF8FflWQ=";
  };
in rec {
  # static by default since CGO is disabled
  uncompressed = pkgs.buildGoModule {
    src = src;
    name = "supervisord";
    vendorHash = "sha256-Uo2CvjCsWAQlVe5swyabfK4ssKqw4DvZS2w4hsOkFGY=";
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
