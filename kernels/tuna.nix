{
  nixpkgs,
  systemConfig,
}: let
  system = systemConfig.system;
  pkgs = nixpkgs.legacyPackages."${system}";
  bootstrap = pkgs.stdenv.mkDerivation {
    name = "aws-bootstrap";
    src = pkgs.fetchFromGitHub {
      owner = "aws";
      repo = "aws-nitro-enclaves-sdk-bootstrap";
      rev = "ca0885b1d7b801f0066881d0e828f786bbbab061";
      sha256 = "sha256-gwOHtj9eKKC+CFCsrDA/Z31VWRJ28/UlLTAH9iIj6iE=";
    };
    patches = [
      ./build.patch
      ./tuna.patch
    ];
    installPhase = ''
      mkdir -p $out
      cp -r ./* $out/
    '';
  };
  outputs = import bootstrap {nixpkgs = pkgs;};
in
  if systemConfig.eif_arch == "x86_64"
  then {
    default = outputs.all;
    kernel = "${outputs.all}/${systemConfig.eif_arch}/bzImage";
    kernelConfig = "${outputs.all}/${systemConfig.eif_arch}/bzImage.config";
    init = "${outputs.all}/${systemConfig.eif_arch}/init";
    nsmKo = "${outputs.all}/${systemConfig.eif_arch}/nsm.ko";
  }
  else if systemConfig.eif_arch == "aarch64"
  then {
    default = outputs.all;
    kernel = "${outputs.all}/${systemConfig.eif_arch}/Image";
    kernelConfig = "${outputs.all}/${systemConfig.eif_arch}/Image.config";
    init = "${outputs.all}/${systemConfig.eif_arch}/init";
    nsmKo = "${outputs.all}/${systemConfig.eif_arch}/nsm.ko";
  }
  else {}
