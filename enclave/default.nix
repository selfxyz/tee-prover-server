{
  nixpkgs,
  systemConfig,
  nitro-util,
  supervisord,
  dnsproxy,
  raw-proxy,
  attestation-server,
  vet,
  kernels,
  dockerType, 
  dockerTag, 
  dockerOrganization,
}: let
  system = systemConfig.system;
  nitro = nitro-util.lib.${system};
  eifArch = systemConfig.eif_arch;
  pkgs = nixpkgs.legacyPackages."${system}";
  supervisord' = "${supervisord}/bin/supervisord";
  dnsproxy' = "${dnsproxy}/bin/dnsproxy";
  itvroProxy = "${raw-proxy}/bin/ip-to-vsock-raw-outgoing";
  vtiriProxy = "${raw-proxy}/bin/vsock-to-ip-raw-incoming";
  attestationServer = "${attestation-server}/bin/attestation-server";
  vet' = "${vet}/bin/vet";
  kernel = "${kernels}/${systemConfig.eif_arch}/bzImage";
  kernelConfig = "${kernels}/${systemConfig.eif_arch}/bzImage.config";
  nsmKo = "${kernels}/${systemConfig.eif_arch}/nsm.ko";
  init = "${kernels}/${systemConfig.eif_arch}/init";
  setup = ./. + "/setup.sh";
  supervisorConf = ./. + "/supervisord.conf";
  app = pkgs.runCommand "app" {} ''
    echo Preparing the app folder
    pwd
    mkdir -p $out
    mkdir -p $out/app
    mkdir -p $out/etc
    cp ${supervisord'} $out/app/supervisord
    cp ${itvroProxy} $out/app/ip-to-vsock-raw-outgoing
    cp ${vtiriProxy} $out/app/vsock-to-ip-raw-incoming
    cp ${attestationServer} $out/app/attestation-server
    cp ${dnsproxy'} $out/app/dnsproxy
    cp ${vet'} $out/app/vet
    cp ${setup} $out/app/setup.sh
    chmod +x $out/app/*
    cp ${supervisorConf} $out/etc/supervisord.conf
  '';
  # kinda hacky, my nix-fu is not great, figure out a better way
  initPerms = pkgs.runCommand "initPerms" {} ''
    cp ${init} $out
    chmod +x $out
  '';
in {
  default = nitro.buildEif {
    name = "enclave";
    arch = eifArch;

    init = initPerms;
    kernel = kernel;
    kernelConfig = kernelConfig;
    nsmKo = nsmKo;
    cmdline = builtins.readFile nitro.blobs.${eifArch}.cmdLine;

    entrypoint = "/app/setup.sh";
    env = "IMAGE_NAME=${dockerOrganization}/tee-server-${dockerType}:${dockerTag}";
    copyToRoot = pkgs.buildEnv {
      name = "image-root";
      paths = [app pkgs.busybox pkgs.nettools pkgs.iproute2 pkgs.iptables-legacy pkgs.iptables-nft pkgs.ipset pkgs.cacert pkgs.docker];
      pathsToLink = ["/bin" "/app" "/etc"];
    };
  };
}
