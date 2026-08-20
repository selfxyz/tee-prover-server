#!/bin/bash
#
# Downloads the compiled witness generator for every ALWAYS_CIRCUITS entry.
#
# These circuits ship in EVERY image variant (see constants.sh), and the server
# panics at boot without them, but they are not in gs://zk_circuits/output --
# that bucket carries only the register, disclose and dsc families. The
# attestation circuit lives in its own ceremony bucket instead, as a sibling of
# the contributions/ directory download_zkeys*.sh already pulls its .zkey from:
#
#   gs://<bucket>/circuits/<name>/contributions/<name>_0000N.zkey   <- the zkey
#   gs://<bucket>/circuits/<name>/<name>_cpp/                       <- this script
#
# Without this the zkey downloads cleanly and the circuit is simply absent, which
# is precisely the split check_circuits.sh reported: a required circuit missing
# while its zkey is present. csca-auto-updater's download_circuit_and_zkey.sh
# fetches the same pair from the same place.
#
# Output lands flat at circuits/<name>_cpp, which both layouts then handle:
# sort_circuits.sh moves it into circuits/common for Dockerfile.tee's filtered
# copies, and the cherrypick path is already flat.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/constants.sh"

OUTPUT_DIR="${1:-circuits}"
mkdir -p "$OUTPUT_DIR"

for name in "${ALWAYS_CIRCUITS[@]}"; do
    # Kept as an explicit case, mirroring download_zkeys*.sh, so a new entry in
    # ALWAYS_CIRCUITS fails loudly here rather than silently downloading nothing.
    case "$name" in
        gcp_jwt_verifier) bucket="ecdsa-fix-plus-jwt" ;;
        *)
            echo "FATAL: no bucket mapping for always-present circuit: $name" >&2
            exit 1
            ;;
    esac

    dest="${OUTPUT_DIR}/${name}_cpp"
    if [ -d "$dest" ]; then
        echo "$dest already present -- leaving it alone."
    else
        src="gs://${bucket}/circuits/${name}/${name}_cpp"
        echo "Downloading $src -> $dest"
        gsutil -m cp -r "$src" "$OUTPUT_DIR/"
    fi

    # Positive assertions, not a trailing `|| true`: a partial copy that leaves
    # the directory without its binary would otherwise surface as a chmod
    # failure inside `docker build`, which is the late signal check_circuits.sh
    # exists to replace.
    if [ ! -d "$dest" ]; then
        echo "FATAL: $dest missing after download" >&2
        exit 1
    fi
    if [ ! -f "${dest}/${name}" ]; then
        echo "FATAL: ${dest}/${name} (witness generator binary) missing after download" >&2
        exit 1
    fi

    chmod +x "${dest}/${name}"
    echo "OK: $dest"
done
