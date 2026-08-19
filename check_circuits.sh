#!/bin/bash

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/constants.sh"

# Layout of the ALWAYS_CIRCUITS artifacts, which differs per image family:
#   (default) circuits/common/<name>_cpp + zkeys/common/<name>.zkey
#             — what Dockerfile.tee COPYs, since its per-variant COPY is filtered by
#               PROOFTYPE/SIZE_FILTER and these circuits ship in every variant.
#   --flat    circuits/<name>_cpp + zkeys/<name>.zkey
#             — what Dockerfile.cherrypick COPYs, since it takes ./circuits and
#               ./zkeys wholesale after sort_circuits.cherrypick.sh flattens them.
# Passed explicitly rather than probed, so each build asserts the layout it will
# actually COPY from instead of accepting either and failing later in `docker build`.
layout="common"
for arg in "$@"; do
    case "$arg" in
        --flat) layout="flat" ;;
        *) echo "usage: $0 [--flat]" >&2; exit 2 ;;
    esac
done

CIRCUITS_ROOT="circuits"
ZKEYS_ROOT="zkeys"

types=("register" "disclose" "dsc")
sizes=("small" "medium" "large")

missing=()
missing_always=0

for type in "${types[@]}"; do
    for size in "${sizes[@]}"; do
        circuits_dir="${CIRCUITS_ROOT}/${type}/${size}"
        zkeys_dir="${ZKEYS_ROOT}/${type}/${size}"

        [[ -d "$circuits_dir" ]] || continue

        shopt -s nullglob
        for path in "${circuits_dir}"/*; do
            [[ -d "$path" ]] || continue

            name="$(basename "$path")"
            base_name="${name%_cpp}"
            zkey_file="${zkeys_dir}/${base_name}.zkey"

            if [[ ! -f "$zkey_file" ]]; then
                missing+=("${type}/${size}/${base_name}.zkey")
            fi
        done
        shopt -u nullglob
    done
done

# ALWAYS_CIRCUITS (constants.sh) ship unconditionally in EVERY image variant, so a
# missing circuit directory or a missing zkey is an ERROR here, never something to
# skip. This block used to skip itself when the directory was absent, which made the
# only loud signal a `COPY` failure partway through seven image builds: a wrong bucket
# string leaves `download_zkeys.sh`'s `latest_file` empty, the workflow's guarded `mv`
# then no-ops by design, and this check passed. That is the failure mode this job
# exists to catch, so it is checked positively.
for name in "${ALWAYS_CIRCUITS[@]}"; do
    if [[ "$layout" == "flat" ]]; then
        circuit_dir="${CIRCUITS_ROOT}/${name}_cpp"
        zkey_file="${ZKEYS_ROOT}/${name}.zkey"
    else
        circuit_dir="${CIRCUITS_ROOT}/common/${name}_cpp"
        zkey_file="${ZKEYS_ROOT}/common/${name}.zkey"
    fi

    if [[ ! -d "$circuit_dir" ]]; then
        missing+=("${circuit_dir}/ (circuit directory, required in every image)")
        missing_always=1
    fi

    if [[ ! -f "$zkey_file" ]]; then
        missing+=("${zkey_file} (required in every image)")
        missing_always=1
    fi
done

if (( ${#missing[@]} > 0 )); then
    echo "Missing circuit artifacts:" >&2
    for m in "${missing[@]}"; do
        echo "  $m" >&2
    done
    if (( missing_always == 1 )); then
        echo >&2
        echo "The entries above marked 'required in every image' come from ALWAYS_CIRCUITS in" >&2
        echo "constants.sh (${layout} layout). Every image variant COPYs them and the server" >&2
        echo "panics at boot without them, so this is fatal here rather than a docker build" >&2
        echo "failure later. Likely causes: the circuit binary was not published to" >&2
        echo "gs://zk_circuits/output, or the ceremony bucket in download_zkeys.sh (or" >&2
        echo "download_zkeys.cherrypick.sh) does not resolve to a .zkey." >&2
    fi
    exit 1
fi

echo "All circuits have corresponding zkeys."
