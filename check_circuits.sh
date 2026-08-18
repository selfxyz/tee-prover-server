#!/bin/bash

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/constants.sh"

CIRCUITS_ROOT="circuits"
ZKEYS_ROOT="zkeys"

types=("register" "disclose" "dsc")
sizes=("small" "medium" "large")

missing=()

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

# ALWAYS_CIRCUITS (constants.sh) ship unconditionally in every image variant,
# under circuits/common and zkeys/common rather than a type/size bucket.
common_circuits_dir="${CIRCUITS_ROOT}/common"
common_zkeys_dir="${ZKEYS_ROOT}/common"

if [[ -d "$common_circuits_dir" ]]; then
    for name in "${ALWAYS_CIRCUITS[@]}"; do
        circuit_dir="${common_circuits_dir}/${name}_cpp"
        zkey_file="${common_zkeys_dir}/${name}.zkey"

        [[ -d "$circuit_dir" ]] || continue

        if [[ ! -f "$zkey_file" ]]; then
            missing+=("common/${name}.zkey")
        fi
    done
fi

if (( ${#missing[@]} > 0 )); then
    echo "Missing zkeys for the following circuits:" >&2
    for m in "${missing[@]}"; do
        echo "  $m" >&2
    done
    exit 1
fi

echo "All circuits have corresponding zkeys."
