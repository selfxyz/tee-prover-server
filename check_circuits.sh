#!/bin/bash

set -euo pipefail

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

if (( ${#missing[@]} > 0 )); then
    echo "Missing zkeys for the following circuits:" >&2
    for m in "${missing[@]}"; do
        echo "  $m" >&2
    done
    exit 1
fi

echo "All circuits have corresponding zkeys."
