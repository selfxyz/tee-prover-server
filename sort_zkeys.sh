#!/bin/bash

ZKEYS_DIR="zkeys"

source constants.sh

sort_zkeys() {
    local CATEGORY="$1"
    shift
    local CIRCUITS=("$@")

    local CATEGORY_DIR="$ZKEYS_DIR/$CATEGORY"

    mkdir -p "$CATEGORY_DIR/small" "$CATEGORY_DIR/medium" "$CATEGORY_DIR/large"

    for circuit in "${CIRCUITS[@]}"; do
        local CIRCUIT_NAME="${circuit%%:*}"
        local SIZE="${circuit##*:}"

        if [[ -f "$CATEGORY_DIR/$CIRCUIT_NAME.zkey" ]]; then
            mv "$CATEGORY_DIR/$CIRCUIT_NAME.zkey" "$CATEGORY_DIR/$SIZE/"
        fi
    done

    find "$CATEGORY_DIR" -maxdepth 1 -type f -name "*.zkey" -exec mv {} "$CATEGORY_DIR/small/" \;
}

sort_zkeys "register" "${register_circuits[@]}"
sort_zkeys "dsc" "${dsc_circuits[@]}"
sort_zkeys "disclose" "${disclose_circuits[@]}"

echo "Zkey files sorted successfully!"