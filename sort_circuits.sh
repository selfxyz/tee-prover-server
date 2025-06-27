#!/bin/bash

CIRCUITS_DIR="circuits"

source constants.sh

sort_folders() {
    local CATEGORY="$1"
    shift
    local CIRCUITS=("$@")

    local CATEGORY_DIR="$CIRCUITS_DIR/$CATEGORY"

    mkdir -p "$CATEGORY_DIR/small" "$CATEGORY_DIR/medium" "$CATEGORY_DIR/large"

    for circuit in "${CIRCUITS[@]}"; do
        local CIRCUIT_NAME="${circuit%%:*}_cpp"
        local SIZE="${circuit##*:}"

        if [[ -d "$CATEGORY_DIR/$CIRCUIT_NAME" ]]; then
            mv "$CATEGORY_DIR/$CIRCUIT_NAME" "$CATEGORY_DIR/$SIZE/"
        fi
    done

    find "$CATEGORY_DIR" -mindepth 1 -maxdepth 1 -type d ! -path "$CATEGORY_DIR/small" ! -path "$CATEGORY_DIR/medium" ! -path "$CATEGORY_DIR/large" -exec mv {} "$CATEGORY_DIR/small/" \;
}

sort_folders "register" "${register_circuits[@]}"
sort_folders "disclose" "${disclose_circuits[@]}"
sort_folders "dsc" "${dsc_circuits[@]}"

echo "Circuit folders sorted successfully!"