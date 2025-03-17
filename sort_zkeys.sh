#!/bin/bash

# Base zkeys directory
ZKEYS_DIR="zkeys"

# Define the circuits and their sizes
register_circuits=(
  "register_sha512_sha512_sha512_ecdsa_secp521r1:large"
  "register_sha512_sha512_sha512_ecdsa_brainpoolP512r1:large" 
  "register_sha384_sha384_sha384_ecdsa_brainpoolP512r1:large" 
  "register_sha256_sha256_sha256_ecdsa_brainpoolP384r1:medium" 
  "register_sha256_sha256_sha256_ecdsa_secp384r1:medium" 
  "register_sha384_sha384_sha384_ecdsa_brainpoolP384r1:medium" 
  "register_sha384_sha384_sha384_ecdsa_secp384r1:medium"
)

dsc_circuits=(
  "dsc_sha256_ecdsa_secp521r1:large"
  "dsc_sha512_ecdsa_secp521r1:large"
  "dsc_sha384_ecdsa_brainpoolP512r1:large" 
  "dsc_sha512_ecdsa_brainpoolP512r1:large" 
  "dsc_sha256_ecdsa_brainpoolP384r1:medium" 
  "dsc_sha256_ecdsa_secp384r1:medium" 
  "dsc_sha384_ecdsa_brainpoolP384r1:medium" 
  "dsc_sha384_ecdsa_secp384r1:medium"
)

disclose_circuits=()

# Function to sort circuits into small, medium, or large
sort_zkeys() {
    local CATEGORY="$1"
    shift
    local CIRCUITS=("$@")

    # Define the category path
    local CATEGORY_DIR="$ZKEYS_DIR/$CATEGORY"

    # Ensure subdirectories exist
    mkdir -p "$CATEGORY_DIR/small" "$CATEGORY_DIR/medium" "$CATEGORY_DIR/large"

    # Move files based on predefined circuit sizes
    for circuit in "${CIRCUITS[@]}"; do
        local CIRCUIT_NAME="${circuit%%:*}"  # Extract circuit name
        local SIZE="${circuit##*:}"          # Extract size

        if [[ -f "$CATEGORY_DIR/$CIRCUIT_NAME.zkey" ]]; then
            mv "$CATEGORY_DIR/$CIRCUIT_NAME.zkey" "$CATEGORY_DIR/$SIZE/"
        fi
    done

    # Move everything else to small
    find "$CATEGORY_DIR" -maxdepth 1 -type f -name "*.zkey" -exec mv {} "$CATEGORY_DIR/small/" \;
}

# Run sorting for register and dsc categories
sort_zkeys "register" "${register_circuits[@]}"
sort_zkeys "dsc" "${dsc_circuits[@]}"
sort_zkeys "disclose" "${dsc_circuits[@]}"

echo "Zkey files sorted successfully!"