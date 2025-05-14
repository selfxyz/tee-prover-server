#!/bin/bash

# Base directory for circuit folders
CIRCUITS_DIR="circuits"

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

# Function to sort folders into size categories
sort_folders() {
    local CATEGORY="$1"
    shift
    local CIRCUITS=("$@")

    # Define the category path
    local CATEGORY_DIR="$CIRCUITS_DIR/$CATEGORY"

    # Ensure size subdirectories exist
    mkdir -p "$CATEGORY_DIR/small" "$CATEGORY_DIR/medium" "$CATEGORY_DIR/large"

    # Move known circuits based on size
    for circuit in "${CIRCUITS[@]}"; do
        local CIRCUIT_NAME="${circuit%%:*}_cpp"
        local SIZE="${circuit##*:}"

        echo $CIRCUIT_NAME $SIZE
        if [[ -d "$CATEGORY_DIR/$CIRCUIT_NAME" ]]; then
            echo "------------"
            echo "$CATEGORY_DIR/$CIRCUIT_NAME" "$CATEGORY_DIR/$SIZE/"
            mv "$CATEGORY_DIR/$CIRCUIT_NAME" "$CATEGORY_DIR/$SIZE/"
        fi
        echo "00000000000000000000000000000000000000000000000000000"
    done

    # Move all remaining folders into small
    find "$CATEGORY_DIR" -mindepth 1 -maxdepth 1 -type d ! -path "$CATEGORY_DIR/small" ! -path "$CATEGORY_DIR/medium" ! -path "$CATEGORY_DIR/large" -exec mv {} "$CATEGORY_DIR/small/" \;
}

# Sort only dsc folders for now

sort_folders "register" "${register_circuits[@]}"
sort_folders "disclose" "${disclose_circuits[@]}"
sort_folders "dsc" "${dsc_circuits[@]}"

echo "Circuit folders sorted successfully!"