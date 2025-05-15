#!/bin/bash

PROOF_SIZE_PAIRS=(
    "register:small"
    "register:medium"
    "register:large"
    "disclose:small"
    "dsc:small"
    "dsc:medium"
    "dsc:large"
)

if [ $# -ne 1 ]; then
    echo "Usage: $0 <tag>"
    exit 1
fi

TAG=$1

pids=()

for ITEM in "${PROOF_SIZE_PAIRS[@]}"; do
    PROOF="${ITEM%%:*}"
    SIZE="${ITEM##*:}"

    echo "Building EIF for ${PROOF} with size ${SIZE}"
    nix build .#musl.enclave-${PROOF}-${SIZE}-${TAG}.default --out-link ./result/${PROOF}-${SIZE}-${TAG}.eif & 
    pids+=($!)
done

wait "${pids[@]}"