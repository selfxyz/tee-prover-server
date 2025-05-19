#!/bin/bash

source constants.sh

if [ $# -ne 1 ]; then
    echo "Usage: $0 <tag>"
    exit 1
fi

TAG=$1

pids=()

for ITEM in "${PROOFS_SIZES[@]}"; do
    PROOF="${ITEM%%:*}"
    SIZE="${ITEM##*:}"

    echo "Building EIF for ${PROOF} with size ${SIZE}"
    nix build .#musl.enclave-${PROOF}-${SIZE}-${TAG}.default --out-link ./result/${PROOF}-${SIZE}-${TAG} & 
    pids+=($!)
done

wait "${pids[@]}"