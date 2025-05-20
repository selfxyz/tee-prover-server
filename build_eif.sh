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

mkdir ./tmp-result
for DIR in $(find ./result/* -type l); do
    type=$(basename $DIR)
    REAL_PATH=$(realpath $DIR)
    unlink $DIR
    echo $REAL_PATH $type
    cp -r $REAL_PATH ./tmp-result/$type
done

cp -r tmp-result/* ./result/
