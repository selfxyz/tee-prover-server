#!/bin/bash

# Define proof type and size as pairs
PROOFS_SIZES=(
    "register:small"
    "register:medium"
    "register:large"
    "disclose:small"
    "dsc:small"
    "dsc:medium"
    "dsc:large"
)

DOCKER_ORG=$1
TAG=$2
TARGET=$3

BUILD_COMMANDS=()
for ITEM in "${PROOFS_SIZES[@]}"; do
    PROOF="${ITEM%%:*}"  
    SIZE="${ITEM##*:}"   

    IMAGE_NAME="${DOCKER_ORG}/tee-server-${PROOF}"
    [[ ${TARGET} == "instance" ]] && IMAGE_NAME+="-${TARGET}"
    [[ "$SIZE" != "small" ]] && IMAGE_NAME+="-${SIZE}"

    BUILD_COMMANDS+=("sudo docker build --build-arg PROOFTYPE=$PROOF --build-arg SIZE_FILTER=$SIZE -f Dockerfile.tee --target=${TARGET} -t ${IMAGE_NAME}:${TAG} .")
done

printf "%s\n" "${BUILD_COMMANDS[@]}" | xargs -I {} -P 2 bash -c "{}"