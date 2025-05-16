#!/bin/bash

source constants.sh

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
    DOCKERFILE="Dockerfile.tee"
    [[ ${TARGET} == "instance" ]] && DOCKERFILE+=".instance"

    BUILD_COMMANDS+=("sudo docker build --build-arg PROOFTYPE=$PROOF --build-arg SIZE_FILTER=$SIZE --build-arg TAG=${TAG} -f ${DOCKERFILE} -t ${IMAGE_NAME}:${TAG} .")
done

printf "%s\n" "${BUILD_COMMANDS[@]}" | xargs -I {} -P 2 bash -c "{}"