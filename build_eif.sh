#!/bin/bash

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

BUILD_COMMANDS=()
for ITEM in "${PROOFS_SIZES[@]}"; do
    PROOF="${ITEM%%:*}"
    SIZE="${ITEM##*:}" 

    IMAGE_NAME="${DOCKER_ORG}/tee-server-${PROOF}"
    [[ "$SIZE" != "small" ]] && IMAGE_NAME+="-${SIZE}"

    OUTPUT_FILE="prover-server-${PROOF}-${SIZE}.eif"

    LOG_FILE="measurements/${PROOF}-${SIZE}.log"
    BUILD_COMMANDS+=("sudo nitro-cli build-enclave --docker-uri ${IMAGE_NAME}:${TAG} --output-file ${OUTPUT_FILE} > ${LOG_FILE} 2>&1")
done

printf "%s\n" "${BUILD_COMMANDS[@]}" | xargs -I {} -P 1 bash -c "{}"