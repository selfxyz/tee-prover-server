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
TYPE=$3

PUSH_COMMANDS=()
for ITEM in "${PROOFS_SIZES[@]}"; do
    PROOF="${ITEM%%:*}"
    SIZE="${ITEM##*:}"

    IMAGE_NAME="${DOCKER_ORG}/tee-server-${PROOF}"
    IMAGE_NAME+="-${SIZE}"
    [[ "$TYPE" == "instance" ]] && IMAGE_NAME+="-${TYPE}"
    PUSH_COMMANDS+=("sudo docker push ${IMAGE_NAME}:${TAG}")
done

printf "%s\n" "${PUSH_COMMANDS[@]}" | xargs -I {} -P 3 bash -c "{}"

echo "Docker images pushed successfully!"