#!/bin/bash

# take in the input as org, proof type, size, tag
if [ $# -ne 4 ]; then
    echo "Usage: $0 <org> <proof> <size> <tag>"
    exit 1
fi

DOCKER_ORG=$1
PROOF=$2
SIZE=$3
TAG=$4

IMAGE_NAME="${DOCKER_ORG}/tee-server-${PROOF}"
[[ "$SIZE" != "small" ]] && IMAGE_NAME+="-${SIZE}"

sudo docker build --build-arg PROOFTYPE=$PROOF --build-arg SIZE_FILTER=$SIZE -f Dockerfile.tee -t ${IMAGE_NAME}:${TAG} .")