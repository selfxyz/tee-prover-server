#!/bin/bash
set -euo pipefail

PROOFS_SIZES=(
  "register:small"
  "register:medium"
  "register:large"
  "disclose:small"
  "dsc:small"
  "dsc:medium"
  "dsc:large"
)

DOCKER_ORG="$1"   # e.g. us-docker.pkg.dev/PROJECT/REPO
TAG="$2"

OUT_FILE="${GITHUB_WORKSPACE:-.}/pushed-image-digests.txt"
: > "$OUT_FILE"

for ITEM in "${PROOFS_SIZES[@]}"; do
  PROOF="${ITEM%%:*}"
  SIZE="${ITEM##*:}"

  IMAGE_NAME="${DOCKER_ORG}/tee-server-${PROOF}"
  [[ "$SIZE" != "small" ]] && IMAGE_NAME+="-${SIZE}"

  IMAGE_REF="${IMAGE_NAME}:${TAG}"
  echo "Pushing ${IMAGE_REF} ..."
  docker push "${IMAGE_REF}"

  # Get the content digest (sha256) from local metadata
  DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE_REF}")
  if [[ -n "$DIGEST" ]]; then
    echo "$DIGEST" >> "$OUT_FILE"
  else
    echo "WARNING: No digest found for ${IMAGE_REF}" >&2
  fi
done

echo "Docker images pushed successfully!"
echo "Wrote pushed image digests to ${OUT_FILE}"
