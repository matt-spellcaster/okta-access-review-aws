#!/usr/bin/env bash
# Build the Lambda image from the locked dependencies.
#   scripts/build_image.sh <image tag>
# Prints nothing secret; the requirements file is deleted afterwards.
set -euo pipefail
tag="${1:?usage: scripts/build_image.sh <image tag>}"
cd "$(dirname "$0")/.."
uv export --frozen --no-dev --no-emit-project --format requirements-txt > requirements.txt
trap 'rm -f requirements.txt' EXIT
docker build --platform linux/arm64 --provenance=false -t "$tag" .
