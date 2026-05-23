#!/usr/bin/env bash
set -euo pipefail

# Build and push Docker images for a HenKaiPan release.
# Usage: ./scripts/build-release.sh v1.17.0

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v1.17.0"
    exit 1
fi

VERSION="$1"
BUILD_DATE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
REGISTRY="ghcr.io/dyallab"

echo "==> Building release ${VERSION}"
echo "    BUILD_DATE=${BUILD_DATE}"
echo ""

check_docker() {
    if ! docker info &>/dev/null; then
        echo "Error: Docker is not running or not accessible"
        exit 1
    fi
}

build_and_push() {
    local name="$1"
    local dockerfile="$2"

    echo "==> Building ${name}:${VERSION} ..."
    docker build \
        --build-arg "VERSION=${VERSION}" \
        --build-arg "BUILD_DATE=${BUILD_DATE}" \
        -f "${dockerfile}" \
        -t "${REGISTRY}/${name}:${VERSION}" \
        -t "${REGISTRY}/${name}:latest" \
        .

    echo "==> Pushing ${name}:${VERSION} ..."
    docker push "${REGISTRY}/${name}:${VERSION}"

    echo "==> Pushing ${name}:latest ..."
    docker push "${REGISTRY}/${name}:latest"

    echo ""
}

check_docker

build_and_push "henkaipan-api" "docker/api.Dockerfile"
build_and_push "henkaipan-worker" "docker/worker.Dockerfile"

echo "==> Done! Release ${VERSION} published."
echo "    https://github.com/Dyallab/HenKaiPan-self-hosted/releases/tag/${VERSION}"
