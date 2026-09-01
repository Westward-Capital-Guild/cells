#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
revision="$(git -C "$repo_root" rev-parse HEAD)"
build_stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
go_version="$(awk '/^toolchain / {sub(/^go/, "", $2); print $2}' "$repo_root/go.mod")"
test -n "$go_version"

docker buildx build \
  --load \
  --platform linux/amd64 \
  --build-arg BUILD_MODE=compile \
  --build-arg GO_VERSION="$go_version" \
  --build-arg VERSION=5.0.2-denox-oidc-poc-v0.2.4 \
  --build-arg GIT_REV="$revision" \
  --build-arg BUILD_STAMP="$build_stamp" \
  --build-arg DOCKER_ENTRYPOINT_SRC_DIR=tools/docker/images/cells \
  --build-arg SOURCE_URL=https://github.com/Westward-Capital-Guild/cells/tree/denox-poc-v0.2.4 \
  --build-arg IMAGE_VENDOR="Westward Capital Guild" \
  -t customer-file-platform-cells:oidc-poc-v0.2.4 \
  -f "$repo_root/tools/docker/images/cells/buildx-dockerfile" \
  "$repo_root"
