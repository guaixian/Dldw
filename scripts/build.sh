#!/usr/bin/env bash
# Build dldw for all supported platforms (run from repo root).
set -euo pipefail

VERSION="${DLDW_VERSION:-1.0.0}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date +%F)"

LDFLAGS="-s -w -X dldw/internal/version.Version=${VERSION} -X dldw/internal/version.Commit=${COMMIT} -X dldw/internal/version.Date=${DATE}"

mkdir -p dist
for target in windows/amd64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
    GOOS="${target%/*}"
    GOARCH="${target#*/}"
    name="dldw-${GOOS}-${GOARCH}"
    [[ "$GOOS" == "windows" ]] && name="${name}.exe"
    echo "building ${name}"
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags "$LDFLAGS" -o "dist/${name}" ./cmd/dldw
done
echo "artifacts in dist/"
