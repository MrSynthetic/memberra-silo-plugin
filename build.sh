#!/usr/bin/env bash
# Build release binaries for Silo's supported platforms into dist/.
set -euo pipefail
cd "$(dirname "$0")"
version="${1:-$(python3 -c 'import json;print(json.load(open("manifest.json"))["version"])')}"
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/arm64; do
  os="${target%/*}" arch="${target#*/}"
  out="dist/memberra-silo-${version}-${os}-${arch}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=${version}" -o "$out" .
  sha256sum "$out" | tee "$out.sha256"
done
