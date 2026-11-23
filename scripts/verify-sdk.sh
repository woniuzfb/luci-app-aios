#!/usr/bin/env bash
set -euo pipefail

# Local OpenWrt SDK packaging verification helper (uses official OpenWrt SDK Docker image)
# Usage: ./scripts/verify-sdk.sh [x86-64-23.05.5|x86-64-25.12.4]

SDK_TAG="${1:-x86-64-23.05.5}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> 1. Building Vite + Vue 3 frontend..."
(cd "${REPO_ROOT}/web" && pnpm test && pnpm build)

echo "==> 2. Compiling OpenWrt packages with openwrt/sdk:${SDK_TAG}..."
docker run --rm \
  -v "${REPO_ROOT}/packages:/builder/package/luci-app-aios-bundle:ro" \
  -v "${REPO_ROOT}/dist-packages:/out" \
  "openwrt/sdk:${SDK_TAG}" \
  bash -c '
    ./scripts/feeds update -a
    ./scripts/feeds install -a
    make defconfig
    make package/luci-app-aios-bundle/luci-app-aios/{clean,compile} V=s
    make package/luci-app-aios-bundle/luci-app-aios-geodata/{clean,compile} V=s
    make package/luci-app-aios-bundle/luci-app-aios-status/{clean,compile} V=s
    mkdir -p /out
    find bin/packages -type f \( -name "luci-app-aios*.ipk" -o -name "luci-app-aios*.apk" \) -exec cp {} /out/ \;
    ls -lh /out
  '
