#!/usr/bin/env bash
set -euo pipefail

# Release helper for luci-app-aios
# Usage: ./scripts/release.sh <version> [--push] [--skip-matrix]
# Example: ./scripts/release.sh v3.0.1 --push

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

usage() {
	cat <<'EOF'
Usage: ./scripts/release.sh <version> [--push] [--skip-matrix]

Options:
  <version>       Release version (e.g. v3.0.1 or 3.0.1)
  --push          Push branch and tag to origin to trigger GitHub Actions release
  --skip-matrix   Skip local .memory/cores multi-version binary matrix verification
EOF
}

die() {
	echo "ERROR: $*" >&2
	exit 1
}

[ $# -ge 1 ] || { usage; exit 1; }
RAW_VER="$1"
shift

DO_PUSH=0
SKIP_MATRIX=0
while [ $# -gt 0 ]; do
	case "$1" in
		--push) DO_PUSH=1; shift ;;
		--skip-matrix) SKIP_MATRIX=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) die "Unknown option: $1" ;;
	esac
done

PKG_VER="${RAW_VER#v}"
TAG="v${PKG_VER}"
if ! printf '%s\n' "$PKG_VER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$'; then
	die "Invalid version format: ${RAW_VER} (expected e.g. v3.0.1 or 3.0.1)"
fi

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
	die "Tag ${TAG} already exists"
fi

if [ -n "$(git status --porcelain)" ]; then
	die "Working tree is not clean. Commit or stash changes before running release.sh"
fi

echo "==> 1. Syncing PKG_VERSION=${PKG_VER} in packages/luci-app-aios/Makefile..."
mk="packages/luci-app-aios/Makefile"
[ -f "$mk" ] || die "Makefile not found: $mk"
awk -v v="$PKG_VER" '
	index($0, "PKG_VERSION:=") == 1 { print "PKG_VERSION:=" v; next }
	{ print }
' "$mk" > "${mk}.tmp"
mv -f "${mk}.tmp" "$mk"

echo "==> 2. Running frontend tests, typecheck, and Vite production build..."
(cd "${REPO_ROOT}/web" && pnpm test && pnpm build)

echo "==> 3. Validating OpenWrt shell and helper scripts..."
sh -n \
	packages/luci-app-aios/root/etc/init.d/aios \
	packages/luci-app-aios/root/usr/libexec/rpcd/luci.aios \
	packages/luci-app-aios/root/usr/share/aios/firewall/fw3_ipt.sh \
	packages/luci-app-aios/root/usr/share/aios/core_manager.sh \
	packages/luci-app-aios/root/etc/hotplug.d/iface/90-aios-gateway \
	packages/luci-app-aios/root/etc/uci-defaults/90-luci-aios
bash -n scripts/core-versions.sh scripts/verify-sdk.sh scripts/release.sh
node --check scripts/verify-core-matrix.mjs

if [ "$SKIP_MATRIX" -eq 0 ] && [ -f "${REPO_ROOT}/.memory/cores/manifest.json" ]; then
	echo "==> 4. Running local multi-version core binary matrix verification..."
	node scripts/verify-core-matrix.mjs
fi

if ! git diff --quiet packages/; then
	git add packages/luci-app-aios/Makefile
	git commit -m "chore(release): bump package version to ${TAG}"
fi

git tag -a "$TAG" -m "Release ${TAG}"
BRANCH="$(git branch --show-current)"
echo "==> Created annotated tag ${TAG} on branch ${BRANCH}."

if [ "$DO_PUSH" -eq 1 ]; then
	echo "==> Pushing ${BRANCH} and ${TAG} to origin..."
	git push origin "$BRANCH"
	git push origin "$TAG"
	echo "==> Release ${TAG} pushed. Monitor GitHub Actions for package build and release publication."
else
	echo "Dry-push mode (tag created locally). Run the following commands to publish:"
	echo "  git push origin ${BRANCH}"
	echo "  git push origin ${TAG}"
fi
