#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORES_DIR="${REPO_ROOT}/.memory/cores"
GEODATA_DIR="${CORES_DIR}/geodata"
MANIFEST="${CORES_DIR}/manifest.json"

XRAY_SRC_DEFAULT="${XRAY_SRC:-${REPO_ROOT}/../Xray-core}"
V2RAY_SRC_DEFAULT="${V2RAY_SRC:-${REPO_ROOT}/../v2ray-core}"

_CLEANUP_TMPDIR=""
_CLEANUP_WT_SRC=""
_CLEANUP_WT_DIR=""

cleanup_all() {
	if [ -n "${_CLEANUP_WT_DIR}" ] && [ -n "${_CLEANUP_WT_SRC}" ]; then
		git -C "${_CLEANUP_WT_SRC}" worktree remove --force "${_CLEANUP_WT_DIR}" >/dev/null 2>&1 || true
		rm -rf "${_CLEANUP_WT_DIR}" >/dev/null 2>&1 || true
	fi
	if [ -n "${_CLEANUP_TMPDIR}" ]; then
		rm -rf "${_CLEANUP_TMPDIR}" >/dev/null 2>&1 || true
	fi
}
trap cleanup_all EXIT

usage() {
	cat <<'EOF'
Usage: scripts/core-versions.sh <command> [args]

Commands:
  list                                              List installed cores, role symlinks, and geodata
  import <xray|v2ray> <bin-path> [--tag <tag>] [--slot <s1,s2>]
                                                    Import an existing local binary into .memory/cores/
  install <xray|v2ray> <tag> [--slot <s1,s2>] [--mirror <prefix>]
                                                    Download & verify official GitHub Release binary
  build <xray|v2ray> <git-ref> [--slot <s1,s2>] [--src <repo-dir>]
                                                    Build from local git repo via temporary git worktree
  use <xray|v2ray> <tag> [--slot <slot>]            Point role symlink (default: current) to <tag>
  sync-geodata [--from <dir>]                       Sync shared geoip.dat / geosite.dat into .memory/cores/geodata/
  remove <xray|v2ray> <tag>                         Remove a non-current version directory
EOF
}

die() {
	echo "ERROR: $*" >&2
	exit 1
}

validate_core() {
	case "$1" in
		xray|v2ray) ;;
		*) die "Invalid core '$1' (expected 'xray' or 'v2ray')" ;;
	esac
}

validate_tag() {
	local t="$1"
	if [ -z "$t" ] || [ "$t" = "." ] || [ "$t" = ".." ]; then
		die "Invalid tag '$t'"
	fi
	if ! printf '%s\n' "$t" | grep -qE '^[a-zA-Z0-9._-]+$'; then
		die "Invalid tag '$t' (allowed: letters, digits, '.', '_', '-')"
	fi
}

calc_sha256() {
	local file="$1"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$file" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$file" | awk '{print $1}'
	else
		die "Neither sha256sum nor shasum found"
	fi
}

detect_release_arch() {
	local os arch
	os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	arch="$(uname -m)"
	case "$os" in
		darwin)
			case "$arch" in
				arm64|aarch64) echo "macos-arm64-v8a" ;;
				x86_64|amd64) echo "macos-64" ;;
				*) die "Unsupported macOS arch: $arch" ;;
			esac
			;;
		linux)
			case "$arch" in
				x86_64|amd64) echo "linux-64" ;;
				arm64|aarch64) echo "linux-arm64-v8a" ;;
				armv7l) echo "linux-arm32-v7a" ;;
				*) die "Unsupported Linux arch: $arch" ;;
			esac
			;;
		*)
			die "Unsupported OS: $os"
			;;
	esac
}

extract_core_version() {
	local bin="$1"
	local line ver
	line="$("$bin" version 2>/dev/null | head -n 1 || true)"
	ver="$(printf '%s\n' "$line" | sed -nE 's/.*[[:space:]]([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n 1)"
	echo "${ver:-unknown}"
}

ensure_dirs() {
	mkdir -p "${CORES_DIR}/xray" "${CORES_DIR}/v2ray" "${GEODATA_DIR}"
	if [ ! -f "${MANIFEST}" ]; then
		cat <<'EOF' > "${MANIFEST}"
{
  "schemaVersion": 1,
  "geodataDir": "geodata",
  "cores": {
    "xray": {
      "slots": {},
      "versions": {}
    },
    "v2ray": {
      "slots": {},
      "versions": {}
    }
  }
}
EOF
	fi
}

update_manifest_version() {
	local core="$1" tag="$2" version="$3" sha256="$4" source="$5" bin_rel="$6" slots_csv="${7:-}"
	node - "${MANIFEST}" "$core" "$tag" "$version" "$sha256" "$source" "$bin_rel" "$slots_csv" <<'NODE'
const fs = require('node:fs');
const [manifestPath, core, tag, version, sha256, source, binRel, slotsCsv] = process.argv.slice(2);
const data = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
data.cores = data.cores || { xray: { slots: {}, versions: {} }, v2ray: { slots: {}, versions: {} } };
data.cores[core] = data.cores[core] || { slots: {}, versions: {} };
data.cores[core].versions[tag] = {
  tag,
  version,
  binary: binRel,
  sha256,
  source,
  installedAt: new Date().toISOString()
};
if (slotsCsv) {
  for (const s of slotsCsv.split(',').map(x => x.trim()).filter(Boolean)) {
    data.cores[core].slots[s] = tag;
  }
}
fs.writeFileSync(manifestPath, JSON.stringify(data, null, 2) + '\n');
NODE
}

update_manifest_slot() {
	local core="$1" slot="$2" tag="$3"
	node - "${MANIFEST}" "$core" "$slot" "$tag" <<'NODE'
const fs = require('node:fs');
const [manifestPath, core, slot, tag] = process.argv.slice(2);
const data = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
data.cores[core].slots[slot] = tag;
fs.writeFileSync(manifestPath, JSON.stringify(data, null, 2) + '\n');
NODE
}

remove_manifest_version() {
	local core="$1" tag="$2"
	node - "${MANIFEST}" "$core" "$tag" <<'NODE'
const fs = require('node:fs');
const [manifestPath, core, tag] = process.argv.slice(2);
const data = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
delete data.cores[core].versions[tag];
for (const [slot, target] of Object.entries(data.cores[core].slots || {})) {
  if (target === tag) delete data.cores[core].slots[slot];
}
fs.writeFileSync(manifestPath, JSON.stringify(data, null, 2) + '\n');
NODE
}

apply_slots() {
	local core="$1" tag="$2" slots_csv="${3:-}"
	[ -z "$slots_csv" ] && return 0
	local IFS=','
	for slot in $slots_csv; do
		slot="$(echo "$slot" | tr -d '[:space:]')"
		[ -z "$slot" ] && continue
		validate_tag "$slot"
		ln -sfn "$tag" "${CORES_DIR}/${core}/${slot}"
	done
}

cmd_list() {
	ensure_dirs
	node - "${MANIFEST}" "${GEODATA_DIR}" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [manifestPath, geoDir] = process.argv.slice(2);
const data = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

for (const core of ['xray', 'v2ray']) {
  const entry = data.cores?.[core] || { slots: {}, versions: {} };
  console.log(`\n[${core}]`);
  const slotsByTag = {};
  for (const [slot, tag] of Object.entries(entry.slots || {})) {
    slotsByTag[tag] = slotsByTag[tag] || [];
    slotsByTag[tag].push(slot);
  }
  const tags = Object.keys(entry.versions || {});
  if (tags.length === 0) {
    console.log('  (no versions installed)');
    continue;
  }
  for (const tag of tags) {
    const v = entry.versions[tag];
    const slots = slotsByTag[tag]?.length ? ` slots=[${slotsByTag[tag].join(',')}]` : '';
    console.log(`  - ${tag} (v${v.version}) src=${v.source} sha256=${(v.sha256 || '').slice(0, 12)}...${slots}`);
  }
}

const geoip = fs.existsSync(path.join(geoDir, 'geoip.dat'));
const geosite = fs.existsSync(path.join(geoDir, 'geosite.dat'));
console.log(`\n[geodata] dir=${geoDir} geoip.dat=${geoip ? 'OK' : 'MISSING'} geosite.dat=${geosite ? 'OK' : 'MISSING'}`);
NODE
}

cmd_sync_geodata() {
	ensure_dirs
	local from_dir=""
	while [ $# -gt 0 ]; do
		case "$1" in
			--from) from_dir="${2:-}"; shift 2 ;;
			*) die "Unknown option for sync-geodata: $1" ;;
		esac
	done

	local candidates=()
	if [ -n "$from_dir" ]; then
		candidates+=("$from_dir")
	else
		candidates+=(
			"${REPO_ROOT}/.memory/Xray-macos-arm64-v8a"
			"${REPO_ROOT}/.memory/v2ray-macos-arm64-v8a"
		)
	fi

	local copied=0
	for dat in geoip.dat geosite.dat; do
		for dir in "${candidates[@]}"; do
			if [ -f "${dir}/${dat}" ]; then
				cp -f "${dir}/${dat}" "${GEODATA_DIR}/${dat}"
				echo "Synced ${dat} from ${dir}"
				copied=$((copied + 1))
				break
			fi
		done
	done

	if [ "$copied" -lt 2 ]; then
		die "Could not sync both geoip.dat and geosite.dat (synced ${copied}/2)"
	fi
}

cmd_import() {
	ensure_dirs
	[ $# -ge 2 ] || die "Usage: import <xray|v2ray> <bin-path> [--tag <tag>] [--slot <s1,s2>]"
	local core="$1" bin_src="$2"
	shift 2
	validate_core "$core"
	[ -x "$bin_src" ] || die "Binary not found or not executable: $bin_src"

	local tag="" slots=""
	while [ $# -gt 0 ]; do
		case "$1" in
			--tag) tag="${2:-}"; shift 2 ;;
			--slot) slots="${2:-}"; shift 2 ;;
			*) die "Unknown option for import: $1" ;;
		esac
	done

	local ver
	ver="$(extract_core_version "$bin_src")"
	if [ -z "$tag" ]; then
		[ "$ver" != "unknown" ] || die "Cannot auto-detect version from $bin_src; pass --tag <tag>"
		tag="v${ver}"
	fi
	validate_tag "$tag"

	local dest_dir="${CORES_DIR}/${core}/${tag}"
	local dest_bin="${dest_dir}/${core}"
	mkdir -p "$dest_dir"
	cp -f "$bin_src" "$dest_bin"
	chmod +x "$dest_bin"

	local sha
	sha="$(calc_sha256 "$dest_bin")"
	update_manifest_version "$core" "$tag" "$ver" "$sha" "import:${bin_src}" "${core}/${tag}/${core}" "$slots"
	apply_slots "$core" "$tag" "$slots"

	local src_dir
	src_dir="$(dirname "$bin_src")"
	for dat in geoip.dat geosite.dat; do
		if [ ! -f "${GEODATA_DIR}/${dat}" ] && [ -f "${src_dir}/${dat}" ]; then
			cp -f "${src_dir}/${dat}" "${GEODATA_DIR}/${dat}"
			echo "Seeded shared ${dat} from ${src_dir}"
		fi
	done

	echo "Imported ${core} ${tag} (v${ver}) -> ${dest_bin}"
}

cmd_install() {
	ensure_dirs
	[ $# -ge 2 ] || die "Usage: install <xray|v2ray> <tag> [--slot <s1,s2>] [--mirror <prefix>]"
	local core="$1" tag="$2"
	shift 2
	validate_core "$core"
	validate_tag "$tag"

	local slots="" mirror=""
	while [ $# -gt 0 ]; do
		case "$1" in
			--slot) slots="${2:-}"; shift 2 ;;
			--mirror) mirror="${2:-}"; shift 2 ;;
			*) die "Unknown option for install: $1" ;;
		esac
	done

	command -v curl >/dev/null 2>&1 || die "curl is required"
	command -v unzip >/dev/null 2>&1 || die "unzip is required"

	local arch asset repo base_url
	arch="$(detect_release_arch)"
	if [ "$core" = "xray" ]; then
		repo="XTLS/Xray-core"
		asset="Xray-${arch}.zip"
	else
		repo="v2fly/v2ray-core"
		asset="v2ray-${arch}.zip"
	fi
	base_url="${mirror}https://github.com/${repo}/releases/download/${tag}"

	_CLEANUP_TMPDIR="$(mktemp -d)"

	echo "Downloading ${base_url}/${asset} ..."
	curl -fsSL -o "${_CLEANUP_TMPDIR}/${asset}" "${base_url}/${asset}"
	curl -fsSL -o "${_CLEANUP_TMPDIR}/${asset}.dgst" "${base_url}/${asset}.dgst"

	local expected actual
	expected="$(grep -iE 'SHA2-?256|SHA256' "${_CLEANUP_TMPDIR}/${asset}.dgst" | head -n 1 | awk -F'=' '{print $NF}' | tr -d '[:space:]')"
	[ -n "$expected" ] || die "Failed to parse SHA256 from ${asset}.dgst"
	actual="$(calc_sha256 "${_CLEANUP_TMPDIR}/${asset}")"
	if [ "$(echo "$expected" | tr '[:upper:]' '[:lower:]')" != "$(echo "$actual" | tr '[:upper:]' '[:lower:]')" ]; then
		die "SHA256 mismatch for ${asset}: expected ${expected}, got ${actual}"
	fi
	echo "SHA256 verified: ${actual}"

	unzip -q -o "${_CLEANUP_TMPDIR}/${asset}" -d "${_CLEANUP_TMPDIR}/unpacked"
	[ -f "${_CLEANUP_TMPDIR}/unpacked/${core}" ] || die "Binary '${core}' not found inside ${asset}"

	local dest_dir="${CORES_DIR}/${core}/${tag}"
	local dest_bin="${dest_dir}/${core}"
	mkdir -p "$dest_dir"
	cp -f "${_CLEANUP_TMPDIR}/unpacked/${core}" "$dest_bin"
	chmod +x "$dest_bin"

	for dat in geoip.dat geosite.dat; do
		if [ ! -f "${GEODATA_DIR}/${dat}" ] && [ -f "${_CLEANUP_TMPDIR}/unpacked/${dat}" ]; then
			cp -f "${_CLEANUP_TMPDIR}/unpacked/${dat}" "${GEODATA_DIR}/${dat}"
			echo "Seeded shared ${dat} from ${asset}"
		fi
	done

	local ver sha
	ver="$(extract_core_version "$dest_bin")"
	sha="$(calc_sha256 "$dest_bin")"
	update_manifest_version "$core" "$tag" "$ver" "$sha" "release:${repo}@${tag}" "${core}/${tag}/${core}" "$slots"
	apply_slots "$core" "$tag" "$slots"

	echo "Installed ${core} ${tag} (v${ver}) -> ${dest_bin}"
}

cmd_build() {
	ensure_dirs
	[ $# -ge 2 ] || die "Usage: build <xray|v2ray> <git-ref> [--slot <s1,s2>] [--src <repo-dir>]"
	local core="$1" ref="$2"
	shift 2
	validate_core "$core"

	local slots="" src_dir=""
	if [ "$core" = "xray" ]; then
		src_dir="${XRAY_SRC_DEFAULT}"
	else
		src_dir="${V2RAY_SRC_DEFAULT}"
	fi
	while [ $# -gt 0 ]; do
		case "$1" in
			--slot) slots="${2:-}"; shift 2 ;;
			--src) src_dir="${2:-}"; shift 2 ;;
			*) die "Unknown option for build: $1" ;;
		esac
	done

	command -v go >/dev/null 2>&1 || die "go is required for source build"
	[ -d "${src_dir}/.git" ] || die "Git repository not found at ${src_dir}"

	local safe_ref
	safe_ref="$(echo "$ref" | tr '/:' '__')"
	validate_tag "$safe_ref"

	_CLEANUP_WT_SRC="$src_dir"
	_CLEANUP_WT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aios-wt-${core}.XXXXXX")"

	echo "Checking out ${core}@${ref} in temporary worktree ${_CLEANUP_WT_DIR} ..."
	git -C "$src_dir" worktree add --detach "${_CLEANUP_WT_DIR}" "$ref" >/dev/null

	local dest_dir="${CORES_DIR}/${core}/${safe_ref}"
	local dest_bin="${dest_dir}/${core}"
	mkdir -p "$dest_dir"

	echo "Building ${core} (${ref}) with CGO_ENABLED=0 -trimpath -ldflags '-s -w' ..."
	(
		cd "${_CLEANUP_WT_DIR}"
		CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$dest_bin" ./main
	)
	chmod +x "$dest_bin"

	local ver sha commit
	ver="$(extract_core_version "$dest_bin")"
	sha="$(calc_sha256 "$dest_bin")"
	commit="$(git -C "${_CLEANUP_WT_DIR}" rev-parse --short HEAD)"
	update_manifest_version "$core" "$safe_ref" "$ver" "$sha" "source:${commit}" "${core}/${safe_ref}/${core}" "$slots"
	apply_slots "$core" "$safe_ref" "$slots"

	echo "Built ${core} ${safe_ref} (v${ver}, commit ${commit}) -> ${dest_bin}"
}

cmd_use() {
	ensure_dirs
	[ $# -ge 2 ] || die "Usage: use <xray|v2ray> <tag> [--slot <slot>]"
	local core="$1" tag="$2"
	shift 2
	validate_core "$core"
	validate_tag "$tag"
	local slot="current"
	while [ $# -gt 0 ]; do
		case "$1" in
			--slot) slot="${2:-current}"; shift 2 ;;
			*) die "Unknown option for use: $1" ;;
		esac
	done
	validate_tag "$slot"
	[ -x "${CORES_DIR}/${core}/${tag}/${core}" ] || die "Installed binary not found for ${core} ${tag}"
	ln -sfn "$tag" "${CORES_DIR}/${core}/${slot}"
	update_manifest_slot "$core" "$slot" "$tag"
	echo "Updated symlink ${core}/${slot} -> ${tag}"
}

cmd_remove() {
	ensure_dirs
	[ $# -ge 2 ] || die "Usage: remove <xray|v2ray> <tag>"
	local core="$1" tag="$2"
	validate_core "$core"
	validate_tag "$tag"
	local cur=""
	if [ -L "${CORES_DIR}/${core}/current" ]; then
		cur="$(readlink "${CORES_DIR}/${core}/current")"
	fi
	if [ "$cur" = "$tag" ]; then
		die "Cannot remove active 'current' version ${core}/${tag}; switch current first"
	fi
	rm -rf "${CORES_DIR:?}/${core}/${tag}"
	for link in "${CORES_DIR}/${core}"/*; do
		if [ -L "$link" ] && [ "$(readlink "$link")" = "$tag" ]; then
			rm -f "$link"
		fi
	done
	remove_manifest_version "$core" "$tag"
	echo "Removed ${core}/${tag}"
}

main() {
	[ $# -ge 1 ] || { usage; exit 1; }
	local cmd="$1"
	shift
	case "$cmd" in
		list) cmd_list "$@" ;;
		import) cmd_import "$@" ;;
		install) cmd_install "$@" ;;
		build) cmd_build "$@" ;;
		use) cmd_use "$@" ;;
		sync-geodata) cmd_sync_geodata "$@" ;;
		remove) cmd_remove "$@" ;;
		-h|--help|help) usage ;;
		*) die "Unknown command: $cmd" ;;
	esac
}

main "$@"
