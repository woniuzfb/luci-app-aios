#!/bin/sh
set -e

. /usr/share/libubox/jshn.sh

NAME=aios
RUNTIME_DIR=/var/etc/aios
PERSIST_DIR=/etc/aios
STATUS_FILE="${RUNTIME_DIR}/install.status"
LOCK_DIR=/var/lock/aios-install.lock
PID_FILE=/var/run/aios.main.pid

mkdir -p "$RUNTIME_DIR" "$PERSIST_DIR" /var/lock

uci_get() {
	local ret
	ret="$(uci -q get "${NAME}.${1}" 2>/dev/null || true)"
	echo "${ret:-$2}"
}

emit_error() {
	local msg="$1"
	local rolled_back="${2:-0}"
	json_init
	json_add_boolean "ok" 0
	[ "$rolled_back" = "1" ] && json_add_boolean "rolled_back" 1
	json_add_string "error" "$msg"
	json_dump
}

write_status() {
	local job_id="$1" state="$2" core="$3" tag="$4" progress="$5" msg="$6"
	json_init
	json_add_string "job_id" "$job_id"
	json_add_string "state" "$state"
	json_add_string "core" "$core"
	json_add_string "tag" "$tag"
	json_add_int "progress" "$progress"
	json_add_string "message" "$msg"
	json_add_int "updated_at" "$(date +%s)"
	json_dump > "${STATUS_FILE}.tmp"
	mv -f "${STATUS_FILE}.tmp" "$STATUS_FILE"
}

validate_tag() {
	local t="$1"
	[ -n "$t" ] && [ "$t" != "." ] && [ "$t" != ".." ] || return 1
	printf '%s\n' "$t" | grep -qE '^[a-zA-Z0-9._-]+$'
}

detect_linux_arch() {
	# Prefer OpenWrt DISTRIB_ARCH to distinguish mips/mipsel and soft-float accurately
	local dist_arch=""
	if [ -r /etc/openwrt_release ]; then
		dist_arch="$(sed -nE "s/^DISTRIB_ARCH=['\"]?([^'\"]+)['\"]?.*/\1/p" /etc/openwrt_release | head -n 1 || true)"
	fi
	case "$dist_arch" in
		x86_64) echo "linux-64"; return 0 ;;
		aarch64_*) echo "linux-arm64-v8a"; return 0 ;;
		arm_cortex-a*) echo "linux-arm32-v7a"; return 0 ;;
		arm_arm1176jzf-s_vfp|arm_*) echo "linux-arm32-v6"; return 0 ;;
		mipsel_*) echo "linux-mips32le"; return 0 ;;
		mips_*) echo "linux-mips32"; return 0 ;;
		mips64el_*) echo "linux-mips64le"; return 0 ;;
		mips64_*) echo "linux-mips64"; return 0 ;;
		riscv64_*) echo "linux-riscv64"; return 0 ;;
		i386_*) echo "linux-32"; return 0 ;;
	esac
	case "$(uname -m)" in
		x86_64|amd64) echo "linux-64" ;;
		aarch64|arm64) echo "linux-arm64-v8a" ;;
		armv7l|armv7*) echo "linux-arm32-v7a" ;;
		armv6l) echo "linux-arm32-v6" ;;
		mips64) echo "linux-mips64" ;;
		mips64el) echo "linux-mips64le" ;;
		mips) echo "linux-mips32" ;;
		mipsel) echo "linux-mips32le" ;;
		riscv64) echo "linux-riscv64" ;;
		i386|i686) echo "linux-32" ;;
		*) echo "" ;;
	esac
}

avail_kb() {
	local dir="$1"
	while [ -n "$dir" ] && [ ! -d "$dir" ] && [ "$dir" != "/" ]; do
		dir="$(dirname "$dir")"
	done
	[ -d "$dir" ] || dir="/"
	df -Pk "$dir" 2>/dev/null | awk 'NR>1 {val=$(NF-2)} END {print val+0}' || echo 0
}

extract_version() {
	local bin="$1" line
	line="$("$bin" version 2>/dev/null | head -n 1 || true)"
	printf '%s\n' "$line" | sed -nE 's/.*[[:space:]]([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n 1
}

detect_bin_core() {
	local bin="$1" line
	line="$("$bin" version 2>/dev/null | head -n 1 || true)"
	case "$line" in
		*[Xx]ray*) echo "xray" ;;
		*V2Ray*|*v2ray*) echo "v2ray" ;;
		*)
			case "$(basename "$bin")" in
				*v2ray*) echo "v2ray" ;;
				*) echo "xray" ;;
			esac
			;;
	esac
}

resolve_asset_dir() {
	local asset
	asset="$(uci_get main.asset_location '')"
	if [ -z "$asset" ]; then
		local cand
		for cand in /usr/share/aios/geodata /usr/share/xray /usr/share/v2ray; do
			if [ -d "$cand" ]; then
				asset="$cand"
				break
			fi
		done
		asset="${asset:-/usr/share/aios/geodata}"
	fi
	echo "$asset"
}

is_allowed_core_bin() {
	local cand="$1" bins_dir="$2"
	[ -n "$cand" ] && [ -x "$cand" ] || return 1
	case "$cand" in
		/usr/bin/aios-xray|/usr/bin/aios-v2ray|/usr/bin/xray|/usr/bin/v2ray)
			return 0
			;;
	esac
	local real_cand real_bins rel slot leaf
	real_cand="$(readlink -f "$cand" 2>/dev/null || echo "")"
	[ -n "$real_cand" ] && [ -x "$real_cand" ] || return 1
	case "$real_cand" in
		/usr/bin/aios-xray|/usr/bin/aios-v2ray|/usr/bin/xray|/usr/bin/v2ray)
			return 0
			;;
	esac
	[ -n "$bins_dir" ] && [ -d "$bins_dir" ] || return 1
	real_bins="$(readlink -f "$bins_dir" 2>/dev/null || echo "$bins_dir")"
	case "$real_cand" in
		"${real_bins}/"*)
			rel="${real_cand#"${real_bins}/"}"
			slot="${rel%%/*}"
			leaf="${rel#*/}"
			if [ "$leaf" != "xray" ] && [ "$leaf" != "v2ray" ]; then
				return 1
			fi
			if [ -z "$slot" ] || [ "$slot" = "." ] || [ "$slot" = ".." ] || [ "$slot" = "current" ]; then
				return 1
			fi
			printf '%s\n' "$slot" | grep -qE '^[a-zA-Z0-9._-]+$' || return 1
			[ "$real_cand" = "${real_bins}/${slot}/${leaf}" ] && return 0
			;;
	esac
	return 1
}

_WORK_TMP=""

cleanup_install() {
	[ -n "${_WORK_TMP:-}" ] && rm -rf "$_WORK_TMP" 2>/dev/null || true
	rm -f "${LOCK_DIR}/pid" 2>/dev/null || true
	rmdir "$LOCK_DIR" 2>/dev/null || true
}

cmd_install() {
	local core="$1" tag="$2" bins_dir="$3" mirror="${4:-}" job_id="${5:-job}"
	if [ -d "$LOCK_DIR" ] && [ -s "${LOCK_DIR}/pid" ]; then
		local lock_pid
		lock_pid="$(cat "${LOCK_DIR}/pid" 2>/dev/null || true)"
		if [ -n "$lock_pid" ] && [ ! -d "/proc/${lock_pid}" ]; then
			rm -rf "$LOCK_DIR" 2>/dev/null || true
		fi
	fi
	if ! mkdir "$LOCK_DIR" 2>/dev/null; then
		# Do NOT overwrite the active job's status file on lock contention
		exit 1
	fi
	echo "$$" > "${LOCK_DIR}/pid"
	_WORK_TMP=""
	trap cleanup_install EXIT

	if [ "$core" != "xray" ] && [ "$core" != "v2ray" ]; then
		write_status "$job_id" "error" "$core" "$tag" 0 "Invalid core: $core"
		exit 1
	fi
	if ! validate_tag "$tag"; then
		write_status "$job_id" "error" "$core" "$tag" 0 "Invalid version tag: $tag"
		exit 1
	fi
	if [ -z "$bins_dir" ]; then
		write_status "$job_id" "error" "$core" "$tag" 0 "bins_dir is not configured"
		exit 1
	fi
	if [ -n "$mirror" ]; then
		if ! printf '%s\n' "$mirror" | grep -qE '^https?://[^[:space:]]+$'; then
			write_status "$job_id" "error" "$core" "$tag" 0 "Invalid mirror URL (must start with http:// or https://)"
			exit 1
		fi
		case "$mirror" in
			*/) ;;
			*) mirror="${mirror}/" ;;
		esac
	fi

	mkdir -p "$bins_dir" "${bins_dir}/.tmp"
	local arch
	arch="$(detect_linux_arch)"
	if [ -z "$arch" ]; then
		write_status "$job_id" "error" "$core" "$tag" 0 "Unsupported CPU architecture: $(uname -m)"
		exit 1
	fi

	# Dual free-space check (persistent dir + temp unpack dir, >= 70MB each)
	local persist_kb tmp_kb
	persist_kb="$(avail_kb "$bins_dir")"
	tmp_kb="$(avail_kb "${bins_dir}/.tmp")"
	if [ "${persist_kb:-0}" -lt 70000 ] || [ "${tmp_kb:-0}" -lt 70000 ]; then
		write_status "$job_id" "error" "$core" "$tag" 0 "Insufficient disk space (persist=${persist_kb}KB, tmp=${tmp_kb}KB, need >=70000KB)"
		exit 1
	fi

	if ! command -v unzip >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1; then
		write_status "$job_id" "error" "$core" "$tag" 0 "Missing required tools: unzip and sha256sum"
		exit 1
	fi
	local dl_cmd=""
	if command -v curl >/dev/null 2>&1; then
		dl_cmd="curl"
	elif command -v wget >/dev/null 2>&1; then
		dl_cmd="wget"
	else
		write_status "$job_id" "error" "$core" "$tag" 0 "Missing downloader: curl or wget"
		exit 1
	fi

	local repo asset base_url
	if [ "$core" = "xray" ]; then
		repo="XTLS/Xray-core"
		asset="Xray-${arch}.zip"
	else
		repo="v2fly/v2ray-core"
		asset="v2ray-${arch}.zip"
	fi
	base_url="${mirror}https://github.com/${repo}/releases/download/${tag}"
	_WORK_TMP="${bins_dir}/.tmp/${job_id}"
	mkdir -p "$_WORK_TMP"

	write_status "$job_id" "running" "$core" "$tag" 15 "Downloading ${asset}"
	if [ "$dl_cmd" = "curl" ]; then
		if ! curl -fsSL --connect-timeout 15 --max-time 300 -o "${_WORK_TMP}/${asset}" "${base_url}/${asset}"; then
			write_status "$job_id" "error" "$core" "$tag" 15 "Failed to download ${asset}"
			exit 1
		fi
		if ! curl -fsSL --connect-timeout 15 --max-time 60 -o "${_WORK_TMP}/${asset}.dgst" "${base_url}/${asset}.dgst"; then
			write_status "$job_id" "error" "$core" "$tag" 35 "Failed to download ${asset}.dgst"
			exit 1
		fi
	else
		if ! wget -q -T 120 -O "${_WORK_TMP}/${asset}" "${base_url}/${asset}"; then
			write_status "$job_id" "error" "$core" "$tag" 15 "Failed to download ${asset}"
			exit 1
		fi
		if ! wget -q -T 60 -O "${_WORK_TMP}/${asset}.dgst" "${base_url}/${asset}.dgst"; then
			write_status "$job_id" "error" "$core" "$tag" 35 "Failed to download ${asset}.dgst"
			exit 1
		fi
	fi

	write_status "$job_id" "running" "$core" "$tag" 55 "Verifying SHA256 digest"
	local expected actual
	expected="$(grep -iE 'SHA2-?256|SHA256' "${_WORK_TMP}/${asset}.dgst" | head -n 1 | awk -F'=' '{print $NF}' | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
	actual="$(sha256sum "${_WORK_TMP}/${asset}" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
	if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
		write_status "$job_id" "error" "$core" "$tag" 55 "SHA256 verification failed"
		exit 1
	fi

	write_status "$job_id" "running" "$core" "$tag" 75 "Extracting ${core} binary"
	mkdir -p "${_WORK_TMP}/unpacked"
	if ! unzip -q -o "${_WORK_TMP}/${asset}" "$core" -d "${_WORK_TMP}/unpacked"; then
		write_status "$job_id" "error" "$core" "$tag" 75 "Failed to extract ${core} from ${asset}"
		exit 1
	fi

	local slot_dir="${bins_dir}/${core}-${tag}"
	mkdir -p "$slot_dir"
	mv -f "${_WORK_TMP}/unpacked/${core}" "${slot_dir}/${core}"
	chmod +x "${slot_dir}/${core}"

	local detected_ver
	detected_ver="$(extract_version "${slot_dir}/${core}")"
	write_status "$job_id" "done" "$core" "$tag" 100 "Installed ${core} ${tag} (v${detected_ver:-unknown}) to ${slot_dir}/${core}"
}

cmd_switch() {
	local target_bin="$1"
	local precompiled_tmp="${2:-}"
	local cfg_bins_dir
	cfg_bins_dir="$(uci_get main.bins_dir '')"

	if ! is_allowed_core_bin "$target_bin" "$cfg_bins_dir"; then
		emit_error "Target binary path is not in allowed whitelist or not executable"
		exit 0
	fi

	local target_core target_ver v2ray_format asset_dir
	target_core="$(detect_bin_core "$target_bin")"
	target_ver="$(extract_version "$target_bin")"
	v2ray_format="$(uci_get main.v2ray_format jsonv4)"
	asset_dir="$(resolve_asset_dir)"

	# 1. Recompile temporary config for target version (dual branch: with or without ucode)
	local test_cfg="${RUNTIME_DIR}/switch_test.json"
	rm -f "$test_cfg"
	if command -v ucode >/dev/null 2>&1 && [ -f /usr/share/aios/gen_config.uc ]; then
		if [ -n "$target_ver" ]; then
			if ! /usr/bin/ucode /usr/share/aios/gen_config.uc --target-core "$target_core" --target-version "$target_ver" > "$test_cfg" 2>"${test_cfg}.err"; then
				local err_msg
				err_msg="$(head -n 3 "${test_cfg}.err" 2>/dev/null || true)"
				rm -f "$test_cfg" "${test_cfg}.err"
				emit_error "ucode compile failed: ${err_msg}"
				exit 0
			fi
		else
			if ! /usr/bin/ucode /usr/share/aios/gen_config.uc --target-core "$target_core" > "$test_cfg" 2>"${test_cfg}.err"; then
				local err_msg
				err_msg="$(head -n 3 "${test_cfg}.err" 2>/dev/null || true)"
				rm -f "$test_cfg" "${test_cfg}.err"
				emit_error "ucode compile failed: ${err_msg}"
				exit 0
			fi
		fi
		rm -f "${test_cfg}.err"
	elif [ -n "$precompiled_tmp" ] && [ -s "$precompiled_tmp" ]; then
		cp -f "$precompiled_tmp" "$test_cfg"
	elif [ -s "${PERSIST_DIR}/compiled.json" ]; then
		cp -f "${PERSIST_DIR}/compiled.json" "$test_cfg"
	else
		emit_error "No ucode available and no precompiled JSON supplied"
		exit 0
	fi

	# 2. Offline -test gate with target binary
	local test_out="" test_ok=0
	if [ "$target_core" = "xray" ]; then
		if test_out="$(XRAY_LOCATION_ASSET="$asset_dir" "$target_bin" run -test -c "$test_cfg" 2>&1)"; then
			test_ok=1
		fi
	else
		if [ "$v2ray_format" = "jsonv5" ]; then
			if test_out="$(V2RAY_LOCATION_ASSET="$asset_dir" "$target_bin" test -format jsonv5 -c "$test_cfg" 2>&1)"; then
				test_ok=1
			fi
		else
			if test_out="$(V2RAY_LOCATION_ASSET="$asset_dir" "$target_bin" test -c "$test_cfg" 2>&1)"; then
				test_ok=1
			fi
		fi
	fi

	if [ "$test_ok" != "1" ]; then
		rm -f "$test_cfg"
		emit_error "Core -test failed: ${test_out}"
		exit 0
	fi

	# 3. Backup current state for automatic rollback
	local prev_bin prev_core_type prev_target_ver bins_dir prev_link="" had_compiled=0 enabled prev_pid=""
	prev_bin="$(uci_get main.core_bin '')"
	prev_core_type="$(uci_get main.core_type auto)"
	prev_target_ver="$(uci_get main.target_version auto)"
	bins_dir="$(uci_get main.bins_dir '')"
	enabled="$(uci_get main.enabled 0)"
	[ -s "$PID_FILE" ] && prev_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
	if [ -n "$bins_dir" ] && [ -L "${bins_dir}/current" ]; then
		prev_link="$(readlink "${bins_dir}/current" 2>/dev/null || true)"
	fi
	if [ -s "${PERSIST_DIR}/compiled.json" ]; then
		had_compiled=1
		cp -f "${PERSIST_DIR}/compiled.json" "${PERSIST_DIR}/compiled.json.bak"
	fi

	# 4. Atomic switch (canonicalized symlink check inside bins_dir, plus UCI sync)
	local next_bin="$target_bin"
	local created_link=0
	if [ -n "$bins_dir" ] && [ -d "$bins_dir" ]; then
		local real_bins real_target
		real_bins="$(readlink -f "$bins_dir" 2>/dev/null || echo "$bins_dir")"
		real_target="$(readlink -f "$target_bin" 2>/dev/null || echo "$target_bin")"
		case "$real_target" in
			"${real_bins}/"*)
				ln -sfn "$real_target" "${bins_dir}/current"
				next_bin="${bins_dir}/current"
				created_link=1
				;;
		esac
	fi

	if [ -n "$precompiled_tmp" ] && [ -s "$precompiled_tmp" ]; then
		cp -f "$precompiled_tmp" "${PERSIST_DIR}/compiled.json"
	fi

	uci set "${NAME}.main.core_bin=${next_bin}"
	if [ "$prev_core_type" != "auto" ] && [ "$prev_core_type" != "$target_core" ]; then
		uci set "${NAME}.main.core_type=${target_core}"
	fi
	# Keep target_version consistent with the newly tested target binary
	if [ "$prev_target_ver" != "auto" ] && [ -n "$target_ver" ] && [ "$prev_target_ver" != "$target_ver" ]; then
		uci set "${NAME}.main.target_version=auto"
	fi
	uci commit "$NAME"
	rm -f "$test_cfg"

	# 5. Restart & short watchdog with automatic rollback
	local was_running=0
	[ -n "$prev_pid" ] && [ -d "/proc/${prev_pid}" ] && was_running=1
	if [ "$enabled" = "1" ] || [ "$was_running" = "1" ]; then
		/etc/init.d/aios stop >/dev/null 2>&1 || true
		FORCE_START=1 /etc/init.d/aios start >/dev/null 2>&1 || true
		sleep 2
		local alive=0 pid="" expected_exe="" actual_exe=""
		expected_exe="$(readlink -f "$target_bin" 2>/dev/null || echo "$target_bin")"
		if [ -s "$PID_FILE" ]; then
			pid="$(cat "$PID_FILE" 2>/dev/null || true)"
			if [ -n "$pid" ] && [ "$pid" != "$prev_pid" ] && [ -d "/proc/${pid}" ]; then
				actual_exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
				if [ -z "$actual_exe" ] || [ "$actual_exe" = "$expected_exe" ]; then
					alive=1
				fi
			fi
		fi
		if [ "$alive" != "1" ]; then
			# Automatic rollback
			if [ -n "$bins_dir" ]; then
				if [ -n "$prev_link" ]; then
					ln -sfn "$prev_link" "${bins_dir}/current"
				elif [ "$created_link" = "1" ]; then
					rm -f "${bins_dir}/current"
				fi
			fi
			if [ "$had_compiled" = "1" ] && [ -s "${PERSIST_DIR}/compiled.json.bak" ]; then
				mv -f "${PERSIST_DIR}/compiled.json.bak" "${PERSIST_DIR}/compiled.json"
			elif [ "$had_compiled" = "0" ]; then
				rm -f "${PERSIST_DIR}/compiled.json"
			fi
			if [ -n "$prev_bin" ]; then
				uci set "${NAME}.main.core_bin=${prev_bin}"
			else
				uci delete "${NAME}.main.core_bin" 2>/dev/null || true
			fi
			uci set "${NAME}.main.core_type=${prev_core_type}"
			uci set "${NAME}.main.target_version=${prev_target_ver}"
			uci commit "$NAME"
			if [ "$enabled" = "1" ] || [ "$was_running" = "1" ]; then
				FORCE_START=1 /etc/init.d/aios start >/dev/null 2>&1 || true
			fi
			emit_error "New core failed watchdog after restart; automatically rolled back" 1
			exit 0
		fi
	fi

	rm -f "${PERSIST_DIR}/compiled.json.bak"
	json_init
	json_add_boolean "ok" 1
	json_add_string "core" "$target_core"
	json_add_string "version" "${target_ver:-unknown}"
	json_add_string "core_bin" "$next_bin"
	json_dump
}

cmd="${1:-}"
[ -n "$cmd" ] || exit 1
shift
case "$cmd" in
	install) cmd_install "$@" ;;
	switch) cmd_switch "$@" ;;
	*) exit 1 ;;
esac
