#!/bin/sh
# Isolated firewall3 (iptables + ipset) backend for legacy OpenWrt (19.07/21.02/LEDE)
# Strictly scoped to AIOS_* chains and aios_* ipsets to avoid colliding with other plugins.

NAME=aios
RUNTIME_DIR=/var/etc/aios
ROUTE_STATE_FILE="${RUNTIME_DIR}/last_route_state"

uci_get() {
	local ret
	ret="$(uci -q get "${NAME}.${1}" 2>/dev/null)"
	echo "${ret:-$2}"
}

TPROXY_MARK="$(uci_get main_tproxy.tproxy_mark 0x3a01)"
OUTBOUND_MARK="$(uci_get main_tproxy.outbound_mark 0x3a03)"
DNS_MARK="$(uci_get main_tproxy.dns_mark 0x3a04)"
ROUTE_TABLE="$(uci_get main_tproxy.route_table 166)"
MODE="$(uci_get main_tproxy.tproxy_mode tproxy)"
TCP4_PORT="$(uci_get main_tproxy.tproxy_port_tcp_v4 12345)"
TCP6_PORT="$(uci_get main_tproxy.tproxy_port_tcp_v6 12346)"
UDP4_PORT="$(uci_get main_tproxy.tproxy_port_udp_v4 12347)"
UDP6_PORT="$(uci_get main_tproxy.tproxy_port_udp_v6 12348)"
IFACES_V4="$(uci -q get "${NAME}.main_tproxy.tproxy_ifaces_v4" 2>/dev/null || true)"
IFACES_V6="$(uci -q get "${NAME}.main_tproxy.tproxy_ifaces_v6" 2>/dev/null || true)"
BP_IFACES_V4="$(uci -q get "${NAME}.main_tproxy.bypass_ifaces_v4" 2>/dev/null || true)"
BP_IFACES_V6="$(uci -q get "${NAME}.main_tproxy.bypass_ifaces_v6" 2>/dev/null || true)"

run_cmd() {
	if ! "$@"; then
		echo "fw3_ipt.sh: command failed: $*" >&2
		return 1
	fi
}

create_ipsets() {
	local ipv6_active=0 cidr ip
	if [ "$MODE" != "redirect" ] && [ -d /proc/sys/net/ipv6 ] && command -v ip6tables >/dev/null 2>&1 && ip6tables -t mangle -L -n >/dev/null 2>&1 && { [ "$TCP6_PORT" -gt 0 ] || [ "$UDP6_PORT" -gt 0 ]; }; then
		ipv6_active=1
	fi

	run_cmd ipset create aios_reserved_v4 hash:net family inet -exist || return 1
	run_cmd ipset flush aios_reserved_v4 || return 1
	for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 224.0.0.0/3; do
		run_cmd ipset add aios_reserved_v4 "$cidr" -exist || return 1
	done

	if [ "$ipv6_active" = "1" ]; then
		run_cmd ipset create aios_reserved_v6 hash:net family inet6 -exist || return 1
		run_cmd ipset flush aios_reserved_v6 || return 1
		for cidr in ::/128 ::1/128 ::ffff:0.0.0.0/96 64:ff9b::/96 100::/64 2001::/32 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8; do
			run_cmd ipset add aios_reserved_v6 "$cidr" -exist || return 1
		done
	else
		ipset create aios_reserved_v6 hash:net family inet6 -exist 2>/dev/null || true
		ipset flush aios_reserved_v6 2>/dev/null || true
		for cidr in ::/128 ::1/128 ::ffff:0.0.0.0/96 64:ff9b::/96 100::/64 2001::/32 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8; do
			ipset add aios_reserved_v6 "$cidr" -exist 2>/dev/null || true
		done
	fi

	run_cmd ipset create aios_bp_v4 hash:net family inet -exist || return 1
	run_cmd ipset flush aios_bp_v4 || return 1
	run_cmd ipset create aios_fw_v4 hash:net family inet -exist || return 1
	run_cmd ipset flush aios_fw_v4 || return 1

	if [ "$ipv6_active" = "1" ]; then
		run_cmd ipset create aios_bp_v6 hash:net family inet6 -exist || return 1
		run_cmd ipset flush aios_bp_v6 || return 1
		run_cmd ipset create aios_fw_v6 hash:net family inet6 -exist || return 1
		run_cmd ipset flush aios_fw_v6 || return 1
	else
		ipset create aios_bp_v6 hash:net family inet6 -exist 2>/dev/null || true
		ipset flush aios_bp_v6 2>/dev/null || true
		ipset create aios_fw_v6 hash:net family inet6 -exist 2>/dev/null || true
		ipset flush aios_fw_v6 2>/dev/null || true
	fi

	for ip in $(uci -q get "${NAME}.main_tproxy.wan_bp_ips" 2>/dev/null); do
		case "$ip" in
			*:*)
				if [ "$ipv6_active" = "1" ]; then
					run_cmd ipset add aios_bp_v6 "$ip" -exist || return 1
				else
					ipset add aios_bp_v6 "$ip" -exist 2>/dev/null || true
				fi
				;;
			*) run_cmd ipset add aios_bp_v4 "$ip" -exist || return 1 ;;
		esac
	done
	for ip in $(uci -q get "${NAME}.main_tproxy.wan_fw_ips" 2>/dev/null); do
		case "$ip" in
			*:*)
				if [ "$ipv6_active" = "1" ]; then
					run_cmd ipset add aios_fw_v6 "$ip" -exist || return 1
				else
					ipset add aios_fw_v6 "$ip" -exist 2>/dev/null || true
				fi
				;;
			*) run_cmd ipset add aios_fw_v4 "$ip" -exist || return 1 ;;
		esac
	done
	return 0
}

flush_route_pair() {
	local mark="$1" table="$2"
	[ -n "$mark" ] && [ -n "$table" ] || return 0
	ip rule del fwmark "$mark" lookup "$table" 2>/dev/null || true
	ip route del local default dev lo table "$table" 2>/dev/null || true
	ip -6 rule del fwmark "$mark" lookup "$table" 2>/dev/null || true
	ip -6 route del local default dev lo table "$table" 2>/dev/null || true
}

start_fw3_apply() {
	create_ipsets || return 1
	mkdir -p "$RUNTIME_DIR" || return 1

	local iface ipv6_active=0
	if [ -d /proc/sys/net/ipv6 ] && command -v ip6tables >/dev/null 2>&1 && ip6tables -t mangle -L -n >/dev/null 2>&1 && { [ "$TCP6_PORT" -gt 0 ] || [ "$UDP6_PORT" -gt 0 ]; }; then
		ipv6_active=1
	fi

	if [ "$MODE" = "redirect" ]; then
		iptables -t nat -N AIOS_REDIRECT 2>/dev/null || true
		run_cmd iptables -t nat -F AIOS_REDIRECT || return 1
		run_cmd iptables -t nat -A AIOS_REDIRECT -m addrtype --dst-type LOCAL -j RETURN || return 1
		run_cmd iptables -t nat -A AIOS_REDIRECT -m mark --mark "$OUTBOUND_MARK" -j RETURN || return 1
		run_cmd iptables -t nat -A AIOS_REDIRECT -m mark --mark "$DNS_MARK" -j RETURN || return 1
		if [ "$TCP4_PORT" -gt 0 ]; then
			run_cmd iptables -t nat -A AIOS_REDIRECT -p tcp -m set --match-set aios_fw_v4 dst -j REDIRECT --to-ports "$TCP4_PORT" || return 1
		fi
		run_cmd iptables -t nat -A AIOS_REDIRECT -m set --match-set aios_reserved_v4 dst -j RETURN || return 1
		run_cmd iptables -t nat -A AIOS_REDIRECT -m set --match-set aios_bp_v4 dst -j RETURN || return 1
		if [ "$TCP4_PORT" -gt 0 ]; then
			run_cmd iptables -t nat -A AIOS_REDIRECT -p tcp -j REDIRECT --to-ports "$TCP4_PORT" || return 1
		fi

		iptables -t nat -N AIOS_REDIRECT_PRE 2>/dev/null || true
		run_cmd iptables -t nat -F AIOS_REDIRECT_PRE || return 1
		for iface in $BP_IFACES_V4; do
			run_cmd iptables -t nat -A AIOS_REDIRECT_PRE -i "$iface" -j RETURN || return 1
		done
		run_cmd iptables -t nat -A AIOS_REDIRECT_PRE -j AIOS_REDIRECT || return 1

		if [ -n "$IFACES_V4" ]; then
			for iface in $IFACES_V4; do
				run_cmd iptables -t nat -A PREROUTING -i "$iface" -p tcp -j AIOS_REDIRECT_PRE || return 1
			done
		else
			run_cmd iptables -t nat -A PREROUTING -p tcp -j AIOS_REDIRECT_PRE || return 1
		fi
		run_cmd iptables -t nat -A OUTPUT -p tcp -j AIOS_REDIRECT || return 1
		return 0
	fi

	# TPROXY dual-stack mode
	printf '%s %s\n' "$TPROXY_MARK" "$ROUTE_TABLE" > "$ROUTE_STATE_FILE" || return 1
	run_cmd ip rule add fwmark "$TPROXY_MARK" lookup "$ROUTE_TABLE" || return 1
	run_cmd ip route add local default dev lo table "$ROUTE_TABLE" || return 1
	if [ "$ipv6_active" = "1" ]; then
		run_cmd ip -6 rule add fwmark "$TPROXY_MARK" lookup "$ROUTE_TABLE" || return 1
		run_cmd ip -6 route add local default dev lo table "$ROUTE_TABLE" || return 1
	else
		ip -6 rule add fwmark "$TPROXY_MARK" lookup "$ROUTE_TABLE" 2>/dev/null || true
		ip -6 route add local default dev lo table "$ROUTE_TABLE" 2>/dev/null || true
	fi

	# IPv4 mangle chains
	if [ "$TCP4_PORT" -gt 0 ] || [ "$UDP4_PORT" -gt 0 ]; then
		iptables -t mangle -N AIOS_PREROUTING_LOCAL 2>/dev/null || true
		run_cmd iptables -t mangle -F AIOS_PREROUTING_LOCAL || return 1
		run_cmd iptables -t mangle -A AIOS_PREROUTING_LOCAL -m addrtype --dst-type LOCAL -j RETURN || return 1
		if [ "$TCP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_PREROUTING_LOCAL -p tcp -j TPROXY --on-port "$TCP4_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_PREROUTING_LOCAL -p udp -j TPROXY --on-port "$UDP4_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi

		iptables -t mangle -N AIOS_PREROUTING 2>/dev/null || true
		run_cmd iptables -t mangle -F AIOS_PREROUTING || return 1
		run_cmd iptables -t mangle -A AIOS_PREROUTING -m addrtype --dst-type LOCAL -j RETURN || return 1
		for iface in $BP_IFACES_V4; do
			run_cmd iptables -t mangle -A AIOS_PREROUTING -i "$iface" -j RETURN || return 1
		done
		if [ "$TCP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_PREROUTING -p tcp -m set --match-set aios_fw_v4 dst -j TPROXY --on-port "$TCP4_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_PREROUTING -p udp -m set --match-set aios_fw_v4 dst -j TPROXY --on-port "$UDP4_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi
		run_cmd iptables -t mangle -A AIOS_PREROUTING -m set --match-set aios_reserved_v4 dst -j RETURN || return 1
		run_cmd iptables -t mangle -A AIOS_PREROUTING -m set --match-set aios_bp_v4 dst -j RETURN || return 1
		if [ "$TCP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port "$TCP4_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port "$UDP4_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi

		iptables -t mangle -N AIOS_OUTPUT 2>/dev/null || true
		run_cmd iptables -t mangle -F AIOS_OUTPUT || return 1
		if ! iptables -t mangle -A AIOS_OUTPUT -m conntrack --ctdir REPLY -j RETURN 2>/dev/null; then
			echo "fw3_ipt.sh: warning: iptables conntrack --ctdir REPLY unavailable (install kmod-ipt-conntrack to prevent local reply loops)" >&2
		fi
		run_cmd iptables -t mangle -A AIOS_OUTPUT -m addrtype --dst-type LOCAL -j RETURN || return 1
		run_cmd iptables -t mangle -A AIOS_OUTPUT -m mark --mark "$OUTBOUND_MARK" -j RETURN || return 1
		run_cmd iptables -t mangle -A AIOS_OUTPUT -m mark --mark "$DNS_MARK" -j RETURN || return 1
		if [ "$TCP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_OUTPUT -p tcp -m set --match-set aios_fw_v4 dst -j MARK --set-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_OUTPUT -p udp -m set --match-set aios_fw_v4 dst -j MARK --set-mark "$TPROXY_MARK" || return 1
		fi
		run_cmd iptables -t mangle -A AIOS_OUTPUT -m set --match-set aios_reserved_v4 dst -j RETURN || return 1
		run_cmd iptables -t mangle -A AIOS_OUTPUT -m set --match-set aios_bp_v4 dst -j RETURN || return 1
		if [ "$TCP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_OUTPUT -p tcp -j MARK --set-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP4_PORT" -gt 0 ]; then
			run_cmd iptables -t mangle -A AIOS_OUTPUT -p udp -j MARK --set-mark "$TPROXY_MARK" || return 1
		fi

		run_cmd iptables -t mangle -A PREROUTING -m mark --mark "$TPROXY_MARK" -j AIOS_PREROUTING_LOCAL || return 1
		if [ -n "$IFACES_V4" ]; then
			for iface in $IFACES_V4; do
				run_cmd iptables -t mangle -A PREROUTING -i "$iface" -j AIOS_PREROUTING || return 1
			done
		else
			run_cmd iptables -t mangle -A PREROUTING -j AIOS_PREROUTING || return 1
		fi
		run_cmd iptables -t mangle -A OUTPUT -j AIOS_OUTPUT || return 1
	fi

	# IPv6 mangle chains (if ip6tables available and IPv6 port configured)
	if [ "$ipv6_active" = "1" ]; then
		ip6tables -t mangle -N AIOS_PREROUTING_LOCAL 2>/dev/null || true
		run_cmd ip6tables -t mangle -F AIOS_PREROUTING_LOCAL || return 1
		run_cmd ip6tables -t mangle -A AIOS_PREROUTING_LOCAL -m addrtype --dst-type LOCAL -j RETURN || return 1
		if [ "$TCP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_PREROUTING_LOCAL -p tcp -j TPROXY --on-port "$TCP6_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_PREROUTING_LOCAL -p udp -j TPROXY --on-port "$UDP6_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi

		ip6tables -t mangle -N AIOS_PREROUTING 2>/dev/null || true
		run_cmd ip6tables -t mangle -F AIOS_PREROUTING || return 1
		run_cmd ip6tables -t mangle -A AIOS_PREROUTING -m addrtype --dst-type LOCAL -j RETURN || return 1
		for iface in $BP_IFACES_V6; do
			run_cmd ip6tables -t mangle -A AIOS_PREROUTING -i "$iface" -j RETURN || return 1
		done
		if [ "$TCP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_PREROUTING -p tcp -m set --match-set aios_fw_v6 dst -j TPROXY --on-port "$TCP6_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_PREROUTING -p udp -m set --match-set aios_fw_v6 dst -j TPROXY --on-port "$UDP6_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi
		run_cmd ip6tables -t mangle -A AIOS_PREROUTING -m set --match-set aios_reserved_v6 dst -j RETURN || return 1
		run_cmd ip6tables -t mangle -A AIOS_PREROUTING -m set --match-set aios_bp_v6 dst -j RETURN || return 1
		if [ "$TCP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port "$TCP6_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port "$UDP6_PORT" --tproxy-mark "$TPROXY_MARK" || return 1
		fi

		ip6tables -t mangle -N AIOS_OUTPUT 2>/dev/null || true
		run_cmd ip6tables -t mangle -F AIOS_OUTPUT || return 1
		if ! ip6tables -t mangle -A AIOS_OUTPUT -m conntrack --ctdir REPLY -j RETURN 2>/dev/null; then
			echo "fw3_ipt.sh: warning: ip6tables conntrack --ctdir REPLY unavailable (install kmod-ipt-conntrack to prevent IPv6 LAN reply loops)" >&2
		fi
		run_cmd ip6tables -t mangle -A AIOS_OUTPUT -m addrtype --dst-type LOCAL -j RETURN || return 1
		run_cmd ip6tables -t mangle -A AIOS_OUTPUT -m mark --mark "$OUTBOUND_MARK" -j RETURN || return 1
		run_cmd ip6tables -t mangle -A AIOS_OUTPUT -m mark --mark "$DNS_MARK" -j RETURN || return 1
		if [ "$TCP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_OUTPUT -p tcp -m set --match-set aios_fw_v6 dst -j MARK --set-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_OUTPUT -p udp -m set --match-set aios_fw_v6 dst -j MARK --set-mark "$TPROXY_MARK" || return 1
		fi
		run_cmd ip6tables -t mangle -A AIOS_OUTPUT -m set --match-set aios_reserved_v6 dst -j RETURN || return 1
		run_cmd ip6tables -t mangle -A AIOS_OUTPUT -m set --match-set aios_bp_v6 dst -j RETURN || return 1
		if [ "$TCP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_OUTPUT -p tcp -j MARK --set-mark "$TPROXY_MARK" || return 1
		fi
		if [ "$UDP6_PORT" -gt 0 ]; then
			run_cmd ip6tables -t mangle -A AIOS_OUTPUT -p udp -j MARK --set-mark "$TPROXY_MARK" || return 1
		fi

		run_cmd ip6tables -t mangle -A PREROUTING -m mark --mark "$TPROXY_MARK" -j AIOS_PREROUTING_LOCAL || return 1
		if [ -n "$IFACES_V6" ]; then
			for iface in $IFACES_V6; do
				run_cmd ip6tables -t mangle -A PREROUTING -i "$iface" -j AIOS_PREROUTING || return 1
			done
		else
			run_cmd ip6tables -t mangle -A PREROUTING -j AIOS_PREROUTING || return 1
		fi
		run_cmd ip6tables -t mangle -A OUTPUT -j AIOS_OUTPUT || return 1
	fi
	return 0
}

start_fw3() {
	stop_fw3
	if ! start_fw3_apply; then
		stop_fw3
		return 1
	fi
	return 0
}

stop_fw3() {
	# Remove all AIOS_* jump rules dynamically (including interface-scoped and local TProxy rules)
	iptables-save -t nat 2>/dev/null | grep -E '^-A (PREROUTING|OUTPUT) .*-j AIOS_REDIRECT(_PRE)?' | sed 's/^-A /iptables -t nat -D /' | sh 2>/dev/null || true
	iptables -t nat -F AIOS_REDIRECT_PRE 2>/dev/null || true
	iptables -t nat -X AIOS_REDIRECT_PRE 2>/dev/null || true
	iptables -t nat -F AIOS_REDIRECT 2>/dev/null || true
	iptables -t nat -X AIOS_REDIRECT 2>/dev/null || true

	iptables-save -t mangle 2>/dev/null | grep -E '^-A (PREROUTING|OUTPUT) .*-j AIOS_(PREROUTING(_LOCAL)?|OUTPUT)' | sed 's/^-A /iptables -t mangle -D /' | sh 2>/dev/null || true
	iptables -t mangle -F AIOS_PREROUTING_LOCAL 2>/dev/null || true
	iptables -t mangle -X AIOS_PREROUTING_LOCAL 2>/dev/null || true
	iptables -t mangle -F AIOS_PREROUTING 2>/dev/null || true
	iptables -t mangle -X AIOS_PREROUTING 2>/dev/null || true
	iptables -t mangle -F AIOS_OUTPUT 2>/dev/null || true
	iptables -t mangle -X AIOS_OUTPUT 2>/dev/null || true

	if command -v ip6tables >/dev/null 2>&1; then
		ip6tables-save -t mangle 2>/dev/null | grep -E '^-A (PREROUTING|OUTPUT) .*-j AIOS_(PREROUTING(_LOCAL)?|OUTPUT)' | sed 's/^-A /ip6tables -t mangle -D /' | sh 2>/dev/null || true
		ip6tables -t mangle -F AIOS_PREROUTING_LOCAL 2>/dev/null || true
		ip6tables -t mangle -X AIOS_PREROUTING_LOCAL 2>/dev/null || true
		ip6tables -t mangle -F AIOS_PREROUTING 2>/dev/null || true
		ip6tables -t mangle -X AIOS_PREROUTING 2>/dev/null || true
		ip6tables -t mangle -F AIOS_OUTPUT 2>/dev/null || true
		ip6tables -t mangle -X AIOS_OUTPUT 2>/dev/null || true
	fi

	flush_route_pair "$TPROXY_MARK" "$ROUTE_TABLE"
	if [ -s "$ROUTE_STATE_FILE" ]; then
		local prev_mark prev_table
		read -r prev_mark prev_table < "$ROUTE_STATE_FILE" 2>/dev/null || true
		flush_route_pair "$prev_mark" "$prev_table"
		rm -f "$ROUTE_STATE_FILE"
	fi

	for setname in aios_reserved_v4 aios_reserved_v6 aios_bp_v4 aios_bp_v6 aios_fw_v4 aios_fw_v6; do
		ipset destroy "$setname" 2>/dev/null || true
	done
}

case "$1" in
	start) start_fw3 ;;
	stop) stop_fw3 ;;
	restart) stop_fw3; start_fw3 ;;
	*) exit 1 ;;
esac
