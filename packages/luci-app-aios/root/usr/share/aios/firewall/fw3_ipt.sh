#!/bin/sh
# Isolated firewall3 (iptables + ipset) backend for legacy OpenWrt (19.07/21.02/LEDE)
# Strictly scoped to AIOS_* chains and aios_* ipsets to avoid colliding with other plugins.

NAME=aios

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

create_ipsets() {
	ipset create aios_reserved_v4 hash:net family inet -exist
	ipset flush aios_reserved_v4
	for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 224.0.0.0/3; do
		ipset add aios_reserved_v4 "$cidr" -exist
	done

	ipset create aios_reserved_v6 hash:net family inet6 -exist 2>/dev/null || true
	ipset flush aios_reserved_v6 2>/dev/null || true
	for cidr in ::/128 ::1/128 ::ffff:0.0.0.0/96 64:ff9b::/96 100::/64 2001::/32 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8; do
		ipset add aios_reserved_v6 "$cidr" -exist 2>/dev/null || true
	done

	ipset create aios_bp_v4 hash:net family inet -exist
	ipset flush aios_bp_v4
	ipset create aios_bp_v6 hash:net family inet6 -exist 2>/dev/null || true
	ipset flush aios_bp_v6 2>/dev/null || true

	local ip
	for ip in $(uci -q get "${NAME}.main_tproxy.wan_bp_ips"); do
		case "$ip" in
			*:*) ipset add aios_bp_v6 "$ip" -exist 2>/dev/null || true ;;
			*) ipset add aios_bp_v4 "$ip" -exist ;;
		esac
	done
}

start_fw3() {
	stop_fw3
	create_ipsets

	if [ "$MODE" = "redirect" ]; then
		iptables -t nat -N AIOS_REDIRECT 2>/dev/null || true
		iptables -t nat -F AIOS_REDIRECT
		iptables -t nat -A AIOS_REDIRECT -m mark --mark "$OUTBOUND_MARK" -j RETURN
		iptables -t nat -A AIOS_REDIRECT -m mark --mark "$DNS_MARK" -j RETURN
		iptables -t nat -A AIOS_REDIRECT -m set --match-set aios_reserved_v4 dst -j RETURN
		iptables -t nat -A AIOS_REDIRECT -m set --match-set aios_bp_v4 dst -j RETURN
		[ "$TCP4_PORT" -gt 0 ] && iptables -t nat -A AIOS_REDIRECT -p tcp -j REDIRECT --to-ports "$TCP4_PORT"
		iptables -t nat -A PREROUTING -p tcp -j AIOS_REDIRECT
		iptables -t nat -A OUTPUT -p tcp -j AIOS_REDIRECT
		return 0
	fi

	# TPROXY dual-stack mode
	ip rule add fwmark "$TPROXY_MARK" lookup "$ROUTE_TABLE" 2>/dev/null || true
	ip route add local default dev lo table "$ROUTE_TABLE" 2>/dev/null || true
	ip -6 rule add fwmark "$TPROXY_MARK" lookup "$ROUTE_TABLE" 2>/dev/null || true
	ip -6 route add local default dev lo table "$ROUTE_TABLE" 2>/dev/null || true

	# IPv4 mangle chains
	iptables -t mangle -N AIOS_PREROUTING 2>/dev/null || true
	iptables -t mangle -F AIOS_PREROUTING
	iptables -t mangle -A AIOS_PREROUTING -m set --match-set aios_reserved_v4 dst -j RETURN
	iptables -t mangle -A AIOS_PREROUTING -m set --match-set aios_bp_v4 dst -j RETURN
	[ "$TCP4_PORT" -gt 0 ] && iptables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port "$TCP4_PORT" --tproxy-mark "$TPROXY_MARK"
	[ "$UDP4_PORT" -gt 0 ] && iptables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port "$UDP4_PORT" --tproxy-mark "$TPROXY_MARK"

	iptables -t mangle -N AIOS_OUTPUT 2>/dev/null || true
	iptables -t mangle -F AIOS_OUTPUT
	iptables -t mangle -A AIOS_OUTPUT -m mark --mark "$OUTBOUND_MARK" -j RETURN
	iptables -t mangle -A AIOS_OUTPUT -m mark --mark "$DNS_MARK" -j RETURN
	iptables -t mangle -A AIOS_OUTPUT -m set --match-set aios_reserved_v4 dst -j RETURN
	iptables -t mangle -A AIOS_OUTPUT -m set --match-set aios_bp_v4 dst -j RETURN
	iptables -t mangle -A AIOS_OUTPUT -p tcp -j MARK --set-mark "$TPROXY_MARK"
	iptables -t mangle -A AIOS_OUTPUT -p udp -j MARK --set-mark "$TPROXY_MARK"

	iptables -t mangle -A PREROUTING -j AIOS_PREROUTING
	iptables -t mangle -A OUTPUT -j AIOS_OUTPUT

	# IPv6 mangle chains (if ip6tables available)
	if command -v ip6tables >/dev/null 2>&1; then
		ip6tables -t mangle -N AIOS_PREROUTING 2>/dev/null || true
		ip6tables -t mangle -F AIOS_PREROUTING
		ip6tables -t mangle -A AIOS_PREROUTING -m set --match-set aios_reserved_v6 dst -j RETURN
		ip6tables -t mangle -A AIOS_PREROUTING -m set --match-set aios_bp_v6 dst -j RETURN
		[ "$TCP6_PORT" -gt 0 ] && ip6tables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port "$TCP6_PORT" --tproxy-mark "$TPROXY_MARK"
		[ "$UDP6_PORT" -gt 0 ] && ip6tables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port "$UDP6_PORT" --tproxy-mark "$TPROXY_MARK"

		ip6tables -t mangle -N AIOS_OUTPUT 2>/dev/null || true
		ip6tables -t mangle -F AIOS_OUTPUT
		ip6tables -t mangle -A AIOS_OUTPUT -m mark --mark "$OUTBOUND_MARK" -j RETURN
		ip6tables -t mangle -A AIOS_OUTPUT -m mark --mark "$DNS_MARK" -j RETURN
		ip6tables -t mangle -A AIOS_OUTPUT -m set --match-set aios_reserved_v6 dst -j RETURN
		ip6tables -t mangle -A AIOS_OUTPUT -m set --match-set aios_bp_v6 dst -j RETURN
		ip6tables -t mangle -A AIOS_OUTPUT -p tcp -j MARK --set-mark "$TPROXY_MARK"
		ip6tables -t mangle -A AIOS_OUTPUT -p udp -j MARK --set-mark "$TPROXY_MARK"

		ip6tables -t mangle -A PREROUTING -j AIOS_PREROUTING
		ip6tables -t mangle -A OUTPUT -j AIOS_OUTPUT
	fi
}

stop_fw3() {
	iptables -t nat -D PREROUTING -p tcp -j AIOS_REDIRECT 2>/dev/null || true
	iptables -t nat -D OUTPUT -p tcp -j AIOS_REDIRECT 2>/dev/null || true
	iptables -t nat -F AIOS_REDIRECT 2>/dev/null || true
	iptables -t nat -X AIOS_REDIRECT 2>/dev/null || true

	iptables -t mangle -D PREROUTING -j AIOS_PREROUTING 2>/dev/null || true
	iptables -t mangle -D OUTPUT -j AIOS_OUTPUT 2>/dev/null || true
	iptables -t mangle -F AIOS_PREROUTING 2>/dev/null || true
	iptables -t mangle -X AIOS_PREROUTING 2>/dev/null || true
	iptables -t mangle -F AIOS_OUTPUT 2>/dev/null || true
	iptables -t mangle -X AIOS_OUTPUT 2>/dev/null || true

	if command -v ip6tables >/dev/null 2>&1; then
		ip6tables -t mangle -D PREROUTING -j AIOS_PREROUTING 2>/dev/null || true
		ip6tables -t mangle -D OUTPUT -j AIOS_OUTPUT 2>/dev/null || true
		ip6tables -t mangle -F AIOS_PREROUTING 2>/dev/null || true
		ip6tables -t mangle -X AIOS_PREROUTING 2>/dev/null || true
		ip6tables -t mangle -F AIOS_OUTPUT 2>/dev/null || true
		ip6tables -t mangle -X AIOS_OUTPUT 2>/dev/null || true
	fi

	ip rule del fwmark "$TPROXY_MARK" lookup "$ROUTE_TABLE" 2>/dev/null || true
	ip route del local default dev lo table "$ROUTE_TABLE" 2>/dev/null || true
	ip -6 rule del fwmark "$TPROXY_MARK" lookup "$ROUTE_TABLE" 2>/dev/null || true
	ip -6 route del local default dev lo table "$ROUTE_TABLE" 2>/dev/null || true

	for set_name in aios_reserved_v4 aios_reserved_v6 aios_bp_v4 aios_bp_v6; do
		ipset destroy "$set_name" 2>/dev/null || true
	done
}

case "$1" in
	start) start_fw3 ;;
	stop) stop_fw3 ;;
	restart) stop_fw3 && start_fw3 ;;
esac
