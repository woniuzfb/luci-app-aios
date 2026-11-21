"use strict";

export const CAPABILITIES = {
	xray: {
		inboundProtocols: ["dokodemo-door", "tunnel", "socks", "http", "vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "masque", "tun"],
		outboundProtocols: ["vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "masque", "freedom", "blackhole", "dns", "socks", "http", "loopback"],
		transports: ["raw", "tcp", "websocket", "ws", "grpc", "httpupgrade", "xhttp", "splithttp", "mkcp", "hysteria", "masque"],
		securities: ["none", "tls", "reality"],
		balancerStrategies: ["random", "roundRobin", "leastPing", "leastLoad"],
		supportsMetrics: true,
		supportsFinalmask: true,
		supportsReality: true,
		supportsVlessFlow: true,
		supportsBurstObservatoryTopLevel: true
	},
	v2ray: {
		inboundProtocols: ["dokodemo-door", "socks", "http", "vless", "vmess", "trojan", "shadowsocks", "hysteria2"],
		outboundProtocols: ["vmess", "vless", "trojan", "shadowsocks", "shadowsocks2022", "hysteria2", "freedom", "blackhole", "dns", "socks", "http", "loopback"],
		transports: ["tcp", "ws", "grpc", "http", "h2", "kcp", "mkcp", "quic", "domainsocket", "hysteria2"],
		securities: ["none", "tls", "utls"],
		balancerStrategies: ["random", "leastPing"],
		supportsMetrics: false,
		supportsFinalmask: false,
		supportsReality: false,
		supportsVlessFlow: false,
		supportsBurstObservatoryTopLevel: false
	}
};

export function supports_feature(core, key) {
	const cap = CAPABILITIES[core] || CAPABILITIES.xray;
	return !!cap[key];
}
