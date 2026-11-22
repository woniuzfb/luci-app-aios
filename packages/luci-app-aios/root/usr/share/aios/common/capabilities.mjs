"use strict";

export const CAPABILITIES = {
	xray: {
		inboundProtocols: ["dokodemo-door", "tunnel", "socks", "http", "vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "masque", "tun"],
		outboundProtocols: ["vless", "vmess", "trojan", "shadowsocks", "hysteria", "wireguard", "masque", "freedom", "blackhole", "dns", "socks", "http", "loopback"],
		transports: ["raw", "tcp", "websocket", "ws", "grpc", "httpupgrade", "xhttp", "mkcp", "hysteria", "masque"],
		securities: ["none", "tls", "reality"],
		balancerStrategies: ["random", "roundRobin", "leastPing", "leastLoad"],
		maxMuxConcurrency: 128,
		supportsMetrics: true,
		supportsFinalmask: true,
		supportsReality: true,
		supportsVlessFlow: true,
		supportsBurstObservatoryTopLevel: true
	},
	v2ray_v4: {
		inboundProtocols: ["dokodemo-door", "socks", "http", "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tun"],
		outboundProtocols: ["vmess", "vless", "trojan", "shadowsocks", "hysteria2", "freedom", "blackhole", "dns", "socks", "http", "loopback"],
		transports: ["tcp", "ws", "grpc", "http", "h2", "kcp", "mkcp", "quic", "domainsocket", "hysteria2"],
		securities: ["none", "tls"],
		balancerStrategies: ["random", "leastPing"],
		maxMuxConcurrency: 1024,
		supportsMetrics: false,
		supportsFinalmask: false,
		supportsReality: false,
		supportsVlessFlow: false,
		supportsBurstObservatoryTopLevel: false
	},
	v2ray_v5: {
		inboundProtocols: ["dokodemo-door", "socks", "http", "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tun"],
		outboundProtocols: ["vmess", "vless", "trojan", "shadowsocks", "shadowsocks2022", "hysteria2", "freedom", "blackhole", "dns", "socks", "http", "loopback"],
		transports: ["tcp", "ws", "grpc", "httpupgrade", "kcp", "mkcp", "quic", "hysteria2"],
		securities: ["none", "tls", "utls"],
		balancerStrategies: ["random", "leastPing", "leastLoad"],
		maxMuxConcurrency: 1024,
		supportsMetrics: false,
		supportsFinalmask: false,
		supportsReality: false,
		supportsVlessFlow: false,
		supportsBurstObservatoryTopLevel: false
	}
};

export function get_capabilities(core, format) {
	if (core === "xray") return CAPABILITIES.xray;
	return format === "jsonv5" ? CAPABILITIES.v2ray_v5 : CAPABILITIES.v2ray_v4;
}

export function supports_feature(core, key, format) {
	const cap = get_capabilities(core, format);
	return !!cap[key];
}

export function validate_stream_combination(core, format, protocol, transport, security) {
	let errors = [];
	if (core === "xray") {
		if (protocol === "hysteria" && transport !== "hysteria") {
			push(errors, "Xray hysteria 协议只能搭配 hysteria 传输方式。");
		}
		if (protocol === "masque" && transport !== "masque") {
			push(errors, "Xray masque 协议只能搭配 masque 传输方式。");
		}
		if (transport === "masque" && protocol !== "masque") {
			push(errors, "Xray masque 传输方式仅适用于 masque 协议。");
		}
		if ((transport === "hysteria" || transport === "masque") && security !== "tls") {
			push(errors, `Xray ${transport} 传输方式必须使用 tls 安全层（不支持 ${security}）。`);
		}
		if (security === "reality" && transport !== "raw" && transport !== "xhttp" && transport !== "grpc") {
			push(errors, `Xray REALITY 仅支持与 raw / xhttp / grpc 传输方式组合，当前为 ${transport}。`);
		}
	} else {
		if (security === "reality") {
			push(errors, `V2Ray ${format || "jsonv4"} 不支持 REALITY 安全层。`);
		}
		if (format !== "jsonv5" && security === "utls") {
			push(errors, "V2Ray jsonv4 不支持独立 utls 安全层，请切换 jsonv5 或改用 tls。");
		}
		if (format === "jsonv5" && security === "utls" && transport !== "tcp" && transport !== "ws") {
			push(errors, `V2Ray jsonv5 uTLS 仅支持 tcp / ws 传输方式，当前为 "${transport}"。`);
		}
		if (format === "jsonv5" && (transport === "http" || transport === "domainsocket")) {
			push(errors, `V2Ray jsonv5 不支持传输方式 "${transport}"。`);
		}
		if (transport === "xhttp" || transport === "splithttp" || transport === "masque") {
			push(errors, `V2Ray ${format || "jsonv4"} 不支持传输方式 "${transport}"。`);
		}
		if (format !== "jsonv5" && transport === "httpupgrade") {
			push(errors, "V2Ray jsonv4 不支持传输方式 \"httpupgrade\"（请切换 jsonv5）。");
		}
	}
	return errors;
}
