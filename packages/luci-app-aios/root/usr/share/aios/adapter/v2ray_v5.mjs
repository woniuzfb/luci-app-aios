"use strict";

import { to_array } from "../common/config.mjs";

function build_v5_stream(item, is_inbound, default_mark) {
	let transport = item.transport || "tcp";
	if (transport === "raw") transport = "tcp";
	if (transport === "websocket") transport = "ws";
	if (transport === "h2") transport = "http";
	if (transport === "hysteria") transport = "hysteria2";
	if (transport === "xhttp" || transport === "splithttp" || transport === "masque") {
		transport = "tcp";
	}

	let transportSettings = {};
	if (transport === "ws") {
		transportSettings = { path: item.ws_path || "/" };
	} else if (transport === "grpc") {
		transportSettings = { serviceName: item.grpc_service_name || "" };
	} else if (transport === "httpupgrade") {
		transportSettings = {
			path: item.httpupgrade_path || "/",
			host: item.httpupgrade_host || ""
		};
	} else if (transport === "hysteria2") {
		transportSettings = {
			password: item.hysteria_auth || item.password || "",
			use_udp_extension: item.hysteria_udp_extension !== "0",
			congestion: (item.hysteria_up_mbps || item.hysteria_down_mbps) ? {
				type: "brutal",
				up_mbps: int(item.hysteria_up_mbps || 50),
				down_mbps: int(item.hysteria_down_mbps || 100)
			} : { type: "bbr" }
		};
	}

	let security = item.security || "none";
	if (security === "reality") security = "utls";

	let ss = {
		transport: transport,
		transportSettings: transportSettings,
		security: security
	};

	if (security === "tls") {
		let tls = {};
		if (item.tls_server_name) tls.serverName = item.tls_server_name;
		if (item.tls_allow_insecure === "1") tls.allowInsecure = true;
		const alpn = to_array(item.tls_alpn);
		if (length(alpn) > 0) tls.nextProtocol = alpn;
		if (item.tls_ech_config) tls.echConfig = item.tls_ech_config;
		ss.securitySettings = tls;
	} else if (security === "utls") {
		ss.securitySettings = {
			tlsConfig: {
				serverName: item.tls_server_name || "",
				allowInsecure: item.tls_allow_insecure === "1"
			},
			imitate: item.tls_fingerprint || "chrome_auto"
		};
	}

	let sock = {};
	const mark = item.sockopt_mark ? int(item.sockopt_mark) : default_mark;
	if (mark != null && mark > 0) sock.mark = mark;
	if (item.sockopt_tproxy && item.sockopt_tproxy !== "off") sock.tproxy = item.sockopt_tproxy;
	if (item.sockopt_tcp_fast_open === "1") sock.tcpFastOpen = true;
	if (item.sockopt_mptcp === "1") sock.mptcp = true;
	if (item.sockopt_interface) sock.bindToDevice = item.sockopt_interface;
	if (length(keys(sock)) > 0) ss.socketSettings = sock;

	return ss;
}

export function compile_v2ray_v5(cfg) {
	const g = cfg.general || {};
	const tp = cfg.transparent_proxy || {};
	const out_mark = tp.enabled === "1" ? int(tp.outbound_mark || "0x3a03") : null;

	let inbounds = [];
	let services = {};
	if (g.stats_enabled === "1") services.stats = {};

	for (let ib in cfg.inbounds) {
		if (ib.enabled === "0") continue;
		if (ib.protocol === "tun") {
			services.tun = {
				name: ib.tun_name || "aios0",
				mtu: int(ib.tun_mtu || 1500),
				tag: ib.tag || "tun-in"
			};
			continue;
		}
		if (ib.protocol === "wireguard" || ib.protocol === "masque") continue;
		const proto = ib.protocol === "tunnel" ? "dokodemo-door" : (ib.protocol === "hysteria" ? "hysteria2" : (ib.protocol || "socks"));
		push(inbounds, {
			tag: ib.tag || ib[".name"],
			listen: ib.listen || "0.0.0.0",
			port: int(ib.port || 1080),
			protocol: proto,
			settings: {},
			streamSettings: build_v5_stream(ib, true, null)
		});
	}

	let outbounds = [];
	for (let ob in cfg.outbounds) {
		if (ob.enabled === "0" || ob.protocol === "wireguard" || ob.protocol === "masque") continue;
		const proto = ob.protocol === "hysteria" ? "hysteria2" : (ob.protocol || "freedom");
		let settings = {};
		if (proto === "shadowsocks2022") {
			settings = {
				address: ob.address || "",
				port: int(ob.port || 8388),
				method: ob.method || "2022-blake3-aes-128-gcm",
				psk: ob.password || ""
			};
		} else if (proto === "vmess" || proto === "vless") {
			settings = { address: ob.address || "", port: int(ob.port || 443), uuid: ob.uuid || "" };
		} else if (proto === "trojan") {
			settings = { address: ob.address || "", port: int(ob.port || 443), password: ob.password || "" };
		} else if (proto === "hysteria2") {
			settings = { server: [{ address: ob.address || "", port: int(ob.port || 443) }] };
		} else if (proto === "freedom") {
			settings = { domainStrategy: ob.domain_strategy || "AsIs" };
		}
		let item = {
			tag: ob.tag || ob[".name"],
			protocol: proto,
			settings: settings,
			streamSettings: build_v5_stream(ob, false, proto === "dns" ? null : out_mark)
		};
		if (ob.dialer_proxy) item.proxySettings = { tag: ob.dialer_proxy, transportLayer: true };
		push(outbounds, item);
	}

	let doc = {
		log: {
			access: { type: (g.access_log === "none" || !g.access_log) ? "None" : "File", path: g.access_log === "none" ? null : g.access_log },
			error: { type: g.error_log ? "File" : "Console", path: g.error_log || null, level: uc(g.log_level || "warning") }
		},
		inbounds: inbounds,
		outbounds: outbounds
	};

	const r = cfg.routing || {};
	if (r.enabled === "1") {
		doc.router = {
			domainStrategy: r.domain_strategy || "IPIfNonMatch",
			rule: map(filter(cfg.routing_rules, x => x.enabled !== "0"), rr => ({
				domain: to_array(rr.domain),
				ip: to_array(rr.ip),
				tag: rr.outbound_tag || null,
				balancingTag: rr.balancer_tag || null
			}))
		};
	}

	if (length(keys(services)) > 0) doc.services = services;
	return doc;
}
