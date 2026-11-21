"use strict";

import { deep_merge, to_array } from "../common/config.mjs";
import { build_stream_settings } from "../common/stream.mjs";

function parse_json_safe(str) {
	if (!str || str === "") return null;
	try { return json(str); } catch (e) { return null; }
}

function build_inbound(item) {
	const proto = item.protocol === "dokodemo-door" && item.use_tunnel === "1" ? "tunnel" : (item.protocol || "socks");
	let obj = {
		tag: item.tag || item[".name"],
		listen: item.listen || "0.0.0.0",
		port: int(item.port || 1080),
		protocol: proto,
		settings: {}
	};

	if (proto === "socks") {
		obj.settings = { auth: item.socks_auth || "noauth", udp: item.socks_udp === "1" };
		if (item.socks_auth === "password" && item.username) {
			obj.settings.accounts = [{ user: item.username, pass: item.password || "" }];
		}
	} else if (proto === "http") {
		if (item.username) {
			obj.settings.accounts = [{ user: item.username, pass: item.password || "" }];
		}
	} else if (proto === "dokodemo-door") {
		obj.settings = {
			network: item.dokodemo_network || "tcp,udp",
			followRedirect: item.dokodemo_follow_redirect === "1"
		};
		if (item.dokodemo_address) obj.settings.address = item.dokodemo_address;
		if (item.dokodemo_port) obj.settings.port = int(item.dokodemo_port);
	} else if (proto === "tunnel") {
		obj.settings = {
			allowedNetwork: item.dokodemo_network || "tcp,udp",
			followRedirect: item.dokodemo_follow_redirect === "1"
		};
		if (item.dokodemo_address) obj.settings.rewriteAddress = item.dokodemo_address;
		if (item.dokodemo_port) obj.settings.rewritePort = int(item.dokodemo_port);
	} else if (proto === "vless") {
		obj.settings = {
			clients: [{
				id: item.uuid || "",
				flow: item.flow || ""
			}],
			decryption: item.decryption || "none"
		};
	} else if (proto === "vmess") {
		obj.settings = { clients: [{ id: item.uuid || "" }] };
	} else if (proto === "trojan") {
		obj.settings = { clients: [{ password: item.password || "" }] };
	} else if (proto === "shadowsocks") {
		obj.settings = {
			method: item.method || "aes-256-gcm",
			password: item.password || "",
			network: item.ss_network || "tcp,udp"
		};
	} else if (proto === "tun") {
		delete obj.listen;
		delete obj.port;
		obj.settings = {
			name: item.tun_name || "xray0",
			MTU: int(item.tun_mtu || 1500)
		};
	}

	if (item.sniffing_enabled === "1") {
		obj.sniffing = {
			enabled: true,
			destOverride: to_array(item.sniffing_dest_override),
			metadataOnly: item.sniffing_metadata_only === "1",
			routeOnly: item.sniffing_route_only === "1"
		};
	}

	if (item.transport || item.security || item.sockopt_tproxy) {
		obj.streamSettings = build_stream_settings(item, "xray", true, null);
	}

	const custom = parse_json_safe(item.custom_config);
	return custom ? deep_merge(obj, custom) : obj;
}

function build_outbound(item, default_mark) {
	const proto = item.protocol === "hysteria2" ? "hysteria" : (item.protocol || "freedom");
	let obj = {
		tag: item.tag || item[".name"],
		protocol: proto,
		settings: {}
	};
	if (item.send_through) obj.sendThrough = item.send_through;

	if (proto === "freedom") {
		if (item.freedom_redirect) obj.settings.redirect = item.freedom_redirect;
	} else if (proto === "blackhole") {
		obj.settings.response = { type: item.blackhole_response || "none" };
	} else if (proto === "dns") {
		if (item.dns_network) obj.settings.network = item.dns_network;
		if (item.dns_address) obj.settings.address = item.dns_address;
		if (item.dns_port) obj.settings.port = int(item.dns_port);
		if (item.dns_non_ip_query) obj.settings.nonIPQuery = item.dns_non_ip_query;
	} else if (proto === "loopback") {
		obj.settings.inboundTag = item.loopback_inbound_tag || "";
	} else if (proto === "vless") {
		obj.settings = {
			vnext: [{
				address: item.address || "",
				port: int(item.port || 443),
				users: [{
					id: item.uuid || "",
					encryption: item.encryption || "none",
					flow: item.flow || ""
				}]
			}]
		};
	} else if (proto === "vmess") {
		obj.settings = {
			vnext: [{
				address: item.address || "",
				port: int(item.port || 443),
				users: [{
					id: item.uuid || "",
					security: item.security_cipher || "auto"
				}]
			}]
		};
	} else if (proto === "trojan") {
		obj.settings = {
			servers: [{
				address: item.address || "",
				port: int(item.port || 443),
				password: item.password || ""
			}]
		};
	} else if (proto === "shadowsocks") {
		obj.settings = {
			servers: [{
				address: item.address || "",
				port: int(item.port || 8388),
				method: item.method || "aes-256-gcm",
				password: item.password || "",
				uot: item.ss_uot === "1"
			}]
		};
	} else if (proto === "hysteria") {
		obj.settings = {
			version: 2,
			address: item.address || "",
			port: int(item.port || 443)
		};
	} else if (proto === "socks" || proto === "http") {
		let srv = { address: item.address || "", port: int(item.port || 1080) };
		if (item.username) srv.users = [{ user: item.username, pass: item.password || "" }];
		obj.settings = { servers: [srv] };
	} else if (proto === "wireguard") {
		obj.settings = {
			secretKey: item.wg_secret_key || "",
			address: to_array(item.wg_address),
			peers: [{
				publicKey: item.wg_peer_public_key || "",
				endpoint: item.wg_endpoint || ""
			}],
			mtu: int(item.wg_mtu || 1420),
			noKernelTun: item.wg_no_kernel_tun !== "0"
		};
	}

	const mark = proto === "dns" ? null : default_mark;
	obj.streamSettings = build_stream_settings(item, "xray", false, mark);

	if (item.mux_enabled === "1") {
		obj.mux = {
			enabled: true,
			concurrency: int(item.mux_concurrency || 8)
		};
	}

	const custom = parse_json_safe(item.custom_config);
	return custom ? deep_merge(obj, custom) : obj;
}

export function compile_xray(cfg) {
	const g = cfg.general || {};
	const tp = cfg.transparent_proxy || {};
	const out_mark = tp.enabled === "1" ? int(tp.outbound_mark || "0x3a03") : null;

	let doc = {
		log: {
			loglevel: g.log_level || "warning",
			access: g.access_log || "none",
			error: g.error_log || "",
			dnsLog: g.dns_log === "1"
		},
		inbounds: [],
		outbounds: []
	};
	if (g.mask_address) doc.log.maskAddress = g.mask_address;

	if (g.stats_enabled === "1") doc.stats = {};

	if (g.api_enabled === "1") {
		const api_port = int(g.api_port || 18080);
		doc.api = {
			tag: "api",
			listen: `127.0.0.1:${api_port}`,
			services: ["HandlerService", "LoggerService", "StatsService", "RoutingService"]
		};
	}

	if (g.metrics_enabled === "1") {
		const mport = int(g.metrics_port || 18888);
		doc.metrics = { tag: "metrics", listen: `127.0.0.1:${mport}` };
	}

	for (let ib in cfg.inbounds) {
		if (ib.enabled === "0") continue;
		push(doc.inbounds, build_inbound(ib));
	}

	for (let ob in cfg.outbounds) {
		if (ob.enabled === "0") continue;
		push(doc.outbounds, build_outbound(ob, out_mark));
	}

	// DNS
	const d = cfg.dns || {};
	if (d.enabled === "1") {
		let servers = [];
		for (let s in cfg.dns_servers) {
			if (s.enabled === "0") continue;
			let srv = { address: s.address };
			if (s.port) srv.port = int(s.port);
			if (s.skip_fallback === "1") srv.skipFallback = true;
			const doms = to_array(s.domains);
			if (length(doms) > 0) srv.domains = doms;
			const exps = to_array(s.expect_ips);
			if (length(exps) > 0) srv.expectedIPs = exps;
			const unexps = to_array(s.unexpected_ips);
			if (length(unexps) > 0) srv.unexpectedIPs = unexps;
			if (s.client_ip) srv.clientIP = s.client_ip;
			push(servers, srv);
		}
		doc.dns = {
			tag: d.tag || "dns-in",
			queryStrategy: d.query_strategy || "UseIP",
			disableCache: d.disable_cache === "1",
			disableFallback: d.disable_fallback === "1",
			disableFallbackIfMatch: d.disable_fallback_if_match === "1",
			serveStale: d.serve_stale === "1",
			enableParallelQuery: d.enable_parallel_query === "1",
			servers: servers
		};
		if (d.client_ip) doc.dns.clientIp = d.client_ip;
	}

	// FakeDNS
	if (length(cfg.fakedns) > 0) {
		doc.fakedns = map(cfg.fakedns, f => ({
			ipPool: f.ip_pool || "198.18.0.0/15",
			poolSize: int(f.pool_size || 65535)
		}));
	}

	// Routing
	const r = cfg.routing || {};
	if (r.enabled === "1") {
		let rules = [];
		for (let rr in cfg.routing_rules) {
			if (rr.enabled === "0") continue;
			let rule = { type: "field" };
			const doms = to_array(rr.domain);
			if (length(doms) > 0) rule.domain = doms;
			const ips = to_array(rr.ip);
			if (length(ips) > 0) rule.ip = ips;
			if (rr.port) rule.port = rr.port;
			if (rr.source_port) rule.sourcePort = rr.source_port;
			if (rr.network) rule.network = rr.network;
			const srcs = to_array(rr.source);
			if (length(srcs) > 0) rule.source = srcs;
			const ibs = to_array(rr.inbound_tag);
			if (length(ibs) > 0) rule.inboundTag = ibs;
			const protos = to_array(rr.protocol);
			if (length(protos) > 0) rule.protocol = protos;
			if (rr.balancer_tag) rule.balancerTag = rr.balancer_tag;
			else if (rr.outbound_tag) rule.outboundTag = rr.outbound_tag;
			push(rules, rule);
		}
		let balancers = map(cfg.balancers, b => {
			let obj = {
				tag: b.tag,
				selector: to_array(b.selector),
				strategy: { type: b.strategy || "random" }
			};
			if (b.fallback_tag) obj.fallbackTag = b.fallback_tag;
			return obj;
		});
		doc.routing = {
			domainStrategy: r.domain_strategy || "IPIfNonMatch",
			domainMatcher: r.domain_matcher || "hybrid",
			rules: rules,
			balancers: balancers
		};
	}

	// Observatory
	const obs = cfg.observatory || {};
	if (obs.enabled === "1") {
		doc.observatory = {
			subjectSelector: to_array(obs.subject_selector),
			probeUrl: obs.probe_url || "https://www.google.com/generate_204",
			probeInterval: obs.probe_interval || "1m",
			enableConcurrency: obs.enable_concurrency === "1"
		};
	}

	// Policy
	const p = cfg.policy || {};
	if (p.enabled === "1") {
		doc.policy = {
			levels: {
				"0": {
					handshake: int(p.handshake || 4),
					connIdle: int(p.conn_idle || 300),
					uplinkOnly: int(p.uplink_only || 2),
					downlinkOnly: int(p.downlink_only || 5),
					bufferSize: int(p.buffer_size || 4)
				}
			},
			system: {
				statsInboundUplink: p.stats_inbound_uplink === "1",
				statsInboundDownlink: p.stats_inbound_downlink === "1",
				statsOutboundUplink: p.stats_outbound_uplink === "1",
				statsOutboundDownlink: p.stats_outbound_downlink === "1"
			}
		};
	}

	return doc;
}
