"use strict";

import { deep_merge, parse_duration_ns, parse_json_safe, to_array } from "../common/config.mjs";
import { resolve_core_features } from "../common/features.mjs";
import { build_stream_settings } from "../common/stream.mjs";

function build_inbound(item) {
	const proto = item.protocol === "tunnel" ? "dokodemo-door" : (item.protocol === "hysteria" ? "hysteria2" : (item.protocol || "socks"));
	let obj = {
		tag: item.tag || item[".name"],
		listen: item.listen || "0.0.0.0",
		port: int(item.port || 1080),
		protocol: proto,
		settings: {}
	};

	const users = parse_json_safe(item.users_json);
	const has_users = type(users) === "array" && length(users) > 0;
	const fallbacks = parse_json_safe(item.fallbacks_json);

	if (proto === "socks") {
		obj.settings = { auth: item.socks_auth || "noauth", udp: item.socks_udp === "1" };
		if (item.socks_ip) obj.settings.ip = item.socks_ip;
		if (item.packet_encoding) obj.settings.packetEncoding = item.packet_encoding;
		if (item.socks_auth === "password") {
			if (has_users) obj.settings.accounts = map(users, u => ({ user: u.username || "", pass: u.password || "" }));
			else if (item.username) obj.settings.accounts = [{ user: item.username, pass: item.password || "" }];
		}
	} else if (proto === "http") {
		if (has_users) obj.settings.accounts = map(users, u => ({ user: u.username || "", pass: u.password || "" }));
		else if (item.username) obj.settings.accounts = [{ user: item.username, pass: item.password || "" }];
		if (item.http_allow_transparent === "1") obj.settings.allowTransparent = true;
		if (item.http_timeout) obj.settings.timeout = int(item.http_timeout);
	} else if (proto === "dokodemo-door") {
		obj.settings = { network: item.dokodemo_network || "tcp,udp", followRedirect: item.dokodemo_follow_redirect === "1" };
		if (item.dokodemo_address) obj.settings.address = item.dokodemo_address;
		if (item.dokodemo_port) obj.settings.port = int(item.dokodemo_port);
	} else if (proto === "vless") {
		obj.settings = {
			clients: has_users ? map(users, u => {
				let x = { id: u.id || "", level: int(u.level || 0) };
				if (u.email) x.email = u.email;
				return x;
			}) : [{ id: item.uuid || "" }],
			decryption: "none"
		};
		if (type(fallbacks) === "array" && length(fallbacks) > 0) obj.settings.fallbacks = fallbacks;
	} else if (proto === "vmess") {
		obj.settings = {
			clients: has_users
				? map(users, u => {
					let x = { id: u.id || "", alterId: int(u.alterId || 0), level: int(u.level || 0) };
					if (u.email) x.email = u.email;
					return x;
				})
				: [{ id: item.uuid || "", alterId: int(item.alter_id || 0) }]
		};
	} else if (proto === "trojan") {
		obj.settings = {
			clients: has_users ? map(users, u => {
				let x = { password: u.password || "", level: int(u.level || 0) };
				if (u.email) x.email = u.email;
				return x;
			}) : [{ password: item.password || "" }]
		};
		if (type(fallbacks) === "array" && length(fallbacks) > 0) obj.settings.fallbacks = fallbacks;
		if (item.packet_encoding) obj.settings.packetEncoding = item.packet_encoding;
	} else if (proto === "shadowsocks") {
		const ssMethod = item.method || "aes-256-gcm";
		if (substr(ssMethod, 0, 12) === "2022-blake3-") {
			die(`V2Ray jsonv4 的 shadowsocks 入站不支持 "${ssMethod}"。`);
		}
		obj.settings = { method: ssMethod, password: item.password || "", network: item.ss_network || "tcp,udp" };
		if (item.packet_encoding) obj.settings.packetEncoding = item.packet_encoding;
	} else if (proto === "hysteria2") {
		obj.settings = {};
		if (item.packet_encoding) obj.settings.packetEncoding = item.packet_encoding;
	}

	if (item.sniffing_enabled === "1") {
		const destOv = to_array(item.sniffing_dest_override);
		obj.sniffing = {
			enabled: true,
			destOverride: length(destOv) > 0 ? destOv : ["http", "tls"],
			metadataOnly: item.sniffing_metadata_only === "1"
		};
	}

	if (item.allocate_strategy) {
		obj.allocate = {
			strategy: item.allocate_strategy,
			refresh: int(item.allocate_refresh || 5),
			concurrency: int(item.allocate_concurrency || 3)
		};
	}

	if (item.transport || (item.security && item.security !== "none") || (item.sockopt_tproxy && item.sockopt_tproxy !== "off")) {
		obj.streamSettings = build_stream_settings(item, "v2ray", true, null, proto);
	}

	const custom = parse_json_safe(item.custom_config);
	return custom ? deep_merge(obj, custom) : obj;
}

function build_outbound(item, default_mark) {
	const proto = item.protocol === "hysteria" ? "hysteria2" : (item.protocol || "freedom");
	let obj = { tag: item.tag || item[".name"], protocol: proto, settings: {} };
	if (item.send_through) obj.sendThrough = item.send_through;

	if (proto === "freedom") {
		if (item.domain_strategy) obj.settings.domainStrategy = item.domain_strategy;
		if (item.freedom_redirect) obj.settings.redirect = item.freedom_redirect;
	} else if (proto === "blackhole") {
		obj.settings.response = { type: item.blackhole_response || "none" };
	} else if (proto === "dns") {
		if (item.dns_network) obj.settings.network = item.dns_network;
		if (item.dns_address) obj.settings.address = item.dns_address;
		if (item.dns_port) obj.settings.port = int(item.dns_port);
	} else if (proto === "loopback") {
		obj.settings.inboundTag = item.loopback_inbound_tag || "";
	} else if (proto === "vless") {
		obj.settings = { vnext: [{ address: item.address || "", port: int(item.port || 443), users: [{ id: item.uuid || "", encryption: "none" }] }] };
	} else if (proto === "vmess") {
		obj.settings = { vnext: [{ address: item.address || "", port: int(item.port || 443), users: [{ id: item.uuid || "", alterId: int(item.alter_id || 0), security: item.security_cipher || "auto" }] }] };
	} else if (proto === "trojan") {
		obj.settings = { servers: [{ address: item.address || "", port: int(item.port || 443), password: item.password || "" }] };
	} else if (proto === "shadowsocks") {
		const ssMethod = item.method || "aes-256-gcm";
		if (substr(ssMethod, 0, 12) === "2022-blake3-") {
			die(`V2Ray jsonv4 的 shadowsocks 出站不支持 "${ssMethod}"，请切换 jsonv5 并使用 shadowsocks2022 协议。`);
		}
		let srv = { address: item.address || "", port: int(item.port || 8388), method: ssMethod, password: item.password || "" };
		if (item.ss_iv_check === "1") srv.ivCheck = true;
		obj.settings = { servers: [srv] };
	} else if (proto === "hysteria2") {
		obj.settings = { servers: [{ address: item.address || "", port: int(item.port || 443) }] };
	} else if (proto === "socks") {
		let srv = { address: item.address || "", port: int(item.port || 1080) };
		if (item.username) srv.users = [{ user: item.username, pass: item.password || "" }];
		obj.settings = { servers: [srv] };
		if (item.socks_version) obj.settings.version = item.socks_version;
	} else if (proto === "http") {
		let srv = { address: item.address || "", port: int(item.port || 8080) };
		if (item.username) srv.users = [{ user: item.username, pass: item.password || "" }];
		obj.settings = { servers: [srv] };
	}

	if (item.dialer_proxy) obj.proxySettings = { tag: item.dialer_proxy, transportLayer: true };

	const mark = proto === "dns" ? null : default_mark;
	obj.streamSettings = build_stream_settings(item, "v2ray", false, mark, proto);

	if (item.mux_enabled === "1") {
		const conc = item.mux_concurrency != null && item.mux_concurrency !== "" ? int(item.mux_concurrency) : 8;
		obj.mux = { enabled: true, concurrency: conc };
	}

	const custom = parse_json_safe(item.custom_config);
	return custom ? deep_merge(obj, custom) : obj;
}

export function compile_v2ray(cfg, opts) {
	const g = cfg.general || {};
	const tp = cfg.transparent_proxy || {};
	const out_mark = tp.enabled === "1" ? int(tp.outbound_mark || "0x3a03") : null;
	const target_ver = (opts && opts.version) || (g.target_version && g.target_version !== "auto" ? g.target_version : null);
	const features = resolve_core_features("v2ray", "jsonv4", target_ver);
	const th = features.thresholds || {};

	let doc = {
		log: { loglevel: g.log_level || "warning", access: g.access_log || "none", error: g.error_log || "" },
		inbounds: [],
		outbounds: []
	};

	if (g.stats_enabled === "1") doc.stats = {};

	let extra_api_rule = null;
	if (g.api_enabled === "1") {
		const api_port = int(g.api_port || 18080);
		let api_services = ["HandlerService", "LoggerService"];
		if (g.stats_enabled === "1") push(api_services, "StatsService");
		if ((cfg.observatory || {}).enabled === "1") push(api_services, "ObservatoryService");
		doc.api = { tag: "api", services: api_services };
		push(doc.inbounds, { tag: "api-in", listen: "127.0.0.1", port: api_port, protocol: "dokodemo-door", settings: { address: "127.0.0.1" } });
		extra_api_rule = { type: "field", inboundTag: ["api-in"], outboundTag: "api" };
	}

	for (let ib in cfg.inbounds) {
		if (ib.enabled === "0" || ib.protocol === "tun") continue;
		if (ib.protocol === "wireguard" || ib.protocol === "masque") {
			die(`V2Ray jsonv4 不支持入站协议 "${ib.protocol}" (${ib.tag || ib[".name"]})。`);
		}
		if ((ib.protocol === "hysteria" || ib.protocol === "hysteria2") && !features.hasHysteria2) {
			die(`V2Ray ${features.version} 不支持 hysteria2 入站协议（需 >= ${th.hysteria2?.since || "5.18.0"}）。`);
		}
		if (ib.packet_encoding === "Stream" && !features.hasPacketEncodingStream) {
			die(`V2Ray ${features.version} 不支持 packetEncoding="Stream"（需 >= ${th.packetEncodingStream?.since || "5.53.0"}）。`);
		}
		push(doc.inbounds, build_inbound(ib));
	}
	for (let ob in cfg.outbounds) {
		if (ob.enabled === "0") continue;
		if (ob.protocol === "wireguard" || ob.protocol === "masque" || ob.protocol === "shadowsocks2022") {
			die(`V2Ray jsonv4 不支持出站协议 "${ob.protocol}" (${ob.tag || ob[".name"]})。`);
		}
		if ((ob.protocol === "hysteria" || ob.protocol === "hysteria2") && !features.hasHysteria2) {
			die(`V2Ray ${features.version} 不支持 hysteria2 出站协议（需 >= ${th.hysteria2?.since || "5.18.0"}）。`);
		}
		push(doc.outbounds, build_outbound(ob, out_mark));
	}

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
			if (length(exps) > 0) srv.expectIPs = exps;
			if (s.client_ip) srv.clientIp = s.client_ip;
			push(servers, srv);
		}
		let qs = d.query_strategy || "UseIP";
		if (qs === "UseSystem") qs = "UseIP";
		doc.dns = {
			tag: d.tag || "dns-in",
			queryStrategy: qs,
			disableCache: d.disable_cache === "1",
			disableFallback: d.disable_fallback === "1",
			disableFallbackIfMatch: d.disable_fallback_if_match === "1",
			servers: servers
		};
		if (d.client_ip) doc.dns.clientIp = d.client_ip;
		let hosts = {};
		const raw_hosts = parse_json_safe(d.hosts_json);
		if (type(raw_hosts) === "object") {
			for (let k in raw_hosts) hosts[k] = raw_hosts[k];
		}
		const host_entries = parse_json_safe(d.host_entries_json);
		if (type(host_entries) === "array" && length(host_entries) > 0) {
			for (let h in host_entries) {
				if (h && h.domain && type(h.addresses) === "array" && length(h.addresses) > 0) {
					hosts[h.domain] = length(h.addresses) === 1 ? h.addresses[0] : h.addresses;
				}
			}
		}
		if (length(keys(hosts)) > 0) doc.dns.hosts = hosts;
	}

	if (length(cfg.fakedns) > 0) {
		doc.fakedns = map(cfg.fakedns, f => ({ ipPool: f.ip_pool || "198.18.0.0/15", poolSize: int(f.pool_size || 65535) }));
	}

	const r = cfg.routing || {};
	if (r.enabled === "1" || extra_api_rule) {
		let rules = [];
		if (extra_api_rule) push(rules, extra_api_rule);
		for (let rr in cfg.routing_rules) {
			if (rr.enabled === "0") continue;
			let rule = { type: "field" };
			const doms = to_array(rr.domain);
			if (length(doms) > 0) rule.domains = doms;
			const ips = to_array(rr.ip);
			if (length(ips) > 0) rule.ip = ips;
			if (rr.port) rule.port = rr.port;
			if (rr.source_port) rule.sourcePort = rr.source_port;
			if (rr.network) rule.network = rr.network;
			const srcs = to_array(rr.source);
			if (length(srcs) > 0) rule.source = srcs;
			const us = to_array(rr.user);
			if (length(us) > 0) rule.user = us;
			const ibs = to_array(rr.inbound_tag);
			if (length(ibs) > 0) rule.inboundTag = ibs;
			const protos = filter(to_array(rr.protocol), p => p !== "quic");
			if (length(protos) > 0) rule.protocol = protos;
			if (rr.attrs) rule.attrs = rr.attrs;
			if (rr.balancer_tag) rule.balancerTag = rr.balancer_tag;
			else if (rr.outbound_tag) rule.outboundTag = rr.outbound_tag;
			push(rules, rule);
		}
		let balancers = map(cfg.balancers, b => {
			let strat = b.strategy || "random";
			if (strat === "roundRobin") strat = "random";
			let out = { tag: b.tag, selector: to_array(b.selector), strategy: { type: strat } };
			if (b.fallback_tag) out.fallbackTag = b.fallback_tag;
			return out;
		});
		doc.routing = {
			domainStrategy: r.domain_strategy || "IPIfNonMatch",
			domainMatcher: r.domain_matcher === "mph" ? "mph" : "linear",
			rules: rules,
			balancers: balancers
		};
	}

	const obs = cfg.observatory || {};
	if (obs.enabled === "1") {
		doc.observatory = {
			subjectSelector: to_array(obs.subject_selector),
			probeURL: obs.probe_url || "https://www.google.com/generate_204",
			probeInterval: obs.probe_interval || "1m"
		};
	}

	const bf = cfg.browser_forwarder || {};
	if (bf.enabled === "1") {
		doc.browserForwarder = { listenAddr: bf.listen_addr || "127.0.0.1", listenPort: int(bf.listen_port || 8088) };
	}

	let v4_services = {};
	const bobs = cfg.burst_observatory || {};
	if (bobs.enabled === "1") {
		if (!features.hasV4Services) {
			die(`V2Ray ${features.version} jsonv4 不支持 services.burstObservatory（需 >= ${th.v4Services?.since || "5.17.0"}）。`);
		}
		v4_services.burstObservatory = {
			subjectSelector: to_array(bobs.subject_selector),
			pingConfig: {
				destination: bobs.destination || "https://www.google.com/generate_204",
				interval: parse_duration_ns(bobs.interval, 60000000000),
				samplingCount: int(bobs.sampling || 3),
				timeout: parse_duration_ns(bobs.timeout, 5000000000)
			}
		};
		if (bobs.connectivity) v4_services.burstObservatory.pingConfig.connectivity = bobs.connectivity;
	}
	for (let ib in cfg.inbounds) {
		if (ib.enabled === "0" || ib.protocol !== "tun") continue;
		if (!features.hasV4Services) {
			die(`V2Ray ${features.version} jsonv4 不支持 services.tun（需 >= ${th.v4Services?.since || "5.17.0"}）。`);
		}
		if (ib.packet_encoding === "Stream" && !features.hasPacketEncodingStream) {
			die(`V2Ray ${features.version} 不支持 packetEncoding="Stream"（需 >= ${th.packetEncodingStream?.since || "5.53.0"}）。`);
		}
		const parse_v4_cidr = (c) => {
			const parts = split(trim(c || ""), "/");
			const addr = parts[0] || "";
			if (index(addr, ":") >= 0) {
				const halves = split(addr, "::");
				if (length(halves) > 2) return null;
				const left = halves[0] ? split(halves[0], ":") : [];
				const right = length(halves) === 2 && halves[1] ? split(halves[1], ":") : [];
				const missing = 8 - (length(left) + length(right));
				if (length(halves) === 1 && missing !== 0) return null;
				if (length(halves) === 2 && missing <= 0) return null;
				let groups = [];
				for (let x in left) push(groups, x);
				for (let i = 0; i < missing; i++) push(groups, "0");
				for (let x in right) push(groups, x);
				if (length(groups) !== 8) return null;
				let bytes = [];
				for (let g in groups) {
					if (!match(g, /^[0-9a-fA-F]{1,4}$/)) return null;
					const val = hex(g);
					push(bytes, (val >> 8) & 0xff, val & 0xff);
				}
				if (length(parts) > 1 && parts[1] !== "" && !match(parts[1], /^[0-9]+$/)) return null;
				const prefix = length(parts) > 1 && parts[1] !== "" ? int(parts[1]) : 128;
				if (prefix < 0 || prefix > 128) return null;
				return { ip: bytes, prefix: prefix };
			}
			const octets = split(addr, ".");
			if (length(octets) !== 4) return null;
			let bytes = [];
			for (let o in octets) {
				if (!match(o, /^[0-9]+$/)) return null;
				const n = int(o);
				if (n < 0 || n > 255) return null;
				push(bytes, n);
			}
			if (length(parts) > 1 && parts[1] !== "" && !match(parts[1], /^[0-9]+$/)) return null;
			const prefix = length(parts) > 1 && parts[1] !== "" ? int(parts[1]) : 32;
			if (prefix < 0 || prefix > 32) return null;
			return { ip: bytes, prefix: prefix };
		};
		let ips = [];
		for (let c in to_array(ib.tun_ips)) {
			const parsed = parse_v4_cidr(c);
			if (parsed) push(ips, parsed);
		}
		let routes = [];
		for (let c in to_array(ib.tun_routes)) {
			const parsed = parse_v4_cidr(c);
			if (parsed) push(routes, parsed);
		}
		let tunSvc = {
			name: ib.tun_name || "aios0",
			mtu: int(ib.tun_mtu || 1500),
			tag: ib.tag || "tun-in",
			ips: length(ips) > 0 ? ips : [{ ip: [10, 0, 0, 1], prefix: 24 }],
			routes: length(routes) > 0 ? routes : [{ ip: [0, 0, 0, 0], prefix: 0 }],
			enablePromiscuousMode: ib.tun_promiscuous !== "0",
			enableSpoofing: ib.tun_spoofing !== "0"
		};
		if (ib.packet_encoding) tunSvc.packetEncoding = ib.packet_encoding;
		if (ib.sniffing_enabled === "1") {
			const destOv = to_array(ib.sniffing_dest_override);
			tunSvc.sniffingSettings = {
				enabled: true,
				destinationOverride: length(destOv) > 0 ? destOv : ["http", "tls"],
				metadataOnly: ib.sniffing_metadata_only === "1"
			};
		}
		v4_services.tun = tunSvc;
		break;
	}
	if (length(keys(v4_services)) > 0) doc.services = v4_services;

	const p = cfg.policy || {};
	if (p.enabled === "1") {
		let levels = {};
		const num_or = (val, def) => (val != null && val !== "" ? int(val) : def);
		const parsed_levels = parse_json_safe(p.policy_levels_json, "policy_levels_json");
		if (type(parsed_levels) === "array" && length(parsed_levels) > 0) {
			for (let lv in parsed_levels) {
				levels[`${lv.level != null && lv.level !== "" ? lv.level : "0"}`] = {
					handshake: num_or(lv.handshake, 4),
					connIdle: num_or(lv.conn_idle, 300),
					uplinkOnly: num_or(lv.uplink_only, 2),
					downlinkOnly: num_or(lv.downlink_only, 5),
					bufferSize: num_or(lv.buffer_size, 4),
					statsUserUplink: !!lv.stats_user_uplink,
					statsUserDownlink: !!lv.stats_user_downlink
				};
			}
		} else {
			levels["0"] = {
				handshake: num_or(p.handshake, 4),
				connIdle: num_or(p.conn_idle, 300),
				uplinkOnly: num_or(p.uplink_only, 2),
				downlinkOnly: num_or(p.downlink_only, 5),
				bufferSize: num_or(p.buffer_size, 4),
				statsUserUplink: true,
				statsUserDownlink: true
			};
		}
		doc.policy = {
			levels: levels,
			system: {
				statsInboundUplink: p.stats_inbound_uplink === "1",
				statsInboundDownlink: p.stats_inbound_downlink === "1",
				statsOutboundUplink: p.stats_outbound_uplink === "1",
				statsOutboundDownlink: p.stats_outbound_downlink === "1"
			}
		};
	}

	const rev = cfg.reverse || {};
	if (rev.enabled === "1") {
		let bridges = [];
		for (let b in to_array(rev.bridges)) {
			const parts = split(b, "|");
			if (length(parts) === 2) push(bridges, { tag: parts[0], domain: parts[1] });
		}
		let portals = [];
		for (let pt in to_array(rev.portals)) {
			const parts = split(pt, "|");
			if (length(parts) === 2) push(portals, { tag: parts[0], domain: parts[1] });
		}
		doc.reverse = { bridges: bridges, portals: portals };
	}

	return doc;
}
