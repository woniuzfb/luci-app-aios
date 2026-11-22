"use strict";

import { deep_merge, kv_to_map, parse_json_safe, to_array } from "../common/config.mjs";
import { build_stream_settings } from "../common/stream.mjs";

function build_inbound(item) {
	const proto = item.protocol === "dokodemo-door" && item.use_tunnel === "1" ? "tunnel" : (item.protocol || "socks");
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
		if (item.socks_auth === "password") {
			if (has_users) obj.settings.users = map(users, u => ({ user: u.username || "", pass: u.password || "" }));
			else if (item.username) obj.settings.users = [{ user: item.username, pass: item.password || "" }];
		}
	} else if (proto === "http") {
		if (has_users) obj.settings.users = map(users, u => ({ user: u.username || "", pass: u.password || "" }));
		else if (item.username) obj.settings.users = [{ user: item.username, pass: item.password || "" }];
		if (item.http_allow_transparent === "1") obj.settings.allowTransparent = true;
	} else if (proto === "dokodemo-door") {
		obj.settings = { network: item.dokodemo_network || "tcp,udp", followRedirect: item.dokodemo_follow_redirect === "1" };
		if (item.dokodemo_address) obj.settings.address = item.dokodemo_address;
		if (item.dokodemo_port) obj.settings.port = int(item.dokodemo_port);
	} else if (proto === "tunnel") {
		obj.settings = { allowedNetwork: item.dokodemo_network || "tcp,udp", followRedirect: item.dokodemo_follow_redirect === "1" };
		if (item.dokodemo_address) obj.settings.rewriteAddress = item.dokodemo_address;
		if (item.dokodemo_port) obj.settings.rewritePort = int(item.dokodemo_port);
		const pm = kv_to_map(parse_json_safe(item.tunnel_port_map_json));
		if (pm) obj.settings.portMap = pm;
		if (item.tunnel_user_level != null && item.tunnel_user_level !== "") obj.settings.userLevel = int(item.tunnel_user_level);
	} else if (proto === "vless") {
		obj.settings = {
			users: has_users
				? map(users, u => {
					let x = { id: u.id || "", flow: u.flow || "", level: int(u.level || 0) };
					if (u.email) x.email = u.email;
					return x;
				})
				: [{ id: item.uuid || "", flow: item.flow || "" }],
			decryption: item.decryption || "none"
		};
		if (type(fallbacks) === "array" && length(fallbacks) > 0) obj.settings.fallbacks = fallbacks;
	} else if (proto === "vmess") {
		obj.settings = {
			users: has_users
				? map(users, u => {
					let x = { id: u.id || "", level: int(u.level || 0) };
					if (u.email) x.email = u.email;
					return x;
				})
				: [{ id: item.uuid || "" }]
		};
	} else if (proto === "trojan") {
		obj.settings = {
			users: has_users
				? map(users, u => {
					let x = { password: u.password || "", level: int(u.level || 0) };
					if (u.email) x.email = u.email;
					return x;
				})
				: [{ password: item.password || "" }]
		};
		if (type(fallbacks) === "array" && length(fallbacks) > 0) obj.settings.fallbacks = fallbacks;
	} else if (proto === "shadowsocks") {
		obj.settings = { method: item.method || "aes-256-gcm", password: item.password || "", network: item.ss_network || "tcp,udp" };
	} else if (proto === "hysteria") {
		obj.settings = {
			version: 2,
			users: has_users
				? map(users, u => {
					let x = { auth: u.auth || u.password || "", level: int(u.level || 0) };
					if (u.email) x.email = u.email;
					return x;
				})
				: [{ auth: item.hysteria_auth || item.password || "" }]
		};
	} else if (proto === "wireguard") {
		obj.settings = {
			secretKey: item.wg_secret_key || "",
			address: to_array(item.wg_address),
			peers: parse_json_safe(item.wg_peers_json) || [],
			mtu: int(item.wg_mtu || 1420)
		};
	} else if (proto === "masque") {
		const addrs = to_array(item.masque_address);
		const mqUsers = has_users
			? map(users, u => ({ email: u.email || u.username || "", pass: u.password || u.auth || "", level: int(u.level || 0) }))
			: ((item.username || item.password) ? [{ email: item.username || "", pass: item.password || "", level: 0 }] : []);
		obj.settings = {
			users: mqUsers,
			address: length(addrs) > 0 ? addrs : ["10.0.0.1/24"],
			mtu: int(item.masque_mtu || 1280)
		};
	} else if (proto === "tun") {
		delete obj.listen;
		delete obj.port;
		let ts = { name: item.tun_name || "xray0", mtu: int(item.tun_mtu || 1500) };
		if (item.tun_desc) ts.desc = item.tun_desc;
		const gw = to_array(item.tun_gateway);
		if (length(gw) > 0) ts.gateway = gw;
		const tdns = to_array(item.tun_dns);
		if (length(tdns) > 0) ts.dns = tdns;
		if (item.tun_user_level != null && item.tun_user_level !== "") ts.userLevel = int(item.tun_user_level);
		const rt = to_array(item.tun_auto_routing_table);
		if (length(rt) > 0) ts.autoSystemRoutingTable = rt;
		if (item.tun_auto_outbounds_interface) ts.autoOutboundsInterface = item.tun_auto_outbounds_interface;
		if (item.tun_auto_dns_to_gateway === "1") ts.autoSystemDnsToGateway = true;
		const wfp = to_array(item.tun_auto_wfp_block_leak);
		if (length(wfp) > 0) ts.autoSystemWfpBlockLeak = wfp;
		obj.settings = ts;
	}

	if (item.sniffing_enabled === "1") {
		const destOv = to_array(item.sniffing_dest_override);
		let sn = {
			enabled: true,
			destOverride: length(destOv) > 0 ? destOv : ["http", "tls"],
			metadataOnly: item.sniffing_metadata_only === "1",
			routeOnly: item.sniffing_route_only === "1"
		};
		const domEx = to_array(item.sniffing_domains_excluded);
		if (length(domEx) > 0) sn.domainsExcluded = domEx;
		const ipEx = to_array(item.sniffing_ips_excluded);
		if (length(ipEx) > 0) sn.ipsExcluded = ipEx;
		obj.sniffing = sn;
	}

	if (item.allocate_strategy) {
		obj.allocate = {
			strategy: item.allocate_strategy,
			refresh: int(item.allocate_refresh || 5),
			concurrency: int(item.allocate_concurrency || 3)
		};
	}

	if (proto !== "tun" && proto !== "wireguard" && (item.transport || item.security || item.sockopt_tproxy)) {
		obj.streamSettings = build_stream_settings(item, "xray", true, null, proto);
	}

	const custom = parse_json_safe(item.custom_config);
	return custom ? deep_merge(obj, custom) : obj;
}

function build_outbound(item, default_mark) {
	const proto = item.protocol === "hysteria2" ? "hysteria" : (item.protocol || "freedom");
	let obj = { tag: item.tag || item[".name"], protocol: proto, settings: {} };
	if (item.send_through) obj.sendThrough = item.send_through;
	if (item.target_strategy) obj.targetStrategy = item.target_strategy;

	if (proto === "freedom") {
		if (item.freedom_redirect) obj.settings.redirect = item.freedom_redirect;
		if (item.user_level != null && item.user_level !== "") obj.settings.userLevel = int(item.user_level);
		if (item.freedom_proxy_protocol) obj.settings.proxyProtocol = int(item.freedom_proxy_protocol);
		const fr = parse_json_safe(item.freedom_final_rules_json);
		if (type(fr) === "array") obj.settings.finalRules = fr;
	} else if (proto === "blackhole") {
		obj.settings.response = { type: item.blackhole_response || "none" };
	} else if (proto === "dns") {
		if (item.dns_network) obj.settings.rewriteNetwork = item.dns_network;
		if (item.dns_address) obj.settings.rewriteAddress = item.dns_address;
		if (item.dns_port) obj.settings.rewritePort = int(item.dns_port);
		if (item.dns_non_ip_query) obj.settings.nonIPQuery = item.dns_non_ip_query;
		const rules = parse_json_safe(item.dns_rules_json);
		if (type(rules) === "array") obj.settings.rules = rules;
	} else if (proto === "loopback") {
		obj.settings.inboundTag = item.loopback_inbound_tag || "";
		if (item.loopback_sniffing_enabled === "1") {
			let sn = {
				enabled: true,
				destOverride: to_array(item.loopback_sniffing_dest_override),
				metadataOnly: item.loopback_sniffing_metadata_only === "1",
				routeOnly: item.loopback_sniffing_route_only === "1"
			};
			const domEx = to_array(item.loopback_sniffing_domains_excluded);
			if (length(domEx) > 0) sn.domainsExcluded = domEx;
			const ipEx = to_array(item.loopback_sniffing_ips_excluded);
			if (length(ipEx) > 0) sn.ipsExcluded = ipEx;
			obj.settings.sniffing = sn;
		}
	} else if (proto === "vless") {
		obj.settings = {
			address: item.address || "",
			port: int(item.port || 443),
			id: item.uuid || "",
			encryption: item.encryption || "none"
		};
		if (item.flow) obj.settings.flow = item.flow;
		if (item.user_level != null && item.user_level !== "") obj.settings.level = int(item.user_level);
		if (item.vless_reverse_tag) obj.settings.reverse = { tag: item.vless_reverse_tag };
	} else if (proto === "vmess") {
		obj.settings = {
			address: item.address || "",
			port: int(item.port || 443),
			id: item.uuid || "",
			security: item.security_cipher || "auto"
		};
		if (item.user_level != null && item.user_level !== "") obj.settings.level = int(item.user_level);
		if (item.vmess_experiments) obj.settings.experiments = item.vmess_experiments;
	} else if (proto === "trojan") {
		obj.settings = { address: item.address || "", port: int(item.port || 443), password: item.password || "" };
		if (item.email) obj.settings.email = item.email;
		if (item.user_level != null && item.user_level !== "") obj.settings.level = int(item.user_level);
	} else if (proto === "shadowsocks") {
		obj.settings = {
			address: item.address || "",
			port: int(item.port || 8388),
			method: item.method || "aes-256-gcm",
			password: item.password || ""
		};
		if (item.email) obj.settings.email = item.email;
		if (item.user_level != null && item.user_level !== "") obj.settings.level = int(item.user_level);
		if (item.ss_uot === "1") obj.settings.uot = true;
		if (item.ss_uot_version) obj.settings.UoTVersion = int(item.ss_uot_version);
	} else if (proto === "hysteria") {
		obj.settings = { version: 2, address: item.address || "", port: int(item.port || 443) };
	} else if (proto === "socks") {
		obj.settings = { address: item.address || "", port: int(item.port || 1080) };
		if (item.username) {
			obj.settings.user = item.username;
			obj.settings.pass = item.password || "";
			if (item.email) obj.settings.email = item.email;
			if (item.user_level != null && item.user_level !== "") obj.settings.level = int(item.user_level);
		}
	} else if (proto === "http") {
		obj.settings = { address: item.address || "", port: int(item.port || 8080) };
		if (item.username) {
			obj.settings.user = item.username;
			obj.settings.pass = item.password || "";
			if (item.email) obj.settings.email = item.email;
			if (item.user_level != null && item.user_level !== "") obj.settings.level = int(item.user_level);
		}
		const hh = kv_to_map(parse_json_safe(item.http_headers_json));
		if (hh) obj.settings.headers = hh;
	} else if (proto === "wireguard") {
		const peers = parse_json_safe(item.wg_peers_json);
		obj.settings = {
			secretKey: item.wg_secret_key || "",
			address: to_array(item.wg_address),
			peers: (type(peers) === "array" && length(peers) > 0) ? peers : [{ publicKey: item.wg_peer_public_key || "", endpoint: item.wg_endpoint || "" }],
			mtu: int(item.wg_mtu || 1420),
			noKernelTun: item.wg_no_kernel_tun === "1"
		};
		const res = to_array(item.wg_reserved);
		if (length(res) > 0) obj.settings.reserved = map(res, n => int(n));
		const rdns = to_array(item.wg_remote_dns);
		if (length(rdns) > 0) obj.settings.remoteDNS = rdns;
	} else if (proto === "masque") {
		obj.settings = { address: item.address || "", port: int(item.port || 443) };
		const rdns = to_array(item.masque_remote_dns);
		if (length(rdns) > 0) obj.settings.remoteDNS = rdns;
	}

	const mark = proto === "dns" ? null : default_mark;
	if (proto !== "wireguard") {
		obj.streamSettings = build_stream_settings(item, "xray", false, mark, proto);
	} else {
		let wgSock = {};
		const m = item.sockopt_mark ? int(item.sockopt_mark) : mark;
		if (m != null && m > 0) wgSock.mark = m;
		if (item.sockopt_interface) wgSock.interface = item.sockopt_interface;
		if (item.domain_strategy) wgSock.domainStrategy = item.domain_strategy;
		if (item.dialer_proxy) wgSock.dialerProxy = item.dialer_proxy;
		if (length(keys(wgSock)) > 0) obj.streamSettings = { sockopt: wgSock };
	}

	if (item.mux_enabled === "1") {
		let conc = int(item.mux_concurrency || 8);
		if (conc > 128) conc = 128;
		obj.mux = { enabled: true, concurrency: conc };
		if (item.mux_xudp_concurrency) obj.mux.xudpConcurrency = int(item.mux_xudp_concurrency);
		if (item.mux_xudp_proxy_udp443) obj.mux.xudpProxyUDP443 = item.mux_xudp_proxy_udp443;
	}

	const custom = parse_json_safe(item.custom_config);
	return custom ? deep_merge(obj, custom) : obj;
}

export function compile_xray(cfg) {
	const g = cfg.general || {};
	const tp = cfg.transparent_proxy || {};
	const out_mark = tp.enabled === "1" ? int(tp.outbound_mark || "0x3a03") : null;

	let doc = {
		log: { loglevel: g.log_level || "warning", access: g.access_log || "none", error: g.error_log || "", dnsLog: g.dns_log === "1" },
		inbounds: [],
		outbounds: []
	};
	if (g.mask_address) doc.log.maskAddress = g.mask_address;

	const env_map = kv_to_map(parse_json_safe(g.inline_env_json));
	if (env_map) doc.env = env_map;
	if (g.geodata_reload_interval) doc.geodata = { reloadInterval: g.geodata_reload_interval };
	if (g.min_version || g.max_version) {
		doc.version = {};
		if (g.min_version) doc.version.min = g.min_version;
		if (g.max_version) doc.version.max = g.max_version;
	}

	if (g.stats_enabled === "1") doc.stats = {};
	if (g.api_enabled === "1") {
		doc.api = { tag: "api", listen: `127.0.0.1:${int(g.api_port || 18080)}`, services: ["HandlerService", "LoggerService", "StatsService", "RoutingService"] };
	}
	if (g.metrics_enabled === "1") {
		doc.metrics = { tag: "metrics", listen: `127.0.0.1:${int(g.metrics_port || 18888)}` };
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
			if (s.server_id) srv.id = s.server_id;
			if (s.port) srv.port = int(s.port);
			if (s.skip_fallback === "1") srv.skipFallback = true;
			const doms = to_array(s.domains);
			if (length(doms) > 0) srv.domains = doms;
			const exps = to_array(s.expect_ips);
			if (length(exps) > 0) srv.expectedIPs = exps;
			const unexps = to_array(s.unexpected_ips);
			if (length(unexps) > 0) srv.unexpectedIPs = unexps;
			if (s.client_ip) srv.clientIP = s.client_ip;
			if (s.query_strategy) srv.queryStrategy = s.query_strategy;
			if (s.disable_cache === "1") srv.disableCache = true;
			if (s.serve_stale === "1") srv.serveStale = true;
			if (s.serve_expired_ttl) srv.serveExpiredTTL = int(s.serve_expired_ttl);
			if (s.timeout_ms) srv.timeoutMs = int(s.timeout_ms);
			if (s.final_query === "1") srv.finalQuery = true;
			if (s.tag) srv.tag = s.tag;
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
		if (d.script) doc.dns.script = d.script;
		if (d.serve_expired_ttl) doc.dns.serveExpiredTTL = int(d.serve_expired_ttl);
		if (d.use_system_hosts === "1") doc.dns.useSystemHosts = true;
		if (d.client_ip) doc.dns.clientIp = d.client_ip;
		const host_entries = parse_json_safe(d.host_entries_json);
		if (type(host_entries) === "array" && length(host_entries) > 0) {
			let hosts = {};
			for (let h in host_entries) {
				if (h && h.domain && type(h.addresses) === "array" && length(h.addresses) > 0) {
					hosts[h.domain] = length(h.addresses) === 1 ? h.addresses[0] : h.addresses;
				}
			}
			if (length(keys(hosts)) > 0) doc.dns.hosts = hosts;
		}
	}

	if (length(cfg.fakedns) > 0) {
		doc.fakedns = map(cfg.fakedns, f => ({ ipPool: f.ip_pool || "198.18.0.0/15", poolSize: int(f.pool_size || 65535) }));
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
			if (rr.local_port) rule.localPort = rr.local_port;
			if (rr.network) rule.network = rr.network;
			const srcs = to_array(rr.source);
			if (length(srcs) > 0) rule.source = srcs;
			const lips = to_array(rr.local_ip);
			if (length(lips) > 0) rule.localIP = lips;
			const us = to_array(rr.user);
			if (length(us) > 0) rule.user = us;
			const ibs = to_array(rr.inbound_tag);
			if (length(ibs) > 0) rule.inboundTag = ibs;
			const procs = to_array(rr.process);
			if (length(procs) > 0) rule.process = procs;
			const protos = to_array(rr.protocol);
			if (length(protos) > 0) rule.protocol = protos;
			if (rr.vless_route) rule.vlessRoute = rr.vless_route;
			if (rr.rule_tag) rule.ruleTag = rr.rule_tag;
			if (rr.webhook_url) {
				let wh = { url: rr.webhook_url };
				if (rr.webhook_deduplication) wh.deduplication = int(rr.webhook_deduplication);
				const whH = kv_to_map(parse_json_safe(rr.webhook_headers_json));
				if (whH) wh.headers = whH;
				rule.webhook = wh;
			}
			const attrs_obj = parse_json_safe(rr.attrs);
			if (attrs_obj) rule.attrs = attrs_obj;
			if (rr.balancer_tag) rule.balancerTag = rr.balancer_tag;
			else if (rr.outbound_tag) rule.outboundTag = rr.outbound_tag;
			push(rules, rule);
		}
		let balancers = map(cfg.balancers, b => {
			let strategyObj = { type: b.strategy || "random" };
			if (b.strategy === "leastLoad") {
				let st = {};
				if (b.strategy_expected != null && b.strategy_expected !== "") st.expected = int(b.strategy_expected);
				if (b.strategy_max_rtt) st.maxRTT = b.strategy_max_rtt;
				if (b.strategy_tolerance != null && b.strategy_tolerance !== "") st.tolerance = +b.strategy_tolerance;
				const bl = to_array(b.strategy_baselines);
				if (length(bl) > 0) st.baselines = bl;
				const costs = parse_json_safe(b.strategy_costs_json);
				if (type(costs) === "array") st.costs = costs;
				if (length(keys(st)) > 0) strategyObj.settings = st;
			}
			let obj = { tag: b.tag, selector: to_array(b.selector), strategy: strategyObj };
			if (b.fallback_tag) obj.fallbackTag = b.fallback_tag;
			return obj;
		});
		doc.routing = { domainStrategy: r.domain_strategy || "IPIfNonMatch", domainMatcher: r.domain_matcher || "hybrid", rules: rules, balancers: balancers };
		if (r.script) doc.routing.script = r.script;
	}

	const obs = cfg.observatory || {};
	if (obs.enabled === "1") {
		doc.observatory = {
			subjectSelector: to_array(obs.subject_selector),
			probeUrl: obs.probe_url || "https://www.google.com/generate_204",
			probeInterval: obs.probe_interval || "1m",
			enableConcurrency: obs.enable_concurrency === "1"
		};
	}

	const bobs = cfg.burst_observatory || {};
	if (bobs.enabled === "1") {
		doc.burstObservatory = {
			subjectSelector: to_array(bobs.subject_selector),
			pingConfig: {
				destination: bobs.destination || "https://www.google.com/generate_204",
				interval: bobs.interval || "1m",
				sampling: int(bobs.sampling || 3),
				timeout: bobs.timeout || "5s"
			}
		};
		if (bobs.connectivity) doc.burstObservatory.pingConfig.connectivity = bobs.connectivity;
	}

	const p = cfg.policy || {};
	if (p.enabled === "1") {
		let levels = {};
		const parsed_levels = parse_json_safe(p.policy_levels_json);
		if (type(parsed_levels) === "array" && length(parsed_levels) > 0) {
			for (let lv in parsed_levels) {
				levels[`${lv.level || "0"}`] = {
					handshake: int(lv.handshake || 4),
					connIdle: int(lv.conn_idle || 300),
					uplinkOnly: int(lv.uplink_only || 2),
					downlinkOnly: int(lv.downlink_only || 5),
					bufferSize: int(lv.buffer_size || 4),
					statsUserUplink: !!lv.stats_user_uplink,
					statsUserDownlink: !!lv.stats_user_downlink
				};
			}
		} else {
			levels["0"] = { handshake: int(p.handshake || 4), connIdle: int(p.conn_idle || 300), uplinkOnly: int(p.uplink_only || 2), downlinkOnly: int(p.downlink_only || 5), bufferSize: int(p.buffer_size || 4) };
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

	// Xray removed legacy top-level reverse in favor of VLESS Reverse Proxy.
	// Skip emitting top-level doc.reverse to avoid Xray startup failure.

	return doc;
}
