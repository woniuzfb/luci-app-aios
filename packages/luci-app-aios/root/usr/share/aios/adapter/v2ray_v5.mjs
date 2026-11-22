"use strict";

import { deep_merge, parse_duration_ns, parse_json_safe, to_array } from "../common/config.mjs";
import { validate_stream_combination } from "../common/capabilities.mjs";

function to_v5_log_level(lv) {
	const v = lc(lv || "warning");
	if (v === "debug") return "Debug";
	if (v === "info") return "Info";
	if (v === "error") return "Error";
	if (v === "none") return "None";
	return "Warning";
}

function to_v5_query_strategy(qs) {
	if (qs === "UseIPv4" || qs === "USE_IP4") return "USE_IP4";
	if (qs === "UseIPv6" || qs === "USE_IP6") return "USE_IP6";
	return "USE_IP";
}

function to_v5_outbound_ds(ds) {
	if (!ds) return null;
	if (ds === "UseIPv4" || ds === "UseIP4" || ds === "ForceIPv4") return "UseIP4";
	if (ds === "UseIPv6" || ds === "UseIP6" || ds === "ForceIPv6") return "UseIP6";
	if (ds === "UseIP" || ds === "UseIPv4v6" || ds === "UseIPv6v4" || ds === "ForceIP") return "UseIP";
	if (ds === "AsIs") return "AsIs";
	return ds;
}

function to_v5_router_ds(ds) {
	if (ds === "IPIfNonMatch" || ds === "IpIfNonMatch") return "IpIfNonMatch";
	if (ds === "IPOnDemand" || ds === "IpOnDemand") return "IpOnDemand";
	if (ds === "UseIp") return "UseIp";
	return "AsIs";
}

function to_v5_quic_security(sec) {
	const v = lc(sec || "none");
	if (v === "aes-128-gcm" || v === "aes128_gcm") return "AES128_GCM";
	if (v === "chacha20-poly1305" || v === "chacha20_poly1305") return "CHACHA20_POLY1305";
	if (v === "auto") return "AUTO";
	if (v === "zero") return "ZERO";
	return "NONE";
}

function is_ip_literal(val) {
	if (!val) return false;
	if (index(val, ":") >= 0) return true;
	const parts = split(val, ".");
	return length(parts) === 4;
}

function parse_cidr_bytes(cidr) {
	const parts = split(trim(cidr || ""), "/");
	const octets = split(parts[0] || "", ".");
	if (length(octets) !== 4) return null;
	let bytes = [];
	for (let o in octets) {
		const n = int(o);
		if (n < 0 || n > 255) return null;
		push(bytes, n);
	}
	return { ip: bytes, prefix: length(parts) > 1 ? int(parts[1]) : 32 };
}

function parse_geoip_entry(raw) {
	let item = trim(raw || "");
	let inv = false;
	if (substr(item, 0, 1) === "!") {
		inv = true;
		item = trim(substr(item, 1));
	}
	if (substr(item, 0, 6) === "geoip:") {
		let code = trim(substr(item, 6));
		if (substr(code, 0, 1) === "!") {
			inv = true;
			code = trim(substr(code, 1));
		}
		let obj = { filePath: "geoip.dat", code: code };
		if (inv) obj.inverseMatch = true;
		return obj;
	}
	if (substr(item, 0, 4) === "ext:") {
		const rest = substr(item, 4);
		const colon = index(rest, ":");
		const fp = colon >= 0 ? substr(rest, 0, colon) : "geoip.dat";
		let code = colon >= 0 ? substr(rest, colon + 1) : rest;
		if (substr(code, 0, 1) === "!") {
			inv = true;
			code = trim(substr(code, 1));
		}
		let obj = { filePath: fp, code: code };
		if (inv) obj.inverseMatch = true;
		return obj;
	}
	const parts = split(item, "/");
	const ip_addr = parts[0] || "";
	const def_prefix = index(ip_addr, ":") >= 0 ? 128 : 32;
	const prefix = length(parts) > 1 && parts[1] !== "" ? int(parts[1]) : def_prefix;
	let obj = { cidr: [{ ipAddr: ip_addr, prefix: prefix }] };
	if (inv) obj.inverseMatch = true;
	return obj;
}

function parse_priority_domain(raw) {
	const s = trim(raw || "");
	if (substr(s, 0, 5) === "full:") return { type: "Full", domain: substr(s, 5) };
	if (substr(s, 0, 7) === "domain:") return { type: "Subdomain", domain: substr(s, 7) };
	if (substr(s, 0, 7) === "regexp:") return { type: "Regex", domain: substr(s, 7) };
	if (substr(s, 0, 8) === "keyword:") return { type: "Keyword", domain: substr(s, 8) };
	return { type: "Subdomain", domain: s };
}

function build_static_host(domain_raw, targets) {
	const s = trim(domain_raw || "");
	let t = "Full";
	let d = s;
	if (substr(s, 0, 5) === "full:") { t = "Full"; d = substr(s, 5); }
	else if (substr(s, 0, 7) === "domain:") { t = "Subdomain"; d = substr(s, 7); }
	else if (substr(s, 0, 7) === "regexp:") { t = "Regex"; d = substr(s, 7); }
	else if (substr(s, 0, 8) === "keyword:") { t = "Keyword"; d = substr(s, 8); }
	let ips = [];
	let proxied = null;
	for (let x in targets) {
		const v = trim(x || "");
		if (!v) continue;
		if (is_ip_literal(v)) push(ips, v);
		else if (!proxied) proxied = v;
	}
	if (proxied) return { type: t, domain: d, proxiedDomain: proxied };
	return { type: t, domain: d, ip: ips };
}

function build_v5_stream(item, is_inbound, default_mark, protocol) {
	let transport = item.transport || "tcp";
	if (transport === "raw") transport = "tcp";
	if (transport === "websocket") transport = "ws";
	if (transport === "mkcp") transport = "kcp";
	if (transport === "h2") transport = "http";
	if (transport === "hysteria") transport = "hysteria2";

	let security = item.security || "none";
	const errs = validate_stream_combination("v2ray", "jsonv5", protocol || item.protocol || "", transport, security);
	if (length(errs) > 0) {
		die(`AIOS v5 stream validation error (${item.tag || item[".name"] || "node"}): ${join("; ", errs)}`);
	}

	let transportSettings = {};
	if (transport === "tcp") {
		if (is_inbound && item.tcp_accept_proxy_protocol === "1") {
			transportSettings.acceptProxyProtocol = true;
		}
	} else if (transport === "ws") {
		transportSettings = { path: item.ws_path || "/" };
		const rawHs = parse_json_safe(item.ws_headers_json, "ws_headers_json");
		let wsHeaders = [];
		let hasHost = false;
		if (type(rawHs) === "array") {
			for (let h in rawHs) {
				if (h && h.key && trim(h.key) !== "") {
					const k = trim(h.key);
					if (lc(k) === "host") hasHost = true;
					push(wsHeaders, { key: k, value: h.value || "" });
				}
			}
		}
		if (item.ws_host && !hasHost) unshift(wsHeaders, { key: "Host", value: item.ws_host });
		if (length(wsHeaders) > 0) transportSettings.header = wsHeaders;
		if (is_inbound && item.tcp_accept_proxy_protocol === "1") transportSettings.acceptProxyProtocol = true;
		if (item.ws_max_early_data) transportSettings.maxEarlyData = int(item.ws_max_early_data);
		if (item.ws_early_data_header) transportSettings.earlyDataHeaderName = item.ws_early_data_header;
	} else if (transport === "grpc") {
		transportSettings = { serviceName: item.grpc_service_name || "" };
	} else if (transport === "httpupgrade") {
		transportSettings = { path: item.httpupgrade_path || "/", host: item.httpupgrade_host || "" };
		const hs = parse_json_safe(item.httpupgrade_headers_json, "httpupgrade_headers_json");
		if (type(hs) === "array" && length(hs) > 0) transportSettings.header = hs;
		if (item.ws_max_early_data) transportSettings.maxEarlyData = int(item.ws_max_early_data);
		if (item.ws_early_data_header) transportSettings.earlyDataHeaderName = item.ws_early_data_header;
	} else if (transport === "kcp") {
		transportSettings = {
			mtu: { value: int(item.mkcp_mtu || 1350) },
			tti: { value: int(item.mkcp_tti || 50) },
			uplinkCapacity: { value: int(item.mkcp_uplink_capacity || 5) },
			downlinkCapacity: { value: int(item.mkcp_downlink_capacity || 20) },
			congestion: item.mkcp_congestion === "1"
		};
		if (item.mkcp_seed) transportSettings.seed = { seed: item.mkcp_seed };
	} else if (transport === "quic") {
		transportSettings = { security: { type: to_v5_quic_security(item.quic_security) }, key: item.quic_key || "" };
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

	let ss = { transport: transport, transportSettings: transportSettings, security: security };

	if (security === "tls") {
		let tls = {};
		if (item.tls_server_name) tls.serverName = item.tls_server_name;
		const alpn = to_array(item.tls_alpn);
		if (length(alpn) > 0) tls.nextProtocol = alpn;
		if (item.tls_disable_system_root === "1") tls.disableSystemRoot = true;
		const pinned = to_array(item.tls_pinned_sha256);
		if (length(pinned) > 0) {
			tls.pinnedPeerCertificateChainSha256 = pinned;
			if (item.tls_allow_insecure === "1") tls.allowInsecureIfPinnedPeerCertificate = true;
		}
		if (item.tls_ech_config) tls.echConfig = item.tls_ech_config;
		if (is_inbound) {
			const certs = parse_json_safe(item.tls_certificates_json, "tls_certificates_json");
			if (type(certs) === "array" && length(certs) > 0) {
				tls.certificate = filter(certs, c => c && c.certificateFile && c.keyFile);
			} else if (item.tls_cert_file && item.tls_key_file) {
				tls.certificate = [{ certificateFile: item.tls_cert_file, keyFile: item.tls_key_file }];
			}
		}
		ss.securitySettings = tls;
	} else if (security === "utls") {
		let tlsCfg = {};
		if (item.tls_server_name) tlsCfg.serverName = item.tls_server_name;
		const alpn = to_array(item.tls_alpn);
		if (length(alpn) > 0) tlsCfg.nextProtocol = alpn;
		if (item.tls_disable_system_root === "1") tlsCfg.disableSystemRoot = true;
		ss.securitySettings = {
			tlsConfig: tlsCfg,
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
			let ips = [];
			for (let c in to_array(ib.tun_ips)) {
				const parsed = parse_cidr_bytes(c);
				if (parsed) push(ips, parsed);
			}
			let routes = [];
			for (let c in to_array(ib.tun_routes)) {
				const parsed = parse_cidr_bytes(c);
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
			services.tun = tunSvc;
			continue;
		}
		if (ib.protocol === "wireguard" || ib.protocol === "masque") {
			die(`V2Ray jsonv5 不支持入站协议 "${ib.protocol}" (${ib.tag || ib[".name"]})。`);
		}
		const proto = ib.protocol === "tunnel" ? "dokodemo-door" : (ib.protocol === "hysteria" ? "hysteria2" : (ib.protocol || "socks"));
		const users = parse_json_safe(ib.users_json, "users_json");
		const has_users = type(users) === "array" && length(users) > 0;
		let settings = {};
		if (proto === "socks") {
			settings = { udpEnabled: ib.socks_udp === "1" };
			if (ib.socks_ip) settings.address = ib.socks_ip;
			if (ib.packet_encoding) settings.packetEncoding = ib.packet_encoding;
		} else if (proto === "http") {
			settings = {};
		} else if (proto === "dokodemo-door") {
			settings = { networks: lc(ib.dokodemo_network || "tcp,udp"), followRedirect: ib.dokodemo_follow_redirect === "1" };
			if (ib.dokodemo_address) settings.address = ib.dokodemo_address;
			if (ib.dokodemo_port) settings.port = int(ib.dokodemo_port);
		} else if (proto === "vmess" || proto === "vless") {
			settings = { users: has_users ? filter(map(users, u => u.id || ""), x => x !== "") : (ib.uuid ? [ib.uuid] : []) };
		} else if (proto === "trojan") {
			settings = { users: has_users ? filter(map(users, u => u.password || ""), x => x !== "") : (ib.password ? [ib.password] : []) };
			if (ib.packet_encoding) settings.packetEncoding = ib.packet_encoding;
		} else if (proto === "shadowsocks") {
			settings = { method: ib.method || "aes-256-gcm", password: ib.password || "", networks: lc(ib.ss_network || "tcp,udp") };
			if (ib.packet_encoding) settings.packetEncoding = ib.packet_encoding;
		} else if (proto === "hysteria2") {
			if (ib.packet_encoding) settings.packetEncoding = ib.packet_encoding;
		}
		let item = {
			tag: ib.tag || ib[".name"],
			listen: ib.listen || "0.0.0.0",
			port: int(ib.port || 1080),
			protocol: proto,
			settings: settings,
			streamSettings: build_v5_stream(ib, true, null, proto)
		};
		if (ib.sniffing_enabled === "1") {
			const destOv = to_array(ib.sniffing_dest_override);
			item.sniffing = {
				enabled: true,
				destOverride: length(destOv) > 0 ? destOv : ["http", "tls"],
				metadataOnly: ib.sniffing_metadata_only === "1"
			};
		}
		const custom = parse_json_safe(ib.custom_config, "custom_config");
		push(inbounds, custom ? deep_merge(item, custom) : item);
	}

	let outbounds = [];
	for (let ob in cfg.outbounds) {
		if (ob.enabled === "0") continue;
		if (ob.protocol === "wireguard" || ob.protocol === "masque") {
			die(`V2Ray jsonv5 不支持出站协议 "${ob.protocol}" (${ob.tag || ob[".name"]})。`);
		}
		const proto = ob.protocol === "hysteria" ? "hysteria2" : (ob.protocol || "freedom");
		let settings = {};
		if (proto === "shadowsocks2022") {
			settings = { address: ob.address || "", port: int(ob.port || 8388), method: ob.method || "2022-blake3-aes-128-gcm", psk: ob.password || "" };
			const ipsk = to_array(ob.ss_ipsk);
			if (length(ipsk) > 0) settings.ipsk = ipsk;
		} else if (proto === "vmess" || proto === "vless") {
			settings = { address: ob.address || "", port: int(ob.port || 443), uuid: ob.uuid || "" };
		} else if (proto === "trojan") {
			settings = { address: ob.address || "", port: int(ob.port || 443), password: ob.password || "" };
		} else if (proto === "shadowsocks") {
			settings = { address: ob.address || "", port: int(ob.port || 8388), method: ob.method || "aes-256-gcm", password: ob.password || "" };
		} else if (proto === "hysteria2") {
			settings = { server: [{ address: ob.address || "", port: int(ob.port || 443) }] };
		} else if (proto === "freedom" || proto === "blackhole" || proto === "dns") {
			settings = {};
		} else if (proto === "loopback") {
			settings = { inboundTag: ob.loopback_inbound_tag || "" };
		} else if (proto === "socks" || proto === "http") {
			settings = { address: ob.address || "", port: int(ob.port || (proto === "http" ? 8080 : 1080)) };
		}
		let item = { tag: ob.tag || ob[".name"], protocol: proto, settings: settings, streamSettings: build_v5_stream(ob, false, proto === "dns" ? null : out_mark, proto) };
		if (ob.send_through) item.sendThrough = ob.send_through;
		const ds = to_v5_outbound_ds(ob.domain_strategy);
		if (ds) item.domainStrategy = ds;
		if (ob.dialer_proxy) item.proxySettings = { tag: ob.dialer_proxy, transportLayer: true };
		if (ob.mux_enabled === "1") item.mux = { enabled: true, concurrency: int(ob.mux_concurrency || 8) };
		const custom = parse_json_safe(ob.custom_config, "custom_config");
		push(outbounds, custom ? deep_merge(item, custom) : item);
	}

	const obs = cfg.observatory || {};
	if (obs.enabled === "1") {
		services.backgroundObservatory = {
			subjectSelector: to_array(obs.subject_selector),
			probeUrl: obs.probe_url || "https://www.google.com/generate_204",
			probeInterval: parse_duration_ns(obs.probe_interval, 60000000000)
		};
	}
	const bobs = cfg.burst_observatory || {};
	if (bobs.enabled === "1") {
		let pingCfg = {
			destination: bobs.destination || "https://www.google.com/generate_204",
			interval: parse_duration_ns(bobs.interval, 60000000000),
			samplingCount: int(bobs.sampling || 3),
			timeout: parse_duration_ns(bobs.timeout, 5000000000)
		};
		if (bobs.connectivity) pingCfg.connectivity = bobs.connectivity;
		services.burstObservatory = { subjectSelector: to_array(bobs.subject_selector), pingConfig: pingCfg };
	}
	const bf = cfg.browser_forwarder || {};
	if (bf.enabled === "1") {
		services.browser = { listenAddr: bf.listen_addr || "127.0.0.1", listenPort: int(bf.listen_port || 8088) };
	}
	const rev = cfg.reverse || {};
	if (rev.enabled === "1") {
		let bridges = [];
		for (let b in to_array(rev.bridges)) {
			const parts = split(b, "|");
			if (length(parts) === 2) push(bridges, { tag: trim(parts[0]), domain: trim(parts[1]) });
		}
		let portals = [];
		for (let pt in to_array(rev.portals)) {
			const parts = split(pt, "|");
			if (length(parts) === 2) push(portals, { tag: trim(parts[0]), domain: trim(parts[1]) });
		}
		services.reverse = { bridgeConfig: bridges, portalConfig: portals };
	}
	const p = cfg.policy || {};
	if (p.enabled === "1") {
		let levelMap = {};
		const parsed_levels = parse_json_safe(p.policy_levels_json, "policy_levels_json");
		if (type(parsed_levels) === "array" && length(parsed_levels) > 0) {
			for (let lv in parsed_levels) {
				const bufKb = int(lv.buffer_size || 4);
				levelMap[`${lv.level || "0"}`] = {
					timeout: {
						handshake: { value: int(lv.handshake || 4) },
						connectionIdle: { value: int(lv.conn_idle || 300) },
						uplinkOnly: { value: int(lv.uplink_only || 2) },
						downlinkOnly: { value: int(lv.downlink_only || 5) }
					},
					stats: {
						userUplink: !!lv.stats_user_uplink,
						userDownlink: !!lv.stats_user_downlink
					},
					buffer: {
						connection: bufKb < 0 ? -1 : bufKb * 1024
					}
				};
			}
		} else {
			const bufKb = int(p.buffer_size || 4);
			levelMap["0"] = {
				timeout: {
					handshake: { value: int(p.handshake || 4) },
					connectionIdle: { value: int(p.conn_idle || 300) },
					uplinkOnly: { value: int(p.uplink_only || 2) },
					downlinkOnly: { value: int(p.downlink_only || 5) }
				},
				stats: { userUplink: true, userDownlink: true },
				buffer: { connection: bufKb < 0 ? -1 : bufKb * 1024 }
			};
		}
		services.policy = {
			level: levelMap,
			system: {
				stats: {
					inboundUplink: p.stats_inbound_uplink === "1",
					inboundDownlink: p.stats_inbound_downlink === "1",
					outboundUplink: p.stats_outbound_uplink === "1",
					outboundDownlink: p.stats_outbound_downlink === "1"
				}
			}
		};
	}

	const has_access_log = g.access_log && g.access_log !== "none";
	let accessLog = has_access_log ? { type: "File", path: g.access_log } : { type: "None" };
	let errorLog = g.error_log
		? { type: "File", path: g.error_log, level: to_v5_log_level(g.log_level) }
		: { type: "Console", level: to_v5_log_level(g.log_level) };
	let doc = {
		log: {
			access: accessLog,
			error: errorLog
		},
		inbounds: inbounds,
		outbounds: outbounds
	};

	const d = cfg.dns || {};
	const r = cfg.routing || {};
	if (d.enabled === "1" || length(cfg.fakedns) > 0) {
		let dnsObj = {
			tag: d.tag || "dns-in",
			queryStrategy: to_v5_query_strategy(d.query_strategy),
			cacheStrategy: d.disable_cache === "1" ? "CacheDisabled" : "CacheEnabled",
			fallbackStrategy: d.disable_fallback === "1" ? "Disabled" : (d.disable_fallback_if_match === "1" ? "DisabledIfAnyMatch" : "Enabled"),
			domainMatcher: r.domain_matcher === "mph" ? "mph" : "linear",
			nameServer: map(filter(cfg.dns_servers, s => s.enabled !== "0"), s => {
				let ep = { address: s.address };
				if (s.port) ep.port = int(s.port);
				let ns = { address: ep };
				if (s.client_ip) ns.clientIp = s.client_ip;
				if (s.skip_fallback === "1") ns.skipFallback = true;
				const doms = to_array(s.domains);
				if (length(doms) > 0) {
					let pDoms = [];
					let gDoms = [];
					for (let rawDom in doms) {
						const trimmed = trim(rawDom || "");
						if (!trimmed) continue;
						if (substr(trimmed, 0, 8) === "geosite:") {
							push(gDoms, { filePath: "geosite.dat", code: substr(trimmed, 8) });
						} else if (substr(trimmed, 0, 4) === "ext:") {
							const rest = substr(trimmed, 4);
							const colon = index(rest, ":");
							push(gDoms, { filePath: colon >= 0 ? substr(rest, 0, colon) : "geosite.dat", code: colon >= 0 ? substr(rest, colon + 1) : rest });
						} else {
							push(pDoms, parse_priority_domain(trimmed));
						}
					}
					if (length(pDoms) > 0) ns.prioritizedDomain = pDoms;
					if (length(gDoms) > 0) ns.geoDomain = gDoms;
				}
				const exps = to_array(s.expect_ips);
				if (length(exps) > 0) ns.geoip = map(exps, parse_geoip_entry);
				if (s.tag) ns.tag = s.tag;
				if (s.query_strategy) ns.queryStrategy = to_v5_query_strategy(s.query_strategy);
				return ns;
			})
		};
		if (d.client_ip) dnsObj.clientIp = d.client_ip;
		const host_entries = parse_json_safe(d.host_entries_json, "host_entries_json");
		if (type(host_entries) === "array" && length(host_entries) > 0) {
			let sh = [];
			for (let h in host_entries) {
				if (h && h.domain && type(h.addresses) === "array" && length(h.addresses) > 0) {
					push(sh, build_static_host(h.domain, h.addresses));
				}
			}
			if (length(sh) > 0) dnsObj.staticHosts = sh;
		}
		if (length(cfg.fakedns) > 0) {
			dnsObj.fakeDns = {
				pools: map(cfg.fakedns, f => ({ ipPool: f.ip_pool || "198.18.0.0/15", lruSize: int(f.pool_size || 65535) }))
			};
		}
		doc.dns = dnsObj;
	}

	if (r.enabled === "1") {
		let rules = [];
		for (let rr in cfg.routing_rules) {
			if (rr.enabled === "0") continue;
			let domains = [];
			let geoDomains = [];
			for (let dom in to_array(rr.domain)) {
				const s = trim(dom || "");
				if (!s) continue;
				if (substr(s, 0, 8) === "geosite:") push(geoDomains, { filePath: "geosite.dat", code: substr(s, 8) });
				else if (substr(s, 0, 4) === "ext:") {
					const rest = substr(s, 4);
					const colon = index(rest, ":");
					push(geoDomains, { filePath: colon >= 0 ? substr(rest, 0, colon) : "geosite.dat", code: colon >= 0 ? substr(rest, colon + 1) : rest });
				}
				else if (substr(s, 0, 5) === "full:") push(domains, { type: "Full", value: substr(s, 5) });
				else if (substr(s, 0, 7) === "domain:") push(domains, { type: "RootDomain", value: substr(s, 7) });
				else if (substr(s, 0, 7) === "regexp:") push(domains, { type: "Regex", value: substr(s, 7) });
				else if (substr(s, 0, 8) === "keyword:") push(domains, { type: "Plain", value: substr(s, 8) });
				else push(domains, { type: "Plain", value: s });
			}
			let rule = {};
			if (length(domains) > 0) rule.domain = domains;
			if (length(geoDomains) > 0) rule.geoDomain = geoDomains;
			const ips = to_array(rr.ip);
			if (length(ips) > 0) rule.geoip = map(ips, parse_geoip_entry);
			if (rr.port) rule.portList = rr.port;
			if (rr.source_port) rule.sourcePortList = rr.source_port;
			if (rr.network) rule.networks = rr.network;
			const srcs = to_array(rr.source);
			if (length(srcs) > 0) rule.sourceGeoip = map(srcs, parse_geoip_entry);
			const us = to_array(rr.user);
			if (length(us) > 0) rule.userEmail = us;
			const ibs = to_array(rr.inbound_tag);
			if (length(ibs) > 0) rule.inboundTag = ibs;
			const protos = filter(to_array(rr.protocol), x => x !== "quic");
			if (length(protos) > 0) rule.protocol = protos;
			rule.domainMatcher = r.domain_matcher === "mph" ? "mph" : "linear";
			if (rr.attrs) rule.attributes = rr.attrs;
			if (rr.outbound_tag) rule.tag = rr.outbound_tag;
			if (rr.balancer_tag) rule.balancingTag = rr.balancer_tag;
			push(rules, rule);
		}
		let balancers = map(cfg.balancers, b => {
			let strat = "random";
			if (b.strategy === "leastPing") strat = "leastping";
			else if (b.strategy === "leastLoad") strat = "leastload";
			let br = { tag: b.tag, outboundSelector: to_array(b.selector), strategy: strat };
			if (b.fallback_tag) br.fallbackTag = b.fallback_tag;
			return br;
		});
		doc.router = {
			domainStrategy: to_v5_router_ds(r.domain_strategy),
			rule: rules,
			balancingRule: balancers
		};
	}

	if (length(keys(services)) > 0) doc.services = services;
	return doc;
}
