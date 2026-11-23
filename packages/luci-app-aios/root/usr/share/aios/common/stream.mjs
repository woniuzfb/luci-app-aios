"use strict";

import { kv_to_map, parse_json_safe, to_array } from "./config.mjs";
import { validate_stream_combination } from "./capabilities.mjs";

function parse_seconds_num(val) {
	if (val == null || val === "") return null;
	if (type(val) === "int" || type(val) === "double") return val > 0 ? int(val) : null;
	const s = trim(replace(`${val}`, /[sS]$/, ""));
	const n = int(s);
	return n > 0 ? n : null;
}

function is_valid_base64_pin(val) {
	const s = trim(`${val || ""}`);
	if (length(s) < 4 || length(s) % 4 !== 0) return false;
	return !!match(s, /^[A-Za-z0-9+\/]+={0,2}$/);
}

export function build_stream_settings(item, core, is_inbound, default_mark, protocol, features) {
	const is_xray = core === "xray";
	let net = item.transport || (is_xray ? "raw" : "tcp");
	if (is_xray && net === "tcp") net = "raw";
	if (is_xray && net === "ws") net = "websocket";
	if (is_xray && net === "hysteria2") net = "hysteria";
	if (is_xray && net === "splithttp") net = "xhttp";
	if (!is_xray && net === "raw") net = "tcp";
	if (!is_xray && net === "websocket") net = "ws";
	if (!is_xray && net === "mkcp") net = "kcp";
	if (!is_xray && net === "h2") net = "http";
	if (!is_xray && net === "hysteria") net = "hysteria2";

	let security = item.security || "none";
	const errs = validate_stream_combination(core, "jsonv4", protocol || item.protocol || "", net, security, is_inbound ? "inbound" : "outbound");
	if (length(errs) > 0) {
		die(`AIOS stream validation error (${item.tag || item[".name"] || "node"}): ${join("; ", errs)}`);
	}

	const streamKey = is_xray ? ((features && features.streamMethodKey) || "method") : "network";
	let ss = {};
	ss[streamKey] = net;
	ss.security = security;

	if (security === "tls") {
		let tls = {};
		if (item.tls_server_name) tls.serverName = item.tls_server_name;
		if (item.tls_allow_insecure === "1") tls.allowInsecure = true;
		const alpn = to_array(item.tls_alpn);
		if (length(alpn) > 0) tls.alpn = alpn;
		const pinned = to_array(item.tls_pinned_sha256);

		if (is_xray) {
			if (item.tls_fingerprint) tls.fingerprint = item.tls_fingerprint;
			if (length(pinned) > 0) tls.pinnedPeerCertSha256 = join(",", pinned);
			if (item.tls_ech_config) tls.echConfigList = item.tls_ech_config;
			if (item.tls_ech_server_keys) tls.echServerKeys = item.tls_ech_server_keys;
			const echSock = parse_json_safe(item.tls_ech_sockopt_json);
			if (type(echSock) === "object") tls.echSockopt = echSock;
			if (item.tls_verify_peer_name) tls.verifyPeerCertByName = item.tls_verify_peer_name;
			if (item.tls_min_version) tls.minVersion = item.tls_min_version;
			if (item.tls_max_version) tls.maxVersion = item.tls_max_version;
			if (item.tls_cipher_suites) tls.cipherSuites = item.tls_cipher_suites;
			if (item.tls_reject_unknown_sni === "1") tls.rejectUnknownSni = true;
			if (item.tls_use_system_ca === "1") tls.useSystemCA = true;
			if (item.tls_disable_system_root === "1") tls.disableSystemRoot = true;
			if (item.tls_enable_session_resumption === "1") tls.enableSessionResumption = true;
			const curves = to_array(item.tls_curve_preferences);
			if (length(curves) > 0) tls.curvePreferences = curves;
		} else {
			if (length(pinned) > 0) {
				let valid_pins = [];
				for (let p in pinned) {
					const s = trim(`${p || ""}`);
					if (!s) continue;
					if (!is_valid_base64_pin(s)) {
						die(`V2Ray tls_pinned_sha256 必须为合法 Base64 编码 (${item.tag || item[".name"] || "node"}): "${s}"。`);
					}
					push(valid_pins, s);
				}
				if (length(valid_pins) > 0) tls.pinnedPeerCertificateChainSha256 = valid_pins;
			}
			if (item.tls_ech_config && trim(`${item.tls_ech_config}`) !== "") {
				const ech = trim(`${item.tls_ech_config}`);
				if (!is_valid_base64_pin(ech)) {
					die(`V2Ray tls_ech_config 必须为合法标准 Base64 编码 (${item.tag || item[".name"] || "node"})。`);
				}
				tls.echConfig = ech;
			}
			if (item.tls_verify_client === "1") tls.verifyClientCertificate = true;
			if (item.tls_disable_system_root === "1") tls.disableSystemRoot = true;
		}

		if (is_inbound) {
			const certs = parse_json_safe(item.tls_certificates_json);
			if (type(certs) === "array" && length(certs) > 0) {
				tls.certificates = filter(certs, c => c && c.certificateFile && c.keyFile);
			} else if (item.tls_cert_file && item.tls_key_file) {
				tls.certificates = [{ certificateFile: item.tls_cert_file, keyFile: item.tls_key_file }];
			}
		}
		ss.tlsSettings = tls;
	} else if (security === "reality" && is_xray) {
		if (is_inbound) {
			let rs = {
				show: item.reality_show === "1",
				target: item.reality_target || item.reality_dest || "",
				xver: int(item.reality_xver || 0),
				serverNames: to_array(item.reality_server_names),
				privateKey: item.reality_private_key || "",
				shortIds: to_array(item.reality_short_ids)
			};
			if (item.reality_mldsa65_seed) rs.mldsa65Seed = item.reality_mldsa65_seed;
			if (item.reality_min_client_ver) rs.minClientVer = item.reality_min_client_ver;
			if (item.reality_max_client_ver) rs.maxClientVer = item.reality_max_client_ver;
			if (item.reality_max_time_diff) rs.maxTimeDiff = int(item.reality_max_time_diff);
			ss.realitySettings = rs;
		} else {
			let rs = {
				show: item.reality_show === "1",
				fingerprint: item.reality_fingerprint || "chrome",
				serverName: item.reality_server_name || "",
				password: item.reality_public_key || "",
				publicKey: item.reality_public_key || "",
				shortId: item.reality_short_id || "",
				spiderX: item.reality_spider_x || "/"
			};
			if (item.reality_mldsa65_verify) rs.mldsa65Verify = item.reality_mldsa65_verify;
			ss.realitySettings = rs;
		}
	}

	// Transport-specific settings
	if (net === "raw" || net === "tcp") {
		let tcp = {};
		if (item.tcp_accept_proxy_protocol === "1") tcp.acceptProxyProtocol = true;
		if (item.tcp_header_type && item.tcp_header_type !== "none") {
			let header = { type: item.tcp_header_type };
			const reqH = kv_to_map(parse_json_safe(item.tcp_request_headers_json));
			if (reqH) header.request = { headers: reqH };
			const respH = kv_to_map(parse_json_safe(item.tcp_response_headers_json));
			if (respH) header.response = { headers: respH };
			tcp.header = header;
		}
		if (length(keys(tcp)) > 0) ss[is_xray ? "rawSettings" : "tcpSettings"] = tcp;
	} else if (net === "websocket" || net === "ws") {
		let ws = { path: item.ws_path || "/" };
		let headers = kv_to_map(parse_json_safe(item.ws_headers_json)) || {};
		if (item.ws_host) {
			if (is_xray) ws.host = item.ws_host;
			else headers.Host = item.ws_host;
		}
		if (length(keys(headers)) > 0) ws.headers = headers;
		if (is_xray && item.ws_heartbeat_period) ws.heartbeatPeriod = int(item.ws_heartbeat_period);
		if (!is_xray && item.ws_max_early_data) {
			ws.maxEarlyData = int(item.ws_max_early_data);
			if (item.ws_early_data_header) ws.earlyDataHeaderName = item.ws_early_data_header;
		}
		ss.wsSettings = ws;
	} else if (net === "grpc") {
		let grpc = { serviceName: item.grpc_service_name || "" };
		if (is_xray) {
			if (item.grpc_authority) grpc.authority = item.grpc_authority;
			if (item.grpc_multi_mode === "1") grpc.multiMode = true;
			if (item.grpc_idle_timeout) grpc.idle_timeout = int(item.grpc_idle_timeout);
			if (item.grpc_health_check_timeout) grpc.health_check_timeout = int(item.grpc_health_check_timeout);
			if (item.grpc_permit_without_stream === "1") grpc.permit_without_stream = true;
			if (item.grpc_initial_windows_size) grpc.initial_windows_size = int(item.grpc_initial_windows_size);
		}
		ss.grpcSettings = grpc;
	} else if (net === "xhttp" && is_xray) {
		let xhttp = { path: item.xhttp_path || "/", mode: item.xhttp_mode || "auto" };
		if (item.xhttp_host) xhttp.host = item.xhttp_host;
		const extra = parse_json_safe(item.xhttp_extra, "xhttp_extra");
		if (extra != null) {
			if (type(extra) !== "object") die(`xhttp_extra 必须为 JSON 对象 (${item.tag || item[".name"] || "node"})。`);
			xhttp.extra = extra;
		}
		ss.xhttpSettings = xhttp;
	} else if (net === "httpupgrade" && is_xray) {
		let hu = { path: item.httpupgrade_path || "/" };
		if (item.httpupgrade_host) hu.host = item.httpupgrade_host;
		const headers = kv_to_map(parse_json_safe(item.httpupgrade_headers_json));
		if (headers) hu.headers = headers;
		ss.httpupgradeSettings = hu;
	} else if (net === "http" && !is_xray) {
		let h2 = { path: item.h2_path || "/", host: to_array(item.h2_host) };
		if (item.h2_method) h2.method = item.h2_method;
		const headers = kv_to_map(parse_json_safe(item.h2_headers_json));
		if (headers) h2.headers = headers;
		ss.httpSettings = h2;
	} else if (net === "kcp" || net === "mkcp") {
		let kcp = {
			mtu: int(item.mkcp_mtu || 1350),
			tti: int(item.mkcp_tti || 50),
			uplinkCapacity: int(item.mkcp_uplink_capacity || 5),
			downlinkCapacity: int(item.mkcp_downlink_capacity || 20)
		};
		if (is_xray) {
			if (item.mkcp_cwnd_multiplier) kcp.cwndMultiplier = int(item.mkcp_cwnd_multiplier);
			if (item.mkcp_max_sending_window) kcp.maxSendingWindow = int(item.mkcp_max_sending_window);
		} else {
			kcp.congestion = item.mkcp_congestion === "1";
			if (item.mkcp_seed) kcp.seed = item.mkcp_seed;
			if (item.mkcp_header_type) kcp.header = { type: item.mkcp_header_type };
		}
		ss.kcpSettings = kcp;
	} else if (net === "quic" && !is_xray) {
		ss.quicSettings = {
			security: item.quic_security || "none",
			key: item.quic_key || "",
			header: { type: item.quic_header_type || "none" }
		};
	} else if (net === "domainsocket" && !is_xray) {
		ss.dsSettings = {
			path: item.ds_path || "",
			abstract: item.ds_abstract === "1",
			padding: item.ds_padding === "1"
		};
	} else if (net === "hysteria" && is_xray) {
		let hy = { version: 2, auth: item.hysteria_auth || item.password || "" };
		const idle = parse_seconds_num(item.hysteria_udp_idle_timeout);
		if (idle != null) hy.udpIdleTimeout = idle;
		if (item.hysteria_masquerade_type) {
			let masq = { type: item.hysteria_masquerade_type };
			if (item.hysteria_masquerade_type === "file" && item.hysteria_masquerade_dir) masq.dir = item.hysteria_masquerade_dir;
			else if (item.hysteria_masquerade_type === "proxy") {
				if (item.hysteria_masquerade_url) masq.url = item.hysteria_masquerade_url;
				if (item.hysteria_masquerade_rewrite_host === "1") masq.rewriteHost = true;
				if (item.hysteria_masquerade_insecure === "1") masq.insecure = true;
			} else if (item.hysteria_masquerade_type === "string") {
				if (item.hysteria_masquerade_content) masq.content = item.hysteria_masquerade_content;
				const mh = kv_to_map(parse_json_safe(item.hysteria_masquerade_headers_json));
				if (mh) masq.headers = mh;
				if (item.hysteria_masquerade_status_code) masq.statusCode = int(item.hysteria_masquerade_status_code);
			}
			hy.masquerade = masq;
		} else if (item.hysteria_masquerade) {
			const rawM = trim(item.hysteria_masquerade);
			if (substr(rawM, 0, 1) === "{") {
				const parsedM = parse_json_safe(rawM);
				if (type(parsedM) === "object") hy.masquerade = parsedM;
			} else if (rawM) {
				hy.masquerade = { type: "proxy", url: rawM };
			}
		}
		ss.hysteriaSettings = hy;
	} else if (net === "hysteria2" && !is_xray) {
		let hy2 = {
			password: item.hysteria_auth || item.password || "",
			use_udp_extension: item.hysteria_udp_extension !== "0"
		};
		if (item.hysteria_up_mbps || item.hysteria_down_mbps) {
			hy2.congestion = {
				type: "brutal",
				up_mbps: int(item.hysteria_up_mbps || 50),
				down_mbps: int(item.hysteria_down_mbps || 100)
			};
		}
		ss.hysteria2Settings = hy2;
	} else if (net === "masque" && is_xray) {
		let mq = {};
		const path = item.masque_path || item.masque_uri;
		if (path) mq.path = path;
		if (!is_inbound) {
			if (item.masque_host) mq.host = item.masque_host;
			if (item.masque_user) mq.user = item.masque_user;
			if (item.masque_pass) mq.pass = item.masque_pass;
			const headers = kv_to_map(parse_json_safe(item.masque_headers_json));
			if (headers) mq.headers = headers;
			const warp = parse_json_safe(item.masque_warp_json);
			if (type(warp) === "object") mq.warp = warp;
		}
		ss.masqueSettings = mq;
	}

	// Xray FinalMask
	if (is_xray) {
		let fm = parse_json_safe(item.finalmask_json, "finalmask_json");
		if (fm != null && type(fm) !== "object") {
			die(`finalmask_json 必须为 JSON 对象 (${item.tag || item[".name"] || "node"})。`);
		}
		if (!fm && net === "hysteria" && (item.hysteria_up_mbps || item.hysteria_down_mbps || item.hysteria_udphop_port || item.hysteria_obfs_password)) {
			fm = {};
			if (item.hysteria_obfs_password) {
				fm.udp = [{ type: "salamander", settings: { password: item.hysteria_obfs_password } }];
			}
			let qp = {};
			if (item.hysteria_up_mbps || item.hysteria_down_mbps) {
				qp.congestion = "brutal";
				if (item.hysteria_up_mbps) qp.brutalUp = `${item.hysteria_up_mbps} mbps`;
				if (item.hysteria_down_mbps) qp.brutalDown = `${item.hysteria_down_mbps} mbps`;
			}
			if (item.hysteria_udphop_port) {
				qp.udpHop = { ports: item.hysteria_udphop_port, interval: int(item.hysteria_udphop_interval || 30) };
			}
			if (length(keys(qp)) > 0) fm.quicParams = qp;
		}
		if (fm) ss.finalmask = fm;
	}

	// Sockopt
	let sockopt = {};
	const mark = item.sockopt_mark ? int(item.sockopt_mark) : default_mark;
	if (mark != null && mark > 0) sockopt.mark = mark;
	if (item.sockopt_tproxy && item.sockopt_tproxy !== "off") sockopt.tproxy = item.sockopt_tproxy;
	if (item.sockopt_tcp_fast_open === "1") {
		sockopt.tcpFastOpen = (is_xray && item.sockopt_tcp_fast_open_queue_length) ? int(item.sockopt_tcp_fast_open_queue_length) : true;
		if (!is_xray && item.sockopt_tcp_fast_open_queue_length) {
			sockopt.tcpFastOpenQueueLength = int(item.sockopt_tcp_fast_open_queue_length);
		}
	}
	if (item.sockopt_mptcp === "1") sockopt[is_xray ? "tcpMptcp" : "mptcp"] = true;
	if (item.sockopt_interface) sockopt[is_xray ? "interface" : "bindToDevice"] = item.sockopt_interface;
	if (item.sockopt_tcp_keepalive_interval) sockopt.tcpKeepAliveInterval = int(item.sockopt_tcp_keepalive_interval);
	if (is_xray) {
		if (item.sockopt_tcp_max_seg) sockopt.tcpMaxSeg = int(item.sockopt_tcp_max_seg);
		if (item.sockopt_tcp_keepalive_idle) sockopt.tcpKeepAliveIdle = int(item.sockopt_tcp_keepalive_idle);
		if (item.sockopt_tcp_user_timeout) sockopt.tcpUserTimeout = int(item.sockopt_tcp_user_timeout);
		if (item.sockopt_tcp_congestion) sockopt.tcpCongestion = item.sockopt_tcp_congestion;
		if (item.sockopt_v6_only === "1") sockopt.V6Only = true;
		if (item.sockopt_tcp_window_clamp) sockopt.tcpWindowClamp = int(item.sockopt_tcp_window_clamp);
		if (item.sockopt_address_port_strategy) sockopt.addressPortStrategy = item.sockopt_address_port_strategy;
		const xff = to_array(item.sockopt_trusted_xff);
		if (length(xff) > 0) sockopt.trustedXForwardedFor = xff;
		const cs = parse_json_safe(item.sockopt_custom_json);
		if (type(cs) === "array") sockopt.customSockopt = cs;
		const has_he_delay = item.sockopt_happy_eyeballs_try_delay_ms != null && item.sockopt_happy_eyeballs_try_delay_ms !== "";
		const has_he_interleave = item.sockopt_happy_eyeballs_interleave != null && item.sockopt_happy_eyeballs_interleave !== "";
		const has_he_max = item.sockopt_happy_eyeballs_max_concurrent_try != null && item.sockopt_happy_eyeballs_max_concurrent_try !== "";
		if (has_he_delay || item.sockopt_happy_eyeballs_prioritize_ipv6 === "1" || has_he_interleave || has_he_max) {
			let he = {};
			if (has_he_delay) he.tryDelayMs = int(item.sockopt_happy_eyeballs_try_delay_ms);
			if (item.sockopt_happy_eyeballs_prioritize_ipv6 === "1") he.prioritizeIPv6 = true;
			if (has_he_interleave) he.interleave = int(item.sockopt_happy_eyeballs_interleave);
			if (has_he_max) he.maxConcurrentTry = int(item.sockopt_happy_eyeballs_max_concurrent_try);
			sockopt.happyEyeballs = he;
		}
		if (item.domain_strategy) sockopt.domainStrategy = item.domain_strategy;
		if (item.dialer_proxy) sockopt.dialerProxy = item.dialer_proxy;
	}
	if (length(keys(sockopt)) > 0) ss.sockopt = sockopt;

	return ss;
}
