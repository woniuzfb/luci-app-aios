"use strict";

import { to_array } from "./config.mjs";

function parse_json_safe(str) {
	if (!str || str === "") return null;
	try {
		return json(str);
	} catch (e) {
		return null;
	}
}

export function build_stream_settings(item, core, is_inbound, default_mark) {
	const is_xray = core === "xray";
	let net = item.transport || (is_xray ? "raw" : "tcp");
	if (is_xray && net === "tcp") net = "raw";
	if (is_xray && net === "ws") net = "websocket";
	if (is_xray && net === "hysteria2") net = "hysteria";
	if (!is_xray && net === "raw") net = "tcp";
	if (!is_xray && net === "websocket") net = "ws";
	if (!is_xray && net === "mkcp") net = "kcp";
	if (!is_xray && net === "h2") net = "http";
	if (!is_xray && net === "hysteria") net = "hysteria2";

	let ss = {};
	if (is_xray) {
		ss.network = net === "raw" ? "raw" : net;
	} else {
		ss.network = net;
	}

	let security = item.security || "none";
	if (!is_xray && security === "reality") {
		security = "tls";
	}
	ss.security = security;

	if (security === "tls") {
		let tls = {};
		if (item.tls_server_name) tls.serverName = item.tls_server_name;
		if (item.tls_allow_insecure === "1") tls.allowInsecure = true;
		const alpn = to_array(item.tls_alpn);
		if (length(alpn) > 0) tls.alpn = alpn;

		if (is_xray) {
			if (item.tls_fingerprint) tls.fingerprint = item.tls_fingerprint;
			if (item.tls_pinned_sha256) tls.pinnedPeerCertSha256 = item.tls_pinned_sha256;
			if (item.tls_ech_config) tls.echConfigList = item.tls_ech_config;
			if (item.tls_verify_peer_name) tls.verifyPeerCertByName = item.tls_verify_peer_name;
		} else {
			if (item.tls_pinned_sha256) {
				tls.pinnedPeerCertificateChainSha256 = to_array(item.tls_pinned_sha256);
			}
			if (item.tls_verify_client === "1") tls.verifyClientCertificate = true;
		}

		if (is_inbound && item.tls_cert_file && item.tls_key_file) {
			tls.certificates = [{
				certificateFile: item.tls_cert_file,
				keyFile: item.tls_key_file
			}];
		}
		ss.tlsSettings = tls;
	} else if (security === "reality" && is_xray) {
		if (is_inbound) {
			ss.realitySettings = {
				show: item.reality_show === "1",
				target: item.reality_target || item.reality_dest || "",
				xver: int(item.reality_xver || 0),
				serverNames: to_array(item.reality_server_names),
				privateKey: item.reality_private_key || "",
				shortIds: to_array(item.reality_short_ids)
			};
			if (item.reality_mldsa65_seed) ss.realitySettings.mldsa65Seed = item.reality_mldsa65_seed;
		} else {
			ss.realitySettings = {
				show: item.reality_show === "1",
				fingerprint: item.reality_fingerprint || "chrome",
				serverName: item.reality_server_name || "",
				password: item.reality_public_key || "",
				publicKey: item.reality_public_key || "",
				shortId: item.reality_short_id || "",
				spiderX: item.reality_spider_x || "/"
			};
			if (item.reality_mldsa65_verify) ss.realitySettings.mldsa65Verify = item.reality_mldsa65_verify;
		}
	}

	// Transport-specific settings
	if (net === "raw" || net === "tcp") {
		let tcp = {};
		if (item.tcp_accept_proxy_protocol === "1") tcp.acceptProxyProtocol = true;
		if (item.tcp_header_type && item.tcp_header_type !== "none") {
			tcp.header = { type: item.tcp_header_type };
		}
		if (length(keys(tcp)) > 0) {
			ss[is_xray ? "rawSettings" : "tcpSettings"] = tcp;
		}
	} else if (net === "websocket" || net === "ws") {
		let ws = { path: item.ws_path || "/" };
		if (item.ws_host) {
			if (is_xray) ws.host = item.ws_host;
			else ws.headers = { Host: item.ws_host };
		}
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
		}
		ss.grpcSettings = grpc;
	} else if ((net === "xhttp" || net === "splithttp") && is_xray) {
		let xhttp = {
			path: item.xhttp_path || "/",
			mode: item.xhttp_mode || "auto"
		};
		if (item.xhttp_host) xhttp.host = item.xhttp_host;
		const extra = parse_json_safe(item.xhttp_extra);
		if (extra) xhttp.extra = extra;
		ss[net === "splithttp" ? "splithttpSettings" : "xhttpSettings"] = xhttp;
	} else if (net === "httpupgrade" && is_xray) {
		let hu = { path: item.httpupgrade_path || "/" };
		if (item.httpupgrade_host) hu.host = item.httpupgrade_host;
		ss.httpupgradeSettings = hu;
	} else if (net === "http" && !is_xray) {
		ss.httpSettings = {
			path: item.h2_path || "/",
			host: to_array(item.h2_host)
		};
	} else if (net === "kcp" || net === "mkcp") {
		let kcp = {
			mtu: int(item.mkcp_mtu || 1350),
			tti: int(item.mkcp_tti || 50),
			uplinkCapacity: int(item.mkcp_uplink_capacity || 5),
			downlinkCapacity: int(item.mkcp_downlink_capacity || 20)
		};
		if (!is_xray) {
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
		let hy = {
			version: 2,
			auth: item.hysteria_auth || item.password || ""
		};
		if (item.hysteria_udp_idle_timeout) hy.udpIdleTimeout = item.hysteria_udp_idle_timeout;
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
	}

	// Xray FinalMask (fragment / salamander / quicParams)
	if (is_xray) {
		let fm = parse_json_safe(item.finalmask_json);
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
				qp.udpHop = {
					ports: item.hysteria_udphop_port,
					interval: int(item.hysteria_udphop_interval || 30)
				};
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
		sockopt.tcpFastOpen = true;
	}
	if (item.sockopt_mptcp === "1") {
		sockopt[is_xray ? "tcpMptcp" : "mptcp"] = true;
	}
	if (item.sockopt_interface) {
		sockopt[is_xray ? "interface" : "bindToDevice"] = item.sockopt_interface;
	}
	if (is_xray) {
		if (item.domain_strategy) sockopt.domainStrategy = item.domain_strategy;
		if (item.dialer_proxy) sockopt.dialerProxy = item.dialer_proxy;
	}
	if (length(keys(sockopt)) > 0) ss.sockopt = sockopt;

	return ss;
}
