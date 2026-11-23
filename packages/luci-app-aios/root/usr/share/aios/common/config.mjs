"use strict";

import { cursor } from "uci";
import { access, popen } from "fs";

export function to_array(v) {
	if (v == null || v === "") return [];
	if (type(v) === "array") return v;
	return [v];
}

export function parse_json_safe(str, field_name) {
	if (!str || str === "") return null;
	try {
		return json(str);
	} catch (e) {
		die(`AIOS invalid JSON${field_name ? ` in ${field_name}` : ""}: ${e}`);
	}
}

export function parse_duration_ns(val, fallback_ns) {
	if (val == null || val === "") return fallback_ns;
	if (type(val) === "int" || type(val) === "double") return val > 0 ? int(val + 0.5) : fallback_ns;
	const s = lc(trim(`${val}`));
	const m = match(s, /^([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s|m|h)?$/);
	if (!m) return fallback_ns;
	const n = double(m[1]);
	const u = m[2] || "ns";
	if (u === "ns") return int(n + 0.5);
	if (u === "us") return int(n * 1000 + 0.5);
	if (u === "ms") return int(n * 1000000 + 0.5);
	if (u === "s") return int(n * 1000000000 + 0.5);
	if (u === "m") return int(n * 60000000000 + 0.5);
	if (u === "h") return int(n * 3600000000000 + 0.5);
	return fallback_ns;
}

export function kv_to_map(pairs) {
	if (type(pairs) !== "array" || length(pairs) === 0) return null;
	let out = {};
	for (let p in pairs) {
		if (p && p.key && trim(p.key) !== "") {
			out[trim(p.key)] = p.value || "";
		}
	}
	return length(keys(out)) > 0 ? out : null;
}

export function resolve_core_bin(general) {
	if (general && general.core_bin && general.core_bin !== "") return general.core_bin;
	for (let cand in ["/usr/bin/aios-xray", "/usr/bin/aios-v2ray", "/usr/bin/xray", "/usr/bin/v2ray"]) {
		if (access(cand, "x")) return cand;
	}
	return "/usr/bin/aios-xray";
}

export function detect_core_type(general) {
	const configured = general.core_type || "auto";
	if (configured === "xray" || configured === "v2ray") {
		return configured;
	}
	const bin = resolve_core_bin(general);
	const proc = popen(`${bin} version 2>/dev/null`, "r");
	if (proc) {
		const line = proc.read("line") || "";
		proc.close();
		if (index(lc(line), "xray") >= 0) return "xray";
		if (index(lc(line), "v2ray") >= 0) return "v2ray";
	}
	return index(lc(bin), "v2ray") >= 0 ? "v2ray" : "xray";
}

export function detect_core_version(general) {
	const bin = resolve_core_bin(general);
	const proc = popen(`${bin} version 2>/dev/null`, "r");
	if (proc) {
		const line = proc.read("line") || "";
		proc.close();
		const m = match(line, /([0-9]+\.[0-9]+\.[0-9]+)/);
		if (m) return m[1];
	}
	return null;
}

export function deep_merge(target, source) {
	if (type(target) !== "object" || type(source) !== "object") {
		return source;
	}
	let out = { ...target };
	for (let k in keys(source)) {
		if (type(source[k]) === "object" && type(out[k]) === "object") {
			out[k] = deep_merge(out[k], source[k]);
		} else {
			out[k] = source[k];
		}
	}
	return out;
}

export function load_config() {
	const c = cursor();
	const raw = c.get_all("aios") || {};

	let result = {
		general: {},
		inbounds: [],
		outbounds: [],
		dns: {},
		dns_servers: [],
		fakedns: [],
		routing: {},
		routing_rules: [],
		balancers: [],
		observatory: {},
		burst_observatory: {},
		browser_forwarder: {},
		policy: {},
		reverse: {},
		transparent_proxy: {},
		lan_hosts: []
	};

	const ordered = sort(values(raw), (a, b) => (a[".index"] || 0) - (b[".index"] || 0));
	for (let sec in ordered) {
		const t = sec[".type"];
		if (t === "general") result.general = sec;
		else if (t === "inbound") push(result.inbounds, sec);
		else if (t === "outbound") push(result.outbounds, sec);
		else if (t === "dns") result.dns = sec;
		else if (t === "dns_server") push(result.dns_servers, sec);
		else if (t === "fakedns") push(result.fakedns, sec);
		else if (t === "routing") result.routing = sec;
		else if (t === "routing_rule") push(result.routing_rules, sec);
		else if (t === "routing_balancer") push(result.balancers, sec);
		else if (t === "observatory") result.observatory = sec;
		else if (t === "burst_observatory") result.burst_observatory = sec;
		else if (t === "browser_forwarder") result.browser_forwarder = sec;
		else if (t === "policy") result.policy = sec;
		else if (t === "reverse") result.reverse = sec;
		else if (t === "transparent_proxy") result.transparent_proxy = sec;
		else if (t === "lan_hosts") push(result.lan_hosts, sec);
	}

	return result;
}
