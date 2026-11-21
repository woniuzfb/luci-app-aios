"use strict";

import { cursor } from "uci";
import { popen } from "fs";

export function to_array(v) {
	if (v == null || v === "") return [];
	if (type(v) === "array") return v;
	return [v];
}

export function detect_core_type(general) {
	const configured = general.core_type || "auto";
	if (configured === "xray" || configured === "v2ray") {
		return configured;
	}
	const bin = general.core_bin || "/usr/bin/xray";
	const proc = popen(`${bin} version 2>/dev/null`, "r");
	if (proc) {
		const line = proc.read("line") || "";
		proc.close();
		if (index(lc(line), "xray") >= 0) return "xray";
		if (index(lc(line), "v2ray") >= 0) return "v2ray";
	}
	return index(lc(bin), "v2ray") >= 0 ? "v2ray" : "xray";
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
		else if (t === "policy") result.policy = sec;
		else if (t === "reverse") result.reverse = sec;
		else if (t === "transparent_proxy") result.transparent_proxy = sec;
		else if (t === "lan_hosts") push(result.lan_hosts, sec);
	}

	return result;
}
