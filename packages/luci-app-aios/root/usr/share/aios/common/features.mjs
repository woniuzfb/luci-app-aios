"use strict";

import { readfile } from "fs";

const SPEC_PATH = "/usr/share/aios/common/core_features.json";

const FALLBACK_SPEC = {
	xray: {
		defaultVersion: "26.11.9",
		features: {
			flatOutbounds: { since: "25.10.15" },
			tunInbound: { since: "26.1.13" },
			hysteria: { since: "26.1.13" },
			dnsRewriteKeys: { since: "26.1.13" },
			geodataCron: { since: "26.1.13" },
			freedomFinalRules: { since: "26.1.13" },
			ssUot: { removedIn: "26.1.13" },
			legacyReverse: { removedIn: "26.4.25" },
			inboundUsersKey: { since: "26.5.9" },
			streamMethodKey: { since: "26.7.11" },
			masque: { since: "26.9.30" },
			requireTlsPublicVlessTrojan: { since: "26.10.0" }
		}
	},
	v2ray: {
		defaultVersion: "5.56.0",
		features: {
			jsonv5: { since: "5.1.0" },
			v5ServicesTun: { since: "5.9.0" },
			shadowsocks2022: { since: "5.12.0" },
			v4Services: { since: "5.17.0" },
			hysteria2: { since: "5.18.0" },
			packetEncodingStream: { since: "5.53.0" }
		}
	}
};

let _spec = null;

function load_spec() {
	if (_spec) return _spec;
	const raw = readfile(SPEC_PATH);
	if (raw) {
		try {
			_spec = json(raw);
			return _spec;
		} catch (e) {
			// Fall back to embedded spec if file is unreadable
		}
	}
	_spec = FALLBACK_SPEC;
	return _spec;
}

export function parse_core_version(raw) {
	if (!raw || raw === "auto") return null;
	const m = match(`${raw}`, /([0-9]+)\.([0-9]+)\.([0-9]+)/);
	if (!m) return null;
	return [int(m[1]), int(m[2]), int(m[3])];
}

export function compare_semver(a, b) {
	const pa = parse_core_version(a);
	const pb = parse_core_version(b);
	if (!pa || !pb) return 0;
	for (let i = 0; i < 3; i++) {
		if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
	}
	return 0;
}

function eval_rule(rule, ver) {
	if (!rule) return false;
	if (rule.since && compare_semver(ver, rule.since) < 0) return false;
	if (rule.removedIn && compare_semver(ver, rule.removedIn) >= 0) return false;
	return true;
}

export function resolve_core_features(core, format, version) {
	const spec = load_spec();
	const coreSpec = spec[core] || spec.xray;
	const parsed = parse_core_version(version);
	const effective = parsed ? `${parsed[0]}.${parsed[1]}.${parsed[2]}` : (coreSpec.defaultVersion || "26.11.9");
	const f = coreSpec.features || {};

	if (core === "xray") {
		const useMethod = eval_rule(f.streamMethodKey, effective);
		const useUsers = eval_rule(f.inboundUsersKey, effective);
		return {
			core: "xray",
			version: effective,
			versionFallback: !parsed,
			streamMethodKey: useMethod ? "method" : "network",
			flatOutbounds: eval_rule(f.flatOutbounds, effective),
			inboundUsersKey: useUsers ? "users" : "legacy",
			hasLegacyReverse: eval_rule(f.legacyReverse, effective),
			hasTunInbound: eval_rule(f.tunInbound, effective),
			hasHysteria: eval_rule(f.hysteria, effective),
			hasMasque: eval_rule(f.masque, effective),
			hasDnsRewriteKeys: eval_rule(f.dnsRewriteKeys, effective),
			hasGeodataCron: eval_rule(f.geodataCron, effective),
			hasFreedomFinalRules: eval_rule(f.freedomFinalRules, effective),
			hasSsUot: eval_rule(f.ssUot, effective),
			requireTlsPublicVlessTrojan: eval_rule(f.requireTlsPublicVlessTrojan, effective),
			thresholds: f
		};
	}

	return {
		core: "v2ray",
		format: format || "jsonv4",
		version: effective,
		versionFallback: !parsed,
		hasJsonV5: eval_rule(f.jsonv5, effective),
		hasV5ServicesTun: eval_rule(f.v5ServicesTun, effective),
		hasV4Services: eval_rule(f.v4Services, effective),
		hasShadowsocks2022: eval_rule(f.shadowsocks2022, effective),
		hasHysteria2: eval_rule(f.hysteria2, effective),
		hasPacketEncodingStream: eval_rule(f.packetEncodingStream, effective),
		thresholds: f
	};
}
