#!/usr/bin/ucode
"use strict";

import { detect_core_type, detect_core_version, load_config } from "./common/config.mjs";
import { compile_xray } from "./adapter/xray.mjs";
import { compile_v2ray } from "./adapter/v2ray.mjs";
import { compile_v2ray_v5 } from "./adapter/v2ray_v5.mjs";

let cli_target_version = null;
let cli_target_core = null;
for (let i = 0; i < length(ARGV); i++) {
	if (ARGV[i] === "--target-version" && i + 1 < length(ARGV)) {
		cli_target_version = ARGV[++i];
	} else if (ARGV[i] === "--target-core" && i + 1 < length(ARGV)) {
		cli_target_core = ARGV[++i];
	}
}

const cfg = load_config();
const general = cfg.general || {};
const core = (cli_target_core === "xray" || cli_target_core === "v2ray")
	? cli_target_core
	: detect_core_type(general);
const target_version = cli_target_version
	|| (general.target_version && general.target_version !== "auto" ? general.target_version : detect_core_version(general));

let compiled;
if (core === "v2ray") {
	compiled = general.v2ray_format === "jsonv5"
		? compile_v2ray_v5(cfg, { version: target_version })
		: compile_v2ray(cfg, { version: target_version });
} else {
	compiled = compile_xray(cfg, { version: target_version });
}

const hook_src = general.custom_configuration_hook;
if (hook_src && hook_src !== "") {
	const fn = loadstring(hook_src)();
	if (type(fn) === "function") {
		compiled = fn(compiled);
	}
}

printf("%.2J\n", compiled);
