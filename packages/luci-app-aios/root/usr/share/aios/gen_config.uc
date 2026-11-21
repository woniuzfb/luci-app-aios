#!/usr/bin/ucode
"use strict";

import { detect_core_type, load_config } from "./common/config.mjs";
import { compile_xray } from "./adapter/xray.mjs";
import { compile_v2ray } from "./adapter/v2ray.mjs";
import { compile_v2ray_v5 } from "./adapter/v2ray_v5.mjs";

const cfg = load_config();
const general = cfg.general || {};
const core = detect_core_type(general);

let compiled;
if (core === "v2ray") {
	compiled = general.v2ray_format === "jsonv5" ? compile_v2ray_v5(cfg) : compile_v2ray(cfg);
} else {
	compiled = compile_xray(cfg);
}

const hook_src = general.custom_configuration_hook;
if (hook_src && hook_src !== "") {
	const fn = loadstring(hook_src)();
	if (type(fn) === "function") {
		compiled = fn(compiled);
	}
}

printf("%.2J\n", compiled);
