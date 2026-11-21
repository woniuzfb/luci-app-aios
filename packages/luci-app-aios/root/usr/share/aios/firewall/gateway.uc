#!/usr/bin/ucode
"use strict";

import { popen } from "fs";
import { connect } from "ubus";

const ubus = connect();
if (!ubus) {
	exit(0);
}

const dump = ubus.call("network.interface", "dump", {});
if (!dump || !dump.interface) {
	exit(0);
}

let gw4 = [];
let pd6 = [];

for (let iface in dump.interface) {
	if (!iface.up) continue;
	for (let r in (iface.route || [])) {
		if (r.target === "0.0.0.0" && r.mask === 0 && r.nexthop && r.nexthop !== "0.0.0.0") {
			push(gw4, r.nexthop);
		}
	}
	for (let p in (iface["ipv6-prefix-assignment"] || [])) {
		if (p.address && p.mask) {
			push(pd6, `${p.address}/${p.mask}`);
		}
	}
}

gw4 = uniq(gw4);
pd6 = uniq(pd6);

let cmds = ["flush set inet aios aios_gateway_v4", "flush set inet aios aios_gateway_v6"];
if (length(gw4) > 0) {
	push(cmds, `add element inet aios aios_gateway_v4 { ${join(", ", gw4)} }`);
}
if (length(pd6) > 0) {
	push(cmds, `add element inet aios aios_gateway_v6 { ${join(", ", pd6)} }`);
}

const proc = popen("nft -f -", "w");
if (proc) {
	proc.write(join("\n", cmds) + "\n");
	proc.close();
}
