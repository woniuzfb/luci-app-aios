import { describe, expect, it } from 'vitest';
import { createDefaultConfig } from '../web/src/schema/defaults';
import { compileConfig } from '../web/src/compiler';
import { BUILTIN_PRESETS } from '../web/src/presets/builtin';
import {
  applyPresetToConfig,
  computePresetDiff,
  createUserPresetFromConfig
} from '../web/src/presets/manager';
import { parseShareUri } from '../web/src/importers/uri';
import { parseUciDump, serializeConfigToUci, type UciRawDump } from '../web/src/schema/uci';
import { computeLineDiff, renderExpectedFirewallRules } from '../web/src/firewall/preview';

describe('Dual-Core Compiler (Xray vs V2Ray jsonv4 & jsonv5)', () => {
  it('compiles Xray-specific fields (metrics, expectedIPs, domain, reality, finalmask)', () => {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'xray';
    cfg.general.metrics_enabled = true;
    cfg.outbounds.unshift({
      id: 'vless_reality',
      enabled: true,
      alias: 'Reality Node',
      tag: 'proxy',
      protocol: 'vless',
      address: '1.2.3.4',
      port: 443,
      uuid: 'b831381d-6324-4d53-ad4f-8cda48b30811',
      flow: 'xtls-rprx-vision',
      transport: 'raw',
      security: 'reality',
      reality_server_name: 'www.microsoft.com',
      reality_public_key: 'pubkey123',
      reality_short_id: 'abcd',
      reality_fingerprint: 'chrome'
    });

    const res = compileConfig(cfg);
    expect(res.core).toBe('xray');
    expect(res.json.metrics).toBeDefined();
    const dns = res.json.dns as { servers: Array<Record<string, unknown>> };
    expect(dns.servers[0].expectedIPs).toEqual(['geoip:cn']);
    const routing = res.json.routing as { rules: Array<Record<string, unknown>> };
    expect(routing.rules.some((r) => Array.isArray(r.domain))).toBe(true);
    const outbounds = res.json.outbounds as Array<Record<string, unknown>>;
    expect((outbounds[0].streamSettings as Record<string, unknown>).security).toBe('reality');
  });

  it('strips/maps Xray-only fields when compiling for V2Ray jsonv4', () => {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv4';
    cfg.general.metrics_enabled = true;
    cfg.observatory.enabled = true;
    cfg.balancers.push({
      id: 'b1',
      tag: 'bal1',
      selector: ['proxy'],
      strategy: 'roundRobin',
      fallback_tag: 'direct'
    });
    cfg.outbounds.unshift({
      id: 'hy2_node',
      enabled: true,
      alias: 'Hy2 Node',
      tag: 'proxy',
      protocol: 'hysteria',
      address: '2.3.4.5',
      port: 443,
      password: 'secret',
      hysteria_up_mbps: 50,
      hysteria_down_mbps: 200,
      transport: 'hysteria',
      security: 'tls',
      dialer_proxy: 'relay'
    });

    const res = compileConfig(cfg);
    expect(res.core).toBe('v2ray');
    expect(res.json.metrics).toBeUndefined();
    expect((res.json.observatory as Record<string, unknown>).probeURL).toBeDefined();

    const dns = res.json.dns as { servers: Array<Record<string, unknown>> };
    expect(dns.servers[0].expectIPs).toEqual(['geoip:cn']);
    expect(dns.servers[0].expectedIPs).toBeUndefined();

    const routing = res.json.routing as {
      rules: Array<Record<string, unknown>>;
      balancers: Array<{ strategy: { type: string }; fallbackTag?: string }>;
    };
    expect(routing.rules.some((r) => Array.isArray(r.domains))).toBe(true);
    expect(routing.balancers[0].strategy.type).toBe('random');
    expect(routing.balancers[0].fallbackTag).toBe('direct');

    const outbounds = res.json.outbounds as Array<Record<string, unknown>>;
    expect(outbounds[0].protocol).toBe('hysteria2');
    expect(outbounds[0].proxySettings).toEqual({ tag: 'relay', transportLayer: true });
    expect((outbounds[0].streamSettings as Record<string, unknown>).hysteria2Settings).toBeDefined();
  });

  it('compiles V2Ray jsonv5 with router, services.tun, shadowsocks2022, and uTLS', () => {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.observatory.enabled = true;
    cfg.inbounds.unshift({
      id: 'tun0',
      enabled: true,
      alias: 'TUN',
      tag: 'tun-in',
      listen: '0.0.0.0',
      port: 0,
      protocol: 'tun',
      tun_name: 'aios0',
      tun_mtu: 1500,
      transport: 'tcp',
      security: 'none'
    });
    cfg.outbounds.unshift({
      id: 'ss2022',
      enabled: true,
      alias: 'SS2022',
      tag: 'proxy-ss2022',
      protocol: 'shadowsocks2022',
      address: 'ss.example.com',
      port: 8388,
      method: '2022-blake3-aes-128-gcm',
      password: 'base64-psk-value',
      transport: 'httpupgrade',
      httpupgrade_path: '/up',
      security: 'utls',
      tls_server_name: 'ss.example.com',
      tls_fingerprint: 'chrome_auto'
    });

    const res = compileConfig(cfg);
    expect(res.core).toBe('v2ray');
    expect(res.json.router).toBeDefined();
    expect(res.json.routing).toBeUndefined();
    const services = res.json.services as Record<string, unknown>;
    expect(services.tun).toBeDefined();
    expect(services.backgroundObservatory).toBeDefined();
    const outbounds = res.json.outbounds as Array<Record<string, unknown>>;
    expect(outbounds[0].protocol).toBe('shadowsocks2022');
    expect((outbounds[0].settings as Record<string, unknown>).psk).toBe('base64-psk-value');
    expect((outbounds[0].streamSettings as Record<string, unknown>).security).toBe('utls');
    expect((outbounds[0].streamSettings as Record<string, unknown>).transport).toBe('httpupgrade');
  });
});

describe('UCI Bidirectional Serialization (/etc/config/aios)', () => {
  it('round-trips full AiosConfig including arrays and nested JSON sections', () => {
    const original = createDefaultConfig();
    original.general.core_type = 'v2ray';
    original.general.v2ray_format = 'jsonv5';
    original.inbounds[0].users = [{ username: 'alice', password: 'pw1', email: 'a@b.c', level: 0 }];
    original.dns.host_entries = [{ domain: 'example.com', addresses: ['1.1.1.1', '2606:4700::1'] }];
    original.transparent_proxy.enabled = true;
    original.transparent_proxy.wan_bp_ips = ['1.2.3.4/32', '2400::/32'];
    original.lan_hosts = [
      { id: 'mac_pc', alias: 'Desktop', macaddr: 'aa:bb:cc:dd:ee:ff', strategy_v4: 'bypass', strategy_v6: 'tproxy' }
    ];

    const uciSections = serializeConfigToUci(original);
    const simulatedDump: UciRawDump = {};
    uciSections.forEach((sec, idx) => {
      simulatedDump[sec.name] = {
        '.type': sec.type,
        '.name': sec.name,
        '.index': idx,
        ...sec.values
      };
    });

    const restored = parseUciDump(simulatedDump);
    expect(restored.general.core_type).toBe('v2ray');
    expect(restored.general.v2ray_format).toBe('jsonv5');
    expect(restored.inbounds[0].users?.[0].username).toBe('alice');
    expect(restored.dns.host_entries?.[0].addresses).toEqual(['1.1.1.1', '2606:4700::1']);
    expect(restored.transparent_proxy.wan_bp_ips).toEqual(['1.2.3.4/32', '2400::/32']);
    expect(restored.lan_hosts[0].macaddr).toBe('aa:bb:cc:dd:ee:ff');
  });
});

describe('Firewall Preview & Diff Engine', () => {
  it('renders isolated nftables/iptables rules and computes live-vs-pending diff', () => {
    const cfg = createDefaultConfig();
    cfg.transparent_proxy.enabled = true;
    cfg.transparent_proxy.dynamic_direct_enabled = true;

    const fw4 = renderExpectedFirewallRules(cfg, 'nftables');
    expect(fw4.backend).toBe('nftables');
    expect(fw4.rules).toContain('table inet aios');
    expect(fw4.rules).toContain('aios_dd_v4');

    const diff = computeLineDiff('', fw4.rules);
    expect(diff.some((d) => d.kind === 'add')).toBe(true);

    cfg.transparent_proxy.firewall_backend = 'iptables';
    const fw3 = renderExpectedFirewallRules(cfg, 'iptables');
    expect(fw3.backend).toBe('iptables');
    expect(fw3.rules).toContain('AIOS_PREROUTING');
  });
});

describe('Preset Manager & Multi-Protocol URI Importer', () => {
  it('saves current config as an isolated user preset and preserves outbounds on apply', () => {
    const current = createDefaultConfig();
    current.outbounds.unshift({
      id: 'my_node',
      enabled: true,
      alias: 'My Custom VLESS',
      tag: 'my-vless',
      protocol: 'vless',
      address: 'example.com',
      port: 443,
      uuid: '11111111-1111-1111-1111-111111111111',
      transport: 'raw',
      security: 'tls'
    });

    const saved = createUserPresetFromConfig(current, {
      name: '家庭主力方案',
      description: '测试保存预设',
      tags: ['home']
    });
    expect(saved.builtin).toBe(false);
    expect(saved.config.outbounds[0].tag).toBe('my-vless');

    const tproxyPreset = BUILTIN_PRESETS[0];
    expect(computePresetDiff(current, tproxyPreset.config).length).toBeGreaterThan(0);

    const applied = applyPresetToConfig(current, tproxyPreset, { preserveOutbounds: true });
    expect(applied.transparent_proxy.enabled).toBe(true);
    expect(applied.outbounds.some((o) => o.tag === 'my-vless')).toBe(true);
  });

  it('parses vless:// reality and hy2:// links', () => {
    const vless = parseShareUri(
      'vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&sni=www.apple.com&pbk=abc123&sid=01ab&flow=xtls-rprx-vision#HK-Reality'
    );
    expect(vless?.security).toBe('reality');
    expect(vless?.reality_public_key).toBe('abc123');

    const hy2 = parseShareUri('hy2://mypass@hy.example.com:8443?sni=hy.example.com&obfs-password=obfs1#JP-Hy2');
    expect(hy2?.protocol).toBe('hysteria');
    expect(hy2?.hysteria_obfs_password).toBe('obfs1');
  });
});
