import { describe, expect, it, vi } from 'vitest';
import { createDefaultConfig } from '../web/src/schema/defaults';
import { compileConfig } from '../web/src/compiler';
import { parseUciDump, serializeConfigToUci, type UciRawDump } from '../web/src/schema/uci';
import { BUILTIN_PRESETS } from '../web/src/presets/builtin';
import { applyPresetToConfig } from '../web/src/presets/manager';
import { parseShareUri } from '../web/src/importers/uri';
import { parseGeoDatIndex } from '../web/src/geodata/parser';
import { validateStreamCombination } from '../web/src/schema/capabilities';
import { renderExpectedFirewallRules, computeLineDiff } from '../web/src/firewall/preview';
import { UbusApiClient } from '../web/src/api/client';

describe('Audit Report Regression & Coverage Tests', () => {
  it('validates geodata/parser.ts on malformed wireType and truncated bytes', () => {
    const valid = new Uint8Array([
      0x0a, 0x08,
      0x0a, 0x02, 0x63, 0x6e,
      0x12, 0x02, 0x08, 0x01
    ]);
    expect(parseGeoDatIndex(valid.buffer)).toEqual([{ code: 'cn', count: 1 }]);

    const badWire = new Uint8Array([0x0b]);
    expect(() => parseGeoDatIndex(badWire.buffer)).toThrow(/wireType/i);

    const truncated = new Uint8Array([0x0a, 0x20, 0x01, 0x02]);
    expect(() => parseGeoDatIndex(truncated.buffer)).toThrow(/Invalid protobuf length/i);
  });

  it('parses UTF-8 VMess remarks, IPv6 hosts, @ in SS passwords, hysteria:// and wireguard://', () => {
    const vmessPayload = Buffer.from(
      JSON.stringify({ v: '2', ps: '香港高速节点', add: '2001:db8::1', port: '443', id: '11111111-1111-1111-1111-111111111111', net: 'ws', tls: 'tls' }),
      'utf-8'
    ).toString('base64');
    const vm = parseShareUri(`vmess://${vmessPayload}`);
    expect(vm?.alias).toBe('香港高速节点');
    expect(vm?.address).toBe('2001:db8::1');

    const vl = parseShareUri('vless://11111111-1111-1111-1111-111111111111@[2001:db8::2]:443?security=tls&sni=example.com#IPv6Node');
    expect(vl?.address).toBe('2001:db8::2');
    expect(vl?.alias).toBe('IPv6Node');

    const ssCred = Buffer.from('aes-256-gcm:p@ss:word@123', 'utf-8').toString('base64');
    const ss = parseShareUri(`ss://${ssCred}@[2001:db8::3]:8388#SSv6`);
    expect(ss?.method).toBe('aes-256-gcm');
    expect(ss?.password).toBe('p@ss:word@123');
    expect(ss?.address).toBe('2001:db8::3');
    expect(ss?.port).toBe(8388);

    const hy = parseShareUri('hysteria://myauth@[2001:db8::4]:8443?sni=hy.example.com&insecure=1#HY');
    expect(hy?.protocol).toBe('hysteria');
    expect(hy?.address).toBe('2001:db8::4');
    expect(hy?.tls_allow_insecure).toBe(true);

    const wg = parseShareUri('wireguard://privkey@[2001:db8::5]:51820?publickey=pubkey&address=10.0.0.2/32&mtu=1280#WG');
    expect(wg?.protocol).toBe('wireguard');
    expect(wg?.wg_secret_key).toBe('privkey');
    expect(wg?.wg_peer_public_key).toBe('pubkey');
    expect(wg?.wg_endpoint).toBe('[2001:db8::5]:51820');
  });

  it('preserves empty UCI lists, deduplicates section names, and round-trips wg_endpoint & dns.hosts', () => {
    const cfg = createDefaultConfig();
    cfg.inbounds = [];
    cfg.outbounds = [
      {
        id: 'main',
        enabled: true,
        alias: 'WG',
        tag: 'wg-out',
        protocol: 'wireguard',
        wg_secret_key: 'sec',
        wg_peer_public_key: 'pub',
        wg_endpoint: '1.2.3.4:51820',
        transport: 'raw',
        security: 'none'
      },
      {
        id: 'dup_out',
        enabled: true,
        alias: 'Direct 1',
        tag: 'd1',
        protocol: 'freedom',
        transport: 'raw',
        security: 'none'
      },
      {
        id: 'dup_out',
        enabled: true,
        alias: 'Direct 2',
        tag: 'd2',
        protocol: 'freedom',
        transport: 'raw',
        security: 'none'
      }
    ];
    cfg.dns.hosts = { 'example.test': '127.0.0.1' };
    cfg.routing_rules = [];

    const sections = serializeConfigToUci(cfg);
    const names = sections.map((s) => s.name);
    expect(new Set(names).size).toBe(names.length);
    expect(sections.find((s) => s.type === 'outbound' && s.values.tag === 'wg-out')?.name).not.toBe('main');

    const dump: UciRawDump = {};
    sections.forEach((sec, idx) => {
      dump[sec.name] = { '.type': sec.type, '.name': sec.name, '.index': idx, ...sec.values };
    });
    const restored = parseUciDump(dump);
    expect(restored.inbounds).toEqual([]);
    expect(restored.routing_rules).toEqual([]);
    expect(restored.dns.hosts).toEqual({ 'example.test': '127.0.0.1' });
    expect(restored.outbounds[0].wg_peer_public_key).toBe('pub');
    expect(restored.outbounds[0].wg_endpoint).toBe('1.2.3.4:51820');
  });

  it('ensures builtin transparent-proxy presets have listeners for all non-zero configured ports', () => {
    for (const preset of BUILTIN_PRESETS) {
      const tp = preset.config.transparent_proxy;
      if (!tp.enabled) continue;
      const listeningPorts = new Set(
        preset.config.inbounds.filter((ib) => ib.enabled).map((ib) => ib.port)
      );
      const requiredPorts = [
        tp.tproxy_port_tcp_v4,
        tp.tproxy_port_udp_v4,
        tp.tproxy_port_tcp_v6,
        tp.tproxy_port_udp_v6,
        ...(tp.fakedns_enabled
          ? [tp.fakedns_port_tcp_v4, tp.fakedns_port_udp_v4, tp.fakedns_port_tcp_v6, tp.fakedns_port_udp_v6]
          : [])
      ].filter((p) => p > 0);
      for (const port of requiredPorts) {
        expect(listeningPorts.has(port), `Preset ${preset.id} missing listener on port ${port}`).toBe(true);
      }
    }
  });

  it('preserves user proxy outbound order when applying presets with preserveOutbounds', () => {
    const cur = createDefaultConfig();
    cur.outbounds = [
      { id: 'p1', enabled: true, alias: 'Primary', tag: 'proxy-primary', protocol: 'vless', address: 'a.example.com', port: 443, uuid: 'u1', transport: 'raw', security: 'tls' },
      { id: 'p2', enabled: true, alias: 'Backup', tag: 'proxy-backup', protocol: 'trojan', address: 'b.example.com', port: 443, password: 'pw', transport: 'raw', security: 'tls' },
      ...cur.outbounds
    ];
    const preset = BUILTIN_PRESETS.find((p) => p.id === 'builtin-classic-cn-split')!;
    const applied = applyPresetToConfig(cur, preset, { preserveOutbounds: true });
    expect(applied.outbounds[0].tag).toBe('proxy-primary');
    expect(applied.outbounds[1].tag).toBe('proxy-backup');
  });

  it('enforces Xray & V2Ray P0 compiler fixes (dns rules/nonIPQuery, hysteria2 inbound, wg inbound, v5 usage/ext-ip/IPv6 TUN/log none)', () => {
    const xCfg = createDefaultConfig();
    xCfg.general.core_type = 'xray';
    xCfg.general.geodata_cron = '0 4 * * *';
    xCfg.inbounds.push(
      { id: 'hy_in', enabled: true, alias: 'HY', tag: 'hy-in', listen: '0.0.0.0', port: 8443, protocol: 'hysteria2', password: 'pw', transport: 'hysteria', security: 'tls' },
      { id: 'wg_in', enabled: true, alias: 'WG', tag: 'wg-in', listen: '0.0.0.0', port: 51820, protocol: 'wireguard', wg_secret_key: 'sec', wg_address: ['10.0.0.1/24'], transport: 'raw', security: 'none' }
    );
    xCfg.outbounds.push({
      id: 'dns_out_custom',
      enabled: true,
      alias: 'DNS',
      tag: 'dns-out-custom',
      protocol: 'dns',
      dns_non_ip_query: 'reject',
      dns_rules_json: '[{"type":"A","action":"accept"}]',
      transport: 'raw',
      security: 'none'
    });
    const xRes = compileConfig(xCfg, { core: 'xray', version: '26.11.9' });
    const xJson = xRes.json as Record<string, any>;
    expect(xJson.geodata).toEqual({ cron: '0 4 * * *' });
    expect(xJson.inbounds.find((i: any) => i.tag === 'hy-in').protocol).toBe('hysteria');
    expect(xJson.inbounds.find((i: any) => i.tag === 'wg-in').settings.address).toBeUndefined();
    const dnsOut = xJson.outbounds.find((o: any) => o.tag === 'dns-out-custom');
    expect(dnsOut.settings.rules).toHaveLength(1);
    expect(dnsOut.settings.nonIPQuery).toBeUndefined();

    const v5Cfg = createDefaultConfig();
    v5Cfg.general.core_type = 'v2ray';
    v5Cfg.general.v2ray_format = 'jsonv5';
    v5Cfg.general.error_log = 'none';
    v5Cfg.inbounds.push({
      id: 'tun_v6',
      enabled: true,
      alias: 'TUN',
      tag: 'tun-in',
      listen: '0.0.0.0',
      port: 0,
      protocol: 'tun',
      tun_ips: ['10.0.0.1/24', 'fd00::1/64'],
      tun_routes: ['0.0.0.0/0', '::/0'],
      transport: 'tcp',
      security: 'none'
    });
    v5Cfg.inbounds[0].security = 'tls';
    v5Cfg.inbounds[0].tls_certificates = [{ certificateFile: '/a.crt', keyFile: '/a.key', usage: 'encipherment' }];
    v5Cfg.routing_rules = [
      { id: 'r1', enabled: true, ip: ['ext-ip:geoip.dat:cn'], outbound_tag: 'direct', balancer_tag: 'bal1' }
    ];
    const v5Res = compileConfig(v5Cfg, { core: 'v2ray', version: '5.56.0' });
    const v5Json = v5Res.json as Record<string, any>;
    expect(v5Json.log.error.type).toBe('None');
    expect(v5Json.inbounds[0].streamSettings.securitySettings.certificate[0].usage).toBe('ENCIPHERMENT');
    expect(v5Json.services.tun.ips).toHaveLength(2);
    expect(v5Json.services.tun.ips[1].ip).toHaveLength(16);
    expect(v5Json.router.rule[0].geoip[0]).toEqual({ filePath: 'geoip.dat', code: 'cn' });
    expect(v5Json.router.rule[0].balancingTag).toBe('bal1');
    expect(v5Json.router.rule[0].tag).toBeUndefined();

    const utlsErrs = validateStreamCombination('v2ray', 'jsonv5', 'vless', 'tcp', 'utls', 'inbound');
    expect(utlsErrs.some((e) => e.level === 'error')).toBe(true);
  });

  it('fixes P0/P1 regressions: URI port 443 & colon passwords, SS inbound users/clients gate, legacy geodata cron, public plaintext VLESS/Trojan, v4 balancer', () => {
    // 1. URI importer: wireguard:// port 443/80 preservation & trojan/hy2 password with colon
    const wg443 = parseShareUri('wireguard://privkey@wg.example.com:443?publickey=pubkey#WG443');
    expect(wg443?.port).toBe(443);
    expect(wg443?.wg_endpoint).toBe('wg.example.com:443');

    const trColon = parseShareUri('trojan://user:pass:123@tr.example.com:443?sni=tr.example.com#TR');
    expect(trColon?.password).toBe('user:pass:123');

    const hyColon = parseShareUri('hy2://user:pass:456@hy.example.com:8443?sni=hy.example.com#HY2');
    expect(hyColon?.password).toBe('user:pass:456');
    expect(hyColon?.hysteria_auth).toBe('user:pass:456');

    // 2. Xray Shadowsocks multi-user inbound version gate: v25.9.11 -> clients, v26.11.9 -> users
    const ssCfg = createDefaultConfig();
    ssCfg.general.core_type = 'xray';
    ssCfg.inbounds = [
      {
        id: 'ss_multi',
        enabled: true,
        alias: 'SS Multi',
        tag: 'ss-in',
        listen: '0.0.0.0',
        port: 8388,
        protocol: 'shadowsocks',
        method: 'aes-256-gcm',
        users: [{ password: 'pw1', email: 'a@test' }],
        transport: 'raw',
        security: 'none'
      }
    ];
    const ssOld = compileConfig(ssCfg, { core: 'xray', version: '25.9.11' }).json as Record<string, any>;
    expect(ssOld.inbounds[0].settings.clients).toHaveLength(1);
    expect(ssOld.inbounds[0].settings.users).toBeUndefined();

    const ssNew = compileConfig(ssCfg, { core: 'xray', version: '26.11.9' }).json as Record<string, any>;
    expect(ssNew.inbounds[0].settings.users).toHaveLength(1);
    expect(ssNew.inbounds[0].settings.clients).toBeUndefined();

    // 3. Legacy geodata_reload_interval "6h" must NOT emit invalid geodata.cron
    const geoCfg = createDefaultConfig();
    geoCfg.general.core_type = 'xray';
    geoCfg.general.geodata_cron = '';
    geoCfg.general.geodata_reload_interval = '6h';
    const geoRes = compileConfig(geoCfg, { core: 'xray', version: '26.11.9' });
    expect((geoRes.json as Record<string, any>).geodata).toBeUndefined();
    expect(geoRes.diagnostics.some((d) => d.level === 'warning' && d.path.includes('geodata'))).toBe(true);

    // 4. Xray v26.11.9 public plaintext VLESS & Trojan check
    const plainCfg = createDefaultConfig();
    plainCfg.general.core_type = 'xray';
    plainCfg.outbounds = [
      { id: 'v_pub', enabled: true, alias: 'VPub', tag: 'v-pub', protocol: 'vless', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'raw', security: 'none' },
      { id: 't_cgnat', enabled: true, alias: 'TCgnat', tag: 't-cgnat', protocol: 'trojan', address: '100.64.0.1', port: 443, password: 'pw', transport: 'raw', security: 'none' },
      { id: 'v_local', enabled: true, alias: 'VLocal', tag: 'v-local', protocol: 'vless', address: 'localhost', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'raw', security: 'none' },
      { id: 't_v4mapped', enabled: true, alias: 'TMapped', tag: 't-mapped', protocol: 'trojan', address: '::ffff:192.168.1.1', port: 443, password: 'pw', transport: 'raw', security: 'none' }
    ];
    const plainRes = compileConfig(plainCfg, { core: 'xray', version: '26.11.9' });
    expect(plainRes.diagnostics.some((d) => d.level === 'error' && d.path.includes('v-pub'))).toBe(true);
    expect(plainRes.diagnostics.some((d) => d.level === 'error' && d.path.includes('t-cgnat'))).toBe(true);
    expect(plainRes.diagnostics.some((d) => d.level === 'error' && d.path.includes('v-local'))).toBe(false);
    expect(plainRes.diagnostics.some((d) => d.level === 'error' && d.path.includes('t-mapped'))).toBe(false);

    // 5. V2Ray jsonv4 balancer preserves leastLoad and fallbackTag
    const v4Cfg = createDefaultConfig();
    v4Cfg.general.core_type = 'v2ray';
    v4Cfg.general.v2ray_format = 'jsonv4';
    v4Cfg.balancers = [{ id: 'b1', enabled: true, tag: 'bal-v4', selector: ['proxy'], strategy: 'leastLoad', fallback_tag: 'direct' }];
    const v4Res = compileConfig(v4Cfg, { core: 'v2ray', version: '5.56.0' }).json as Record<string, any>;
    expect(v4Res.routing.balancers[0].strategy).toEqual({ type: 'leastLoad' });
    expect(v4Res.routing.balancers[0].fallbackTag).toBe('direct');
  });

  it('covers P2 fixes: dotless/.internal plaintext hosts, fakedns preset 5350..5352 DNS inbounds, firewall preview & UbusApiClient', async () => {
    // 1. Dotless & .internal hostnames allowed for plaintext VLESS/Trojan on Xray 26.11.9
    const intCfg = createDefaultConfig();
    intCfg.general.core_type = 'xray';
    intCfg.outbounds = [
      { id: 'v_dotless', enabled: true, alias: 'VDotless', tag: 'v-dotless', protocol: 'vless', address: 'myhost', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'raw', security: 'none' },
      { id: 't_internal', enabled: true, alias: 'TInternal', tag: 't-internal', protocol: 'trojan', address: 'api.internal', port: 443, password: 'pw', transport: 'raw', security: 'none' }
    ];
    const intRes = compileConfig(intCfg, { core: 'xray', version: '26.11.9' });
    expect(intRes.diagnostics.some((d) => d.level === 'error')).toBe(false);

    // 2. builtin-xray-tproxy-fakedns includes 5350..5352 DNS inbounds matching dnsmasq_enabled
    const fakednsPreset = BUILTIN_PRESETS.find((p) => p.id === 'builtin-xray-tproxy-fakedns')!;
    const ports = new Set(fakednsPreset.config.inbounds.filter((i) => i.enabled).map((i) => i.port));
    expect(ports.has(5350)).toBe(true);
    expect(ports.has(5351)).toBe(true);
    expect(ports.has(5352)).toBe(true);

    // 3. firewall/preview.ts port range off-by-one, redirect/tproxy chains, FakeDNS Ping NAT chains & diff
    const prev = renderExpectedFirewallRules(fakednsPreset.config, 'nftables');
    const dnsChange = prev.changes.find((c) => c.scope === 'dnsmasq');
    expect(dnsChange?.detail).toContain('5350..5352');
    expect(prev.rules).toContain('chain fakedns_ping_prerouting { type nat hook prerouting');
    expect(prev.rules).toContain('chain fakedns_ping_output { type nat hook output');
    const diff = computeLineDiff('table inet aios {\n}\n', prev.rules);
    expect(diff.some((d) => d.kind === 'add')).toBe(true);

    // 4. UbusApiClient JSON-RPC call & error handling
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        jsonrpc: '2.0',
        id: 1,
        result: [0, { running: true, pid: 1234, core_type: 'xray', core_bin: '/usr/bin/aios-xray', active_firewall: 'nftables' }]
      })
    });
    vi.stubGlobal('fetch', fetchMock);
    try {
      const client = new UbusApiClient('test-sid');
      const status = await client.getServiceStatus();
      expect(status.running).toBe(true);
      expect(status.pid).toBe(1234);
      expect(fetchMock).toHaveBeenCalledWith('/ubus', expect.objectContaining({ method: 'POST' }));

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ jsonrpc: '2.0', id: 2, result: [6] })
      });
      await expect(client.getServiceStatus()).rejects.toThrow(/ubus/i);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
