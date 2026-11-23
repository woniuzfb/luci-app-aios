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
import { UbusApiClient, createApiClient } from '../web/src/api/client';

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
        result: [0, { running: true, pid: '1234', rss_kb: 20480 }]
      })
    });
    vi.stubGlobal('fetch', fetchMock);
    try {
      const client = new UbusApiClient('test-sid');
      const status = await client.getServiceStatus();
      expect(status.running).toBe(true);
      expect(status.pid).toBe('1234');
      expect(status.rss_kb).toBe(20480);
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

  it('fixes Xray SS-2022 multi-user inbound, freedom.finalRules gate, and UCI policy override', () => {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'xray';
    cfg.inbounds = [
      {
        id: 'ss22',
        enabled: true,
        alias: 'SS2022',
        tag: 'ss-2022-in',
        protocol: 'shadowsocks',
        listen: '0.0.0.0',
        port: 8388,
        method: '2022-blake3-aes-128-gcm',
        password: 'server-psk-base64-key==',
        users: [{ password: 'user-psk-base64-key==', email: 'u1@example.com', level: 0 }]
      },
      {
        id: 'ss_aead',
        enabled: true,
        alias: 'SSAEAD',
        tag: 'ss-aead-in',
        protocol: 'shadowsocks',
        listen: '0.0.0.0',
        port: 8389,
        method: 'aes-256-gcm',
        users: [{ password: 'pw1', email: 'u2@example.com', level: 0 }]
      }
    ];
    cfg.outbounds = [
      {
        id: 'direct',
        enabled: true,
        alias: 'Direct',
        tag: 'direct',
        protocol: 'freedom',
        freedom_final_rules_json: '[{"domain":["example.com"],"action":"block"}]'
      }
    ];

    const res26 = compileConfig(cfg, { core: 'xray', version: '26.11.9' });
    const j26 = res26.json as Record<string, any>;
    const ss22In = j26.inbounds.find((i: any) => i.tag === 'ss-2022-in');
    expect(ss22In.settings.password).toBe('server-psk-base64-key==');
    expect(ss22In.settings.users[0].method).toBeUndefined();
    const ssAeadIn = j26.inbounds.find((i: any) => i.tag === 'ss-aead-in');
    expect(ssAeadIn.settings.users[0].method).toBe('aes-256-gcm');
    expect(j26.outbounds[0].settings.finalRules).toBeDefined();

    const res25 = compileConfig(cfg, { core: 'xray', version: '25.9.11' });
    const j25 = res25.json as Record<string, any>;
    expect(j25.outbounds[0].settings.finalRules).toBeUndefined();
    expect(res25.diagnostics.some((d) => d.path.includes('freedom_final_rules_json') && d.level === 'warning')).toBe(true);

    const dump: UciRawDump = {
      main: { '.type': 'general', '.name': 'main', core_type: 'xray' },
      main_policy: {
        '.type': 'policy',
        '.name': 'main_policy',
        enabled: '1',
        handshake: '9',
        conn_idle: '600',
        uplink_only: '0',
        downlink_only: '0',
        buffer_size: '0'
      }
    };
    const parsed = parseUciDump(dump);
    expect(parsed.policy.levels).toEqual([]);
    const pJson = compileConfig(parsed, { core: 'xray', version: '26.11.9' }).json as Record<string, any>;
    expect(pJson.policy.levels['0'].handshake).toBe(9);
    expect(pJson.policy.levels['0'].connIdle).toBe(600);
    expect(pJson.policy.levels['0'].uplinkOnly).toBe(0);
    expect(pJson.policy.levels['0'].bufferSize).toBe(0);
  });

  it('fixes V2Ray jsonv4/jsonv5 quic routing, xchacha20 block, ext-domain, Base64 pin, staticHosts & reality error', () => {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.routing_rules = [
      { id: 'r_quic', enabled: true, alias: 'BlockQUIC', protocol: ['quic'], outbound_tag: 'block' },
      { id: 'r_ext', enabled: true, alias: 'ExtDomain', domain: ['ext-domain:geosite.dat:cn'], outbound_tag: 'direct' }
    ];
    cfg.dns_servers = [
      { id: 'd1', enabled: true, alias: 'CN', address: '223.5.5.5', domains: ['ext-domain:geosite.dat:cn'] }
    ];
    cfg.dns.hosts = { 'dup.example.com': '1.2.3.4' };
    cfg.dns.host_entries = [
      { domain: 'dup.example.com', addresses: ['5.6.7.8'] },
      { domain: 'empty.example.com', addresses: ['  ', ''] }
    ];
    cfg.outbounds = [
      { id: 'direct', enabled: true, alias: 'Direct', tag: 'direct', protocol: 'freedom' },
      { id: 'block', enabled: true, alias: 'Block', tag: 'block', protocol: 'blackhole' },
      { id: 'ss_xchacha', enabled: true, alias: 'SSXC', tag: 'ss-xc', protocol: 'shadowsocks', address: '1.1.1.1', port: 443, method: 'xchacha20-poly1305', password: 'pw' },
      { id: 'bad_pin', enabled: true, alias: 'BadPin', tag: 'bad-pin', protocol: 'vmess', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'ws', security: 'tls', tls_pinned_sha256: ['de:ad:be:ef'] },
      { id: 'v5_reality', enabled: true, alias: 'V5R', tag: 'v5-r', protocol: 'vless', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'grpc', security: 'reality' }
    ];

    const v5Res = compileConfig(cfg, { core: 'v2ray', version: '5.56.0' });
    const v5Json = v5Res.json as Record<string, any>;
    expect(v5Json.router.rule[0].protocol).toEqual(['quic']);
    expect(v5Json.router.rule[1].geoDomain[0]).toEqual({ filePath: 'geosite.dat', code: 'cn' });
    expect(v5Json.dns.nameServer[0].geoDomain[0]).toEqual({ filePath: 'geosite.dat', code: 'cn' });
    const dupEntries = (v5Json.dns.staticHosts || []).filter((h: any) => h.domain === 'dup.example.com');
    expect(dupEntries.length).toBe(1);
    expect(dupEntries[0].ip).toEqual(['5.6.7.8']);
    expect((v5Json.dns.staticHosts || []).some((h: any) => h.domain === 'empty.example.com')).toBe(false);
    expect(v5Res.diagnostics.some((d) => d.path.includes('ss-xc') && d.level === 'error')).toBe(true);
    expect(v5Res.diagnostics.some((d) => d.path.includes('tls_pinned_sha256') && d.level === 'error')).toBe(true);
    const realityErrs = v5Res.diagnostics.filter((d) => d.path.includes('v5-r') && d.level === 'error');
    expect(realityErrs.length).toBe(1);

    cfg.general.v2ray_format = 'jsonv4';
    const v4Res = compileConfig(cfg, { core: 'v2ray', version: '5.56.0' });
    const v4Json = v4Res.json as Record<string, any>;
    const quicRuleV4 = v4Json.routing.rules.find((r: any) => r.outboundTag === 'block');
    expect(quicRuleV4?.protocol).toEqual(['quic']);
    expect(v4Res.diagnostics.some((d) => d.path.includes('ss-xc') && d.level === 'error')).toBe(true);
  });

  it('covers FakeDNS preset dns_servers, URI importer edge cases, GeoData parser guards & firewall diff', async () => {
    const fakednsPreset = BUILTIN_PRESETS.find((p) => p.id === 'builtin-xray-tproxy-fakedns')!;
    expect(fakednsPreset.config.dns_servers.some((s) => s.address === 'fakedns')).toBe(true);

    const barePct = parseShareUri('vless://11111111-1111-1111-1111-111111111111@example.com:443?type=httpupgrade&path=%2Fhu&host=h.example.com&security=reality&pbk=pub&pqv=pqv123#50%Off');
    expect(barePct).not.toBeNull();
    expect(barePct?.alias).toBe('50%Off');
    expect(barePct?.httpupgrade_path).toBe('/hu');
    expect(barePct?.httpupgrade_host).toBe('h.example.com');
    expect(barePct?.reality_mldsa65_verify).toBe('pqv123');

    const trojanR = parseShareUri('trojan://secret@example.com:443?security=reality&sni=www.example.com&fp=chrome&pbk=pub1&sid=ab12&spx=%2F#TR');
    expect(trojanR?.reality_public_key).toBe('pub1');
    expect(trojanR?.reality_short_id).toBe('ab12');
    expect(trojanR?.reality_server_name).toBe('www.example.com');

    const hy2 = parseShareUri('hy2://pass@example.com:443?mport=20000-30000&sni=example.com#HY2');
    expect(hy2?.hysteria_udphop_port).toBe('20000-30000');

    const wg = parseShareUri('wireguard://privkey@1.2.3.4:51820?publickey=pubkey&presharedkey=psk1&reserved=1,2,3#WG');
    expect(wg?.wg_reserved).toEqual(['1', '2', '3']);
    expect(wg?.wg_peers?.[0]?.preSharedKey).toBe('psk1');

    expect(() => parseGeoDatIndex(new Uint8Array([0x80, 0x80, 0x80]).buffer)).toThrow();
    expect(() => parseGeoDatIndex(new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]).buffer)).toThrow();
    expect(() => parseGeoDatIndex(new Uint8Array([0x00, 0x00, 0x00]).buffer)).toThrow();

    const redirCfg = createDefaultConfig();
    redirCfg.transparent_proxy.enabled = true;
    redirCfg.transparent_proxy.tproxy_mode = 'redirect';
    const fw3Prev = renderExpectedFirewallRules(redirCfg, 'iptables');
    expect(fw3Prev.changes.some((c) => c.scope === 'ip-rule')).toBe(false);
    const dupDiff = computeLineDiff('{\n}\n}\n', '{\n}\n');
    expect(dupDiff.filter((d) => d.kind === 'del' && d.text === '}').length).toBe(1);

    const mockApi = createApiClient();
    const info = await mockApi.getCoreInfo();
    expect(typeof info.core_version).toBe('string');

    // Verify Xray plaintext VLESS target address boundary (CGNAT blocked, reserved private suffixes allowed)
    const plainCfg = createDefaultConfig();
    plainCfg.general.core_type = 'xray';
    plainCfg.outbounds = [
      {
        id: 'o_cgnat',
        enabled: true,
        alias: 'CGNAT',
        tag: 'p-cgnat',
        protocol: 'vless',
        address: '100.64.0.1',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        encryption: 'none',
        transport: 'raw',
        security: 'none'
      },
      {
        id: 'o_localdom',
        enabled: true,
        alias: 'LocalDomain',
        tag: 'p-localdom',
        protocol: 'vless',
        address: 'app.localdomain',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        encryption: 'none',
        transport: 'raw',
        security: 'none'
      },
      {
        id: 'o_test',
        enabled: true,
        alias: 'TestDomain',
        tag: 'p-test',
        protocol: 'vless',
        address: 'app.test',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        encryption: 'none',
        transport: 'raw',
        security: 'none'
      }
    ];
    const plainRes = compileConfig(plainCfg, { core: 'xray', version: '26.11.9' });
    expect(plainRes.diagnostics.some((d) => d.path.includes('p-cgnat') && d.level === 'error')).toBe(true);
    expect(plainRes.diagnostics.some((d) => d.path.includes('p-localdom') && d.level === 'error')).toBe(false);
    expect(plainRes.diagnostics.some((d) => d.path.includes('p-test') && d.level === 'error')).toBe(false);
  });

  it('covers 2026-11-24 review fixes: SS-2022 case, target addr edges, URI ss://, parser varint32, fw4 preview & saveConfig rollback', async () => {
    // 1. Xray SS-2022 uppercase normalization & MASQUE mux warning & 4 target address edge cases
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'xray';
    cfg.inbounds = [
      {
        id: 'ss_upper_in',
        enabled: true,
        alias: 'SSUpperIn',
        tag: 'ss-upper-in',
        protocol: 'shadowsocks',
        listen: '127.0.0.1',
        port: 18388,
        method: '2022-BLAKE3-AES-128-GCM',
        password: 'AAAAAAAAAAAAAAAAAAAAAA==',
        users: [{ password: 'BBBBBBBBBBBBBBBBBBBBBB==', email: 'u1@test', level: 0 }]
      }
    ];
    cfg.outbounds = [
      {
        id: 'ss_upper_out',
        enabled: true,
        alias: 'SSUpperOut',
        tag: 'ss-upper-out',
        protocol: 'shadowsocks',
        address: '1.1.1.1',
        port: 8388,
        method: '2022-BLAKE3-AES-128-GCM',
        password: 'AAAAAAAAAAAAAAAAAAAAAA=='
      },
      {
        id: 'masque_mux',
        enabled: true,
        alias: 'MasqueMux',
        tag: 'masque-mux',
        protocol: 'masque',
        address: '1.1.1.1',
        port: 443,
        transport: 'masque',
        security: 'tls',
        mux_enabled: true
      },
      {
        id: 'v_hex_mapped',
        enabled: true,
        alias: 'HexMapped',
        tag: 'v-hex-mapped',
        protocol: 'vless',
        address: '::ffff:c0a8:101',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        encryption: 'none',
        transport: 'raw',
        security: 'none'
      },
      {
        id: 'v_bad_mapped',
        enabled: true,
        alias: 'BadMapped',
        tag: 'v-bad-mapped',
        protocol: 'vless',
        address: '::ffff:10.0.0.999',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        encryption: 'none',
        transport: 'raw',
        security: 'none'
      },
      {
        id: 'v_double_dot',
        enabled: true,
        alias: 'DoubleDot',
        tag: 'v-double-dot',
        protocol: 'vless',
        address: 'foo.local..',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        encryption: 'none',
        transport: 'raw',
        security: 'none'
      },
      {
        id: 'v_numeric_dotless',
        enabled: true,
        alias: 'NumDotless',
        tag: 'v-num-dotless',
        protocol: 'vless',
        address: '12345',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        encryption: 'none',
        transport: 'raw',
        security: 'none'
      }
    ];
    const res = compileConfig(cfg, { core: 'xray', version: '26.11.9' });
    const j = res.json as Record<string, any>;
    expect(j.inbounds[0].settings.method).toBe('2022-blake3-aes-128-gcm');
    expect(j.outbounds.find((o: any) => o.tag === 'ss-upper-out').settings.method).toBe('2022-blake3-aes-128-gcm');
    expect(res.diagnostics.some((d) => d.path === 'outbounds.masque-mux.mux' && d.level === 'warning')).toBe(true);
    expect(res.diagnostics.some((d) => d.path.includes('v-hex-mapped') && d.level === 'error')).toBe(false);
    expect(res.diagnostics.some((d) => d.path.includes('v-bad-mapped') && d.level === 'error')).toBe(true);
    expect(res.diagnostics.some((d) => d.path.includes('v-double-dot') && d.level === 'error')).toBe(true);
    expect(res.diagnostics.some((d) => d.path.includes('v-num-dotless') && d.level === 'error')).toBe(true);

    // 2. URI importer: SIP002 %3A credentials, ?plugin= containing @, mixed % decoding, xhttp_mode scoping
    const ssSip = parseShareUri('ss://2022-blake3-aes-128-gcm%3Apass1%3Apass2@1.2.3.4:8388?plugin=v2ray-plugin%3Bhost%3Dfoo@bar#HK%2050%Off');
    expect(ssSip).not.toBeNull();
    expect(ssSip?.method).toBe('2022-blake3-aes-128-gcm');
    expect(ssSip?.password).toBe('pass1:pass2');
    expect(ssSip?.address).toBe('1.2.3.4');
    expect(ssSip?.port).toBe(8388);
    expect(ssSip?.alias).toBe('HK 50%Off');

    const vlessGrpc = parseShareUri('vless://11111111-1111-1111-1111-111111111111@example.com:443?type=grpc&mode=gun&serviceName=svc#G');
    expect(vlessGrpc?.xhttp_mode).toBeUndefined();
    const trojanXhttp = parseShareUri('trojan://pw@example.com:443?type=xhttp&mode=packet-up&path=/x#T');
    expect(trojanXhttp?.xhttp_mode).toBe('packet-up');

    // 3. GeoData parser: reject 5-byte varint32 overflow on length field
    const overflowLen = new Uint8Array([0x0a, 0x80, 0x80, 0x80, 0x80, 0x10]);
    expect(() => parseGeoDatIndex(overflowLen.buffer)).toThrow(/varint32 overflow/i);

    // 4. Firewall preview fw4 parity (MAC ACL, reserved elements, Dynamic Direct, fakedns fallback port)
    const fwCfg = createDefaultConfig();
    fwCfg.transparent_proxy.enabled = true;
    fwCfg.transparent_proxy.tproxy_mode = 'tproxy';
    fwCfg.transparent_proxy.fakedns_enabled = true;
    fwCfg.transparent_proxy.fakedns_port_tcp_v4 = 0;
    fwCfg.transparent_proxy.dynamic_direct_enabled = true;
    fwCfg.lan_hosts = [
      { id: 'h1', alias: 'BypassPC', macaddr: 'aa:bb:cc:dd:ee:ff', strategy_v4: 'bypass', strategy_v6: 'tproxy' }
    ];
    const fw4Prev = renderExpectedFirewallRules(fwCfg, 'nftables');
    expect(fw4Prev.rules).toContain('elements = { 0.0.0.0/8');
    expect(fw4Prev.rules).toContain('set aios_mac_bp_v4');
    expect(fw4Prev.rules).toContain('set aios_mac_tp_v6');
    expect(fw4Prev.rules).toContain('update @aios_dd_v4');
    expect(fw4Prev.rules).toContain(`tproxy ip to :${fwCfg.transparent_proxy.tproxy_port_tcp_v4} accept`);

    // 5. UbusApiClient.saveConfig concurrency guard & rollback boundary
    let mode: 'fail-add' | 'fail-write' | 'slow-get' = 'fail-add';
    const calls: string[] = [];
    const fetchMock = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body || '{}'));
      const [, obj, method] = body.params || [];
      calls.push(`${obj}.${method}`);
      if (obj === 'uci' && method === 'get') {
        if (mode === 'slow-get') await new Promise((r) => setTimeout(r, 20));
        return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: [0, { values: {} }] }) };
      }
      if (mode === 'fail-add' && obj === 'uci' && method === 'add') {
        return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: [1] }) };
      }
      if (mode === 'fail-write' && obj === 'luci.aios' && method === 'writeCompiledConfig') {
        return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: [0, { ok: false, error: 'disk full' }] }) };
      }
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: [0, { ok: true }] }) };
    });
    vi.stubGlobal('fetch', fetchMock);
    try {
      const client = new UbusApiClient('test-sid');
      // Failure before commit -> must revert
      await expect(client.saveConfig(createDefaultConfig(), '{}')).rejects.toThrow();
      expect(calls).toContain('uci.revert');

      // Failure after commit (writeCompiledConfig) -> must NOT revert
      calls.length = 0;
      mode = 'fail-write';
      await expect(client.saveConfig(createDefaultConfig(), '{}')).rejects.toThrow(/UCI 配置已提交/);
      expect(calls).not.toContain('uci.revert');

      // Concurrent saveConfig -> rejected by saveInFlight lock
      calls.length = 0;
      mode = 'slow-get';
      const p1 = client.saveConfig(createDefaultConfig(), '{}');
      await expect(client.saveConfig(createDefaultConfig(), '{}')).rejects.toThrow(/已有保存操作正在进行中/);
      await p1;
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
