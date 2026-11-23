import { describe, expect, it } from 'vitest';
import { createDefaultConfig } from '../web/src/schema/defaults';
import { compileConfig } from '../web/src/compiler';
import { getCoreCapabilities, validateStreamCombination } from '../web/src/schema/capabilities';
import { parseUciDump, serializeConfigToUci, type UciRawDump } from '../web/src/schema/uci';
import { BUILTIN_PRESETS } from '../web/src/presets/builtin';
import { applyPresetToConfig } from '../web/src/presets/manager';

describe('Gap-Closure Regression Tests', () => {
  it('round-trips extended StreamFields and top-level sections through UCI', () => {
    const original = createDefaultConfig();
    original.general.core_type = 'v2ray';
    original.general.v2ray_format = 'jsonv5';
    original.general.inline_env = [{ key: 'DEMO_FLAG', value: 'true' }];
    original.general.geodata_reload_interval = '6h';
    original.inbounds[0].tcp_request_headers = [{ key: 'Host', value: 'example.com' }];
    original.inbounds[0].httpupgrade_headers = [{ key: 'X-Test', value: '1' }];
    original.inbounds[0].h2_headers = [{ key: 'X-H2', value: 'yes' }];
    original.inbounds[0].tls_curve_preferences = ['X25519MLKEM768', 'X25519'];
    original.inbounds[0].mkcp_cwnd_multiplier = 3;
    original.inbounds[0].quic_security = 'aes-128-gcm';
    original.inbounds[0].ds_path = '/var/run/test.sock';
    original.inbounds[0].masque_uri = '/masque';
    original.inbounds[0].masque_headers = [{ key: 'X-M', value: 'ok' }];
    original.inbounds[0].sockopt_mark = 255;
    original.burst_observatory = {
      enabled: true,
      subject_selector: ['proxy'],
      destination: 'https://example.com/204',
      connectivity: '',
      interval: '1m',
      sampling: 3,
      timeout: '5s'
    };
    original.browser_forwarder = { enabled: true, listen_addr: '::1', listen_port: 8081 };
    original.policy.levels = [
      { level: '0', handshake: 4, conn_idle: 300, uplink_only: 2, downlink_only: 5, buffer_size: 4, stats_user_uplink: true, stats_user_downlink: false },
      { level: '2', handshake: 10, conn_idle: 600, uplink_only: 3, downlink_only: 6, buffer_size: 16, stats_user_uplink: false, stats_user_downlink: true }
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
    expect(restored.general.inline_env).toEqual([{ key: 'DEMO_FLAG', value: 'true' }]);
    expect(restored.general.geodata_reload_interval).toBe('6h');
    expect(restored.inbounds[0].tcp_request_headers).toEqual([{ key: 'Host', value: 'example.com' }]);
    expect(restored.inbounds[0].httpupgrade_headers).toEqual([{ key: 'X-Test', value: '1' }]);
    expect(restored.inbounds[0].h2_headers).toEqual([{ key: 'X-H2', value: 'yes' }]);
    expect(restored.inbounds[0].tls_curve_preferences).toEqual(['X25519MLKEM768', 'X25519']);
    expect(restored.inbounds[0].mkcp_cwnd_multiplier).toBe(3);
    expect(restored.inbounds[0].quic_security).toBe('aes-128-gcm');
    expect(restored.inbounds[0].ds_path).toBe('/var/run/test.sock');
    expect(restored.inbounds[0].masque_uri).toBe('/masque');
    expect(restored.inbounds[0].masque_headers).toEqual([{ key: 'X-M', value: 'ok' }]);
    expect(restored.inbounds[0].sockopt_mark).toBe(255);
    expect(restored.burst_observatory?.enabled).toBe(true);
    expect(restored.burst_observatory?.sampling).toBe(3);
    expect(restored.browser_forwarder?.listen_port).toBe(8081);
    expect(restored.policy.levels?.length).toBe(2);
    expect(restored.policy.levels?.[1].level).toBe('2');
  });

  it('compiles V2Ray jsonv5 complete services and PascalCase log level', () => {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.general.log_level = 'warning';
    cfg.general.api_enabled = true;
    cfg.dns.enabled = true;
    cfg.fakedns = [{ id: 'f1', ip_pool: '198.18.0.0/15', pool_size: 65535 }];
    cfg.burst_observatory = {
      enabled: true,
      subject_selector: ['proxy'],
      destination: 'https://example.com/204',
      connectivity: '',
      interval: '1m',
      sampling: 4,
      timeout: '5s'
    };
    cfg.browser_forwarder = { enabled: true, listen_addr: '::1', listen_port: 8080 };
    cfg.policy.enabled = true;
    cfg.reverse = { enabled: true, bridges: ['b1|int.example.com'], portals: ['p1|ext.example.com'] };
    cfg.outbounds.unshift({
      id: 'ss2022_ipsk',
      enabled: true,
      alias: 'SS2022 iPSK',
      tag: 'proxy-ss2022-ipsk',
      protocol: 'shadowsocks2022',
      address: 'ss.example.com',
      port: 8388,
      method: '2022-blake3-aes-128-gcm',
      password: 'demo',
      ss_ipsk: ['demo1', 'demo2'],
      transport: 'tcp',
      security: 'none'
    });

    const res = compileConfig(cfg);
    expect(((res.json.log as Record<string, unknown>).error as Record<string, unknown>).level).toBe('Warning');
    const dns = res.json.dns as Record<string, unknown>;
    expect(dns).toBeDefined();
    expect(dns.fakeDns).toEqual({ pools: [{ ipPool: '198.18.0.0/15', lruSize: 65535 }] });
    const services = res.json.services as Record<string, Record<string, unknown>>;
    expect(services.fakedns).toBeUndefined();
    expect(services.api).toBeUndefined();
    expect(services.burstObservatory).toBeDefined();
    expect((services.burstObservatory.pingConfig as Record<string, unknown>).samplingCount).toBe(4);
    expect(services.browser).toEqual({ listenAddr: '::1', listenPort: 8080 });
    expect(services.policy).toEqual({
      level: {
        '0': {
          timeout: {
            handshake: { value: 4 },
            connectionIdle: { value: 300 },
            uplinkOnly: { value: 2 },
            downlinkOnly: { value: 5 }
          },
          stats: { userUplink: true, userDownlink: true },
          buffer: { connection: 4096 }
        }
      },
      system: {
        stats: {
          inboundUplink: true,
          inboundDownlink: true,
          outboundUplink: true,
          outboundDownlink: true
        }
      }
    });
    expect(services.reverse).toBeDefined();
    const outbounds = res.json.outbounds as Array<Record<string, unknown>>;
    expect((outbounds[0].settings as Record<string, unknown>).ipsk).toEqual(['demo1', 'demo2']);
  });

  it('emits error diagnostic when shadowsocks2022 is used under V2Ray jsonv4', () => {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv4';
    cfg.outbounds.unshift({
      id: 'ss2022_v4',
      enabled: true,
      alias: 'SS2022 v4',
      tag: 'proxy-ss2022-v4',
      protocol: 'shadowsocks2022',
      address: 'ss.example.com',
      port: 8388,
      method: '2022-blake3-aes-128-gcm',
      password: 'demo',
      transport: 'tcp',
      security: 'none'
    });

    const res = compileConfig(cfg);
    expect(res.diagnostics.some((d) => d.level === 'error' && d.message.includes('shadowsocks2022'))).toBe(true);
  });

  it('enforces Xray method, flat outbounds, Hysteria/MASQUE, DNS server-level fields, and defaults', () => {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'xray';
    cfg.dns.script = '/etc/aios/dns.lua';
    cfg.dns.serve_expired_ttl = 3600;
    cfg.dns_servers[0].server_id = 'cn-primary';
    cfg.dns_servers[0].timeout_ms = 2500;
    cfg.dns_servers[0].final_query = true;
    cfg.routing.script = '/etc/aios/route.lua';
    cfg.routing_rules[0].local_port = '10800-10810';
    cfg.routing_rules[0].vless_route = '1';
    cfg.routing_rules[0].rule_tag = 'private-direct';
    cfg.balancers.push({
      id: 'b_load',
      tag: 'bal-load',
      selector: ['proxy'],
      strategy: 'leastLoad',
      fallback_tag: 'direct',
      strategy_expected: 2,
      strategy_max_rtt: '1s',
      strategy_tolerance: 0.05,
      strategy_baselines: ['500ms']
    });

    cfg.inbounds.unshift(
      {
        id: 'masque_in',
        enabled: true,
        alias: 'MASQUE In',
        tag: 'masque-in',
        listen: '0.0.0.0',
        port: 443,
        protocol: 'masque',
        users: [{ email: 'u1', password: 'v1', level: 0 }],
        masque_address: ['10.0.0.1/24'],
        masque_mtu: 1300,
        transport: 'masque',
        masque_path: '/.well-known/masque/ip/{target}/{ipproto}/',
        masque_host: 'ignored.test',
        security: 'tls'
      },
      {
        id: 'tun_in',
        enabled: true,
        alias: 'TUN In',
        tag: 'tun-in',
        listen: '0.0.0.0',
        port: 0,
        protocol: 'tun',
        tun_name: 'xray0',
        tun_mtu: 1500,
        tun_gateway: ['10.0.0.1/16'],
        transport: 'raw',
        security: 'none'
      }
    );

    cfg.outbounds.unshift(
      {
        id: 'vless_flat',
        enabled: true,
        alias: 'VLESS Flat',
        tag: 'proxy-vless',
        protocol: 'vless',
        address: 'vless.test',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        encryption: 'none',
        flow: 'xtls-rprx-vision',
        user_level: 0,
        transport: 'raw',
        security: 'reality',
        reality_server_name: 'www.test',
        reality_public_key: 'pub',
        sockopt_happy_eyeballs_try_delay_ms: 250,
        mux_enabled: true,
        mux_concurrency: 256
      },
      {
        id: 'hy2_xray',
        enabled: true,
        alias: 'Hy2 Xray',
        tag: 'proxy-hy2',
        protocol: 'hysteria',
        address: 'hy.test',
        port: 443,
        password: 'v1',
        transport: 'hysteria',
        hysteria_udp_idle_timeout: '60s',
        hysteria_masquerade_type: 'proxy',
        hysteria_masquerade_url: 'https://example.test',
        security: 'tls'
      },
      {
        id: 'wg_out',
        enabled: true,
        alias: 'WG Out',
        tag: 'proxy-wg',
        protocol: 'wireguard',
        wg_secret_key: 'k1',
        wg_address: ['10.0.0.2/32'],
        wg_peer_public_key: 'p1',
        wg_endpoint: '1.2.3.4:51820',
        transport: 'raw',
        security: 'none'
      }
    );

    const res = compileConfig(cfg);
    const outbounds = res.json.outbounds as Array<Record<string, unknown>>;
    const inbounds = res.json.inbounds as Array<Record<string, unknown>>;

    const vlessOut = outbounds.find((o) => o.tag === 'proxy-vless')!;
    const vlessStream = vlessOut.streamSettings as Record<string, unknown>;
    expect(vlessStream.method).toBe('raw');
    expect(vlessStream.network).toBeUndefined();
    expect((vlessStream.sockopt as Record<string, unknown>).happyEyeballs).toEqual({ tryDelayMs: 250 });
    expect((vlessOut.settings as Record<string, unknown>).address).toBe('vless.test');
    expect((vlessOut.mux as Record<string, unknown>).concurrency).toBe(128);

    const hyOut = outbounds.find((o) => o.tag === 'proxy-hy2')!;
    const hySettings = (hyOut.streamSettings as Record<string, unknown>).hysteriaSettings as Record<string, unknown>;
    expect(hySettings.udpIdleTimeout).toBe(60);
    expect(hySettings.masquerade).toEqual({ type: 'proxy', url: 'https://example.test' });

    const mqIn = inbounds.find((i) => i.tag === 'masque-in')!;
    expect(mqIn.settings).toEqual({
      users: [{ email: 'u1', pass: 'v1', level: 0 }],
      address: ['10.0.0.1/24'],
      mtu: 1300
    });
    expect((mqIn.streamSettings as Record<string, unknown>).masqueSettings).toEqual({
      path: '/.well-known/masque/ip/{target}/{ipproto}/'
    });

    const wgOut = outbounds.find((o) => o.tag === 'proxy-wg')!;
    expect((wgOut.settings as Record<string, unknown>).noKernelTun).toBe(false);

    const tunIn = inbounds.find((i) => i.tag === 'tun-in')!;
    expect((tunIn.settings as Record<string, unknown>).mtu).toBe(1500);
    expect((tunIn.settings as Record<string, unknown>).MTU).toBeUndefined();

    const dns = res.json.dns as Record<string, unknown>;
    expect(dns.timeoutMs).toBeUndefined();
    expect(dns.finalQuery).toBeUndefined();
    expect(dns.serveExpiredTTL).toBe(3600);
    const dnsSrv0 = (dns.servers as Array<Record<string, unknown>>)[0];
    expect(dnsSrv0.timeoutMs).toBe(2500);
    expect(dnsSrv0.finalQuery).toBe(true);
  });

  it('enforces V2Ray jsonv5 official DNS, Router, Inbound users/sniffing, Outbound & capability contracts', () => {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.dns.query_strategy = 'UseIPv4';
    cfg.dns.host_entries = [{ domain: 'full:cloudflare.com', addresses: ['1.1.1.1'] }];
    cfg.fakedns = [{ id: 'f1', ip_pool: '198.18.0.0/15', pool_size: 65535 }];
    cfg.routing.domain_strategy = 'IPIfNonMatch';
    cfg.routing_rules[0].port = '80,443';
    cfg.routing_rules[0].source_port = '1024-65535';
    cfg.routing_rules[0].network = 'tcp,udp';
    cfg.routing_rules[0].source = ['192.168.1.0/24'];
    cfg.routing_rules[0].user = ['alice'];
    cfg.balancers.push({ id: 'b1', tag: 'bal1', selector: ['proxy'], strategy: 'leastPing' });
    cfg.balancers.push({ id: 'b2', tag: 'bal2', selector: ['proxy'], strategy: 'leastLoad' });

    cfg.inbounds.unshift(
      {
        id: 'vmess_in',
        enabled: true,
        alias: 'VMess In',
        tag: 'vmess-in',
        listen: '0.0.0.0',
        port: 10086,
        protocol: 'vmess',
        users: [{ id: '11111111-1111-1111-1111-111111111111' }],
        sniffing_enabled: true,
        sniffing_dest_override: ['http', 'tls'],
        transport: 'tcp',
        security: 'none'
      },
      {
        id: 'doko_in',
        enabled: true,
        alias: 'Doko In',
        tag: 'doko-in',
        listen: '127.0.0.1',
        port: 12345,
        protocol: 'dokodemo-door',
        dokodemo_network: 'tcp,udp',
        dokodemo_follow_redirect: true,
        transport: 'tcp',
        security: 'none'
      }
    );

    cfg.outbounds.unshift({
      id: 'loop_v5',
      enabled: true,
      alias: 'Loopback v5',
      tag: 'loop-v5',
      protocol: 'loopback',
      loopback_inbound_tag: 'reentry',
      send_through: '192.168.1.2',
      domain_strategy: 'UseIPv4',
      mux_enabled: true,
      mux_concurrency: 16,
      transport: 'tcp',
      security: 'none'
    });

    const res = compileConfig(cfg);
    const dns = res.json.dns as Record<string, unknown>;
    expect(dns.queryStrategy).toBe('USE_IP4');
    expect(dns.fakeDns).toEqual({ pools: [{ ipPool: '198.18.0.0/15', lruSize: 65535 }] });
    expect(dns.staticHosts).toEqual([{ type: 'Full', domain: 'cloudflare.com', ip: ['1.1.1.1'] }]);
    const ns0 = (dns.nameServer as Array<Record<string, unknown>>)[0];
    expect(ns0.address).toEqual({ address: '223.5.5.5', port: 53 });
    expect(ns0.geoip).toEqual([{ filePath: 'geoip.dat', code: 'cn' }]);
    expect(ns0.geoDomain).toEqual([{ filePath: 'geosite.dat', code: 'cn' }]);

    const router = res.json.router as Record<string, unknown>;
    expect(router.domainStrategy).toBe('IpIfNonMatch');
    const rule0 = (router.rule as Array<Record<string, unknown>>)[0];
    expect(rule0.portList).toBe('80,443');
    expect(rule0.sourcePortList).toBe('1024-65535');
    expect(rule0.networks).toBe('tcp,udp');
    expect(rule0.userEmail).toEqual(['alice']);
    const bals = router.balancingRule as Array<Record<string, unknown>>;
    expect(bals[0].strategy).toBe('leastping');
    expect(bals[1].strategy).toBe('leastload');

    const inbounds = res.json.inbounds as Array<Record<string, unknown>>;
    const vmessIn = inbounds.find((i) => i.tag === 'vmess-in')!;
    expect((vmessIn.settings as Record<string, unknown>).users).toEqual(['11111111-1111-1111-1111-111111111111']);
    expect(vmessIn.sniffing).toEqual({ enabled: true, destOverride: ['http', 'tls'], metadataOnly: false });
    expect(vmessIn.sniffingSettings).toBeUndefined();
    const socksIn = inbounds.find((i) => i.tag === 'socks-in')!;
    expect((socksIn.settings as Record<string, unknown>).auth).toBeUndefined();
    expect((socksIn.settings as Record<string, unknown>).udpEnabled).toBe(true);
    const dokoIn = inbounds.find((i) => i.tag === 'doko-in')!;
    expect((dokoIn.settings as Record<string, unknown>).networks).toBe('tcp,udp');

    const outbounds = res.json.outbounds as Array<Record<string, unknown>>;
    const loopOut = outbounds.find((o) => o.tag === 'loop-v5')!;
    expect(loopOut.settings).toEqual({ inboundTag: 'reentry' });
    expect(loopOut.sendThrough).toBe('192.168.1.2');
    expect(loopOut.domainStrategy).toBe('UseIP4');
    expect(loopOut.mux).toEqual({ enabled: true, concurrency: 16 });

    expect(getCoreCapabilities('v2ray', 'jsonv4').securities).toEqual(['none', 'tls']);
    expect(getCoreCapabilities('v2ray', 'jsonv4').inboundProtocols).toContain('tun');
    expect(getCoreCapabilities('v2ray', 'jsonv5').securities).toEqual(['none', 'tls', 'utls']);
    expect(getCoreCapabilities('v2ray', 'jsonv5').sniffingDestOverrides).toContain('quic');
    expect(validateStreamCombination('xray', 'jsonv4', 'vless', 'websocket', 'reality').some((i) => i.level === 'error')).toBe(true);
    expect(validateStreamCombination('v2ray', 'jsonv5', 'vmess', 'grpc', 'tls')).toEqual([]);
    expect(validateStreamCombination('v2ray', 'jsonv5', 'vmess', 'httpupgrade', 'tls')).toEqual([]);
    expect(validateStreamCombination('v2ray', 'jsonv5', 'hysteria2', 'hysteria2', 'tls')).toEqual([]);
    expect(validateStreamCombination('v2ray', 'jsonv5', 'vmess', 'grpc', 'utls').some((i) => i.level === 'error')).toBe(true);
    expect(validateStreamCombination('v2ray', 'jsonv5', 'vmess', 'tcp', 'utls')).toEqual([]);

    // Verify Xray inbounds use users (not clients/accounts)
    const xCfg = createDefaultConfig();
    xCfg.general.core_type = 'xray';
    xCfg.inbounds[0].socks_auth = 'password';
    xCfg.inbounds[0].username = 'alice';
    xCfg.inbounds[0].password = 'demo-pw';
    xCfg.inbounds.unshift({
      id: 'vless_in_x',
      enabled: true,
      alias: 'VLESS In',
      tag: 'vless-in',
      listen: '0.0.0.0',
      port: 443,
      protocol: 'vless',
      uuid: '11111111-1111-1111-1111-111111111111',
      transport: 'raw',
      security: 'none'
    });
    const xRes = compileConfig(xCfg);
    const xInbounds = xRes.json.inbounds as Array<Record<string, unknown>>;
    const xVlessIn = xInbounds.find((i) => i.tag === 'vless-in')!;
    expect((xVlessIn.settings as Record<string, unknown>).users).toBeDefined();
    expect((xVlessIn.settings as Record<string, unknown>).clients).toBeUndefined();
    const xSocksIn = xInbounds.find((i) => i.tag === 'socks-in')!;
    expect((xSocksIn.settings as Record<string, unknown>).users).toEqual([{ user: 'alice', pass: 'demo-pw' }]);
    expect((xSocksIn.settings as Record<string, unknown>).accounts).toBeUndefined();

    cfg.outbounds[0].custom_config = '{bad json';
    const badRes = compileConfig(cfg);
    expect(badRes.diagnostics.some((d) => d.level === 'error' && d.path.includes('custom_config'))).toBe(true);
  });

  it('matches real Xray 26.11.9 & V2Ray 5.56.0 contracts for TUN, v4 burstObservatory, v5 QUIC, and Xray legacy reverse', () => {
    // 1. Xray skips removed top-level reverse and emits warning
    const xCfg = createDefaultConfig();
    xCfg.general.core_type = 'xray';
    xCfg.reverse = { enabled: true, bridges: ['b1|int.example.com'], portals: ['p1|ext.example.com'] };
    const xRes = compileConfig(xCfg);
    expect(xRes.json.reverse).toBeUndefined();
    expect(xRes.diagnostics.some((d) => d.level === 'warning' && d.path === 'reverse')).toBe(true);

    // 2. V2Ray v4 services.burstObservatory uses ns int64 & services.tun uses destinationOverride
    const v4Cfg = createDefaultConfig();
    v4Cfg.general.core_type = 'v2ray';
    v4Cfg.general.v2ray_format = 'jsonv4';
    v4Cfg.burst_observatory = {
      enabled: true,
      subject_selector: ['proxy'],
      destination: 'https://www.google.com/generate_204',
      connectivity: '',
      interval: '1m',
      sampling: 3,
      timeout: '5s'
    };
    v4Cfg.inbounds.push({
      id: 'tun_v4',
      enabled: true,
      alias: 'TUN',
      tag: 'tun-in',
      listen: '0.0.0.0',
      port: 0,
      protocol: 'tun',
      tun_name: 'aios0',
      tun_mtu: 1500,
      sniffing_enabled: true,
      sniffing_dest_override: ['http', 'tls'],
      transport: 'tcp',
      security: 'none'
    });
    const v4Res = compileConfig(v4Cfg);
    const v4Svcs = v4Res.json.services as Record<string, Record<string, unknown>>;
    expect((v4Svcs.burstObservatory.pingConfig as Record<string, unknown>).interval).toBe(60000000000);
    expect((v4Svcs.burstObservatory.pingConfig as Record<string, unknown>).timeout).toBe(5000000000);
    expect((v4Svcs.tun.sniffingSettings as Record<string, unknown>).destinationOverride).toEqual(['http', 'tls']);
    expect((v4Svcs.tun.sniffingSettings as Record<string, unknown>).destOverride).toBeUndefined();

    // 3. V2Ray v5 services.tun uses destinationOverride & QUIC security uses SecurityConfig object
    const v5Cfg = createDefaultConfig();
    v5Cfg.general.core_type = 'v2ray';
    v5Cfg.general.v2ray_format = 'jsonv5';
    v5Cfg.inbounds.push({
      id: 'tun_v5',
      enabled: true,
      alias: 'TUN',
      tag: 'tun-in',
      listen: '0.0.0.0',
      port: 0,
      protocol: 'tun',
      tun_name: 'aios0',
      tun_mtu: 1500,
      sniffing_enabled: true,
      sniffing_dest_override: ['http', 'tls'],
      transport: 'tcp',
      security: 'none'
    });
    v5Cfg.outbounds.unshift({
      id: 'quic_v5',
      enabled: true,
      alias: 'QUIC',
      tag: 'proxy-quic',
      protocol: 'vmess',
      address: 'example.com',
      port: 443,
      uuid: '11111111-1111-1111-1111-111111111111',
      transport: 'quic',
      quic_security: 'aes-128-gcm',
      quic_key: 'secret',
      security: 'none'
    });
    const v5Res = compileConfig(v5Cfg);
    const v5Svcs = v5Res.json.services as Record<string, Record<string, unknown>>;
    expect((v5Svcs.tun.sniffingSettings as Record<string, unknown>).destinationOverride).toEqual(['http', 'tls']);
    const quicOut = (v5Res.json.outbounds as Array<Record<string, unknown>>)[0];
    expect((quicOut.streamSettings as Record<string, Record<string, unknown>>).transportSettings).toEqual({
      security: { type: 'AES128_GCM' },
      key: 'secret'
    });
  });

  it('switches Xray syntax across legacy (25.9.0), transitional (26.6.27), and modern (26.11.9) via core_features.json', () => {
    const makeBaseXray = () => {
      const cfg = createDefaultConfig();
      cfg.general.core_type = 'xray';
      cfg.reverse = { enabled: true, bridges: ['b1|int.example.com'], portals: ['p1|ext.example.com'] };
      cfg.inbounds[0].socks_auth = 'password';
      cfg.inbounds[0].username = 'alice';
      cfg.inbounds[0].password = 'pw';
      cfg.inbounds.unshift({
        id: 'vl_in',
        enabled: true,
        alias: 'VLESS In',
        tag: 'vless-in',
        listen: '0.0.0.0',
        port: 443,
        protocol: 'vless',
        uuid: '11111111-1111-1111-1111-111111111111',
        transport: 'raw',
        security: 'none'
      });
      cfg.outbounds.unshift({
        id: 'vl_out',
        enabled: true,
        alias: 'VLESS Out',
        tag: 'proxy-vless',
        protocol: 'vless',
        address: 'example.com',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        transport: 'raw',
        security: 'none'
      });
      return cfg;
    };

    // 1. Legacy Xray 25.9.0: network + clients/accounts + vnext + legacy reverse
    const legacyRes = compileConfig(makeBaseXray(), { core: 'xray', version: '25.9.0' });
    const legIn = legacyRes.json.inbounds as Array<Record<string, unknown>>;
    const legOut = legacyRes.json.outbounds as Array<Record<string, unknown>>;
    expect(((legOut[0].streamSettings as Record<string, unknown>).network)).toBe('raw');
    expect(((legOut[0].streamSettings as Record<string, unknown>).method)).toBeUndefined();
    expect((legOut[0].settings as Record<string, unknown>).vnext).toBeDefined();
    expect((legIn[0].settings as Record<string, unknown>).clients).toBeDefined();
    expect((legIn.find((i) => i.tag === 'socks-in')!.settings as Record<string, unknown>).accounts).toBeDefined();
    expect(legacyRes.json.reverse).toBeDefined();

    // 2. Transitional Xray 26.6.27: network + users + flat outbounds + no legacy reverse
    const midRes = compileConfig(makeBaseXray(), { core: 'xray', version: '26.6.27' });
    const midIn = midRes.json.inbounds as Array<Record<string, unknown>>;
    const midOut = midRes.json.outbounds as Array<Record<string, unknown>>;
    expect(((midOut[0].streamSettings as Record<string, unknown>).network)).toBe('raw');
    expect(((midOut[0].streamSettings as Record<string, unknown>).method)).toBeUndefined();
    expect((midOut[0].settings as Record<string, unknown>).address).toBe('example.com');
    expect((midIn[0].settings as Record<string, unknown>).users).toBeDefined();
    expect(midRes.json.reverse).toBeUndefined();

    // 3. Modern Xray 26.11.9: method + users + flat outbounds + no legacy reverse
    const modRes = compileConfig(makeBaseXray(), { core: 'xray', version: '26.11.9' });
    const modOut = modRes.json.outbounds as Array<Record<string, unknown>>;
    expect(((modOut[0].streamSettings as Record<string, unknown>).method)).toBe('raw');
    expect(((modOut[0].streamSettings as Record<string, unknown>).network)).toBeUndefined();
    expect((modOut[0].settings as Record<string, unknown>).address).toBe('example.com');

    // 4. V2Ray version gating (v5.16.0 rejects v4 services & hysteria2; v5.11.0 rejects shadowsocks2022)
    const v4Old = createDefaultConfig();
    v4Old.general.core_type = 'v2ray';
    v4Old.general.v2ray_format = 'jsonv4';
    v4Old.burst_observatory = { enabled: true, subject_selector: ['proxy'], destination: 'https://example.com/204', connectivity: '', interval: '1m', sampling: 3, timeout: '5s' };
    v4Old.outbounds.unshift({ id: 'hy2_old', enabled: true, alias: 'hy2', tag: 'hy2-old', protocol: 'hysteria2', address: 'example.com', port: 443, password: 'pw', transport: 'hysteria2', security: 'tls' });
    const v4OldRes = compileConfig(v4Old, { core: 'v2ray', version: '5.16.0' });
    expect(v4OldRes.diagnostics.some((d) => d.level === 'error' && d.path === 'burst_observatory')).toBe(true);
    expect(v4OldRes.diagnostics.some((d) => d.level === 'error' && d.path === 'outbounds.hy2-old')).toBe(true);

    const v5Old = createDefaultConfig();
    v5Old.general.core_type = 'v2ray';
    v5Old.general.v2ray_format = 'jsonv5';
    v5Old.outbounds.unshift({ id: 'ss22_old', enabled: true, alias: 'ss22', tag: 'ss22-old', protocol: 'shadowsocks2022', address: 'example.com', port: 8388, method: '2022-blake3-aes-128-gcm', password: 'demo', transport: 'tcp', security: 'none' });
    const v5OldRes = compileConfig(v5Old, { core: 'v2ray', version: '5.11.0' });
    expect(v5OldRes.diagnostics.some((d) => d.level === 'error' && d.path === 'outbounds.ss22-old')).toBe(true);
  });

  it('omits ObservatoryService when observatory is disabled in V2Ray v4 and preserves host env on preset apply', () => {
    const v4NoObs = createDefaultConfig();
    v4NoObs.general.core_type = 'v2ray';
    v4NoObs.general.v2ray_format = 'jsonv4';
    v4NoObs.general.api_enabled = true;
    v4NoObs.general.stats_enabled = true;
    v4NoObs.observatory.enabled = false;
    const res1 = compileConfig(v4NoObs, { core: 'v2ray', version: '5.56.0' });
    expect((res1.json.api as { services: string[] }).services).toEqual(['HandlerService', 'LoggerService', 'StatsService']);

    v4NoObs.observatory.enabled = true;
    const res2 = compileConfig(v4NoObs, { core: 'v2ray', version: '5.56.0' });
    expect((res2.json.api as { services: string[] }).services).toContain('ObservatoryService');

    const cur = createDefaultConfig();
    cur.general.core_type = 'v2ray';
    cur.general.core_bin = '/mnt/sda1/aios/bins/current';
    cur.general.bins_dir = '/mnt/sda1/aios/bins';
    cur.general.asset_location = '/usr/share/aios/geodata';
    cur.general.target_version = '5.56.0';
    cur.general.v2ray_format = 'jsonv5';

    const classic = BUILTIN_PRESETS.find((p) => p.id === 'builtin-classic-cn-split')!;
    const appliedClassic = applyPresetToConfig(cur, classic, { preserveOutbounds: true });
    expect(appliedClassic.general.core_bin).toBe('/mnt/sda1/aios/bins/current');
    expect(appliedClassic.general.bins_dir).toBe('/mnt/sda1/aios/bins');
    expect(appliedClassic.general.asset_location).toBe('/usr/share/aios/geodata');
    expect(appliedClassic.general.target_version).toBe('5.56.0');
    expect(appliedClassic.general.v2ray_format).toBe('jsonv5');
    expect(appliedClassic.general.core_type).toBe('v2ray');

    const xrayTproxy = BUILTIN_PRESETS.find((p) => p.id === 'builtin-xray-tproxy-fakedns')!;
    const appliedXray = applyPresetToConfig(cur, xrayTproxy, { preserveOutbounds: true });
    expect(appliedXray.general.core_bin).toBe('/mnt/sda1/aios/bins/current');
    expect(appliedXray.general.bins_dir).toBe('/mnt/sda1/aios/bins');
  });
});
