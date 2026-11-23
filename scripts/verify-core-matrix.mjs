#!/usr/bin/env node
import { createServer } from '../web/node_modules/vite/dist/node/index.js';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const CORES_DIR = path.join(REPO_ROOT, '.memory', 'cores');
const MANIFEST_PATH = path.join(CORES_DIR, 'manifest.json');
const GEODATA_DIR = path.join(CORES_DIR, 'geodata');

function parseArgs(argv) {
  const opts = { core: null, tag: null, slot: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--core') opts.core = argv[++i];
    else if (a === '--tag') opts.tag = argv[++i];
    else if (a === '--slot') opts.slot = argv[++i];
    else if (a === '--json') opts.json = true;
    else if (a === '-h' || a === '--help') {
      console.log('Usage: node scripts/verify-core-matrix.mjs [--core xray|v2ray] [--tag <tag>] [--slot <slot>] [--json]');
      process.exit(0);
    }
  }
  return opts;
}

function buildXrayFixtures(createDefaultConfig) {
  const fixtures = [];

  // 1. Full protocol + transport + DNS + Routing + Balancer + Observatory + Policy + API/Metrics
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'xray';
    cfg.general.error_log = '';
    cfg.general.api_enabled = true;
    cfg.general.metrics_enabled = true;
    cfg.general.stats_enabled = true;
    cfg.general.inline_env = [{ key: 'XRAY_TEST_FLAG', value: '1' }];
    cfg.general.geodata_reload_interval = '6h';
    cfg.dns.enabled = true;
    cfg.dns.serve_stale = true;
    cfg.dns.serve_expired_ttl = 3600;
    cfg.dns_servers[0].server_id = 'cn-1';
    cfg.dns_servers[0].timeout_ms = 2500;
    cfg.dns_servers[0].final_query = true;
    cfg.fakedns = [{ id: 'f1', ip_pool: '198.18.0.0/15', pool_size: 65535 }];
    cfg.observatory.enabled = true;
    cfg.burst_observatory = { enabled: true, subject_selector: ['proxy'], destination: 'https://www.google.com/generate_204', connectivity: '', interval: '1m', sampling: 3, timeout: '5s' };
    cfg.policy.enabled = true;
    cfg.routing.enabled = true;
    cfg.routing_rules[0].local_port = '10800-10810';
    cfg.routing_rules[0].vless_route = '1';
    cfg.routing_rules[0].rule_tag = 'r1';
    cfg.routing_rules[0].webhook_url = 'https://example.com/hook';
    cfg.routing_rules[0].webhook_deduplication = 60;
    cfg.routing_rules[0].attrs = '{"x-test":"1"}';
    cfg.balancers = [
      { id: 'b1', tag: 'bal-rr', selector: ['proxy'], strategy: 'roundRobin', fallback_tag: 'direct' },
      { id: 'b2', tag: 'bal-ll', selector: ['proxy'], strategy: 'leastLoad', fallback_tag: 'direct', strategy_expected: 2, strategy_max_rtt: '1s', strategy_tolerance: 0.05, strategy_baselines: ['500ms'] }
    ];
    cfg.inbounds = [
      { id: 'ib_socks', enabled: true, alias: 's', tag: 'ib-socks', listen: '127.0.0.1', port: 10801, protocol: 'socks', socks_auth: 'password', username: 'u', password: 'p', socks_udp: true, transport: 'raw', security: 'none', sniffing_enabled: true, sniffing_dest_override: ['http', 'tls', 'quic'] },
      { id: 'ib_http', enabled: true, alias: 'h', tag: 'ib-http', listen: '127.0.0.1', port: 10802, protocol: 'http', username: 'u', password: 'p', http_allow_transparent: true, transport: 'raw', security: 'none' },
      { id: 'ib_tunnel', enabled: true, alias: 't', tag: 'ib-tunnel', listen: '127.0.0.1', port: 10803, protocol: 'tunnel', dokodemo_network: 'tcp,udp', dokodemo_address: '1.1.1.1', dokodemo_port: 53, tunnel_port_map: [{ key: '53', value: '8.8.8.8:53' }], tunnel_user_level: 0, transport: 'raw', security: 'none' },
      { id: 'ib_vless', enabled: true, alias: 'vl', tag: 'ib-vless', listen: '127.0.0.1', port: 10804, protocol: 'vless', uuid: '11111111-1111-1111-1111-111111111111', decryption: 'none', transport: 'raw', security: 'none' },
      { id: 'ib_vmess', enabled: true, alias: 'vm', tag: 'ib-vmess', listen: '127.0.0.1', port: 10805, protocol: 'vmess', uuid: '11111111-1111-1111-1111-111111111111', transport: 'websocket', ws_path: '/ws', ws_host: 'example.com', security: 'none' },
      { id: 'ib_trojan', enabled: true, alias: 'tr', tag: 'ib-trojan', listen: '127.0.0.1', port: 10806, protocol: 'trojan', password: 'secret', transport: 'grpc', grpc_service_name: 'svc', security: 'none' },
      { id: 'ib_ss', enabled: true, alias: 'ss', tag: 'ib-ss', listen: '127.0.0.1', port: 10807, protocol: 'shadowsocks', method: 'aes-256-gcm', password: 'secret', ss_network: 'tcp,udp', transport: 'raw', security: 'none' }
    ];
    cfg.outbounds = [
      { id: 'ob_vless', enabled: true, alias: 'vl', tag: 'proxy-vless', protocol: 'vless', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', encryption: 'none', flow: 'xtls-rprx-vision', user_level: 0, transport: 'raw', security: 'reality', reality_server_name: 'www.example.com', reality_public_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', reality_short_id: '01234567', sockopt_happy_eyeballs_try_delay_ms: 250, mux_enabled: true, mux_concurrency: 128 },
      { id: 'ob_vmess', enabled: true, alias: 'vm', tag: 'proxy-vmess', protocol: 'vmess', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', security_cipher: 'auto', vmess_experiments: 'AuthenticatedLength', transport: 'websocket', ws_path: '/ws', ws_host: 'example.com', security: 'tls', tls_server_name: 'example.com' },
      { id: 'ob_trojan', enabled: true, alias: 'tr', tag: 'proxy-trojan', protocol: 'trojan', address: 'example.com', port: 443, password: 'pw', email: 'a@b.c', user_level: 0, transport: 'grpc', grpc_service_name: 'svc', security: 'tls', tls_server_name: 'example.com' },
      { id: 'ob_ss', enabled: true, alias: 'ss', tag: 'proxy-ss', protocol: 'shadowsocks', address: 'example.com', port: 8388, method: 'aes-256-gcm', password: 'pw', ss_uot: true, ss_uot_version: 2, transport: 'httpupgrade', httpupgrade_path: '/hu', httpupgrade_host: 'example.com', security: 'tls' },
      { id: 'ob_xhttp', enabled: true, alias: 'xh', tag: 'proxy-xhttp', protocol: 'vless', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', encryption: 'none', transport: 'xhttp', xhttp_path: '/x', xhttp_mode: 'auto', security: 'tls' },
      { id: 'ob_mkcp', enabled: true, alias: 'kcp', tag: 'proxy-mkcp', protocol: 'vmess', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'mkcp', mkcp_mtu: 1350, mkcp_tti: 50, mkcp_cwnd_multiplier: 2, mkcp_max_sending_window: 2097152, security: 'none' },
      { id: 'ob_hy', enabled: true, alias: 'hy', tag: 'proxy-hy', protocol: 'hysteria', address: 'example.com', port: 443, password: 'pw', transport: 'hysteria', hysteria_udp_idle_timeout: '60s', hysteria_masquerade_type: 'proxy', hysteria_masquerade_url: 'https://example.com', hysteria_up_mbps: 50, hysteria_down_mbps: 100, hysteria_obfs_password: 'obfs', hysteria_udphop_port: '20000-30000', security: 'tls', tls_server_name: 'example.com' },
      { id: 'ob_mq', enabled: true, alias: 'mq', tag: 'proxy-mq', protocol: 'masque', address: 'example.com', port: 443, transport: 'masque', masque_host: 'example.com', masque_path: '/.well-known/masque/ip/{target}/{ipproto}/', masque_user: 'u', masque_pass: 'p', masque_headers: [{ key: 'X-A', value: '1' }], security: 'tls', tls_server_name: 'example.com' },
      { id: 'ob_wg', enabled: true, alias: 'wg', tag: 'proxy-wg', protocol: 'wireguard', wg_secret_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', wg_address: ['10.0.0.2/32'], wg_peer_public_key: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=', wg_endpoint: '1.2.3.4:51820', wg_no_kernel_tun: true, transport: 'raw', security: 'none' },
      { id: 'ob_socks_noauth', enabled: true, alias: 'sn', tag: 'socks-noauth', protocol: 'socks', address: '127.0.0.1', port: 1080, user_level: 0, email: 'a@b.c', transport: 'raw', security: 'none' },
      { id: 'ob_http_auth', enabled: true, alias: 'ha', tag: 'http-auth', protocol: 'http', address: '127.0.0.1', port: 8080, username: 'u', password: 'p', http_headers: [{ key: 'User-Agent', value: 'test' }], transport: 'raw', security: 'none' },
      { id: 'ob_free', enabled: true, alias: 'fr', tag: 'direct', protocol: 'freedom', domain_strategy: 'UseIP', transport: 'raw', security: 'none' },
      { id: 'ob_bh', enabled: true, alias: 'bh', tag: 'block', protocol: 'blackhole', transport: 'raw', security: 'none' },
      { id: 'ob_dns', enabled: true, alias: 'dn', tag: 'dns-out', protocol: 'dns', dns_non_ip_query: 'drop', transport: 'raw', security: 'none' },
      { id: 'ob_loop', enabled: true, alias: 'lp', tag: 'loop', protocol: 'loopback', loopback_inbound_tag: 'ib-socks', loopback_sniffing_enabled: true, loopback_sniffing_dest_override: ['http', 'tls'], transport: 'raw', security: 'none' }
    ];
    fixtures.push({ name: 'xray_full', format: 'json', args: ['run', '-test', '-c'], cfg });
  }

  // 2. TUN + WireGuard + REALITY inbound
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'xray';
    cfg.general.error_log = '';
    cfg.inbounds.push(
      { id: 'ib_tun', enabled: true, alias: 'tun', tag: 'tun-in', listen: '0.0.0.0', port: 0, protocol: 'tun', tun_name: 'utun99', tun_mtu: 1500, tun_gateway: ['10.0.0.1/16'], tun_dns: ['1.1.1.1'], tun_user_level: 0, tun_auto_routing_table: ['0.0.0.0/0'], tun_auto_outbounds_interface: 'auto', tun_auto_dns_to_gateway: true, transport: 'raw', security: 'none' },
      { id: 'ib_wg', enabled: true, alias: 'wg', tag: 'wg-in', listen: '127.0.0.1', port: 51820, protocol: 'wireguard', wg_secret_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', wg_address: ['10.0.0.1/32'], wg_peers: [{ publicKey: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=', allowedIPs: ['10.0.0.2/32'] }], wg_mtu: 1420, transport: 'raw', security: 'none' },
      { id: 'ib_rel', enabled: true, alias: 'rel', tag: 'rel-in', listen: '127.0.0.1', port: 14430, protocol: 'vless', uuid: '11111111-1111-1111-1111-111111111111', decryption: 'none', transport: 'raw', security: 'reality', reality_target: 'www.example.com:443', reality_server_names: ['www.example.com'], reality_private_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', reality_short_ids: ['01234567'] }
    );
    fixtures.push({ name: 'xray_tun_wg_reality_in', format: 'json', args: ['run', '-test', '-c'], cfg });
  }

  // 3. Legacy reverse skipped cleanly on Xray
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'xray';
    cfg.general.error_log = '';
    cfg.reverse = { enabled: true, bridges: ['b1|int.example.com'], portals: ['p1|ext.example.com'] };
    fixtures.push({ name: 'xray_legacy_reverse', format: 'json', args: ['run', '-test', '-c'], cfg });
  }

  return fixtures;
}

function buildV2RayFixtures(createDefaultConfig) {
  const fixtures = [];

  // 1. jsonv4 full
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv4';
    cfg.general.error_log = '';
    cfg.general.api_enabled = true;
    cfg.general.stats_enabled = true;
    cfg.dns.enabled = true;
    cfg.fakedns = [{ id: 'f1', ip_pool: '198.18.0.0/15', pool_size: 65535 }];
    cfg.observatory.enabled = true;
    cfg.browser_forwarder = { enabled: true, listen_addr: '127.0.0.1', listen_port: 8088 };
    cfg.policy.enabled = true;
    cfg.reverse = { enabled: true, bridges: ['b1|int.example.com'], portals: ['p1|ext.example.com'] };
    cfg.inbounds = [
      { id: 'ib_socks', enabled: true, alias: 's', tag: 'ib-socks', listen: '127.0.0.1', port: 20801, protocol: 'socks', socks_auth: 'password', username: 'u', password: 'p', socks_udp: true, transport: 'tcp', security: 'none', sniffing_enabled: true },
      { id: 'ib_http', enabled: true, alias: 'h', tag: 'ib-http', listen: '127.0.0.1', port: 20802, protocol: 'http', username: 'u', password: 'p', http_allow_transparent: true, transport: 'tcp', security: 'none' },
      { id: 'ib_doko', enabled: true, alias: 'd', tag: 'ib-doko', listen: '127.0.0.1', port: 20803, protocol: 'dokodemo-door', dokodemo_network: 'tcp,udp', dokodemo_address: '1.1.1.1', dokodemo_port: 53, transport: 'tcp', security: 'none' },
      { id: 'ib_vmess', enabled: true, alias: 'vm', tag: 'ib-vmess', listen: '127.0.0.1', port: 20804, protocol: 'vmess', uuid: '11111111-1111-1111-1111-111111111111', transport: 'ws', ws_path: '/ws', ws_host: 'example.com', security: 'none' },
      { id: 'ib_vless', enabled: true, alias: 'vl', tag: 'ib-vless', listen: '127.0.0.1', port: 20805, protocol: 'vless', uuid: '11111111-1111-1111-1111-111111111111', transport: 'grpc', grpc_service_name: 'svc', security: 'none' },
      { id: 'ib_trojan', enabled: true, alias: 'tr', tag: 'ib-trojan', listen: '127.0.0.1', port: 20806, protocol: 'trojan', password: 'pw', transport: 'tcp', security: 'none' },
      { id: 'ib_ss', enabled: true, alias: 'ss', tag: 'ib-ss', listen: '127.0.0.1', port: 20807, protocol: 'shadowsocks', method: 'aes-256-gcm', password: 'pw', ss_network: 'tcp,udp', transport: 'tcp', security: 'none' }
    ];
    cfg.outbounds = [
      { id: 'ob_vmess', enabled: true, alias: 'vm', tag: 'proxy-vmess', protocol: 'vmess', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'ws', ws_path: '/ws', ws_host: 'example.com', security: 'tls', tls_server_name: 'example.com', mux_enabled: true, mux_concurrency: 8 },
      { id: 'ob_vless', enabled: true, alias: 'vl', tag: 'proxy-vless', protocol: 'vless', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'grpc', grpc_service_name: 'svc', security: 'tls' },
      { id: 'ob_trojan', enabled: true, alias: 'tr', tag: 'proxy-trojan', protocol: 'trojan', address: 'example.com', port: 443, password: 'pw', transport: 'http', h2_path: '/h2', h2_host: ['example.com'], security: 'tls' },
      { id: 'ob_ss', enabled: true, alias: 'ss', tag: 'proxy-ss', protocol: 'shadowsocks', address: 'example.com', port: 8388, method: 'aes-256-gcm', password: 'pw', transport: 'kcp', mkcp_seed: 'seed', security: 'none' },
      { id: 'ob_hy2', enabled: true, alias: 'hy2', tag: 'proxy-hy2', protocol: 'hysteria2', address: 'example.com', port: 443, password: 'pw', transport: 'hysteria2', hysteria_up_mbps: 50, hysteria_down_mbps: 100, security: 'tls', tls_server_name: 'example.com' },
      { id: 'ob_free', enabled: true, alias: 'fr', tag: 'direct', protocol: 'freedom', domain_strategy: 'UseIP', transport: 'tcp', security: 'none' },
      { id: 'ob_bh', enabled: true, alias: 'bh', tag: 'block', protocol: 'blackhole', transport: 'tcp', security: 'none' },
      { id: 'ob_dns', enabled: true, alias: 'dn', tag: 'dns-out', protocol: 'dns', transport: 'tcp', security: 'none' },
      { id: 'ob_loop', enabled: true, alias: 'lp', tag: 'loop', protocol: 'loopback', loopback_inbound_tag: 'ib-socks', transport: 'tcp', security: 'none' }
    ];
    fixtures.push({ name: 'v4_full', format: 'jsonv4', args: ['test', '-c'], cfg });
  }

  // 2. jsonv4 services.burstObservatory + services.tun
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv4';
    cfg.general.error_log = '';
    cfg.observatory.enabled = false;
    cfg.burst_observatory = { enabled: true, subject_selector: ['proxy'], destination: 'https://www.google.com/generate_204', connectivity: '', interval: '1m', sampling: 3, timeout: '5s' };
    cfg.inbounds.push({ id: 'ib_tun', enabled: true, alias: 'tun', tag: 'tun-in', listen: '0.0.0.0', port: 0, protocol: 'tun', tun_name: 'aios0', tun_mtu: 1500, tun_ips: ['10.0.0.1/24'], tun_routes: ['0.0.0.0/0'], sniffing_enabled: true, sniffing_dest_override: ['http', 'tls'], transport: 'tcp', security: 'none' });
    fixtures.push({ name: 'v4_services_burst_tun', format: 'jsonv4', args: ['test', '-c'], cfg });
  }

  // 3. jsonv5 full
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.general.error_log = '';
    cfg.general.stats_enabled = true;
    cfg.dns.enabled = true;
    cfg.dns.query_strategy = 'UseIPv4';
    cfg.dns.host_entries = [{ domain: 'full:cloudflare.com', addresses: ['1.1.1.1'] }];
    cfg.dns_servers[0].query_strategy = 'UseIPv4';
    cfg.fakedns = [{ id: 'f1', ip_pool: '198.18.0.0/15', pool_size: 65535 }];
    cfg.observatory.enabled = true;
    cfg.browser_forwarder = { enabled: true, listen_addr: '127.0.0.1', listen_port: 8089 };
    cfg.policy.enabled = true;
    cfg.reverse = { enabled: true, bridges: ['b1|int.example.com'], portals: ['p1|ext.example.com'] };
    cfg.routing.enabled = true;
    cfg.routing.domain_strategy = 'IPIfNonMatch';
    cfg.routing_rules[0].port = '80,443';
    cfg.routing_rules[0].source_port = '1024-65535';
    cfg.routing_rules[0].network = 'tcp,udp';
    cfg.routing_rules[0].source = ['192.168.1.0/24'];
    cfg.routing_rules[0].user = ['alice@example.com'];
    cfg.balancers = [{ id: 'b1', tag: 'bal-lp', selector: ['proxy'], strategy: 'leastPing', fallback_tag: 'direct' }];
    cfg.inbounds = [
      { id: 'ib_socks', enabled: true, alias: 's', tag: 'ib-socks', listen: '127.0.0.1', port: 30801, protocol: 'socks', socks_udp: true, socks_ip: '127.0.0.1', transport: 'tcp', security: 'none', sniffing_enabled: true, sniffing_dest_override: ['http', 'tls', 'quic'] },
      { id: 'ib_http', enabled: true, alias: 'h', tag: 'ib-http', listen: '127.0.0.1', port: 30802, protocol: 'http', transport: 'tcp', security: 'none' },
      { id: 'ib_doko', enabled: true, alias: 'd', tag: 'ib-doko', listen: '127.0.0.1', port: 30803, protocol: 'dokodemo-door', dokodemo_network: 'tcp,udp', dokodemo_address: '1.1.1.1', dokodemo_port: 53, transport: 'tcp', security: 'none' },
      { id: 'ib_vmess', enabled: true, alias: 'vm', tag: 'ib-vmess', listen: '127.0.0.1', port: 30804, protocol: 'vmess', uuid: '11111111-1111-1111-1111-111111111111', transport: 'ws', ws_path: '/ws', ws_host: 'example.com', tcp_accept_proxy_protocol: true, security: 'none' },
      { id: 'ib_vless', enabled: true, alias: 'vl', tag: 'ib-vless', listen: '127.0.0.1', port: 30805, protocol: 'vless', uuid: '11111111-1111-1111-1111-111111111111', transport: 'grpc', grpc_service_name: 'svc', security: 'none' },
      { id: 'ib_trojan', enabled: true, alias: 'tr', tag: 'ib-trojan', listen: '127.0.0.1', port: 30806, protocol: 'trojan', password: 'pw', transport: 'httpupgrade', httpupgrade_path: '/hu', httpupgrade_host: 'example.com', httpupgrade_headers: [{ key: 'X-Test', value: '1' }], security: 'none' },
      { id: 'ib_ss', enabled: true, alias: 'ss', tag: 'ib-ss', listen: '127.0.0.1', port: 30807, protocol: 'shadowsocks', method: 'aes-256-gcm', password: 'pw', ss_network: 'tcp,udp', transport: 'kcp', mkcp_seed: 'seed123', security: 'none' }
    ];
    cfg.outbounds = [
      { id: 'ob_vmess', enabled: true, alias: 'vm', tag: 'proxy-vmess', protocol: 'vmess', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'ws', ws_path: '/ws', ws_host: 'example.com', ws_headers: [{ key: 'X-W', value: '1' }], security: 'utls', tls_server_name: 'example.com', tls_fingerprint: 'chrome_auto', mux_enabled: true, mux_concurrency: 8 },
      { id: 'ob_vless', enabled: true, alias: 'vl', tag: 'proxy-vless', protocol: 'vless', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'grpc', grpc_service_name: 'svc', security: 'tls', tls_server_name: 'example.com' },
      { id: 'ob_trojan', enabled: true, alias: 'tr', tag: 'proxy-trojan', protocol: 'trojan', address: 'example.com', port: 443, password: 'pw', transport: 'httpupgrade', httpupgrade_path: '/hu', httpupgrade_host: 'example.com', httpupgrade_headers: [{ key: 'X-H', value: '1' }], security: 'tls', tls_server_name: 'example.com' },
      { id: 'ob_ss', enabled: true, alias: 'ss', tag: 'proxy-ss', protocol: 'shadowsocks', address: 'example.com', port: 8388, method: 'aes-256-gcm', password: 'pw', transport: 'kcp', mkcp_seed: 'seed', security: 'none' },
      { id: 'ob_ss2022', enabled: true, alias: 'ss22', tag: 'proxy-ss2022', protocol: 'shadowsocks2022', address: 'example.com', port: 8389, method: '2022-blake3-aes-128-gcm', password: 'AAAAAAAAAAAAAAAAAAAAAA==', ss_ipsk: ['BBBBBBBBBBBBBBBBBBBBBB=='], transport: 'tcp', security: 'none' },
      { id: 'ob_hy2', enabled: true, alias: 'hy2', tag: 'proxy-hy2', protocol: 'hysteria2', address: 'example.com', port: 443, password: 'pw', transport: 'hysteria2', hysteria_up_mbps: 50, hysteria_down_mbps: 100, security: 'tls', tls_server_name: 'example.com' },
      { id: 'ob_socks', enabled: true, alias: 'sk', tag: 'out-socks', protocol: 'socks', address: '127.0.0.1', port: 1080, transport: 'tcp', security: 'none' },
      { id: 'ob_http', enabled: true, alias: 'ht', tag: 'out-http', protocol: 'http', address: '127.0.0.1', port: 8080, transport: 'tcp', security: 'none' },
      { id: 'ob_free', enabled: true, alias: 'fr', tag: 'direct', protocol: 'freedom', domain_strategy: 'UseIPv4', send_through: '0.0.0.0', transport: 'tcp', security: 'none' },
      { id: 'ob_bh', enabled: true, alias: 'bh', tag: 'block', protocol: 'blackhole', transport: 'tcp', security: 'none' },
      { id: 'ob_dns', enabled: true, alias: 'dn', tag: 'dns-out', protocol: 'dns', transport: 'tcp', security: 'none' },
      { id: 'ob_loop', enabled: true, alias: 'lp', tag: 'loop', protocol: 'loopback', loopback_inbound_tag: 'ib-socks', transport: 'tcp', security: 'none' }
    ];
    fixtures.push({ name: 'v5_full', format: 'jsonv5', args: ['test', '-format', 'jsonv5', '-c'], cfg });
  }

  // 4. jsonv5 burstObservatory + leastLoad
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.general.error_log = '';
    cfg.observatory.enabled = false;
    cfg.burst_observatory = { enabled: true, subject_selector: ['proxy'], destination: 'https://www.google.com/generate_204', connectivity: 'http://connectivitycheck.platform.hicloud.com/generate_204', interval: '1m', sampling: 3, timeout: '5s' };
    cfg.balancers = [{ id: 'b2', tag: 'bal-ll', selector: ['proxy'], strategy: 'leastLoad', fallback_tag: 'direct' }];
    fixtures.push({ name: 'v5_burst_leastload', format: 'jsonv5', args: ['test', '-format', 'jsonv5', '-c'], cfg });
  }

  // 5. jsonv5 services.tun
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.general.error_log = '';
    cfg.inbounds.push({ id: 'ib_tun', enabled: true, alias: 'tun', tag: 'tun-in', listen: '0.0.0.0', port: 0, protocol: 'tun', tun_name: 'aios0', tun_mtu: 1500, tun_ips: ['10.0.0.1/24'], tun_routes: ['0.0.0.0/0'], sniffing_enabled: true, sniffing_dest_override: ['http', 'tls'], transport: 'tcp', security: 'none' });
    fixtures.push({ name: 'v5_services_tun', format: 'jsonv5', args: ['test', '-format', 'jsonv5', '-c'], cfg });
  }

  // 6. jsonv5 QUIC
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.general.error_log = '';
    cfg.outbounds.unshift({ id: 'ob_q', enabled: true, alias: 'q', tag: 'proxy-quic', protocol: 'vmess', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'quic', quic_security: 'aes-128-gcm', quic_key: 'k', security: 'none' });
    fixtures.push({ name: 'v5_quic', format: 'jsonv5', args: ['test', '-format', 'jsonv5', '-c'], cfg });
  }

  // 7. jsonv5 TLS pinned + EarlyData
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.general.error_log = '';
    cfg.outbounds.unshift(
      { id: 'ob_ws_ed', enabled: true, alias: 'w', tag: 'proxy-ws-ed', protocol: 'vmess', address: 'example.com', port: 443, uuid: '11111111-1111-1111-1111-111111111111', transport: 'ws', ws_path: '/ws', ws_max_early_data: 2048, ws_early_data_header: 'Sec-WebSocket-Protocol', security: 'tls', tls_server_name: 'example.com', tls_pinned_sha256: ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='], tls_allow_insecure: true },
      { id: 'ob_hu_ed', enabled: true, alias: 'h', tag: 'proxy-hu-ed', protocol: 'trojan', address: 'example.com', port: 443, password: 'pw', transport: 'httpupgrade', httpupgrade_path: '/hu', httpupgrade_host: 'example.com', ws_max_early_data: 2048, ws_early_data_header: 'Sec-WebSocket-Protocol', security: 'tls', tls_server_name: 'example.com' }
    );
    fixtures.push({ name: 'v5_tls_pinned_earlydata', format: 'jsonv5', args: ['test', '-format', 'jsonv5', '-c'], cfg });
  }

  // 8. jsonv5 router attrs + domain types + inverse geoip
  {
    const cfg = createDefaultConfig();
    cfg.general.core_type = 'v2ray';
    cfg.general.v2ray_format = 'jsonv5';
    cfg.general.error_log = '';
    cfg.routing_rules.unshift({
      id: 'rr_edge', enabled: true, alias: 'edge',
      domain: ['full:example.com', 'domain:google.com', 'regexp:^foo\\.', 'keyword:bar', 'geosite:cn'],
      ip: ['!geoip:cn', '10.0.0.0/8'],
      attrs: "attrs[':method'] == 'GET'",
      protocol: ['http', 'tls'],
      outbound_tag: 'direct'
    });
    fixtures.push({ name: 'v5_router_attrs_geo', format: 'jsonv5', args: ['test', '-format', 'jsonv5', '-c'], cfg });
  }

  return fixtures;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!existsSync(MANIFEST_PATH)) {
    console.error(`Manifest not found at ${MANIFEST_PATH}. Run scripts/core-versions.sh import/install/build first.`);
    process.exit(1);
  }
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
  const targets = [];

  for (const core of ['xray', 'v2ray']) {
    if (opts.core && opts.core !== core) continue;
    const entry = manifest.cores?.[core];
    if (!entry) continue;
    const slotTag = opts.slot ? entry.slots?.[opts.slot] : null;
    for (const [tag, meta] of Object.entries(entry.versions || {})) {
      if (opts.tag && opts.tag !== tag) continue;
      if (opts.slot && slotTag !== tag) continue;
      const binPath = path.join(CORES_DIR, meta.binary);
      if (!existsSync(binPath)) continue;
      targets.push({ core, tag, version: meta.version, binPath });
    }
  }

  if (targets.length === 0) {
    console.error('No matching installed core binaries found in .memory/cores/manifest.json.');
    process.exit(1);
  }

  const server = await createServer({
    root: path.join(REPO_ROOT, 'web'),
    logLevel: 'silent',
    server: { middlewareMode: true },
    resolve: { alias: { '@': path.join(REPO_ROOT, 'web', 'src') } }
  });

  const workDir = mkdtempSync(path.join(tmpdir(), 'aios-matrix-'));
  const results = [];

  try {
    const { createDefaultConfig } = await server.ssrLoadModule('/src/schema/defaults.ts');
    const { compileConfig } = await server.ssrLoadModule('/src/compiler/index.ts');
    const { resolveCoreFeatures } = await server.ssrLoadModule('/src/schema/features.ts');

    for (const target of targets) {
      const features = resolveCoreFeatures(target.core, 'jsonv4', target.version);
      const fixtures = target.core === 'xray'
        ? buildXrayFixtures(createDefaultConfig).map((fx) => {
            if (features.core === 'xray') {
              if (!features.hasMasque) {
                fx.cfg.outbounds = fx.cfg.outbounds.filter((o) => o.protocol !== 'masque');
                fx.cfg.inbounds = fx.cfg.inbounds.filter((i) => i.protocol !== 'masque');
              }
              if (!features.hasHysteria) {
                fx.cfg.outbounds = fx.cfg.outbounds.filter((o) => o.protocol !== 'hysteria' && o.protocol !== 'hysteria2');
                fx.cfg.inbounds = fx.cfg.inbounds.filter((i) => i.protocol !== 'hysteria' && i.protocol !== 'hysteria2');
              }
              if (!features.hasTunInbound) {
                fx.cfg.inbounds = fx.cfg.inbounds.filter((i) => i.protocol !== 'tun');
              }
            }
            return fx;
          })
        : buildV2RayFixtures(createDefaultConfig);

      for (const fx of fixtures) {
        const compiled = compileConfig(fx.cfg, { core: target.core, version: target.version });
        const diagErrors = compiled.diagnostics.filter((d) => d.level === 'error');
        const cfgFile = path.join(workDir, `${target.core}_${target.tag}_${fx.name}.json`);
        writeFileSync(cfgFile, JSON.stringify(compiled.json, null, 2));

        if (diagErrors.length > 0) {
          results.push({
            core: target.core,
            tag: target.tag,
            version: target.version,
            format: fx.format,
            fixture: fx.name,
            status: 'FAIL_DIAG',
            detail: diagErrors.map((d) => `${d.path}: ${d.message}`).join('; ')
          });
          continue;
        }

        try {
          execFileSync(target.binPath, [...fx.args, cfgFile], {
            env: {
              ...process.env,
              XRAY_LOCATION_ASSET: GEODATA_DIR,
              V2RAY_LOCATION_ASSET: GEODATA_DIR
            },
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
          });
          results.push({
            core: target.core,
            tag: target.tag,
            version: target.version,
            format: fx.format,
            fixture: fx.name,
            status: 'PASS',
            detail: ''
          });
        } catch (e) {
          const combined = `${e.stdout || ''}\n${e.stderr || ''}`.trim();
          const tail = combined.split('\n').slice(-2).join(' | ');
          results.push({
            core: target.core,
            tag: target.tag,
            version: target.version,
            format: fx.format,
            fixture: fx.name,
            status: 'FAIL_BIN',
            detail: tail
          });
        }
      }
    }
  } finally {
    await server.close();
    rmSync(workDir, { recursive: true, force: true });
  }

  if (opts.json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    console.log('| Core | Tag | Version | Format | Fixture | Status |');
    console.log('| :--- | :--- | :--- | :--- | :--- | :--- |');
    for (const r of results) {
      console.log(`| ${r.core} | ${r.tag} | ${r.version} | ${r.format} | ${r.fixture} | ${r.status} |`);
    }
    const failed = results.filter((r) => r.status !== 'PASS');
    if (failed.length > 0) {
      console.log('\nFailures:');
      for (const f of failed) {
        console.log(`- [${f.core}/${f.tag}/${f.fixture}] ${f.status}: ${f.detail}`);
      }
    }
    console.log(`\nSummary: ${results.length - failed.length}/${results.length} passed.`);
  }

  if (results.some((r) => r.status !== 'PASS')) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
