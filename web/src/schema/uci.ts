import type {
  AiosConfig,
  DnsServerConfig,
  FakeDnsPoolConfig,
  InboundConfig,
  LanHostRule,
  OutboundConfig,
  RoutingBalancerConfig,
  RoutingRuleConfig
} from '@/schema/types';
import { createDefaultConfig } from '@/schema/defaults';

export interface UciSectionPayload {
  type: string;
  name: string;
  values: Record<string, string | string[]>;
}

export type UciRawDump = Record<
  string,
  Record<string, string | string[] | number | boolean | undefined>
>;

function asBool(v: unknown, fallback = false): boolean {
  if (v === undefined || v === null || v === '') return fallback;
  if (typeof v === 'boolean') return v;
  return String(v) === '1' || String(v).toLowerCase() === 'true';
}

function asNum(v: unknown, fallback = 0): number {
  if (v === undefined || v === null || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function asStr(v: unknown, fallback = ''): string {
  if (v === undefined || v === null) return fallback;
  return String(v);
}

function asArray(v: unknown): string[] {
  if (v === undefined || v === null || v === '') return [];
  if (Array.isArray(v)) return v.map((x) => String(x)).filter(Boolean);
  return [String(v)].filter(Boolean);
}

function parseJsonField<T>(v: unknown, fallback: T): T {
  if (typeof v !== 'string' || !v.trim()) return fallback;
  try {
    return JSON.parse(v) as T;
  } catch {
    return fallback;
  }
}

function boolStr(v?: boolean): string {
  return v ? '1' : '0';
}

function setIfNonEmpty(
  out: Record<string, string | string[]>,
  key: string,
  val: string | number | boolean | string[] | undefined
) {
  if (val === undefined || val === null) return;
  if (Array.isArray(val)) {
    if (val.length > 0) out[key] = val.map((x) => String(x));
  } else if (typeof val === 'boolean') {
    out[key] = val ? '1' : '0';
  } else if (typeof val === 'number') {
    if (Number.isFinite(val)) out[key] = String(val);
  } else if (val !== '') {
    out[key] = val;
  }
}

function setJsonIfNonEmpty(out: Record<string, string | string[]>, key: string, val: unknown) {
  if (!val) return;
  if (Array.isArray(val) && val.length === 0) return;
  if (typeof val === 'object' && Object.keys(val as Record<string, unknown>).length === 0) return;
  out[key] = JSON.stringify(val);
}

function sanitizeUciName(raw: string, fallbackPrefix: string, idx: number): string {
  const cleaned = raw.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^_+/, '');
  return cleaned || `${fallbackPrefix}_${idx}`;
}

export function serializeConfigToUci(cfg: AiosConfig): UciSectionPayload[] {
  const sections: UciSectionPayload[] = [];

  // 1. general
  const g = cfg.general;
  const gVals: Record<string, string | string[]> = {};
  setIfNonEmpty(gVals, 'enabled', g.enabled);
  setIfNonEmpty(gVals, 'core_type', g.core_type);
  setIfNonEmpty(gVals, 'core_bin', g.core_bin);
  setIfNonEmpty(gVals, 'v2ray_format', g.v2ray_format);
  setIfNonEmpty(gVals, 'asset_location', g.asset_location);
  setIfNonEmpty(gVals, 'geoloader', g.geoloader);
  setIfNonEmpty(gVals, 'go_memlimit', g.go_memlimit);
  setIfNonEmpty(gVals, 'rlimit_nofile', g.rlimit_nofile);
  setIfNonEmpty(gVals, 'rlimit_data', g.rlimit_data);
  setIfNonEmpty(gVals, 'config_file', g.config_file);
  setIfNonEmpty(gVals, 'log_level', g.log_level);
  setIfNonEmpty(gVals, 'access_log', g.access_log);
  setIfNonEmpty(gVals, 'error_log', g.error_log);
  setIfNonEmpty(gVals, 'dns_log', g.dns_log);
  setIfNonEmpty(gVals, 'mask_address', g.mask_address);
  setIfNonEmpty(gVals, 'stats_enabled', g.stats_enabled);
  setIfNonEmpty(gVals, 'api_enabled', g.api_enabled);
  setIfNonEmpty(gVals, 'api_port', g.api_port);
  setIfNonEmpty(gVals, 'metrics_enabled', g.metrics_enabled);
  setIfNonEmpty(gVals, 'metrics_port', g.metrics_port);
  setIfNonEmpty(gVals, 'conflict_policy', g.conflict_policy);
  setIfNonEmpty(gVals, 'custom_configuration_hook', g.custom_configuration_hook);
  sections.push({ type: 'general', name: 'main', values: gVals });

  // 2. inbounds
  cfg.inbounds.forEach((ib, idx) => {
    const v: Record<string, string | string[]> = {};
    setIfNonEmpty(v, 'enabled', ib.enabled);
    setIfNonEmpty(v, 'alias', ib.alias);
    setIfNonEmpty(v, 'tag', ib.tag);
    setIfNonEmpty(v, 'listen', ib.listen);
    setIfNonEmpty(v, 'port', ib.port);
    setIfNonEmpty(v, 'protocol', ib.protocol);
    setIfNonEmpty(v, 'use_tunnel', ib.use_tunnel);
    setIfNonEmpty(v, 'transport', ib.transport);
    setIfNonEmpty(v, 'security', ib.security);
    setIfNonEmpty(v, 'socks_auth', ib.socks_auth);
    setIfNonEmpty(v, 'socks_udp', ib.socks_udp);
    setIfNonEmpty(v, 'socks_ip', ib.socks_ip);
    setIfNonEmpty(v, 'username', ib.username);
    setIfNonEmpty(v, 'password', ib.password);
    setIfNonEmpty(v, 'dokodemo_network', ib.dokodemo_network);
    setIfNonEmpty(v, 'dokodemo_address', ib.dokodemo_address);
    setIfNonEmpty(v, 'dokodemo_port', ib.dokodemo_port);
    setIfNonEmpty(v, 'dokodemo_follow_redirect', ib.dokodemo_follow_redirect);
    setIfNonEmpty(v, 'uuid', ib.uuid);
    setIfNonEmpty(v, 'flow', ib.flow);
    setIfNonEmpty(v, 'decryption', ib.decryption);
    setIfNonEmpty(v, 'alter_id', ib.alter_id);
    setIfNonEmpty(v, 'method', ib.method);
    setIfNonEmpty(v, 'ss_network', ib.ss_network);
    setIfNonEmpty(v, 'tun_name', ib.tun_name);
    setIfNonEmpty(v, 'tun_mtu', ib.tun_mtu);
    setIfNonEmpty(v, 'sniffing_enabled', ib.sniffing_enabled);
    setIfNonEmpty(v, 'sniffing_dest_override', ib.sniffing_dest_override);
    setIfNonEmpty(v, 'sniffing_domains_excluded', ib.sniffing_domains_excluded);
    setIfNonEmpty(v, 'sniffing_ips_excluded', ib.sniffing_ips_excluded);
    setIfNonEmpty(v, 'sniffing_metadata_only', ib.sniffing_metadata_only);
    setIfNonEmpty(v, 'sniffing_route_only', ib.sniffing_route_only);
    setIfNonEmpty(v, 'allocate_strategy', ib.allocate_strategy);
    setIfNonEmpty(v, 'allocate_refresh', ib.allocate_refresh);
    setIfNonEmpty(v, 'allocate_concurrency', ib.allocate_concurrency);
    setIfNonEmpty(v, 'sockopt_tproxy', ib.sockopt_tproxy);
    setIfNonEmpty(v, 'tls_server_name', ib.tls_server_name);
    setIfNonEmpty(v, 'tls_alpn', ib.tls_alpn);
    setIfNonEmpty(v, 'reality_target', ib.reality_target);
    setIfNonEmpty(v, 'reality_private_key', ib.reality_private_key);
    setIfNonEmpty(v, 'reality_server_names', ib.reality_server_names);
    setIfNonEmpty(v, 'reality_short_ids', ib.reality_short_ids);
    setIfNonEmpty(v, 'reality_mldsa65_seed', ib.reality_mldsa65_seed);
    setIfNonEmpty(v, 'ws_path', ib.ws_path);
    setIfNonEmpty(v, 'ws_host', ib.ws_host);
    setIfNonEmpty(v, 'grpc_service_name', ib.grpc_service_name);
    setIfNonEmpty(v, 'xhttp_path', ib.xhttp_path);
    setIfNonEmpty(v, 'xhttp_host', ib.xhttp_host);
    setIfNonEmpty(v, 'xhttp_mode', ib.xhttp_mode);
    setIfNonEmpty(v, 'custom_config', ib.custom_config);
    setJsonIfNonEmpty(v, 'users_json', ib.users);
    setJsonIfNonEmpty(v, 'fallbacks_json', ib.fallbacks);
    setJsonIfNonEmpty(v, 'tls_certificates_json', ib.tls_certificates);
    sections.push({ type: 'inbound', name: sanitizeUciName(ib.id, 'in', idx), values: v });
  });

  // 3. outbounds
  cfg.outbounds.forEach((ob, idx) => {
    const v: Record<string, string | string[]> = {};
    setIfNonEmpty(v, 'enabled', ob.enabled);
    setIfNonEmpty(v, 'alias', ob.alias);
    setIfNonEmpty(v, 'tag', ob.tag);
    setIfNonEmpty(v, 'protocol', ob.protocol);
    setIfNonEmpty(v, 'send_through', ob.send_through);
    setIfNonEmpty(v, 'address', ob.address);
    setIfNonEmpty(v, 'port', ob.port);
    setIfNonEmpty(v, 'uuid', ob.uuid);
    setIfNonEmpty(v, 'encryption', ob.encryption);
    setIfNonEmpty(v, 'flow', ob.flow);
    setIfNonEmpty(v, 'alter_id', ob.alter_id);
    setIfNonEmpty(v, 'security_cipher', ob.security_cipher);
    setIfNonEmpty(v, 'password', ob.password);
    setIfNonEmpty(v, 'method', ob.method);
    setIfNonEmpty(v, 'ss_uot', ob.ss_uot);
    setIfNonEmpty(v, 'ss_iv_check', ob.ss_iv_check);
    setIfNonEmpty(v, 'username', ob.username);
    setIfNonEmpty(v, 'freedom_redirect', ob.freedom_redirect);
    setIfNonEmpty(v, 'blackhole_response', ob.blackhole_response);
    setIfNonEmpty(v, 'dns_network', ob.dns_network);
    setIfNonEmpty(v, 'dns_address', ob.dns_address);
    setIfNonEmpty(v, 'dns_port', ob.dns_port);
    setIfNonEmpty(v, 'dns_non_ip_query', ob.dns_non_ip_query);
    setIfNonEmpty(v, 'loopback_inbound_tag', ob.loopback_inbound_tag);
    setIfNonEmpty(v, 'transport', ob.transport);
    setIfNonEmpty(v, 'security', ob.security);
    setIfNonEmpty(v, 'domain_strategy', ob.domain_strategy);
    setIfNonEmpty(v, 'dialer_proxy', ob.dialer_proxy);
    setIfNonEmpty(v, 'tls_server_name', ob.tls_server_name);
    setIfNonEmpty(v, 'tls_allow_insecure', ob.tls_allow_insecure);
    setIfNonEmpty(v, 'tls_alpn', ob.tls_alpn);
    setIfNonEmpty(v, 'tls_fingerprint', ob.tls_fingerprint);
    setIfNonEmpty(v, 'tls_pinned_sha256', ob.tls_pinned_sha256);
    setIfNonEmpty(v, 'tls_ech_config', ob.tls_ech_config);
    setIfNonEmpty(v, 'reality_server_name', ob.reality_server_name);
    setIfNonEmpty(v, 'reality_public_key', ob.reality_public_key);
    setIfNonEmpty(v, 'reality_short_id', ob.reality_short_id);
    setIfNonEmpty(v, 'reality_spider_x', ob.reality_spider_x);
    setIfNonEmpty(v, 'reality_fingerprint', ob.reality_fingerprint);
    setIfNonEmpty(v, 'reality_mldsa65_verify', ob.reality_mldsa65_verify);
    setIfNonEmpty(v, 'ws_path', ob.ws_path);
    setIfNonEmpty(v, 'ws_host', ob.ws_host);
    setIfNonEmpty(v, 'grpc_service_name', ob.grpc_service_name);
    setIfNonEmpty(v, 'grpc_multi_mode', ob.grpc_multi_mode);
    setIfNonEmpty(v, 'xhttp_path', ob.xhttp_path);
    setIfNonEmpty(v, 'xhttp_host', ob.xhttp_host);
    setIfNonEmpty(v, 'xhttp_mode', ob.xhttp_mode);
    setIfNonEmpty(v, 'xhttp_extra', ob.xhttp_extra);
    setIfNonEmpty(v, 'httpupgrade_path', ob.httpupgrade_path);
    setIfNonEmpty(v, 'httpupgrade_host', ob.httpupgrade_host);
    setIfNonEmpty(v, 'h2_path', ob.h2_path);
    setIfNonEmpty(v, 'h2_host', ob.h2_host);
    setIfNonEmpty(v, 'hysteria_auth', ob.hysteria_auth);
    setIfNonEmpty(v, 'hysteria_up_mbps', ob.hysteria_up_mbps);
    setIfNonEmpty(v, 'hysteria_down_mbps', ob.hysteria_down_mbps);
    setIfNonEmpty(v, 'hysteria_obfs_password', ob.hysteria_obfs_password);
    setIfNonEmpty(v, 'hysteria_udphop_port', ob.hysteria_udphop_port);
    setIfNonEmpty(v, 'finalmask_json', ob.finalmask_json);
    setIfNonEmpty(v, 'wg_secret_key', ob.wg_secret_key);
    setIfNonEmpty(v, 'wg_address', ob.wg_address);
    setIfNonEmpty(v, 'wg_reserved', ob.wg_reserved);
    setIfNonEmpty(v, 'wg_mtu', ob.wg_mtu);
    setIfNonEmpty(v, 'wg_no_kernel_tun', ob.wg_no_kernel_tun);
    setIfNonEmpty(v, 'mux_enabled', ob.mux_enabled);
    setIfNonEmpty(v, 'mux_concurrency', ob.mux_concurrency);
    setIfNonEmpty(v, 'mux_xudp_concurrency', ob.mux_xudp_concurrency);
    setIfNonEmpty(v, 'mux_xudp_proxy_udp443', ob.mux_xudp_proxy_udp443);
    setIfNonEmpty(v, 'sockopt_tcp_fast_open', ob.sockopt_tcp_fast_open);
    setIfNonEmpty(v, 'sockopt_mptcp', ob.sockopt_mptcp);
    setIfNonEmpty(v, 'sockopt_interface', ob.sockopt_interface);
    setIfNonEmpty(v, 'custom_config', ob.custom_config);
    setJsonIfNonEmpty(v, 'wg_peers_json', ob.wg_peers);
    setJsonIfNonEmpty(v, 'ws_headers_json', ob.ws_headers);
    sections.push({ type: 'outbound', name: sanitizeUciName(ob.id, 'out', idx), values: v });
  });

  // 4. dns & dns_servers & fakedns
  const d = cfg.dns;
  const dVals: Record<string, string | string[]> = {
    enabled: boolStr(d.enabled),
    tag: d.tag,
    query_strategy: d.query_strategy,
    disable_cache: boolStr(d.disable_cache),
    disable_fallback: boolStr(d.disable_fallback),
    disable_fallback_if_match: boolStr(d.disable_fallback_if_match),
    serve_stale: boolStr(d.serve_stale),
    enable_parallel_query: boolStr(d.enable_parallel_query)
  };
  setIfNonEmpty(dVals, 'client_ip', d.client_ip);
  setJsonIfNonEmpty(dVals, 'host_entries_json', d.host_entries);
  sections.push({ type: 'dns', name: 'main_dns', values: dVals });

  cfg.dns_servers.forEach((s, idx) => {
    const v: Record<string, string | string[]> = {};
    setIfNonEmpty(v, 'enabled', s.enabled);
    setIfNonEmpty(v, 'alias', s.alias);
    setIfNonEmpty(v, 'address', s.address);
    setIfNonEmpty(v, 'port', s.port);
    setIfNonEmpty(v, 'skip_fallback', s.skip_fallback);
    setIfNonEmpty(v, 'domains', s.domains);
    setIfNonEmpty(v, 'expect_ips', s.expect_ips);
    setIfNonEmpty(v, 'unexpected_ips', s.unexpected_ips);
    setIfNonEmpty(v, 'client_ip', s.client_ip);
    sections.push({ type: 'dns_server', name: sanitizeUciName(s.id, 'dns', idx), values: v });
  });

  cfg.fakedns.forEach((f, idx) => {
    sections.push({
      type: 'fakedns',
      name: sanitizeUciName(f.id, 'fake', idx),
      values: { ip_pool: f.ip_pool, pool_size: String(f.pool_size) }
    });
  });

  // 5. routing & routing_rules & balancers
  sections.push({
    type: 'routing',
    name: 'main_routing',
    values: {
      enabled: boolStr(cfg.routing.enabled),
      domain_strategy: cfg.routing.domain_strategy,
      domain_matcher: cfg.routing.domain_matcher
    }
  });

  cfg.routing_rules.forEach((r, idx) => {
    const v: Record<string, string | string[]> = {};
    setIfNonEmpty(v, 'enabled', r.enabled);
    setIfNonEmpty(v, 'alias', r.alias);
    setIfNonEmpty(v, 'domain', r.domain);
    setIfNonEmpty(v, 'ip', r.ip);
    setIfNonEmpty(v, 'port', r.port);
    setIfNonEmpty(v, 'source_port', r.source_port);
    setIfNonEmpty(v, 'network', r.network);
    setIfNonEmpty(v, 'source', r.source);
    setIfNonEmpty(v, 'local_ip', r.local_ip);
    setIfNonEmpty(v, 'user', r.user);
    setIfNonEmpty(v, 'inbound_tag', r.inbound_tag);
    setIfNonEmpty(v, 'protocol', r.protocol);
    setIfNonEmpty(v, 'process', r.process);
    setIfNonEmpty(v, 'attrs', r.attrs);
    setIfNonEmpty(v, 'outbound_tag', r.outbound_tag);
    setIfNonEmpty(v, 'balancer_tag', r.balancer_tag);
    sections.push({ type: 'routing_rule', name: sanitizeUciName(r.id, 'rule', idx), values: v });
  });

  cfg.balancers.forEach((b, idx) => {
    const v: Record<string, string | string[]> = {
      tag: b.tag,
      strategy: b.strategy
    };
    setIfNonEmpty(v, 'selector', b.selector);
    setIfNonEmpty(v, 'fallback_tag', b.fallback_tag);
    sections.push({ type: 'routing_balancer', name: sanitizeUciName(b.id, 'bal', idx), values: v });
  });

  // 6. observatory, policy, reverse
  const obsVals: Record<string, string | string[]> = {
    enabled: boolStr(cfg.observatory.enabled),
    probe_url: cfg.observatory.probe_url,
    probe_interval: cfg.observatory.probe_interval,
    enable_concurrency: boolStr(cfg.observatory.enable_concurrency)
  };
  setIfNonEmpty(obsVals, 'subject_selector', cfg.observatory.subject_selector);
  sections.push({ type: 'observatory', name: 'main_observatory', values: obsVals });

  sections.push({
    type: 'policy',
    name: 'main_policy',
    values: {
      enabled: boolStr(cfg.policy.enabled),
      handshake: String(cfg.policy.handshake),
      conn_idle: String(cfg.policy.conn_idle),
      uplink_only: String(cfg.policy.uplink_only),
      downlink_only: String(cfg.policy.downlink_only),
      buffer_size: String(cfg.policy.buffer_size),
      stats_inbound_uplink: boolStr(cfg.policy.stats_inbound_uplink),
      stats_inbound_downlink: boolStr(cfg.policy.stats_inbound_downlink),
      stats_outbound_uplink: boolStr(cfg.policy.stats_outbound_uplink),
      stats_outbound_downlink: boolStr(cfg.policy.stats_outbound_downlink)
    }
  });

  const revVals: Record<string, string | string[]> = { enabled: boolStr(cfg.reverse.enabled) };
  setIfNonEmpty(revVals, 'bridges', cfg.reverse.bridges);
  setIfNonEmpty(revVals, 'portals', cfg.reverse.portals);
  sections.push({ type: 'reverse', name: 'main_reverse', values: revVals });

  // 7. transparent_proxy & lan_hosts
  const tp = cfg.transparent_proxy;
  const tpVals: Record<string, string | string[]> = {
    enabled: boolStr(tp.enabled),
    firewall_backend: tp.firewall_backend,
    firewall_priority: String(tp.firewall_priority),
    route_table: String(tp.route_table),
    tproxy_mark: tp.tproxy_mark,
    dynamic_direct_mark: tp.dynamic_direct_mark,
    outbound_mark: tp.outbound_mark,
    dns_mark: tp.dns_mark,
    ct_direct_mark: tp.ct_direct_mark,
    tproxy_mode: tp.tproxy_mode,
    tproxy_port_tcp_v4: String(tp.tproxy_port_tcp_v4),
    tproxy_port_tcp_v6: String(tp.tproxy_port_tcp_v6),
    tproxy_port_udp_v4: String(tp.tproxy_port_udp_v4),
    tproxy_port_udp_v6: String(tp.tproxy_port_udp_v6),
    fakedns_enabled: boolStr(tp.fakedns_enabled),
    fakedns_pool_v4: tp.fakedns_pool_v4,
    fakedns_pool_v6: tp.fakedns_pool_v6,
    fakedns_port_tcp_v4: String(tp.fakedns_port_tcp_v4),
    fakedns_port_tcp_v6: String(tp.fakedns_port_tcp_v6),
    fakedns_port_udp_v4: String(tp.fakedns_port_udp_v4),
    fakedns_port_udp_v6: String(tp.fakedns_port_udp_v6),
    fakedns_ping_response: boolStr(tp.fakedns_ping_response),
    dynamic_direct_enabled: boolStr(tp.dynamic_direct_enabled),
    dynamic_direct_timeout: String(tp.dynamic_direct_timeout),
    dnsmasq_enabled: boolStr(tp.dnsmasq_enabled),
    dnsmasq_integration_mode: tp.dnsmasq_integration_mode,
    dnsmasq_port_start: String(tp.dnsmasq_port_start),
    dnsmasq_port_count: String(tp.dnsmasq_port_count),
    default_port_policy: tp.default_port_policy
  };
  setIfNonEmpty(tpVals, 'dnsmasq_instances', tp.dnsmasq_instances);
  setIfNonEmpty(tpVals, 'tproxy_ifaces_v4', tp.tproxy_ifaces_v4);
  setIfNonEmpty(tpVals, 'tproxy_ifaces_v6', tp.tproxy_ifaces_v6);
  setIfNonEmpty(tpVals, 'bypass_ifaces_v4', tp.bypass_ifaces_v4);
  setIfNonEmpty(tpVals, 'bypass_ifaces_v6', tp.bypass_ifaces_v6);
  setIfNonEmpty(tpVals, 'wan_bp_ips', tp.wan_bp_ips);
  setIfNonEmpty(tpVals, 'wan_fw_ips', tp.wan_fw_ips);
  sections.push({ type: 'transparent_proxy', name: 'main_tproxy', values: tpVals });

  cfg.lan_hosts.forEach((h, idx) => {
    sections.push({
      type: 'lan_hosts',
      name: sanitizeUciName(h.id, 'lan', idx),
      values: {
        alias: h.alias,
        macaddr: h.macaddr,
        strategy_v4: h.strategy_v4,
        strategy_v6: h.strategy_v6
      }
    });
  });

  return sections;
}

export function parseUciDump(raw: UciRawDump): AiosConfig {
  const def = createDefaultConfig();
  const ordered = Object.values(raw).sort(
    (a, b) => asNum(a['.index'], 0) - asNum(b['.index'], 0)
  );

  const inbounds: InboundConfig[] = [];
  const outbounds: OutboundConfig[] = [];
  const dnsServers: DnsServerConfig[] = [];
  const fakedns: FakeDnsPoolConfig[] = [];
  const routingRules: RoutingRuleConfig[] = [];
  const balancers: RoutingBalancerConfig[] = [];
  const lanHosts: LanHostRule[] = [];

  for (const s of ordered) {
    const type = asStr(s['.type']);
    const name = asStr(s['.name']);

    if (type === 'general') {
      def.general = {
        ...def.general,
        enabled: asBool(s.enabled, def.general.enabled),
        core_type: asStr(s.core_type, def.general.core_type) as AiosConfig['general']['core_type'],
        core_bin: asStr(s.core_bin, def.general.core_bin),
        v2ray_format: asStr(s.v2ray_format, def.general.v2ray_format) as 'jsonv4' | 'jsonv5',
        asset_location: asStr(s.asset_location, def.general.asset_location),
        geoloader: asStr(s.geoloader, def.general.geoloader) as 'memconservative' | 'standard',
        go_memlimit: asStr(s.go_memlimit, ''),
        rlimit_nofile: asStr(s.rlimit_nofile, def.general.rlimit_nofile),
        rlimit_data: asStr(s.rlimit_data, ''),
        config_file: asStr(s.config_file, ''),
        log_level: asStr(s.log_level, def.general.log_level) as AiosConfig['general']['log_level'],
        access_log: asStr(s.access_log, def.general.access_log),
        error_log: asStr(s.error_log, def.general.error_log),
        dns_log: asBool(s.dns_log, false),
        mask_address: asStr(s.mask_address, '') as AiosConfig['general']['mask_address'],
        stats_enabled: asBool(s.stats_enabled, true),
        api_enabled: asBool(s.api_enabled, true),
        api_port: asNum(s.api_port, 18080),
        metrics_enabled: asBool(s.metrics_enabled, true),
        metrics_port: asNum(s.metrics_port, 18888),
        conflict_policy: asStr(s.conflict_policy, 'warn') as AiosConfig['general']['conflict_policy'],
        custom_configuration_hook: asStr(s.custom_configuration_hook, '')
      };
    } else if (type === 'inbound') {
      inbounds.push({
        id: name,
        enabled: asBool(s.enabled, true),
        alias: asStr(s.alias, name),
        tag: asStr(s.tag, name),
        listen: asStr(s.listen, '0.0.0.0'),
        port: asNum(s.port, 1080),
        protocol: asStr(s.protocol, 'socks'),
        use_tunnel: asBool(s.use_tunnel, false),
        transport: asStr(s.transport, 'raw'),
        security: asStr(s.security, 'none') as InboundConfig['security'],
        socks_auth: asStr(s.socks_auth, 'noauth') as 'noauth' | 'password',
        socks_udp: asBool(s.socks_udp, true),
        socks_ip: asStr(s.socks_ip, ''),
        username: asStr(s.username, ''),
        password: asStr(s.password, ''),
        dokodemo_network: asStr(s.dokodemo_network, 'tcp,udp'),
        dokodemo_address: asStr(s.dokodemo_address, ''),
        dokodemo_port: s.dokodemo_port ? asNum(s.dokodemo_port) : undefined,
        dokodemo_follow_redirect: asBool(s.dokodemo_follow_redirect, false),
        uuid: asStr(s.uuid, ''),
        flow: asStr(s.flow, ''),
        decryption: asStr(s.decryption, 'none'),
        alter_id: asNum(s.alter_id, 0),
        method: asStr(s.method, ''),
        ss_network: asStr(s.ss_network, 'tcp,udp'),
        tun_name: asStr(s.tun_name, ''),
        tun_mtu: s.tun_mtu ? asNum(s.tun_mtu, 1500) : undefined,
        sniffing_enabled: asBool(s.sniffing_enabled, false),
        sniffing_dest_override: asArray(s.sniffing_dest_override),
        sniffing_domains_excluded: asArray(s.sniffing_domains_excluded),
        sniffing_ips_excluded: asArray(s.sniffing_ips_excluded),
        sniffing_metadata_only: asBool(s.sniffing_metadata_only, false),
        sniffing_route_only: asBool(s.sniffing_route_only, false),
        allocate_strategy: asStr(s.allocate_strategy, '') as '' | 'always' | 'random',
        allocate_refresh: s.allocate_refresh ? asNum(s.allocate_refresh) : undefined,
        allocate_concurrency: s.allocate_concurrency ? asNum(s.allocate_concurrency) : undefined,
        sockopt_tproxy: asStr(s.sockopt_tproxy, 'off') as 'off' | 'redirect' | 'tproxy',
        tls_server_name: asStr(s.tls_server_name, ''),
        tls_alpn: asArray(s.tls_alpn),
        reality_target: asStr(s.reality_target, ''),
        reality_private_key: asStr(s.reality_private_key, ''),
        reality_server_names: asArray(s.reality_server_names),
        reality_short_ids: asArray(s.reality_short_ids),
        reality_mldsa65_seed: asStr(s.reality_mldsa65_seed, ''),
        ws_path: asStr(s.ws_path, ''),
        ws_host: asStr(s.ws_host, ''),
        grpc_service_name: asStr(s.grpc_service_name, ''),
        xhttp_path: asStr(s.xhttp_path, ''),
        xhttp_host: asStr(s.xhttp_host, ''),
        xhttp_mode: asStr(s.xhttp_mode, 'auto') as InboundConfig['xhttp_mode'],
        custom_config: asStr(s.custom_config, ''),
        users: parseJsonField(s.users_json, []),
        fallbacks: parseJsonField(s.fallbacks_json, []),
        tls_certificates: parseJsonField(s.tls_certificates_json, [])
      });
    } else if (type === 'outbound') {
      outbounds.push({
        id: name,
        enabled: asBool(s.enabled, true),
        alias: asStr(s.alias, name),
        tag: asStr(s.tag, name),
        protocol: asStr(s.protocol, 'freedom'),
        send_through: asStr(s.send_through, ''),
        address: asStr(s.address, ''),
        port: s.port ? asNum(s.port) : undefined,
        uuid: asStr(s.uuid, ''),
        encryption: asStr(s.encryption, 'none'),
        flow: asStr(s.flow, ''),
        alter_id: asNum(s.alter_id, 0),
        security_cipher: asStr(s.security_cipher, 'auto'),
        password: asStr(s.password, ''),
        method: asStr(s.method, ''),
        ss_uot: asBool(s.ss_uot, false),
        ss_iv_check: asBool(s.ss_iv_check, false),
        username: asStr(s.username, ''),
        freedom_redirect: asStr(s.freedom_redirect, ''),
        blackhole_response: asStr(s.blackhole_response, 'none') as 'none' | 'http',
        dns_network: asStr(s.dns_network, ''),
        dns_address: asStr(s.dns_address, ''),
        dns_port: s.dns_port ? asNum(s.dns_port) : undefined,
        dns_non_ip_query: asStr(s.dns_non_ip_query, '') as '' | 'skip' | 'drop',
        loopback_inbound_tag: asStr(s.loopback_inbound_tag, ''),
        transport: asStr(s.transport, 'raw'),
        security: asStr(s.security, 'none') as OutboundConfig['security'],
        domain_strategy: asStr(s.domain_strategy, ''),
        dialer_proxy: asStr(s.dialer_proxy, ''),
        tls_server_name: asStr(s.tls_server_name, ''),
        tls_allow_insecure: asBool(s.tls_allow_insecure, false),
        tls_alpn: asArray(s.tls_alpn),
        tls_fingerprint: asStr(s.tls_fingerprint, ''),
        tls_pinned_sha256: asArray(s.tls_pinned_sha256),
        tls_ech_config: asStr(s.tls_ech_config, ''),
        reality_server_name: asStr(s.reality_server_name, ''),
        reality_public_key: asStr(s.reality_public_key, ''),
        reality_short_id: asStr(s.reality_short_id, ''),
        reality_spider_x: asStr(s.reality_spider_x, ''),
        reality_fingerprint: asStr(s.reality_fingerprint, ''),
        reality_mldsa65_verify: asStr(s.reality_mldsa65_verify, ''),
        ws_path: asStr(s.ws_path, ''),
        ws_host: asStr(s.ws_host, ''),
        grpc_service_name: asStr(s.grpc_service_name, ''),
        grpc_multi_mode: asBool(s.grpc_multi_mode, false),
        xhttp_path: asStr(s.xhttp_path, ''),
        xhttp_host: asStr(s.xhttp_host, ''),
        xhttp_mode: asStr(s.xhttp_mode, 'auto') as OutboundConfig['xhttp_mode'],
        xhttp_extra: asStr(s.xhttp_extra, ''),
        httpupgrade_path: asStr(s.httpupgrade_path, ''),
        httpupgrade_host: asStr(s.httpupgrade_host, ''),
        h2_path: asStr(s.h2_path, ''),
        h2_host: asArray(s.h2_host),
        hysteria_auth: asStr(s.hysteria_auth, ''),
        hysteria_up_mbps: s.hysteria_up_mbps ? asNum(s.hysteria_up_mbps) : undefined,
        hysteria_down_mbps: s.hysteria_down_mbps ? asNum(s.hysteria_down_mbps) : undefined,
        hysteria_obfs_password: asStr(s.hysteria_obfs_password, ''),
        hysteria_udphop_port: asStr(s.hysteria_udphop_port, ''),
        finalmask_json: asStr(s.finalmask_json, ''),
        wg_secret_key: asStr(s.wg_secret_key, ''),
        wg_address: asArray(s.wg_address),
        wg_reserved: asArray(s.wg_reserved),
        wg_mtu: s.wg_mtu ? asNum(s.wg_mtu, 1420) : undefined,
        wg_no_kernel_tun: asBool(s.wg_no_kernel_tun, true),
        mux_enabled: asBool(s.mux_enabled, false),
        mux_concurrency: s.mux_concurrency !== undefined ? asNum(s.mux_concurrency, 8) : undefined,
        mux_xudp_concurrency: s.mux_xudp_concurrency ? asNum(s.mux_xudp_concurrency) : undefined,
        mux_xudp_proxy_udp443: asStr(s.mux_xudp_proxy_udp443, '') as OutboundConfig['mux_xudp_proxy_udp443'],
        sockopt_tcp_fast_open: asBool(s.sockopt_tcp_fast_open, false),
        sockopt_mptcp: asBool(s.sockopt_mptcp, false),
        sockopt_interface: asStr(s.sockopt_interface, ''),
        custom_config: asStr(s.custom_config, ''),
        wg_peers: parseJsonField(s.wg_peers_json, []),
        ws_headers: parseJsonField(s.ws_headers_json, [])
      });
    } else if (type === 'dns') {
      def.dns = {
        ...def.dns,
        enabled: asBool(s.enabled, true),
        tag: asStr(s.tag, 'dns-in'),
        query_strategy: asStr(s.query_strategy, 'UseIP') as AiosConfig['dns']['query_strategy'],
        disable_cache: asBool(s.disable_cache, false),
        disable_fallback: asBool(s.disable_fallback, false),
        disable_fallback_if_match: asBool(s.disable_fallback_if_match, false),
        serve_stale: asBool(s.serve_stale, false),
        enable_parallel_query: asBool(s.enable_parallel_query, false),
        client_ip: asStr(s.client_ip, ''),
        host_entries: parseJsonField(s.host_entries_json, [])
      };
    } else if (type === 'dns_server') {
      dnsServers.push({
        id: name,
        enabled: asBool(s.enabled, true),
        alias: asStr(s.alias, name),
        address: asStr(s.address, ''),
        port: s.port ? asNum(s.port) : undefined,
        skip_fallback: asBool(s.skip_fallback, false),
        domains: asArray(s.domains),
        expect_ips: asArray(s.expect_ips),
        unexpected_ips: asArray(s.unexpected_ips),
        client_ip: asStr(s.client_ip, '')
      });
    } else if (type === 'fakedns') {
      fakedns.push({
        id: name,
        ip_pool: asStr(s.ip_pool, '198.18.0.0/15'),
        pool_size: asNum(s.pool_size, 65535)
      });
    } else if (type === 'routing') {
      def.routing = {
        enabled: asBool(s.enabled, true),
        domain_strategy: asStr(s.domain_strategy, 'IPIfNonMatch') as AiosConfig['routing']['domain_strategy'],
        domain_matcher: asStr(s.domain_matcher, 'hybrid') as AiosConfig['routing']['domain_matcher']
      };
    } else if (type === 'routing_rule') {
      routingRules.push({
        id: name,
        enabled: asBool(s.enabled, true),
        alias: asStr(s.alias, name),
        domain: asArray(s.domain),
        ip: asArray(s.ip),
        port: asStr(s.port, ''),
        source_port: asStr(s.source_port, ''),
        network: asStr(s.network, '') as RoutingRuleConfig['network'],
        source: asArray(s.source),
        local_ip: asArray(s.local_ip),
        user: asArray(s.user),
        inbound_tag: asArray(s.inbound_tag),
        protocol: asArray(s.protocol),
        process: asArray(s.process),
        attrs: asStr(s.attrs, ''),
        outbound_tag: asStr(s.outbound_tag, ''),
        balancer_tag: asStr(s.balancer_tag, '')
      });
    } else if (type === 'routing_balancer') {
      balancers.push({
        id: name,
        tag: asStr(s.tag, name),
        selector: asArray(s.selector),
        strategy: asStr(s.strategy, 'random') as RoutingBalancerConfig['strategy'],
        fallback_tag: asStr(s.fallback_tag, '')
      });
    } else if (type === 'observatory') {
      def.observatory = {
        enabled: asBool(s.enabled, false),
        subject_selector: asArray(s.subject_selector),
        probe_url: asStr(s.probe_url, 'https://www.google.com/generate_204'),
        probe_interval: asStr(s.probe_interval, '1m'),
        enable_concurrency: asBool(s.enable_concurrency, false)
      };
    } else if (type === 'policy') {
      def.policy = {
        enabled: asBool(s.enabled, true),
        handshake: asNum(s.handshake, 4),
        conn_idle: asNum(s.conn_idle, 300),
        uplink_only: asNum(s.uplink_only, 2),
        downlink_only: asNum(s.downlink_only, 5),
        buffer_size: asNum(s.buffer_size, 4),
        stats_inbound_uplink: asBool(s.stats_inbound_uplink, true),
        stats_inbound_downlink: asBool(s.stats_inbound_downlink, true),
        stats_outbound_uplink: asBool(s.stats_outbound_uplink, true),
        stats_outbound_downlink: asBool(s.stats_outbound_downlink, true)
      };
    } else if (type === 'reverse') {
      def.reverse = {
        enabled: asBool(s.enabled, false),
        bridges: asArray(s.bridges),
        portals: asArray(s.portals)
      };
    } else if (type === 'transparent_proxy') {
      def.transparent_proxy = {
        ...def.transparent_proxy,
        enabled: asBool(s.enabled, false),
        firewall_backend: asStr(s.firewall_backend, 'auto') as AiosConfig['transparent_proxy']['firewall_backend'],
        firewall_priority: asNum(s.firewall_priority, 10),
        route_table: asNum(s.route_table, 166),
        tproxy_mark: asStr(s.tproxy_mark, '0x3a01'),
        dynamic_direct_mark: asStr(s.dynamic_direct_mark, '0x3a02'),
        outbound_mark: asStr(s.outbound_mark, '0x3a03'),
        dns_mark: asStr(s.dns_mark, '0x3a04'),
        ct_direct_mark: asStr(s.ct_direct_mark, '0x3a0a'),
        tproxy_mode: asStr(s.tproxy_mode, 'tproxy') as 'tproxy' | 'redirect',
        tproxy_port_tcp_v4: asNum(s.tproxy_port_tcp_v4, 12345),
        tproxy_port_tcp_v6: asNum(s.tproxy_port_tcp_v6, 12346),
        tproxy_port_udp_v4: asNum(s.tproxy_port_udp_v4, 12347),
        tproxy_port_udp_v6: asNum(s.tproxy_port_udp_v6, 12348),
        fakedns_enabled: asBool(s.fakedns_enabled, false),
        fakedns_pool_v4: asStr(s.fakedns_pool_v4, '198.18.0.0/15'),
        fakedns_pool_v6: asStr(s.fakedns_pool_v6, '2001:2::/48'),
        fakedns_port_tcp_v4: asNum(s.fakedns_port_tcp_v4, 12355),
        fakedns_port_tcp_v6: asNum(s.fakedns_port_tcp_v6, 12356),
        fakedns_port_udp_v4: asNum(s.fakedns_port_udp_v4, 12357),
        fakedns_port_udp_v6: asNum(s.fakedns_port_udp_v6, 12358),
        fakedns_ping_response: asBool(s.fakedns_ping_response, true),
        dynamic_direct_enabled: asBool(s.dynamic_direct_enabled, false),
        dynamic_direct_timeout: asNum(s.dynamic_direct_timeout, 1800),
        dnsmasq_enabled: asBool(s.dnsmasq_enabled, false),
        dnsmasq_integration_mode: asStr(s.dnsmasq_integration_mode, 'global') as 'global' | 'per_instance',
        dnsmasq_instances: asArray(s.dnsmasq_instances),
        dnsmasq_port_start: asNum(s.dnsmasq_port_start, 5350),
        dnsmasq_port_count: asNum(s.dnsmasq_port_count, 3),
        default_port_policy: asStr(s.default_port_policy, 'forwarded') as 'forwarded' | 'bypassed',
        tproxy_ifaces_v4: asArray(s.tproxy_ifaces_v4),
        tproxy_ifaces_v6: asArray(s.tproxy_ifaces_v6),
        bypass_ifaces_v4: asArray(s.bypass_ifaces_v4),
        bypass_ifaces_v6: asArray(s.bypass_ifaces_v6),
        wan_bp_ips: asArray(s.wan_bp_ips),
        wan_fw_ips: asArray(s.wan_fw_ips)
      };
    } else if (type === 'lan_hosts') {
      lanHosts.push({
        id: name,
        alias: asStr(s.alias, name),
        macaddr: asStr(s.macaddr, ''),
        strategy_v4: asStr(s.strategy_v4, 'default') as LanHostRule['strategy_v4'],
        strategy_v6: asStr(s.strategy_v6, 'default') as LanHostRule['strategy_v6']
      });
    }
  }

  if (inbounds.length > 0) def.inbounds = inbounds;
  if (outbounds.length > 0) def.outbounds = outbounds;
  if (dnsServers.length > 0) def.dns_servers = dnsServers;
  def.fakedns = fakedns;
  if (routingRules.length > 0) def.routing_rules = routingRules;
  def.balancers = balancers;
  def.lan_hosts = lanHosts;

  return def;
}
