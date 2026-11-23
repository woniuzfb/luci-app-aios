import type {
  AiosConfig,
  DnsServerConfig,
  FakeDnsPoolConfig,
  InboundConfig,
  LanHostRule,
  OutboundConfig,
  RoutingBalancerConfig,
  RoutingRuleConfig,
  StreamFields
} from '@/schema/types';
import { createDefaultConfig, CURRENT_SCHEMA_VERSION } from '@/schema/defaults';

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

function asOptNum(v: unknown): number | undefined {
  if (v === undefined || v === null || v === '') return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
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

function serializeStreamFields(v: Record<string, string | string[]>, s: StreamFields) {
  setIfNonEmpty(v, 'transport', s.transport);
  setIfNonEmpty(v, 'security', s.security);
  // TLS
  setIfNonEmpty(v, 'tls_server_name', s.tls_server_name);
  setIfNonEmpty(v, 'tls_allow_insecure', s.tls_allow_insecure);
  setIfNonEmpty(v, 'tls_alpn', s.tls_alpn);
  setIfNonEmpty(v, 'tls_fingerprint', s.tls_fingerprint);
  setIfNonEmpty(v, 'tls_pinned_sha256', s.tls_pinned_sha256);
  setIfNonEmpty(v, 'tls_ech_config', s.tls_ech_config);
  setIfNonEmpty(v, 'tls_ech_server_keys', s.tls_ech_server_keys);
  setIfNonEmpty(v, 'tls_ech_sockopt_json', s.tls_ech_sockopt_json);
  setIfNonEmpty(v, 'tls_verify_peer_name', s.tls_verify_peer_name);
  setIfNonEmpty(v, 'tls_verify_client', s.tls_verify_client);
  setIfNonEmpty(v, 'tls_min_version', s.tls_min_version);
  setIfNonEmpty(v, 'tls_max_version', s.tls_max_version);
  setIfNonEmpty(v, 'tls_cipher_suites', s.tls_cipher_suites);
  setIfNonEmpty(v, 'tls_reject_unknown_sni', s.tls_reject_unknown_sni);
  setIfNonEmpty(v, 'tls_use_system_ca', s.tls_use_system_ca);
  setIfNonEmpty(v, 'tls_disable_system_root', s.tls_disable_system_root);
  setIfNonEmpty(v, 'tls_enable_session_resumption', s.tls_enable_session_resumption);
  setIfNonEmpty(v, 'tls_curve_preferences', s.tls_curve_preferences);
  setIfNonEmpty(v, 'tls_cert_file', s.tls_cert_file);
  setIfNonEmpty(v, 'tls_key_file', s.tls_key_file);
  setJsonIfNonEmpty(v, 'tls_certificates_json', s.tls_certificates);
  // REALITY
  setIfNonEmpty(v, 'reality_show', s.reality_show);
  setIfNonEmpty(v, 'reality_fingerprint', s.reality_fingerprint);
  setIfNonEmpty(v, 'reality_server_name', s.reality_server_name);
  setIfNonEmpty(v, 'reality_public_key', s.reality_public_key);
  setIfNonEmpty(v, 'reality_short_id', s.reality_short_id);
  setIfNonEmpty(v, 'reality_spider_x', s.reality_spider_x);
  setIfNonEmpty(v, 'reality_mldsa65_verify', s.reality_mldsa65_verify);
  setIfNonEmpty(v, 'reality_target', s.reality_target);
  setIfNonEmpty(v, 'reality_xver', s.reality_xver);
  setIfNonEmpty(v, 'reality_server_names', s.reality_server_names);
  setIfNonEmpty(v, 'reality_private_key', s.reality_private_key);
  setIfNonEmpty(v, 'reality_short_ids', s.reality_short_ids);
  setIfNonEmpty(v, 'reality_mldsa65_seed', s.reality_mldsa65_seed);
  setIfNonEmpty(v, 'reality_min_client_ver', s.reality_min_client_ver);
  setIfNonEmpty(v, 'reality_max_client_ver', s.reality_max_client_ver);
  setIfNonEmpty(v, 'reality_max_time_diff', s.reality_max_time_diff);
  // TCP / WS / gRPC / XHTTP / HTTPUpgrade / H2 / mKCP / QUIC / DS / Hysteria / MASQUE
  setIfNonEmpty(v, 'tcp_accept_proxy_protocol', s.tcp_accept_proxy_protocol);
  setIfNonEmpty(v, 'tcp_header_type', s.tcp_header_type);
  setJsonIfNonEmpty(v, 'tcp_request_headers_json', s.tcp_request_headers);
  setJsonIfNonEmpty(v, 'tcp_response_headers_json', s.tcp_response_headers);
  setIfNonEmpty(v, 'ws_path', s.ws_path);
  setIfNonEmpty(v, 'ws_host', s.ws_host);
  setJsonIfNonEmpty(v, 'ws_headers_json', s.ws_headers);
  setIfNonEmpty(v, 'ws_max_early_data', s.ws_max_early_data);
  setIfNonEmpty(v, 'ws_early_data_header', s.ws_early_data_header);
  setIfNonEmpty(v, 'ws_heartbeat_period', s.ws_heartbeat_period);
  setIfNonEmpty(v, 'grpc_service_name', s.grpc_service_name);
  setIfNonEmpty(v, 'grpc_authority', s.grpc_authority);
  setIfNonEmpty(v, 'grpc_multi_mode', s.grpc_multi_mode);
  setIfNonEmpty(v, 'grpc_idle_timeout', s.grpc_idle_timeout);
  setIfNonEmpty(v, 'grpc_health_check_timeout', s.grpc_health_check_timeout);
  setIfNonEmpty(v, 'grpc_permit_without_stream', s.grpc_permit_without_stream);
  setIfNonEmpty(v, 'grpc_initial_windows_size', s.grpc_initial_windows_size);
  setIfNonEmpty(v, 'xhttp_path', s.xhttp_path);
  setIfNonEmpty(v, 'xhttp_host', s.xhttp_host);
  setIfNonEmpty(v, 'xhttp_mode', s.xhttp_mode);
  setIfNonEmpty(v, 'xhttp_extra', s.xhttp_extra);
  setIfNonEmpty(v, 'httpupgrade_path', s.httpupgrade_path);
  setIfNonEmpty(v, 'httpupgrade_host', s.httpupgrade_host);
  setJsonIfNonEmpty(v, 'httpupgrade_headers_json', s.httpupgrade_headers);
  setIfNonEmpty(v, 'h2_path', s.h2_path);
  setIfNonEmpty(v, 'h2_host', s.h2_host);
  setIfNonEmpty(v, 'h2_method', s.h2_method);
  setJsonIfNonEmpty(v, 'h2_headers_json', s.h2_headers);
  setIfNonEmpty(v, 'mkcp_mtu', s.mkcp_mtu);
  setIfNonEmpty(v, 'mkcp_tti', s.mkcp_tti);
  setIfNonEmpty(v, 'mkcp_uplink_capacity', s.mkcp_uplink_capacity);
  setIfNonEmpty(v, 'mkcp_downlink_capacity', s.mkcp_downlink_capacity);
  setIfNonEmpty(v, 'mkcp_congestion', s.mkcp_congestion);
  setIfNonEmpty(v, 'mkcp_seed', s.mkcp_seed);
  setIfNonEmpty(v, 'mkcp_header_type', s.mkcp_header_type);
  setIfNonEmpty(v, 'mkcp_cwnd_multiplier', s.mkcp_cwnd_multiplier);
  setIfNonEmpty(v, 'mkcp_max_sending_window', s.mkcp_max_sending_window);
  setIfNonEmpty(v, 'quic_security', s.quic_security);
  setIfNonEmpty(v, 'quic_key', s.quic_key);
  setIfNonEmpty(v, 'quic_header_type', s.quic_header_type);
  setIfNonEmpty(v, 'ds_path', s.ds_path);
  setIfNonEmpty(v, 'ds_abstract', s.ds_abstract);
  setIfNonEmpty(v, 'ds_padding', s.ds_padding);
  setIfNonEmpty(v, 'hysteria_auth', s.hysteria_auth);
  setIfNonEmpty(v, 'hysteria_up_mbps', s.hysteria_up_mbps);
  setIfNonEmpty(v, 'hysteria_down_mbps', s.hysteria_down_mbps);
  setIfNonEmpty(v, 'hysteria_udp_extension', s.hysteria_udp_extension);
  setIfNonEmpty(v, 'hysteria_udp_idle_timeout', s.hysteria_udp_idle_timeout);
  setIfNonEmpty(v, 'hysteria_masquerade', s.hysteria_masquerade);
  setIfNonEmpty(v, 'hysteria_masquerade_type', s.hysteria_masquerade_type);
  setIfNonEmpty(v, 'hysteria_masquerade_dir', s.hysteria_masquerade_dir);
  setIfNonEmpty(v, 'hysteria_masquerade_url', s.hysteria_masquerade_url);
  setIfNonEmpty(v, 'hysteria_masquerade_rewrite_host', s.hysteria_masquerade_rewrite_host);
  setIfNonEmpty(v, 'hysteria_masquerade_insecure', s.hysteria_masquerade_insecure);
  setIfNonEmpty(v, 'hysteria_masquerade_content', s.hysteria_masquerade_content);
  setJsonIfNonEmpty(v, 'hysteria_masquerade_headers_json', s.hysteria_masquerade_headers);
  setIfNonEmpty(v, 'hysteria_masquerade_status_code', s.hysteria_masquerade_status_code);
  setIfNonEmpty(v, 'hysteria_udphop_port', s.hysteria_udphop_port);
  setIfNonEmpty(v, 'hysteria_udphop_interval', s.hysteria_udphop_interval);
  setIfNonEmpty(v, 'hysteria_obfs_password', s.hysteria_obfs_password);
  setIfNonEmpty(v, 'masque_host', s.masque_host);
  setIfNonEmpty(v, 'masque_path', s.masque_path);
  setIfNonEmpty(v, 'masque_user', s.masque_user);
  setIfNonEmpty(v, 'masque_pass', s.masque_pass);
  setIfNonEmpty(v, 'masque_warp_json', s.masque_warp_json);
  setIfNonEmpty(v, 'masque_uri', s.masque_uri);
  setIfNonEmpty(v, 'masque_auth', s.masque_auth);
  setJsonIfNonEmpty(v, 'masque_headers_json', s.masque_headers);
  setIfNonEmpty(v, 'finalmask_json', s.finalmask_json);
  // Sockopt
  setIfNonEmpty(v, 'sockopt_mark', s.sockopt_mark);
  setIfNonEmpty(v, 'sockopt_tproxy', s.sockopt_tproxy);
  setIfNonEmpty(v, 'sockopt_tcp_fast_open', s.sockopt_tcp_fast_open);
  setIfNonEmpty(v, 'sockopt_tcp_fast_open_queue_length', s.sockopt_tcp_fast_open_queue_length);
  setIfNonEmpty(v, 'sockopt_mptcp', s.sockopt_mptcp);
  setIfNonEmpty(v, 'sockopt_interface', s.sockopt_interface);
  setIfNonEmpty(v, 'sockopt_tcp_max_seg', s.sockopt_tcp_max_seg);
  setIfNonEmpty(v, 'sockopt_tcp_keepalive_idle', s.sockopt_tcp_keepalive_idle);
  setIfNonEmpty(v, 'sockopt_tcp_keepalive_interval', s.sockopt_tcp_keepalive_interval);
  setIfNonEmpty(v, 'sockopt_tcp_user_timeout', s.sockopt_tcp_user_timeout);
  setIfNonEmpty(v, 'sockopt_tcp_congestion', s.sockopt_tcp_congestion);
  setIfNonEmpty(v, 'sockopt_v6_only', s.sockopt_v6_only);
  setIfNonEmpty(v, 'sockopt_tcp_window_clamp', s.sockopt_tcp_window_clamp);
  setIfNonEmpty(v, 'sockopt_address_port_strategy', s.sockopt_address_port_strategy);
  setIfNonEmpty(v, 'sockopt_trusted_xff', s.sockopt_trusted_xff);
  setIfNonEmpty(v, 'sockopt_custom_json', s.sockopt_custom_json);
  setIfNonEmpty(v, 'sockopt_happy_eyeballs_try_delay_ms', s.sockopt_happy_eyeballs_try_delay_ms);
  setIfNonEmpty(v, 'sockopt_happy_eyeballs_prioritize_ipv6', s.sockopt_happy_eyeballs_prioritize_ipv6);
  setIfNonEmpty(v, 'sockopt_happy_eyeballs_interleave', s.sockopt_happy_eyeballs_interleave);
  setIfNonEmpty(v, 'sockopt_happy_eyeballs_max_concurrent_try', s.sockopt_happy_eyeballs_max_concurrent_try);
  setIfNonEmpty(v, 'domain_strategy', s.domain_strategy);
  setIfNonEmpty(v, 'dialer_proxy', s.dialer_proxy);
}

function parseStreamFields(s: Record<string, unknown>): StreamFields {
  return {
    transport: asStr(s.transport, 'raw'),
    security: asStr(s.security, 'none') as StreamFields['security'],
    tls_server_name: asStr(s.tls_server_name, ''),
    tls_allow_insecure: asBool(s.tls_allow_insecure, false),
    tls_alpn: asArray(s.tls_alpn),
    tls_fingerprint: asStr(s.tls_fingerprint, ''),
    tls_pinned_sha256: asArray(s.tls_pinned_sha256),
    tls_ech_config: asStr(s.tls_ech_config, ''),
    tls_ech_server_keys: asStr(s.tls_ech_server_keys, ''),
    tls_ech_sockopt_json: asStr(s.tls_ech_sockopt_json, ''),
    tls_verify_peer_name: asStr(s.tls_verify_peer_name, ''),
    tls_verify_client: asBool(s.tls_verify_client, false),
    tls_min_version: asStr(s.tls_min_version, ''),
    tls_max_version: asStr(s.tls_max_version, ''),
    tls_cipher_suites: asStr(s.tls_cipher_suites, ''),
    tls_reject_unknown_sni: asBool(s.tls_reject_unknown_sni, false),
    tls_use_system_ca: asBool(s.tls_use_system_ca, false),
    tls_disable_system_root: asBool(s.tls_disable_system_root, false),
    tls_enable_session_resumption: asBool(s.tls_enable_session_resumption, false),
    tls_curve_preferences: asArray(s.tls_curve_preferences),
    tls_cert_file: asStr(s.tls_cert_file, ''),
    tls_key_file: asStr(s.tls_key_file, ''),
    tls_certificates: parseJsonField(s.tls_certificates_json, []),
    reality_show: asBool(s.reality_show, false),
    reality_fingerprint: asStr(s.reality_fingerprint, ''),
    reality_server_name: asStr(s.reality_server_name, ''),
    reality_public_key: asStr(s.reality_public_key, ''),
    reality_short_id: asStr(s.reality_short_id, ''),
    reality_spider_x: asStr(s.reality_spider_x, ''),
    reality_mldsa65_verify: asStr(s.reality_mldsa65_verify, ''),
    reality_target: asStr(s.reality_target, ''),
    reality_xver: asOptNum(s.reality_xver),
    reality_server_names: asArray(s.reality_server_names),
    reality_private_key: asStr(s.reality_private_key, ''),
    reality_short_ids: asArray(s.reality_short_ids),
    reality_mldsa65_seed: asStr(s.reality_mldsa65_seed, ''),
    reality_min_client_ver: asStr(s.reality_min_client_ver, ''),
    reality_max_client_ver: asStr(s.reality_max_client_ver, ''),
    reality_max_time_diff: asOptNum(s.reality_max_time_diff),
    tcp_accept_proxy_protocol: asBool(s.tcp_accept_proxy_protocol, false),
    tcp_header_type: asStr(s.tcp_header_type, 'none') as 'none' | 'http',
    tcp_request_headers: parseJsonField(s.tcp_request_headers_json, []),
    tcp_response_headers: parseJsonField(s.tcp_response_headers_json, []),
    ws_path: asStr(s.ws_path, ''),
    ws_host: asStr(s.ws_host, ''),
    ws_headers: parseJsonField(s.ws_headers_json, []),
    ws_max_early_data: asOptNum(s.ws_max_early_data),
    ws_early_data_header: asStr(s.ws_early_data_header, ''),
    ws_heartbeat_period: asOptNum(s.ws_heartbeat_period),
    grpc_service_name: asStr(s.grpc_service_name, ''),
    grpc_authority: asStr(s.grpc_authority, ''),
    grpc_multi_mode: asBool(s.grpc_multi_mode, false),
    grpc_idle_timeout: asOptNum(s.grpc_idle_timeout),
    grpc_health_check_timeout: asOptNum(s.grpc_health_check_timeout),
    grpc_permit_without_stream: asBool(s.grpc_permit_without_stream, false),
    grpc_initial_windows_size: asOptNum(s.grpc_initial_windows_size),
    xhttp_path: asStr(s.xhttp_path, ''),
    xhttp_host: asStr(s.xhttp_host, ''),
    xhttp_mode: asStr(s.xhttp_mode, 'auto') as StreamFields['xhttp_mode'],
    xhttp_extra: asStr(s.xhttp_extra, ''),
    httpupgrade_path: asStr(s.httpupgrade_path, ''),
    httpupgrade_host: asStr(s.httpupgrade_host, ''),
    httpupgrade_headers: parseJsonField(s.httpupgrade_headers_json, []),
    h2_path: asStr(s.h2_path, ''),
    h2_host: asArray(s.h2_host),
    h2_method: asStr(s.h2_method, ''),
    h2_headers: parseJsonField(s.h2_headers_json, []),
    mkcp_mtu: asOptNum(s.mkcp_mtu),
    mkcp_tti: asOptNum(s.mkcp_tti),
    mkcp_uplink_capacity: asOptNum(s.mkcp_uplink_capacity),
    mkcp_downlink_capacity: asOptNum(s.mkcp_downlink_capacity),
    mkcp_congestion: asBool(s.mkcp_congestion, false),
    mkcp_seed: asStr(s.mkcp_seed, ''),
    mkcp_header_type: asStr(s.mkcp_header_type, ''),
    mkcp_cwnd_multiplier: asOptNum(s.mkcp_cwnd_multiplier),
    mkcp_max_sending_window: asOptNum(s.mkcp_max_sending_window),
    quic_security: asStr(s.quic_security, ''),
    quic_key: asStr(s.quic_key, ''),
    quic_header_type: asStr(s.quic_header_type, ''),
    ds_path: asStr(s.ds_path, ''),
    ds_abstract: asBool(s.ds_abstract, false),
    ds_padding: asBool(s.ds_padding, false),
    hysteria_auth: asStr(s.hysteria_auth, ''),
    hysteria_up_mbps: asOptNum(s.hysteria_up_mbps),
    hysteria_down_mbps: asOptNum(s.hysteria_down_mbps),
    hysteria_udp_extension: s.hysteria_udp_extension !== undefined ? asBool(s.hysteria_udp_extension, true) : undefined,
    hysteria_udp_idle_timeout: asOptNum(s.hysteria_udp_idle_timeout) ?? asStr(s.hysteria_udp_idle_timeout, ''),
    hysteria_masquerade: asStr(s.hysteria_masquerade, ''),
    hysteria_masquerade_type: asStr(s.hysteria_masquerade_type, '') as StreamFields['hysteria_masquerade_type'],
    hysteria_masquerade_dir: asStr(s.hysteria_masquerade_dir, ''),
    hysteria_masquerade_url: asStr(s.hysteria_masquerade_url, ''),
    hysteria_masquerade_rewrite_host: asBool(s.hysteria_masquerade_rewrite_host, false),
    hysteria_masquerade_insecure: asBool(s.hysteria_masquerade_insecure, false),
    hysteria_masquerade_content: asStr(s.hysteria_masquerade_content, ''),
    hysteria_masquerade_headers: parseJsonField(s.hysteria_masquerade_headers_json, []),
    hysteria_masquerade_status_code: asOptNum(s.hysteria_masquerade_status_code),
    hysteria_udphop_port: asStr(s.hysteria_udphop_port, ''),
    hysteria_udphop_interval: asOptNum(s.hysteria_udphop_interval),
    hysteria_obfs_password: asStr(s.hysteria_obfs_password, ''),
    masque_host: asStr(s.masque_host, ''),
    masque_path: asStr(s.masque_path, ''),
    masque_user: asStr(s.masque_user, ''),
    masque_pass: asStr(s.masque_pass, ''),
    masque_warp_json: asStr(s.masque_warp_json, ''),
    masque_uri: asStr(s.masque_uri, ''),
    masque_auth: asStr(s.masque_auth, ''),
    masque_headers: parseJsonField(s.masque_headers_json, []),
    finalmask_json: asStr(s.finalmask_json, ''),
    sockopt_mark: asOptNum(s.sockopt_mark),
    sockopt_tproxy: asStr(s.sockopt_tproxy, 'off') as StreamFields['sockopt_tproxy'],
    sockopt_tcp_fast_open: asBool(s.sockopt_tcp_fast_open, false),
    sockopt_tcp_fast_open_queue_length: asOptNum(s.sockopt_tcp_fast_open_queue_length),
    sockopt_mptcp: asBool(s.sockopt_mptcp, false),
    sockopt_interface: asStr(s.sockopt_interface, ''),
    sockopt_tcp_max_seg: asOptNum(s.sockopt_tcp_max_seg),
    sockopt_tcp_keepalive_idle: asOptNum(s.sockopt_tcp_keepalive_idle),
    sockopt_tcp_keepalive_interval: asOptNum(s.sockopt_tcp_keepalive_interval),
    sockopt_tcp_user_timeout: asOptNum(s.sockopt_tcp_user_timeout),
    sockopt_tcp_congestion: asStr(s.sockopt_tcp_congestion, ''),
    sockopt_v6_only: asBool(s.sockopt_v6_only, false),
    sockopt_tcp_window_clamp: asOptNum(s.sockopt_tcp_window_clamp),
    sockopt_address_port_strategy: asStr(s.sockopt_address_port_strategy, ''),
    sockopt_trusted_xff: asArray(s.sockopt_trusted_xff),
    sockopt_custom_json: asStr(s.sockopt_custom_json, ''),
    sockopt_happy_eyeballs_try_delay_ms: asOptNum(s.sockopt_happy_eyeballs_try_delay_ms),
    sockopt_happy_eyeballs_prioritize_ipv6: asBool(s.sockopt_happy_eyeballs_prioritize_ipv6, false),
    sockopt_happy_eyeballs_interleave: asOptNum(s.sockopt_happy_eyeballs_interleave),
    sockopt_happy_eyeballs_max_concurrent_try: asOptNum(s.sockopt_happy_eyeballs_max_concurrent_try),
    domain_strategy: asStr(s.domain_strategy, ''),
    dialer_proxy: asStr(s.dialer_proxy, '')
  };
}

export function serializeConfigToUci(cfg: AiosConfig): UciSectionPayload[] {
  const sections: UciSectionPayload[] = [];

  // 1. general
  const g = cfg.general;
  const gVals: Record<string, string | string[]> = {};
  setIfNonEmpty(gVals, 'schema_version', g.schema_version ?? CURRENT_SCHEMA_VERSION);
  setIfNonEmpty(gVals, 'enabled', g.enabled);
  setIfNonEmpty(gVals, 'core_type', g.core_type);
  setIfNonEmpty(gVals, 'core_bin', g.core_bin);
  setIfNonEmpty(gVals, 'bins_dir', g.bins_dir);
  setIfNonEmpty(gVals, 'target_version', g.target_version || 'auto');
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
  setJsonIfNonEmpty(gVals, 'inline_env_json', g.inline_env);
  const rawCron = (g.geodata_cron || '').trim() ||
    ((g.geodata_reload_interval || '').trim().split(/\s+/).filter(Boolean).length === 5
      ? (g.geodata_reload_interval || '').trim()
      : '');
  setIfNonEmpty(gVals, 'geodata_cron', rawCron);
  setIfNonEmpty(gVals, 'geodata_outbound', g.geodata_outbound);
  setIfNonEmpty(gVals, 'geodata_assets_json', g.geodata_assets_json);
  setIfNonEmpty(gVals, 'min_version', g.min_version);
  setIfNonEmpty(gVals, 'max_version', g.max_version);
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
    setIfNonEmpty(v, 'socks_auth', ib.socks_auth);
    setIfNonEmpty(v, 'socks_udp', ib.socks_udp);
    setIfNonEmpty(v, 'socks_ip', ib.socks_ip);
    setIfNonEmpty(v, 'http_allow_transparent', ib.http_allow_transparent);
    setIfNonEmpty(v, 'http_timeout', ib.http_timeout);
    setIfNonEmpty(v, 'packet_encoding', ib.packet_encoding);
    setIfNonEmpty(v, 'username', ib.username);
    setIfNonEmpty(v, 'password', ib.password);
    setIfNonEmpty(v, 'dokodemo_network', ib.dokodemo_network);
    setIfNonEmpty(v, 'dokodemo_address', ib.dokodemo_address);
    setIfNonEmpty(v, 'dokodemo_port', ib.dokodemo_port);
    setIfNonEmpty(v, 'dokodemo_follow_redirect', ib.dokodemo_follow_redirect);
    setJsonIfNonEmpty(v, 'tunnel_port_map_json', ib.tunnel_port_map);
    setIfNonEmpty(v, 'tunnel_user_level', ib.tunnel_user_level);
    setIfNonEmpty(v, 'uuid', ib.uuid);
    setIfNonEmpty(v, 'flow', ib.flow);
    setIfNonEmpty(v, 'decryption', ib.decryption);
    setIfNonEmpty(v, 'alter_id', ib.alter_id);
    setIfNonEmpty(v, 'method', ib.method);
    setIfNonEmpty(v, 'ss_network', ib.ss_network);
    setIfNonEmpty(v, 'wg_secret_key', ib.wg_secret_key);
    setIfNonEmpty(v, 'wg_address', ib.wg_address);
    setIfNonEmpty(v, 'wg_mtu', ib.wg_mtu);
    setJsonIfNonEmpty(v, 'wg_peers_json', ib.wg_peers);
    setIfNonEmpty(v, 'masque_address', ib.masque_address);
    setIfNonEmpty(v, 'masque_mtu', ib.masque_mtu);
    setIfNonEmpty(v, 'tun_name', ib.tun_name);
    setIfNonEmpty(v, 'tun_desc', ib.tun_desc);
    setIfNonEmpty(v, 'tun_mtu', ib.tun_mtu);
    setIfNonEmpty(v, 'tun_gateway', ib.tun_gateway);
    setIfNonEmpty(v, 'tun_dns', ib.tun_dns);
    setIfNonEmpty(v, 'tun_user_level', ib.tun_user_level);
    setIfNonEmpty(v, 'tun_auto_routing_table', ib.tun_auto_routing_table);
    setIfNonEmpty(v, 'tun_auto_outbounds_interface', ib.tun_auto_outbounds_interface);
    setIfNonEmpty(v, 'tun_auto_dns_to_gateway', ib.tun_auto_dns_to_gateway);
    setIfNonEmpty(v, 'tun_auto_wfp_block_leak', ib.tun_auto_wfp_block_leak);
    setIfNonEmpty(v, 'tun_ips', ib.tun_ips);
    setIfNonEmpty(v, 'tun_routes', ib.tun_routes);
    setIfNonEmpty(v, 'tun_promiscuous', ib.tun_promiscuous);
    setIfNonEmpty(v, 'tun_spoofing', ib.tun_spoofing);
    setIfNonEmpty(v, 'sniffing_enabled', ib.sniffing_enabled);
    setIfNonEmpty(v, 'sniffing_dest_override', ib.sniffing_dest_override);
    setIfNonEmpty(v, 'sniffing_domains_excluded', ib.sniffing_domains_excluded);
    setIfNonEmpty(v, 'sniffing_ips_excluded', ib.sniffing_ips_excluded);
    setIfNonEmpty(v, 'sniffing_metadata_only', ib.sniffing_metadata_only);
    setIfNonEmpty(v, 'sniffing_route_only', ib.sniffing_route_only);
    setIfNonEmpty(v, 'allocate_strategy', ib.allocate_strategy);
    setIfNonEmpty(v, 'allocate_refresh', ib.allocate_refresh);
    setIfNonEmpty(v, 'allocate_concurrency', ib.allocate_concurrency);
    setIfNonEmpty(v, 'custom_config', ib.custom_config);
    setJsonIfNonEmpty(v, 'users_json', ib.users);
    setJsonIfNonEmpty(v, 'fallbacks_json', ib.fallbacks);
    serializeStreamFields(v, ib);
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
    setIfNonEmpty(v, 'target_strategy', ob.target_strategy);
    setIfNonEmpty(v, 'address', ob.address);
    setIfNonEmpty(v, 'port', ob.port);
    setIfNonEmpty(v, 'email', ob.email);
    setIfNonEmpty(v, 'user_level', ob.user_level);
    setIfNonEmpty(v, 'uuid', ob.uuid);
    setIfNonEmpty(v, 'encryption', ob.encryption);
    setIfNonEmpty(v, 'flow', ob.flow);
    setIfNonEmpty(v, 'vless_reverse_tag', ob.vless_reverse_tag);
    setIfNonEmpty(v, 'alter_id', ob.alter_id);
    setIfNonEmpty(v, 'security_cipher', ob.security_cipher);
    setIfNonEmpty(v, 'vmess_experiments', ob.vmess_experiments);
    setIfNonEmpty(v, 'password', ob.password);
    setIfNonEmpty(v, 'method', ob.method);
    setIfNonEmpty(v, 'ss_uot', ob.ss_uot);
    setIfNonEmpty(v, 'ss_uot_version', ob.ss_uot_version);
    setIfNonEmpty(v, 'ss_iv_check', ob.ss_iv_check);
    setIfNonEmpty(v, 'ss_ipsk', ob.ss_ipsk);
    setIfNonEmpty(v, 'socks_version', ob.socks_version);
    setIfNonEmpty(v, 'username', ob.username);
    setJsonIfNonEmpty(v, 'http_headers_json', ob.http_headers);
    setIfNonEmpty(v, 'freedom_redirect', ob.freedom_redirect);
    setIfNonEmpty(v, 'freedom_proxy_protocol', ob.freedom_proxy_protocol);
    setIfNonEmpty(v, 'freedom_final_rules_json', ob.freedom_final_rules_json);
    setIfNonEmpty(v, 'blackhole_response', ob.blackhole_response);
    setIfNonEmpty(v, 'dns_network', ob.dns_network);
    setIfNonEmpty(v, 'dns_address', ob.dns_address);
    setIfNonEmpty(v, 'dns_port', ob.dns_port);
    setIfNonEmpty(v, 'dns_non_ip_query', ob.dns_non_ip_query);
    setIfNonEmpty(v, 'dns_rules_json', ob.dns_rules_json);
    setIfNonEmpty(v, 'loopback_inbound_tag', ob.loopback_inbound_tag);
    setIfNonEmpty(v, 'loopback_sniffing_enabled', ob.loopback_sniffing_enabled);
    setIfNonEmpty(v, 'loopback_sniffing_dest_override', ob.loopback_sniffing_dest_override);
    setIfNonEmpty(v, 'loopback_sniffing_domains_excluded', ob.loopback_sniffing_domains_excluded);
    setIfNonEmpty(v, 'loopback_sniffing_ips_excluded', ob.loopback_sniffing_ips_excluded);
    setIfNonEmpty(v, 'loopback_sniffing_metadata_only', ob.loopback_sniffing_metadata_only);
    setIfNonEmpty(v, 'loopback_sniffing_route_only', ob.loopback_sniffing_route_only);
    setIfNonEmpty(v, 'wg_secret_key', ob.wg_secret_key);
    setIfNonEmpty(v, 'wg_address', ob.wg_address);
    setIfNonEmpty(v, 'wg_reserved', ob.wg_reserved);
    setIfNonEmpty(v, 'wg_remote_dns', ob.wg_remote_dns);
    setIfNonEmpty(v, 'wg_mtu', ob.wg_mtu);
    setIfNonEmpty(v, 'wg_no_kernel_tun', ob.wg_no_kernel_tun);
    setIfNonEmpty(v, 'wg_peer_public_key', ob.wg_peer_public_key);
    setIfNonEmpty(v, 'wg_endpoint', ob.wg_endpoint);
    setJsonIfNonEmpty(v, 'wg_peers_json', ob.wg_peers);
    setIfNonEmpty(v, 'masque_remote_dns', ob.masque_remote_dns);
    setIfNonEmpty(v, 'mux_enabled', ob.mux_enabled);
    setIfNonEmpty(v, 'mux_concurrency', ob.mux_concurrency);
    setIfNonEmpty(v, 'mux_xudp_concurrency', ob.mux_xudp_concurrency);
    setIfNonEmpty(v, 'mux_xudp_proxy_udp443', ob.mux_xudp_proxy_udp443);
    setIfNonEmpty(v, 'custom_config', ob.custom_config);
    serializeStreamFields(v, ob);
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
  setIfNonEmpty(dVals, 'script', d.script);
  setIfNonEmpty(dVals, 'serve_expired_ttl', d.serve_expired_ttl);
  setIfNonEmpty(dVals, 'use_system_hosts', d.use_system_hosts);
  setIfNonEmpty(dVals, 'client_ip', d.client_ip);
  setJsonIfNonEmpty(dVals, 'hosts_json', d.hosts);
  setJsonIfNonEmpty(dVals, 'host_entries_json', d.host_entries);
  sections.push({ type: 'dns', name: 'main_dns', values: dVals });

  cfg.dns_servers.forEach((s, idx) => {
    const v: Record<string, string | string[]> = {};
    setIfNonEmpty(v, 'server_id', s.server_id);
    setIfNonEmpty(v, 'enabled', s.enabled);
    setIfNonEmpty(v, 'alias', s.alias);
    setIfNonEmpty(v, 'address', s.address);
    setIfNonEmpty(v, 'port', s.port);
    setIfNonEmpty(v, 'skip_fallback', s.skip_fallback);
    setIfNonEmpty(v, 'final_query', s.final_query);
    setIfNonEmpty(v, 'timeout_ms', s.timeout_ms);
    setIfNonEmpty(v, 'domains', s.domains);
    setIfNonEmpty(v, 'expect_ips', s.expect_ips);
    setIfNonEmpty(v, 'unexpected_ips', s.unexpected_ips);
    setIfNonEmpty(v, 'client_ip', s.client_ip);
    setIfNonEmpty(v, 'query_strategy', s.query_strategy);
    setIfNonEmpty(v, 'disable_cache', s.disable_cache);
    setIfNonEmpty(v, 'serve_stale', s.serve_stale);
    setIfNonEmpty(v, 'serve_expired_ttl', s.serve_expired_ttl);
    setIfNonEmpty(v, 'tag', s.tag);
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
  const rVals: Record<string, string | string[]> = {
    enabled: boolStr(cfg.routing.enabled),
    domain_strategy: cfg.routing.domain_strategy,
    domain_matcher: cfg.routing.domain_matcher
  };
  setIfNonEmpty(rVals, 'script', cfg.routing.script);
  sections.push({
    type: 'routing',
    name: 'main_routing',
    values: rVals
  });

  cfg.routing_rules.forEach((r, idx) => {
    const v: Record<string, string | string[]> = {};
    setIfNonEmpty(v, 'enabled', r.enabled);
    setIfNonEmpty(v, 'alias', r.alias);
    setIfNonEmpty(v, 'domain', r.domain);
    setIfNonEmpty(v, 'ip', r.ip);
    setIfNonEmpty(v, 'port', r.port);
    setIfNonEmpty(v, 'source_port', r.source_port);
    setIfNonEmpty(v, 'local_port', r.local_port);
    setIfNonEmpty(v, 'network', r.network);
    setIfNonEmpty(v, 'source', r.source);
    setIfNonEmpty(v, 'local_ip', r.local_ip);
    setIfNonEmpty(v, 'user', r.user);
    setIfNonEmpty(v, 'inbound_tag', r.inbound_tag);
    setIfNonEmpty(v, 'protocol', r.protocol);
    setIfNonEmpty(v, 'process', r.process);
    setIfNonEmpty(v, 'vless_route', r.vless_route);
    setIfNonEmpty(v, 'rule_tag', r.rule_tag);
    setIfNonEmpty(v, 'webhook_url', r.webhook_url);
    setIfNonEmpty(v, 'webhook_deduplication', r.webhook_deduplication);
    setJsonIfNonEmpty(v, 'webhook_headers_json', r.webhook_headers);
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
    setIfNonEmpty(v, 'strategy_expected', b.strategy_expected);
    setIfNonEmpty(v, 'strategy_max_rtt', b.strategy_max_rtt);
    setIfNonEmpty(v, 'strategy_tolerance', b.strategy_tolerance);
    setIfNonEmpty(v, 'strategy_baselines', b.strategy_baselines);
    setIfNonEmpty(v, 'strategy_costs_json', b.strategy_costs_json);
    sections.push({ type: 'routing_balancer', name: sanitizeUciName(b.id, 'bal', idx), values: v });
  });

  // 6. observatory, burst_observatory, browser_forwarder, policy, reverse
  const obsVals: Record<string, string | string[]> = {
    enabled: boolStr(cfg.observatory.enabled),
    probe_url: cfg.observatory.probe_url,
    probe_interval: cfg.observatory.probe_interval,
    enable_concurrency: boolStr(cfg.observatory.enable_concurrency)
  };
  setIfNonEmpty(obsVals, 'subject_selector', cfg.observatory.subject_selector);
  sections.push({ type: 'observatory', name: 'main_observatory', values: obsVals });

  if (cfg.burst_observatory) {
    const bo = cfg.burst_observatory;
    const boVals: Record<string, string | string[]> = {
      enabled: boolStr(bo.enabled),
      destination: bo.destination,
      interval: bo.interval,
      sampling: String(bo.sampling),
      timeout: bo.timeout
    };
    setIfNonEmpty(boVals, 'connectivity', bo.connectivity);
    setIfNonEmpty(boVals, 'subject_selector', bo.subject_selector);
    sections.push({ type: 'burst_observatory', name: 'main_burst_observatory', values: boVals });
  }

  if (cfg.browser_forwarder) {
    sections.push({
      type: 'browser_forwarder',
      name: 'main_browser_forwarder',
      values: {
        enabled: boolStr(cfg.browser_forwarder.enabled),
        listen_addr: cfg.browser_forwarder.listen_addr,
        listen_port: String(cfg.browser_forwarder.listen_port)
      }
    });
  }

  const pVals: Record<string, string | string[]> = {
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
  };
  setJsonIfNonEmpty(pVals, 'policy_levels_json', cfg.policy.levels);
  sections.push({ type: 'policy', name: 'main_policy', values: pVals });

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

  // Deduplicate section names & avoid collisions with reserved singleton section names
  const RESERVED_NAMES = new Set([
    'main',
    'main_dns',
    'main_routing',
    'main_observatory',
    'main_burst_observatory',
    'main_policy',
    'main_reverse',
    'main_browser_forwarder',
    'main_tproxy'
  ]);
  const usedNames = new Set<string>();
  const deduped = sections.map((sec) => {
    const isSingleton = [
      'general',
      'dns',
      'routing',
      'observatory',
      'burst_observatory',
      'policy',
      'reverse',
      'browser_forwarder',
      'transparent_proxy'
    ].includes(sec.type);
    let candidate = sec.name;
    if (!isSingleton && RESERVED_NAMES.has(candidate)) {
      candidate = `${sec.type}_${candidate}`;
    }
    if (usedNames.has(candidate)) {
      let n = 2;
      while (usedNames.has(`${candidate}_${n}`)) n++;
      candidate = `${candidate}_${n}`;
    }
    usedNames.add(candidate);
    return candidate === sec.name ? sec : { ...sec, name: candidate };
  });

  return deduped;
}

export function parseUciDump(raw: UciRawDump): AiosConfig {
  const def = createDefaultConfig();
  const ordered = Object.values(raw).sort(
    (a, b) => asNum(a['.index'], 0) - asNum(b['.index'], 0)
  );

  let hasMain = false;
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
      hasMain = true;
      def.general = {
        ...def.general,
        schema_version: asNum(s.schema_version, CURRENT_SCHEMA_VERSION),
        enabled: asBool(s.enabled, def.general.enabled),
        core_type: asStr(s.core_type, def.general.core_type) as AiosConfig['general']['core_type'],
        core_bin: asStr(s.core_bin, def.general.core_bin),
        bins_dir: asStr(s.bins_dir, ''),
        target_version: asStr(s.target_version, 'auto'),
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
        custom_configuration_hook: asStr(s.custom_configuration_hook, ''),
        inline_env: parseJsonField(s.inline_env_json, []),
        geodata_cron: asStr(
          s.geodata_cron,
          asStr(s.geodata_reload_interval, '').trim().split(/\s+/).filter(Boolean).length === 5
            ? asStr(s.geodata_reload_interval, '')
            : ''
        ),
        geodata_outbound: asStr(s.geodata_outbound, ''),
        geodata_assets_json: asStr(s.geodata_assets_json, ''),
        min_version: asStr(s.min_version, ''),
        max_version: asStr(s.max_version, '')
      };
    } else if (type === 'inbound') {
      inbounds.push({
        ...parseStreamFields(s),
        id: name,
        enabled: asBool(s.enabled, true),
        alias: asStr(s.alias, name),
        tag: asStr(s.tag, name),
        listen: asStr(s.listen, '0.0.0.0'),
        port: asNum(s.port, 1080),
        protocol: asStr(s.protocol, 'socks'),
        use_tunnel: asBool(s.use_tunnel, false),
        socks_auth: asStr(s.socks_auth, 'noauth') as 'noauth' | 'password',
        socks_udp: asBool(s.socks_udp, true),
        socks_ip: asStr(s.socks_ip, ''),
        http_allow_transparent: asBool(s.http_allow_transparent, false),
        http_timeout: asOptNum(s.http_timeout),
        packet_encoding: asStr(s.packet_encoding, '') as InboundConfig['packet_encoding'],
        username: asStr(s.username, ''),
        password: asStr(s.password, ''),
        dokodemo_network: asStr(s.dokodemo_network, 'tcp,udp'),
        dokodemo_address: asStr(s.dokodemo_address, ''),
        dokodemo_port: asOptNum(s.dokodemo_port),
        dokodemo_follow_redirect: asBool(s.dokodemo_follow_redirect, false),
        tunnel_port_map: parseJsonField(s.tunnel_port_map_json, []),
        tunnel_user_level: asOptNum(s.tunnel_user_level),
        uuid: asStr(s.uuid, ''),
        flow: asStr(s.flow, ''),
        decryption: asStr(s.decryption, 'none'),
        alter_id: asNum(s.alter_id, 0),
        method: asStr(s.method, ''),
        ss_network: asStr(s.ss_network, 'tcp,udp'),
        wg_secret_key: asStr(s.wg_secret_key, ''),
        wg_address: asArray(s.wg_address),
        wg_mtu: asOptNum(s.wg_mtu),
        wg_peers: parseJsonField(s.wg_peers_json, []),
        masque_address: asArray(s.masque_address),
        masque_mtu: asOptNum(s.masque_mtu),
        tun_name: asStr(s.tun_name, ''),
        tun_desc: asStr(s.tun_desc, ''),
        tun_mtu: asOptNum(s.tun_mtu),
        tun_gateway: asArray(s.tun_gateway),
        tun_dns: asArray(s.tun_dns),
        tun_user_level: asOptNum(s.tun_user_level),
        tun_auto_routing_table: asArray(s.tun_auto_routing_table),
        tun_auto_outbounds_interface: asStr(s.tun_auto_outbounds_interface, ''),
        tun_auto_dns_to_gateway: asBool(s.tun_auto_dns_to_gateway, false),
        tun_auto_wfp_block_leak: asArray(s.tun_auto_wfp_block_leak),
        tun_ips: asArray(s.tun_ips),
        tun_routes: asArray(s.tun_routes),
        tun_promiscuous: s.tun_promiscuous !== undefined ? asBool(s.tun_promiscuous, true) : undefined,
        tun_spoofing: s.tun_spoofing !== undefined ? asBool(s.tun_spoofing, true) : undefined,
        sniffing_enabled: asBool(s.sniffing_enabled, false),
        sniffing_dest_override: asArray(s.sniffing_dest_override),
        sniffing_domains_excluded: asArray(s.sniffing_domains_excluded),
        sniffing_ips_excluded: asArray(s.sniffing_ips_excluded),
        sniffing_metadata_only: asBool(s.sniffing_metadata_only, false),
        sniffing_route_only: asBool(s.sniffing_route_only, false),
        allocate_strategy: asStr(s.allocate_strategy, '') as '' | 'always' | 'random',
        allocate_refresh: asOptNum(s.allocate_refresh),
        allocate_concurrency: asOptNum(s.allocate_concurrency),
        custom_config: asStr(s.custom_config, ''),
        users: parseJsonField(s.users_json, []),
        fallbacks: parseJsonField(s.fallbacks_json, [])
      });
    } else if (type === 'outbound') {
      outbounds.push({
        ...parseStreamFields(s),
        id: name,
        enabled: asBool(s.enabled, true),
        alias: asStr(s.alias, name),
        tag: asStr(s.tag, name),
        protocol: asStr(s.protocol, 'freedom'),
        send_through: asStr(s.send_through, ''),
        target_strategy: asStr(s.target_strategy, ''),
        address: asStr(s.address, ''),
        port: asOptNum(s.port),
        email: asStr(s.email, ''),
        user_level: asOptNum(s.user_level),
        uuid: asStr(s.uuid, ''),
        encryption: asStr(s.encryption, 'none'),
        flow: asStr(s.flow, ''),
        vless_reverse_tag: asStr(s.vless_reverse_tag, ''),
        alter_id: asNum(s.alter_id, 0),
        security_cipher: asStr(s.security_cipher, 'auto'),
        vmess_experiments: asStr(s.vmess_experiments, ''),
        password: asStr(s.password, ''),
        method: asStr(s.method, ''),
        ss_uot: asBool(s.ss_uot, false),
        ss_uot_version: asOptNum(s.ss_uot_version),
        ss_iv_check: asBool(s.ss_iv_check, false),
        ss_ipsk: asArray(s.ss_ipsk),
        socks_version: asStr(s.socks_version, '5') as OutboundConfig['socks_version'],
        username: asStr(s.username, ''),
        http_headers: parseJsonField(s.http_headers_json, []),
        freedom_redirect: asStr(s.freedom_redirect, ''),
        freedom_proxy_protocol: asOptNum(s.freedom_proxy_protocol),
        freedom_final_rules_json: asStr(s.freedom_final_rules_json, ''),
        blackhole_response: asStr(s.blackhole_response, 'none') as 'none' | 'http',
        dns_network: asStr(s.dns_network, ''),
        dns_address: asStr(s.dns_address, ''),
        dns_port: asOptNum(s.dns_port),
        dns_non_ip_query: asStr(s.dns_non_ip_query, '') as '' | 'skip' | 'drop',
        dns_rules_json: asStr(s.dns_rules_json, ''),
        loopback_inbound_tag: asStr(s.loopback_inbound_tag, ''),
        loopback_sniffing_enabled: asBool(s.loopback_sniffing_enabled, false),
        loopback_sniffing_dest_override: asArray(s.loopback_sniffing_dest_override),
        loopback_sniffing_domains_excluded: asArray(s.loopback_sniffing_domains_excluded),
        loopback_sniffing_ips_excluded: asArray(s.loopback_sniffing_ips_excluded),
        loopback_sniffing_metadata_only: asBool(s.loopback_sniffing_metadata_only, false),
        loopback_sniffing_route_only: asBool(s.loopback_sniffing_route_only, false),
        wg_secret_key: asStr(s.wg_secret_key, ''),
        wg_address: asArray(s.wg_address),
        wg_reserved: asArray(s.wg_reserved),
        wg_remote_dns: asArray(s.wg_remote_dns),
        wg_mtu: asOptNum(s.wg_mtu),
        wg_no_kernel_tun: asBool(s.wg_no_kernel_tun, false),
        wg_peer_public_key: asStr(s.wg_peer_public_key, ''),
        wg_endpoint: asStr(s.wg_endpoint, ''),
        wg_peers: parseJsonField(s.wg_peers_json, []),
        masque_remote_dns: asArray(s.masque_remote_dns),
        mux_enabled: asBool(s.mux_enabled, false),
        mux_concurrency: asOptNum(s.mux_concurrency),
        mux_xudp_concurrency: asOptNum(s.mux_xudp_concurrency),
        mux_xudp_proxy_udp443: asStr(s.mux_xudp_proxy_udp443, '') as OutboundConfig['mux_xudp_proxy_udp443'],
        custom_config: asStr(s.custom_config, '')
      });
    } else if (type === 'dns') {
      def.dns = {
        ...def.dns,
        enabled: asBool(s.enabled, true),
        tag: asStr(s.tag, 'dns-in'),
        script: asStr(s.script, ''),
        query_strategy: asStr(s.query_strategy, 'UseIP') as AiosConfig['dns']['query_strategy'],
        disable_cache: asBool(s.disable_cache, false),
        disable_fallback: asBool(s.disable_fallback, false),
        disable_fallback_if_match: asBool(s.disable_fallback_if_match, false),
        serve_stale: asBool(s.serve_stale, false),
        serve_expired_ttl: asOptNum(s.serve_expired_ttl),
        enable_parallel_query: asBool(s.enable_parallel_query, false),
        use_system_hosts: asBool(s.use_system_hosts, false),
        client_ip: asStr(s.client_ip, ''),
        hosts: parseJsonField(s.hosts_json, {}),
        host_entries: parseJsonField(s.host_entries_json, [])
      };
    } else if (type === 'dns_server') {
      dnsServers.push({
        id: name,
        server_id: asStr(s.server_id, ''),
        enabled: asBool(s.enabled, true),
        alias: asStr(s.alias, name),
        address: asStr(s.address, ''),
        port: asOptNum(s.port),
        skip_fallback: asBool(s.skip_fallback, false),
        final_query: asBool(s.final_query, false),
        timeout_ms: asOptNum(s.timeout_ms),
        domains: asArray(s.domains),
        expect_ips: asArray(s.expect_ips),
        unexpected_ips: asArray(s.unexpected_ips),
        client_ip: asStr(s.client_ip, ''),
        query_strategy: asStr(s.query_strategy, '') as DnsServerConfig['query_strategy'],
        disable_cache: asBool(s.disable_cache, false),
        serve_stale: asBool(s.serve_stale, false),
        serve_expired_ttl: asOptNum(s.serve_expired_ttl),
        tag: asStr(s.tag, '')
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
        script: asStr(s.script, ''),
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
        local_port: asStr(s.local_port, ''),
        network: asStr(s.network, '') as RoutingRuleConfig['network'],
        source: asArray(s.source),
        local_ip: asArray(s.local_ip),
        user: asArray(s.user),
        inbound_tag: asArray(s.inbound_tag),
        protocol: asArray(s.protocol),
        process: asArray(s.process),
        vless_route: asStr(s.vless_route, ''),
        rule_tag: asStr(s.rule_tag, ''),
        webhook_url: asStr(s.webhook_url, ''),
        webhook_deduplication: asOptNum(s.webhook_deduplication),
        webhook_headers: parseJsonField(s.webhook_headers_json, []),
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
        fallback_tag: asStr(s.fallback_tag, ''),
        strategy_expected: asOptNum(s.strategy_expected),
        strategy_max_rtt: asStr(s.strategy_max_rtt, ''),
        strategy_tolerance: asOptNum(s.strategy_tolerance),
        strategy_baselines: asArray(s.strategy_baselines),
        strategy_costs_json: asStr(s.strategy_costs_json, '')
      });
    } else if (type === 'observatory') {
      def.observatory = {
        enabled: asBool(s.enabled, false),
        subject_selector: asArray(s.subject_selector),
        probe_url: asStr(s.probe_url, 'https://www.google.com/generate_204'),
        probe_interval: asStr(s.probe_interval, '1m'),
        enable_concurrency: asBool(s.enable_concurrency, false)
      };
    } else if (type === 'burst_observatory') {
      def.burst_observatory = {
        enabled: asBool(s.enabled, false),
        subject_selector: asArray(s.subject_selector),
        destination: asStr(s.destination, 'https://www.google.com/generate_204'),
        connectivity: asStr(s.connectivity, ''),
        interval: asStr(s.interval, '1m'),
        sampling: asNum(s.sampling, 3),
        timeout: asStr(s.timeout, '5s')
      };
    } else if (type === 'browser_forwarder') {
      def.browser_forwarder = {
        enabled: asBool(s.enabled, false),
        listen_addr: asStr(s.listen_addr, '127.0.0.1'),
        listen_port: asNum(s.listen_port, 8088)
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
        stats_outbound_downlink: asBool(s.stats_outbound_downlink, true),
        levels: parseJsonField(s.policy_levels_json, [])
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

  if (hasMain) {
    def.inbounds = inbounds;
    def.outbounds = outbounds;
    def.dns_servers = dnsServers;
    def.routing_rules = routingRules;
  } else {
    if (inbounds.length > 0) def.inbounds = inbounds;
    if (outbounds.length > 0) def.outbounds = outbounds;
    if (dnsServers.length > 0) def.dns_servers = dnsServers;
    if (routingRules.length > 0) def.routing_rules = routingRules;
  }
  def.fakedns = fakedns;
  def.balancers = balancers;
  def.lan_hosts = lanHosts;

  return def;
}
