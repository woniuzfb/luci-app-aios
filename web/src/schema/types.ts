export type CoreType = 'xray' | 'v2ray';
export type CoreSelection = 'auto' | CoreType;
export type FirewallBackend = 'auto' | 'nftables' | 'iptables' | 'none';
export type ConflictPolicy = 'warn' | 'block' | 'ignore';

export interface KeyValuePair {
  key: string;
  value: string;
}

export interface GeneralConfig {
  enabled: boolean;
  core_type: CoreSelection;
  core_bin: string;
  bins_dir?: string;
  target_version?: string;
  v2ray_format: 'jsonv4' | 'jsonv5';
  asset_location: string;
  geoloader: 'memconservative' | 'standard';
  go_memlimit: string;
  rlimit_nofile: string;
  rlimit_data: string;
  config_file: string;
  log_level: 'debug' | 'info' | 'warning' | 'error' | 'none';
  access_log: string;
  error_log: string;
  dns_log: boolean;
  mask_address: '' | 'quarter' | 'half' | 'full';
  stats_enabled: boolean;
  api_enabled: boolean;
  api_port: number;
  metrics_enabled: boolean;
  metrics_port: number;
  conflict_policy: ConflictPolicy;
  custom_configuration_hook: string;
  // Xray top-level extensions
  inline_env?: KeyValuePair[];
  geodata_cron?: string;
  geodata_outbound?: string;
  geodata_assets_json?: string;
  /** @deprecated Legacy alias; prefer geodata_cron */
  geodata_reload_interval?: string;
  min_version?: string;
  max_version?: string;
}

export interface TlsCertificate {
  certificateFile: string;
  keyFile: string;
  usage?: 'encipherment' | 'verify' | 'issue' | 'verifyclient';
}

export interface FallbackItem {
  name?: string;
  alpn?: string;
  path?: string;
  dest: string;
  xver?: number;
}

export interface InboundUser {
  id?: string;
  password?: string;
  username?: string;
  auth?: string;
  flow?: string;
  alterId?: number;
  email?: string;
  level?: number;
}

export interface WireguardPeer {
  publicKey: string;
  preSharedKey?: string;
  endpoint: string;
  allowedIPs?: string[];
  keepAlive?: number;
}

export interface StreamFields {
  transport: string;
  security: 'none' | 'tls' | 'reality' | 'utls';
  // TLS
  tls_server_name?: string;
  tls_allow_insecure?: boolean;
  tls_alpn?: string[];
  tls_fingerprint?: string;
  tls_pinned_sha256?: string[];
  tls_ech_config?: string;
  tls_ech_server_keys?: string;
  tls_ech_sockopt_json?: string;
  tls_verify_peer_name?: string;
  tls_verify_client?: boolean;
  tls_min_version?: string;
  tls_max_version?: string;
  tls_cipher_suites?: string;
  tls_reject_unknown_sni?: boolean;
  tls_use_system_ca?: boolean;
  tls_disable_system_root?: boolean;
  tls_enable_session_resumption?: boolean;
  tls_curve_preferences?: string[];
  tls_certificates?: TlsCertificate[];
  tls_cert_file?: string;
  tls_key_file?: string;
  // REALITY (Xray)
  reality_show?: boolean;
  reality_fingerprint?: string;
  reality_server_name?: string;
  reality_public_key?: string;
  reality_short_id?: string;
  reality_spider_x?: string;
  reality_mldsa65_verify?: string;
  reality_target?: string;
  reality_xver?: number;
  reality_server_names?: string[];
  reality_private_key?: string;
  reality_short_ids?: string[];
  reality_mldsa65_seed?: string;
  reality_min_client_ver?: string;
  reality_max_client_ver?: string;
  reality_max_time_diff?: number;
  // Transport specifics
  tcp_accept_proxy_protocol?: boolean;
  tcp_header_type?: 'none' | 'http';
  tcp_request_headers?: KeyValuePair[];
  tcp_response_headers?: KeyValuePair[];
  ws_path?: string;
  ws_host?: string;
  ws_headers?: KeyValuePair[];
  ws_max_early_data?: number;
  ws_early_data_header?: string;
  ws_heartbeat_period?: number;
  grpc_service_name?: string;
  grpc_authority?: string;
  grpc_multi_mode?: boolean;
  grpc_idle_timeout?: number;
  grpc_health_check_timeout?: number;
  grpc_permit_without_stream?: boolean;
  grpc_initial_windows_size?: number;
  xhttp_path?: string;
  xhttp_host?: string;
  xhttp_mode?: 'auto' | 'packet-up' | 'stream-up' | 'stream-one';
  xhttp_extra?: string;
  httpupgrade_path?: string;
  httpupgrade_host?: string;
  httpupgrade_headers?: KeyValuePair[];
  h2_path?: string;
  h2_host?: string[];
  h2_method?: string;
  h2_headers?: KeyValuePair[];
  mkcp_mtu?: number;
  mkcp_tti?: number;
  mkcp_uplink_capacity?: number;
  mkcp_downlink_capacity?: number;
  mkcp_congestion?: boolean;
  mkcp_seed?: string;
  mkcp_header_type?: string;
  mkcp_cwnd_multiplier?: number;
  mkcp_max_sending_window?: number;
  quic_security?: string;
  quic_key?: string;
  quic_header_type?: string;
  ds_path?: string;
  ds_abstract?: boolean;
  ds_padding?: boolean;
  hysteria_auth?: string;
  hysteria_up_mbps?: number;
  hysteria_down_mbps?: number;
  hysteria_udp_extension?: boolean;
  hysteria_udp_idle_timeout?: number | string;
  hysteria_masquerade?: string;
  hysteria_masquerade_type?: '' | 'file' | 'proxy' | 'string';
  hysteria_masquerade_dir?: string;
  hysteria_masquerade_url?: string;
  hysteria_masquerade_rewrite_host?: boolean;
  hysteria_masquerade_insecure?: boolean;
  hysteria_masquerade_content?: string;
  hysteria_masquerade_headers?: KeyValuePair[];
  hysteria_masquerade_status_code?: number;
  hysteria_udphop_port?: string;
  hysteria_udphop_interval?: number;
  hysteria_obfs_password?: string;
  // MASQUE transport (Xray)
  masque_host?: string;
  masque_path?: string;
  masque_user?: string;
  masque_pass?: string;
  masque_warp_json?: string;
  masque_uri?: string;
  masque_auth?: string;
  masque_headers?: KeyValuePair[];
  finalmask_json?: string;
  // Sockopt
  sockopt_mark?: number;
  sockopt_tproxy?: 'off' | 'redirect' | 'tproxy';
  sockopt_tcp_fast_open?: boolean;
  sockopt_tcp_fast_open_queue_length?: number;
  sockopt_mptcp?: boolean;
  sockopt_interface?: string;
  sockopt_tcp_max_seg?: number;
  sockopt_tcp_keepalive_idle?: number;
  sockopt_tcp_keepalive_interval?: number;
  sockopt_tcp_user_timeout?: number;
  sockopt_tcp_congestion?: string;
  sockopt_v6_only?: boolean;
  sockopt_tcp_window_clamp?: number;
  sockopt_address_port_strategy?: string;
  sockopt_trusted_xff?: string[];
  sockopt_custom_json?: string;
  sockopt_happy_eyeballs_try_delay_ms?: number;
  sockopt_happy_eyeballs_prioritize_ipv6?: boolean;
  sockopt_happy_eyeballs_interleave?: number;
  sockopt_happy_eyeballs_max_concurrent_try?: number;
  domain_strategy?: string;
  dialer_proxy?: string;
}

export interface InboundConfig extends StreamFields {
  id: string;
  enabled: boolean;
  alias: string;
  tag: string;
  listen: string;
  port: number;
  protocol: string;
  use_tunnel?: boolean;
  socks_auth?: 'noauth' | 'password';
  socks_udp?: boolean;
  socks_ip?: string;
  http_allow_transparent?: boolean;
  http_timeout?: number;
  packet_encoding?: '' | 'None' | 'Packet' | 'Stream';
  username?: string;
  password?: string;
  users?: InboundUser[];
  fallbacks?: FallbackItem[];
  dokodemo_network?: string;
  dokodemo_address?: string;
  dokodemo_port?: number;
  dokodemo_follow_redirect?: boolean;
  tunnel_port_map?: KeyValuePair[];
  tunnel_user_level?: number;
  uuid?: string;
  flow?: string;
  decryption?: string;
  alter_id?: number;
  method?: string;
  ss_network?: string;
  // WireGuard inbound (Xray)
  wg_secret_key?: string;
  wg_address?: string[];
  wg_peers?: WireguardPeer[];
  wg_mtu?: number;
  // MASQUE inbound (Xray)
  masque_address?: string[];
  masque_mtu?: number;
  // TUN inbound (Xray / V2Ray v5 services.tun)
  tun_name?: string;
  tun_desc?: string;
  tun_mtu?: number;
  tun_gateway?: string[];
  tun_dns?: string[];
  tun_user_level?: number;
  tun_auto_routing_table?: string[];
  tun_auto_outbounds_interface?: string;
  tun_auto_dns_to_gateway?: boolean;
  tun_auto_wfp_block_leak?: string[];
  tun_ips?: string[];
  tun_routes?: string[];
  tun_promiscuous?: boolean;
  tun_spoofing?: boolean;
  sniffing_enabled?: boolean;
  sniffing_dest_override?: string[];
  sniffing_domains_excluded?: string[];
  sniffing_ips_excluded?: string[];
  sniffing_metadata_only?: boolean;
  sniffing_route_only?: boolean;
  allocate_strategy?: '' | 'always' | 'random';
  allocate_refresh?: number;
  allocate_concurrency?: number;
  custom_config?: string;
}

export interface OutboundConfig extends StreamFields {
  id: string;
  enabled: boolean;
  alias: string;
  tag: string;
  protocol: string;
  send_through?: string;
  target_strategy?: string;
  address?: string;
  port?: number;
  email?: string;
  user_level?: number;
  uuid?: string;
  encryption?: string;
  flow?: string;
  vless_reverse_tag?: string;
  alter_id?: number;
  security_cipher?: string;
  vmess_experiments?: string;
  password?: string;
  method?: string;
  ss_uot?: boolean;
  ss_uot_version?: number;
  ss_iv_check?: boolean;
  ss_ipsk?: string[];
  socks_version?: '5' | '4a' | '4';
  username?: string;
  http_headers?: KeyValuePair[];
  freedom_redirect?: string;
  freedom_proxy_protocol?: number;
  freedom_final_rules_json?: string;
  blackhole_response?: 'none' | 'http';
  dns_network?: string;
  dns_address?: string;
  dns_port?: number;
  dns_non_ip_query?: '' | 'skip' | 'drop';
  dns_rules_json?: string;
  loopback_inbound_tag?: string;
  loopback_sniffing_enabled?: boolean;
  loopback_sniffing_dest_override?: string[];
  loopback_sniffing_domains_excluded?: string[];
  loopback_sniffing_ips_excluded?: string[];
  loopback_sniffing_metadata_only?: boolean;
  loopback_sniffing_route_only?: boolean;
  wg_secret_key?: string;
  wg_address?: string[];
  wg_peers?: WireguardPeer[];
  wg_peer_public_key?: string;
  wg_endpoint?: string;
  wg_mtu?: number;
  wg_reserved?: string[];
  wg_remote_dns?: string[];
  wg_no_kernel_tun?: boolean;
  masque_remote_dns?: string[];
  mux_enabled?: boolean;
  mux_concurrency?: number;
  mux_xudp_concurrency?: number;
  mux_xudp_proxy_udp443?: '' | 'reject' | 'allow' | 'skip';
  custom_config?: string;
}

export interface DnsServerConfig {
  id: string;
  server_id?: string;
  enabled: boolean;
  alias: string;
  address: string;
  port?: number;
  skip_fallback?: boolean;
  final_query?: boolean;
  timeout_ms?: number;
  domains?: string[];
  expect_ips?: string[];
  unexpected_ips?: string[];
  client_ip?: string;
  query_strategy?: '' | 'UseIP' | 'UseIPv4' | 'UseIPv6' | 'UseSystem';
  disable_cache?: boolean;
  serve_stale?: boolean;
  serve_expired_ttl?: number;
  tag?: string;
}

export interface DnsHostEntry {
  domain: string;
  addresses: string[];
}

export interface DnsConfig {
  enabled: boolean;
  tag: string;
  script?: string;
  query_strategy: 'UseIP' | 'UseIPv4' | 'UseIPv6' | 'UseSystem';
  disable_cache: boolean;
  disable_fallback: boolean;
  disable_fallback_if_match: boolean;
  serve_stale: boolean;
  serve_expired_ttl?: number;
  enable_parallel_query: boolean;
  use_system_hosts?: boolean;
  client_ip: string;
  hosts: Record<string, string[]>;
  host_entries?: DnsHostEntry[];
}

export interface FakeDnsPoolConfig {
  id: string;
  ip_pool: string;
  pool_size: number;
}

export interface RoutingRuleConfig {
  id: string;
  enabled: boolean;
  alias: string;
  domain?: string[];
  ip?: string[];
  port?: string;
  source_port?: string;
  local_port?: string;
  network?: '' | 'tcp' | 'udp' | 'tcp,udp';
  source?: string[];
  local_ip?: string[];
  user?: string[];
  inbound_tag?: string[];
  protocol?: string[];
  process?: string[];
  vless_route?: string;
  rule_tag?: string;
  webhook_url?: string;
  webhook_deduplication?: number;
  webhook_headers?: KeyValuePair[];
  attrs?: string;
  outbound_tag?: string;
  balancer_tag?: string;
}

export interface RoutingBalancerConfig {
  id: string;
  tag: string;
  selector: string[];
  strategy: 'random' | 'roundRobin' | 'leastPing' | 'leastLoad';
  fallback_tag?: string;
  strategy_expected?: number;
  strategy_max_rtt?: string;
  strategy_tolerance?: number;
  strategy_baselines?: string[];
  strategy_costs_json?: string;
}

export interface RoutingConfig {
  enabled: boolean;
  script?: string;
  domain_strategy: 'AsIs' | 'IPIfNonMatch' | 'IPOnDemand';
  domain_matcher: 'hybrid' | 'linear' | 'mph';
}

export interface ObservatoryConfig {
  enabled: boolean;
  subject_selector: string[];
  probe_url: string;
  probe_interval: string;
  enable_concurrency: boolean;
}

export interface BurstObservatoryConfig {
  enabled: boolean;
  subject_selector: string[];
  destination: string;
  connectivity: string;
  interval: string;
  sampling: number;
  timeout: string;
}

export interface BrowserForwarderConfig {
  enabled: boolean;
  listen_addr: string;
  listen_port: number;
}

export interface PolicyLevelConfig {
  level: string;
  handshake: number;
  conn_idle: number;
  uplink_only: number;
  downlink_only: number;
  buffer_size: number;
  stats_user_uplink: boolean;
  stats_user_downlink: boolean;
}

export interface PolicyConfig {
  enabled: boolean;
  handshake: number;
  conn_idle: number;
  uplink_only: number;
  downlink_only: number;
  buffer_size: number;
  stats_inbound_uplink: boolean;
  stats_inbound_downlink: boolean;
  stats_outbound_uplink: boolean;
  stats_outbound_downlink: boolean;
  levels?: PolicyLevelConfig[];
}

export interface ReverseConfig {
  enabled: boolean;
  bridges: string[];
  portals: string[];
}

export interface LanHostRule {
  id: string;
  alias: string;
  macaddr: string;
  strategy_v4: 'default' | 'tproxy' | 'bypass';
  strategy_v6: 'default' | 'tproxy' | 'bypass';
}

export interface TransparentProxyConfig {
  enabled: boolean;
  firewall_backend: FirewallBackend;
  firewall_priority: number;
  route_table: number;
  tproxy_mark: string;
  dynamic_direct_mark: string;
  outbound_mark: string;
  dns_mark: string;
  ct_direct_mark: string;
  tproxy_mode: 'tproxy' | 'redirect';
  tproxy_port_tcp_v4: number;
  tproxy_port_tcp_v6: number;
  tproxy_port_udp_v4: number;
  tproxy_port_udp_v6: number;
  fakedns_enabled: boolean;
  fakedns_pool_v4: string;
  fakedns_pool_v6: string;
  fakedns_port_tcp_v4: number;
  fakedns_port_tcp_v6: number;
  fakedns_port_udp_v4: number;
  fakedns_port_udp_v6: number;
  fakedns_ping_response: boolean;
  dynamic_direct_enabled: boolean;
  dynamic_direct_timeout: number;
  dnsmasq_enabled: boolean;
  dnsmasq_integration_mode: 'global' | 'per_instance';
  dnsmasq_instances: string[];
  dnsmasq_port_start: number;
  dnsmasq_port_count: number;
  default_port_policy: 'forwarded' | 'bypassed';
  tproxy_ifaces_v4: string[];
  tproxy_ifaces_v6: string[];
  bypass_ifaces_v4: string[];
  bypass_ifaces_v6: string[];
  wan_bp_ips: string[];
  wan_fw_ips: string[];
}

export interface AiosConfig {
  general: GeneralConfig;
  inbounds: InboundConfig[];
  outbounds: OutboundConfig[];
  dns: DnsConfig;
  dns_servers: DnsServerConfig[];
  fakedns: FakeDnsPoolConfig[];
  routing: RoutingConfig;
  routing_rules: RoutingRuleConfig[];
  balancers: RoutingBalancerConfig[];
  observatory: ObservatoryConfig;
  burst_observatory?: BurstObservatoryConfig;
  browser_forwarder?: BrowserForwarderConfig;
  policy: PolicyConfig;
  reverse: ReverseConfig;
  transparent_proxy: TransparentProxyConfig;
  lan_hosts: LanHostRule[];
}

export interface AiosPreset {
  id: string;
  name: string;
  description: string;
  builtin: boolean;
  recommendedCore?: CoreSelection;
  createdAt: string;
  updatedAt?: string;
  tags: string[];
  config: AiosConfig;
}
