export type CoreType = 'xray' | 'v2ray';
export type CoreSelection = 'auto' | CoreType;
export type FirewallBackend = 'auto' | 'nftables' | 'iptables' | 'none';
export type ConflictPolicy = 'warn' | 'block' | 'ignore';

export interface GeneralConfig {
  enabled: boolean;
  core_type: CoreSelection;
  core_bin: string;
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
}

export interface KeyValuePair {
  key: string;
  value: string;
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
  tls_verify_peer_name?: string;
  tls_verify_client?: boolean;
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
  hysteria_udp_idle_timeout?: string;
  hysteria_udphop_port?: string;
  hysteria_udphop_interval?: number;
  hysteria_obfs_password?: string;
  finalmask_json?: string;
  // Sockopt
  sockopt_mark?: number;
  sockopt_tproxy?: 'off' | 'redirect' | 'tproxy';
  sockopt_tcp_fast_open?: boolean;
  sockopt_tcp_fast_open_queue_length?: number;
  sockopt_mptcp?: boolean;
  sockopt_interface?: string;
  sockopt_tcp_keepalive_interval?: number;
  sockopt_tcp_congestion?: string;
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
  username?: string;
  password?: string;
  users?: InboundUser[];
  fallbacks?: FallbackItem[];
  dokodemo_network?: string;
  dokodemo_address?: string;
  dokodemo_port?: number;
  dokodemo_follow_redirect?: boolean;
  uuid?: string;
  flow?: string;
  decryption?: string;
  alter_id?: number;
  method?: string;
  ss_network?: string;
  tun_name?: string;
  tun_mtu?: number;
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
  address?: string;
  port?: number;
  uuid?: string;
  encryption?: string;
  flow?: string;
  alter_id?: number;
  security_cipher?: string;
  password?: string;
  method?: string;
  ss_uot?: boolean;
  ss_iv_check?: boolean;
  username?: string;
  freedom_redirect?: string;
  blackhole_response?: 'none' | 'http';
  dns_network?: string;
  dns_address?: string;
  dns_port?: number;
  dns_non_ip_query?: '' | 'skip' | 'drop';
  loopback_inbound_tag?: string;
  wg_secret_key?: string;
  wg_address?: string[];
  wg_peers?: WireguardPeer[];
  wg_peer_public_key?: string;
  wg_endpoint?: string;
  wg_mtu?: number;
  wg_reserved?: string[];
  wg_no_kernel_tun?: boolean;
  mux_enabled?: boolean;
  mux_concurrency?: number;
  mux_xudp_concurrency?: number;
  mux_xudp_proxy_udp443?: '' | 'reject' | 'allow' | 'skip';
  custom_config?: string;
}

export interface DnsServerConfig {
  id: string;
  enabled: boolean;
  alias: string;
  address: string;
  port?: number;
  skip_fallback?: boolean;
  domains?: string[];
  expect_ips?: string[];
  unexpected_ips?: string[];
  client_ip?: string;
}

export interface DnsHostEntry {
  domain: string;
  addresses: string[];
}

export interface DnsConfig {
  enabled: boolean;
  tag: string;
  query_strategy: 'UseIP' | 'UseIPv4' | 'UseIPv6' | 'UseSystem';
  disable_cache: boolean;
  disable_fallback: boolean;
  disable_fallback_if_match: boolean;
  serve_stale: boolean;
  enable_parallel_query: boolean;
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
  network?: '' | 'tcp' | 'udp' | 'tcp,udp';
  source?: string[];
  local_ip?: string[];
  user?: string[];
  inbound_tag?: string[];
  protocol?: string[];
  process?: string[];
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
}

export interface RoutingConfig {
  enabled: boolean;
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
