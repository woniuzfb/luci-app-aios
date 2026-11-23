import type { AiosConfig } from './types';

export function createDefaultConfig(): AiosConfig {
  return {
    general: {
      enabled: false,
      core_type: 'auto',
      core_bin: '/usr/bin/xray',
      bins_dir: '',
      target_version: 'auto',
      v2ray_format: 'jsonv4',
      asset_location: '/usr/share/xray',
      geoloader: 'memconservative',
      go_memlimit: '',
      rlimit_nofile: '102400',
      rlimit_data: '',
      config_file: '',
      log_level: 'warning',
      access_log: 'none',
      error_log: '/var/log/aios-error.log',
      dns_log: false,
      mask_address: '',
      stats_enabled: true,
      api_enabled: true,
      api_port: 18080,
      metrics_enabled: true,
      metrics_port: 18888,
      conflict_policy: 'warn',
      custom_configuration_hook: ''
    },
    inbounds: [
      {
        id: 'socks_local',
        enabled: true,
        alias: 'Local SOCKS5',
        tag: 'socks-in',
        listen: '127.0.0.1',
        port: 10800,
        protocol: 'socks',
        transport: 'raw',
        security: 'none',
        socks_auth: 'noauth',
        socks_udp: true,
        sniffing_enabled: true,
        sniffing_dest_override: ['http', 'tls', 'quic']
      },
      {
        id: 'http_local',
        enabled: true,
        alias: 'Local HTTP',
        tag: 'http-in',
        listen: '127.0.0.1',
        port: 10801,
        protocol: 'http',
        transport: 'raw',
        security: 'none',
        sniffing_enabled: true,
        sniffing_dest_override: ['http', 'tls']
      }
    ],
    outbounds: [
      {
        id: 'direct_out',
        enabled: true,
        alias: 'Direct',
        tag: 'direct',
        protocol: 'freedom',
        transport: 'raw',
        security: 'none',
        domain_strategy: 'UseIP'
      },
      {
        id: 'block_out',
        enabled: true,
        alias: 'Block',
        tag: 'block',
        protocol: 'blackhole',
        transport: 'raw',
        security: 'none',
        blackhole_response: 'none'
      },
      {
        id: 'dns_out',
        enabled: true,
        alias: 'DNS Outbound',
        tag: 'dns-out',
        protocol: 'dns',
        transport: 'raw',
        security: 'none'
      }
    ],
    dns: {
      enabled: true,
      tag: 'dns-in',
      query_strategy: 'UseIP',
      disable_cache: false,
      disable_fallback: false,
      disable_fallback_if_match: false,
      serve_stale: false,
      enable_parallel_query: false,
      client_ip: '',
      hosts: {}
    },
    dns_servers: [
      {
        id: 'dns_cn',
        enabled: true,
        alias: 'AliDNS (CN)',
        address: '223.5.5.5',
        port: 53,
        skip_fallback: true,
        domains: ['geosite:cn'],
        expect_ips: ['geoip:cn']
      },
      {
        id: 'dns_global',
        enabled: true,
        alias: 'Cloudflare DNS',
        address: '1.1.1.1',
        port: 53
      }
    ],
    fakedns: [],
    routing: {
      enabled: true,
      domain_strategy: 'IPIfNonMatch',
      domain_matcher: 'hybrid'
    },
    routing_rules: [
      {
        id: 'rule_private',
        enabled: true,
        alias: 'Direct Private IP',
        ip: ['geoip:private'],
        outbound_tag: 'direct'
      },
      {
        id: 'rule_cn_ip',
        enabled: true,
        alias: 'Direct CN IP',
        ip: ['geoip:cn'],
        outbound_tag: 'direct'
      },
      {
        id: 'rule_cn_domain',
        enabled: true,
        alias: 'Direct CN Domain',
        domain: ['geosite:cn'],
        outbound_tag: 'direct'
      },
      {
        id: 'rule_ads',
        enabled: true,
        alias: 'Block Ads',
        domain: ['geosite:category-ads-all'],
        outbound_tag: 'block'
      }
    ],
    balancers: [],
    observatory: {
      enabled: false,
      subject_selector: [],
      probe_url: 'https://www.google.com/generate_204',
      probe_interval: '1m',
      enable_concurrency: false
    },
    burst_observatory: {
      enabled: false,
      subject_selector: [],
      destination: 'https://www.google.com/generate_204',
      connectivity: '',
      interval: '1m',
      sampling: 3,
      timeout: '5s'
    },
    browser_forwarder: {
      enabled: false,
      listen_addr: '127.0.0.1',
      listen_port: 8088
    },
    policy: {
      enabled: true,
      handshake: 4,
      conn_idle: 300,
      uplink_only: 2,
      downlink_only: 5,
      buffer_size: 4,
      stats_inbound_uplink: true,
      stats_inbound_downlink: true,
      stats_outbound_uplink: true,
      stats_outbound_downlink: true,
      levels: [
        {
          level: '0',
          handshake: 4,
          conn_idle: 300,
          uplink_only: 2,
          downlink_only: 5,
          buffer_size: 4,
          stats_user_uplink: true,
          stats_user_downlink: true
        }
      ]
    },
    reverse: {
      enabled: false,
      bridges: [],
      portals: []
    },
    transparent_proxy: {
      enabled: false,
      firewall_backend: 'auto',
      firewall_priority: 10,
      route_table: 166,
      tproxy_mark: '0x3a01',
      dynamic_direct_mark: '0x3a02',
      outbound_mark: '0x3a03',
      dns_mark: '0x3a04',
      ct_direct_mark: '0x3a0a',
      tproxy_mode: 'tproxy',
      tproxy_port_tcp_v4: 12345,
      tproxy_port_tcp_v6: 12346,
      tproxy_port_udp_v4: 12347,
      tproxy_port_udp_v6: 12348,
      fakedns_enabled: false,
      fakedns_pool_v4: '198.18.0.0/15',
      fakedns_pool_v6: '2001:2::/48',
      fakedns_port_tcp_v4: 12355,
      fakedns_port_tcp_v6: 12356,
      fakedns_port_udp_v4: 12357,
      fakedns_port_udp_v6: 12358,
      fakedns_ping_response: true,
      dynamic_direct_enabled: false,
      dynamic_direct_timeout: 1800,
      dnsmasq_enabled: false,
      dnsmasq_integration_mode: 'global',
      dnsmasq_instances: [],
      dnsmasq_port_start: 5350,
      dnsmasq_port_count: 3,
      default_port_policy: 'forwarded',
      tproxy_ifaces_v4: ['br-lan'],
      tproxy_ifaces_v6: ['br-lan'],
      bypass_ifaces_v4: [],
      bypass_ifaces_v6: [],
      wan_bp_ips: [],
      wan_fw_ips: []
    },
    lan_hosts: []
  };
}
