import type { AiosPreset } from '@/schema/types';
import { createDefaultConfig } from '@/schema/defaults';

function buildXrayDualStackTproxyPreset(): AiosPreset {
  const cfg = createDefaultConfig();
  cfg.general.core_type = 'xray';
  cfg.inbounds.push(
    {
      id: 'tproxy_tcp4',
      enabled: true,
      alias: 'TProxy TCP IPv4',
      tag: 'tproxy-tcp4',
      listen: '0.0.0.0',
      port: 12345,
      protocol: 'dokodemo-door',
      use_tunnel: true,
      dokodemo_network: 'tcp',
      dokodemo_follow_redirect: true,
      transport: 'raw',
      security: 'none',
      sockopt_tproxy: 'tproxy',
      sniffing_enabled: true,
      sniffing_dest_override: ['http', 'tls']
    },
    {
      id: 'tproxy_udp4',
      enabled: true,
      alias: 'TProxy UDP IPv4',
      tag: 'tproxy-udp4',
      listen: '0.0.0.0',
      port: 12347,
      protocol: 'dokodemo-door',
      use_tunnel: true,
      dokodemo_network: 'udp',
      dokodemo_follow_redirect: true,
      transport: 'raw',
      security: 'none',
      sockopt_tproxy: 'tproxy',
      sniffing_enabled: true,
      sniffing_dest_override: ['quic']
    },
    {
      id: 'tproxy_fakedns_tcp4',
      enabled: true,
      alias: 'FakeDNS TProxy TCP4',
      tag: 'tproxy-fakedns-tcp4',
      listen: '0.0.0.0',
      port: 12355,
      protocol: 'dokodemo-door',
      use_tunnel: true,
      dokodemo_network: 'tcp',
      dokodemo_follow_redirect: true,
      transport: 'raw',
      security: 'none',
      sockopt_tproxy: 'tproxy',
      sniffing_enabled: true,
      sniffing_dest_override: ['fakedns'],
      sniffing_metadata_only: true
    },
    {
      id: 'tproxy_fakedns_udp4',
      enabled: true,
      alias: 'FakeDNS TProxy UDP4',
      tag: 'tproxy-fakedns-udp4',
      listen: '0.0.0.0',
      port: 12357,
      protocol: 'dokodemo-door',
      use_tunnel: true,
      dokodemo_network: 'udp',
      dokodemo_follow_redirect: true,
      transport: 'raw',
      security: 'none',
      sockopt_tproxy: 'tproxy',
      sniffing_enabled: true,
      sniffing_dest_override: ['fakedns'],
      sniffing_metadata_only: true
    },
    {
      id: 'tproxy_tcp6',
      enabled: true,
      alias: 'TProxy TCP IPv6',
      tag: 'tproxy-tcp6',
      listen: '::',
      port: 12346,
      protocol: 'dokodemo-door',
      use_tunnel: true,
      dokodemo_network: 'tcp',
      dokodemo_follow_redirect: true,
      transport: 'raw',
      security: 'none',
      sockopt_tproxy: 'tproxy',
      sniffing_enabled: true,
      sniffing_dest_override: ['http', 'tls']
    },
    {
      id: 'tproxy_udp6',
      enabled: true,
      alias: 'TProxy UDP IPv6',
      tag: 'tproxy-udp6',
      listen: '::',
      port: 12348,
      protocol: 'dokodemo-door',
      use_tunnel: true,
      dokodemo_network: 'udp',
      dokodemo_follow_redirect: true,
      transport: 'raw',
      security: 'none',
      sockopt_tproxy: 'tproxy',
      sniffing_enabled: true,
      sniffing_dest_override: ['quic']
    },
    {
      id: 'tproxy_fakedns_tcp6',
      enabled: true,
      alias: 'FakeDNS TProxy TCP6',
      tag: 'tproxy-fakedns-tcp6',
      listen: '::',
      port: 12356,
      protocol: 'dokodemo-door',
      use_tunnel: true,
      dokodemo_network: 'tcp',
      dokodemo_follow_redirect: true,
      transport: 'raw',
      security: 'none',
      sockopt_tproxy: 'tproxy',
      sniffing_enabled: true,
      sniffing_dest_override: ['fakedns'],
      sniffing_metadata_only: true
    },
    {
      id: 'tproxy_fakedns_udp6',
      enabled: true,
      alias: 'FakeDNS TProxy UDP6',
      tag: 'tproxy-fakedns-udp6',
      listen: '::',
      port: 12358,
      protocol: 'dokodemo-door',
      use_tunnel: true,
      dokodemo_network: 'udp',
      dokodemo_follow_redirect: true,
      transport: 'raw',
      security: 'none',
      sockopt_tproxy: 'tproxy',
      sniffing_enabled: true,
      sniffing_dest_override: ['fakedns'],
      sniffing_metadata_only: true
    },
    ...[5350, 5351, 5352].map((port) => ({
      id: `dns_in_${port}`,
      enabled: true,
      alias: `Dnsmasq DNS (${port})`,
      tag: `dns-in-${port}`,
      listen: '127.0.0.1',
      port,
      protocol: 'dokodemo-door' as const,
      use_tunnel: true,
      dokodemo_address: '1.1.1.1',
      dokodemo_port: 53,
      dokodemo_network: 'tcp,udp',
      transport: 'raw',
      security: 'none' as const
    }))
  );
  cfg.routing_rules.unshift({
    id: 'rule_dns_dnsmasq',
    enabled: true,
    alias: 'Dnsmasq DNS -> dns-out',
    inbound_tag: ['dns-in-5350', 'dns-in-5351', 'dns-in-5352'],
    outbound_tag: 'dns-out'
  });
  cfg.fakedns = [
    { id: 'fake_v4', ip_pool: '198.18.0.0/15', pool_size: 65535 },
    { id: 'fake_v6', ip_pool: '2001:2::/48', pool_size: 65535 }
  ];
  cfg.dns.serve_stale = true;
  cfg.dns.enable_parallel_query = true;
  cfg.transparent_proxy.enabled = true;
  cfg.transparent_proxy.fakedns_enabled = true;
  cfg.transparent_proxy.dynamic_direct_enabled = true;
  cfg.transparent_proxy.dnsmasq_enabled = true;

  return {
    id: 'builtin-xray-tproxy-fakedns',
    name: 'Xray 双栈透明代理 + FakeDNS + Dynamic Direct',
    description: '吸收 luci-app-xray 最佳实践：独立 table inet aios 隔离防火墙、双栈 TProxy、FakeDNS 与内核态动态直连。',
    builtin: true,
    recommendedCore: 'xray',
    createdAt: '2026-01-01T00:00:00.000Z',
    tags: ['xray', 'tproxy', 'fakedns', 'dynamic-direct'],
    config: cfg
  };
}

function buildClassicSplitPreset(): AiosPreset {
  const cfg = createDefaultConfig();
  cfg.general.core_type = 'auto';
  cfg.inbounds.push({
    id: 'tproxy_all',
    enabled: true,
    alias: 'TProxy TCP+UDP',
    tag: 'tproxy-in',
    listen: '0.0.0.0',
    port: 12345,
    protocol: 'dokodemo-door',
    dokodemo_network: 'tcp,udp',
    dokodemo_follow_redirect: true,
    transport: 'tcp',
    security: 'none',
    sockopt_tproxy: 'tproxy',
    sniffing_enabled: true,
    sniffing_dest_override: ['http', 'tls']
  });
  cfg.transparent_proxy.enabled = true;
  cfg.transparent_proxy.tproxy_port_tcp_v4 = 12345;
  cfg.transparent_proxy.tproxy_port_udp_v4 = 12345;
  cfg.transparent_proxy.tproxy_port_tcp_v6 = 0;
  cfg.transparent_proxy.tproxy_port_udp_v6 = 0;
  cfg.transparent_proxy.tproxy_ifaces_v6 = [];
  cfg.transparent_proxy.fakedns_enabled = false;
  cfg.transparent_proxy.dynamic_direct_enabled = false;

  return {
    id: 'builtin-classic-cn-split',
    name: '经典国内直连 / 国外代理（Xray & V2Ray 通用）',
    description: '同时兼容 Xray-core（全版本）与 V2Ray jsonv4/jsonv5，兼顾 OpenWrt fw4 与旧版 fw3 iptables。',
    builtin: true,
    recommendedCore: 'auto',
    createdAt: '2026-01-01T00:00:00.000Z',
    tags: ['xray', 'v2ray', 'classic', 'fw3-compatible'],
    config: cfg
  };
}

function buildTunPreset(): AiosPreset {
  const cfg = createDefaultConfig();
  cfg.general.core_type = 'xray';
  cfg.inbounds.push({
    id: 'tun_in',
    enabled: true,
    alias: 'TUN Interface',
    tag: 'tun-in',
    listen: '0.0.0.0',
    port: 0,
    protocol: 'tun',
    tun_name: 'aios0',
    tun_mtu: 1500,
    transport: 'raw',
    security: 'none',
    sniffing_enabled: true,
    sniffing_dest_override: ['http', 'tls', 'quic']
  });
  cfg.transparent_proxy.enabled = false;

  return {
    id: 'builtin-xray-tun',
    name: '极简 TUN 模式（免防火墙规则）',
    description: '利用原生 TUN 接管流量（需 Xray >= 26.1.13，或 V2Ray >= 5.17 jsonv4 / >= 5.9 jsonv5），无需配置 nftables/iptables。',
    builtin: true,
    recommendedCore: 'xray',
    createdAt: '2026-01-01T00:00:00.000Z',
    tags: ['xray', 'v2ray', 'tun', 'zero-firewall'],
    config: cfg
  };
}

function buildLocalProxyOnlyPreset(): AiosPreset {
  const cfg = createDefaultConfig();
  cfg.transparent_proxy.enabled = false;
  cfg.transparent_proxy.dnsmasq_enabled = false;
  return {
    id: 'builtin-local-proxy',
    name: '仅本地 SOCKS5 / HTTP 代理',
    description: '关闭透明代理与防火墙接管，仅在 10800 (SOCKS5) 与 10801 (HTTP) 提供本地代理服务。',
    builtin: true,
    recommendedCore: 'auto',
    createdAt: '2026-01-01T00:00:00.000Z',
    tags: ['xray', 'v2ray', 'local'],
    config: cfg
  };
}

export const BUILTIN_PRESETS: AiosPreset[] = [
  buildXrayDualStackTproxyPreset(),
  buildClassicSplitPreset(),
  buildTunPreset(),
  buildLocalProxyOnlyPreset()
];
