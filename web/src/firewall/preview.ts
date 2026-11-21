import type { AiosConfig } from '@/schema/types';

export interface FirewallChangeItem {
  scope: 'nftables' | 'iptables' | 'ip-rule' | 'ipset' | 'dnsmasq';
  action: 'create' | 'modify' | 'delete';
  target: string;
  detail: string;
}

export interface DiffLine {
  kind: 'same' | 'add' | 'del';
  text: string;
}

export function renderExpectedFirewallRules(
  cfg: AiosConfig,
  detectedBackend: 'nftables' | 'iptables' | 'none' = 'nftables'
): { backend: 'nftables' | 'iptables' | 'none'; rules: string; changes: FirewallChangeItem[] } {
  const tp = cfg.transparent_proxy;
  const backend =
    tp.firewall_backend === 'auto' ? detectedBackend : tp.firewall_backend;

  const changes: FirewallChangeItem[] = [];

  if (!tp.enabled || backend === 'none') {
    changes.push({
      scope: backend === 'iptables' ? 'iptables' : 'nftables',
      action: 'delete',
      target: backend === 'iptables' ? 'AIOS_* chains & aios_* ipsets' : 'table inet aios',
      detail: '透明代理未启用或后端设为 none，将清理 AIOS 独立防火墙规则（不影响其他插件）。'
    });
    return {
      backend,
      rules: '# 透明代理未启用（或 firewall_backend=none），AIOS 不会向系统注入防火墙规则。\n',
      changes
    };
  }

  changes.push({
    scope: 'ip-rule',
    action: 'create',
    target: `fwmark ${tp.tproxy_mark} -> table ${tp.route_table}`,
    detail: `IPv4 / IPv6 策略路由：local default dev lo table ${tp.route_table}`
  });

  if (tp.dnsmasq_enabled) {
    changes.push({
      scope: 'dnsmasq',
      action: 'create',
      target:
        tp.dnsmasq_integration_mode === 'per_instance'
          ? `/tmp/dnsmasq.<inst>.d/aios.conf (${tp.dnsmasq_instances.join(', ') || '未指定'})`
          : '/tmp/dnsmasq.d/aios.conf',
      detail: `转发至 127.0.0.1#${tp.dnsmasq_port_start}..${tp.dnsmasq_port_start + tp.dnsmasq_port_count}`
    });
  }

  if (backend === 'nftables') {
    changes.push({
      scope: 'nftables',
      action: 'create',
      target: 'table inet aios (独立表，不修改 table inet fw4)',
      detail: `chains: tproxy_divert, tproxy_dispatch, prerouting, output, lan_filter${tp.fakedns_enabled && tp.fakedns_ping_response ? ', fakedns_ping_*' : ''}`
    });
    if (tp.dynamic_direct_enabled) {
      changes.push({
        scope: 'nftables',
        action: 'create',
        target: 'sets: aios_dd_v4, aios_dd_v6',
        detail: `Dynamic Direct 内核态动态直连，超时 ${tp.dynamic_direct_timeout}s，ct mark ${tp.ct_direct_mark}`
      });
    }

    const lines: string[] = [
      '# Expected isolated nftables ruleset (table inet aios)',
      'table inet aios {',
      `  # Marks: tproxy=${tp.tproxy_mark}, dd=${tp.dynamic_direct_mark}, outbound=${tp.outbound_mark}, dns=${tp.dns_mark}, ct_dd=${tp.ct_direct_mark}`,
      '  set aios_reserved_v4 { type ipv4_addr; flags interval; }',
      '  set aios_reserved_v6 { type ipv6_addr; flags interval; }',
      '  set aios_gateway_v4  { type ipv4_addr; flags interval; }',
      '  set aios_gateway_v6  { type ipv6_addr; flags interval; }'
    ];
    if (tp.wan_bp_ips.length > 0) {
      lines.push(`  set aios_bp_ips { elements = { ${tp.wan_bp_ips.join(', ')} } }`);
    }
    if (tp.wan_fw_ips.length > 0) {
      lines.push(`  set aios_fw_ips { elements = { ${tp.wan_fw_ips.join(', ')} } }`);
    }
    if (tp.dynamic_direct_enabled) {
      lines.push(`  set aios_dd_v4 { type ipv4_addr; flags dynamic,timeout; # ${tp.dynamic_direct_timeout}s }`);
      lines.push(`  set aios_dd_v6 { type ipv6_addr; flags dynamic,timeout; # ${tp.dynamic_direct_timeout}s }`);
    }
    lines.push('  chain tproxy_divert {');
    lines.push(`    type filter hook prerouting priority filter +${tp.firewall_priority}; policy accept;`);
    lines.push(`    meta mark ${tp.tproxy_mark} goto tproxy_dispatch`);
    lines.push('  }');
    lines.push('  chain tproxy_dispatch {');
    if (tp.fakedns_enabled) {
      lines.push(`    ip protocol tcp ip daddr ${tp.fakedns_pool_v4} tproxy ip to :${tp.fakedns_port_tcp_v4} accept`);
      lines.push(`    ip protocol udp ip daddr ${tp.fakedns_pool_v4} tproxy ip to :${tp.fakedns_port_udp_v4} accept`);
      lines.push(`    ip6 nexthdr tcp ip6 daddr ${tp.fakedns_pool_v6} tproxy ip6 to :${tp.fakedns_port_tcp_v6} accept`);
      lines.push(`    ip6 nexthdr udp ip6 daddr ${tp.fakedns_pool_v6} tproxy ip6 to :${tp.fakedns_port_udp_v6} accept`);
    }
    if (tp.tproxy_port_tcp_v4 > 0) lines.push(`    ip protocol tcp tproxy ip to :${tp.tproxy_port_tcp_v4} accept`);
    if (tp.tproxy_port_udp_v4 > 0) lines.push(`    ip protocol udp tproxy ip to :${tp.tproxy_port_udp_v4} accept`);
    if (tp.tproxy_port_tcp_v6 > 0) lines.push(`    ip6 nexthdr tcp tproxy ip6 to :${tp.tproxy_port_tcp_v6} accept`);
    if (tp.tproxy_port_udp_v6 > 0) lines.push(`    ip6 nexthdr udp tproxy ip6 to :${tp.tproxy_port_udp_v6} accept`);
    lines.push('  }');
    lines.push('  chain prerouting {');
    lines.push(`    type filter hook prerouting priority mangle +${tp.firewall_priority}; policy accept;`);
    if (tp.tproxy_ifaces_v4.length > 0) {
      lines.push(`    ip protocol { tcp, udp } iifname { "${tp.tproxy_ifaces_v4.join('", "')}" } goto lan_filter`);
    }
    if (tp.tproxy_ifaces_v6.length > 0) {
      lines.push(`    ip6 nexthdr { tcp, udp } iifname { "${tp.tproxy_ifaces_v6.join('", "')}" } goto lan_filter`);
    }
    lines.push('  }');
    lines.push('  chain output {');
    lines.push(`    type route hook output priority mangle +${tp.firewall_priority}; policy accept;`);
    lines.push(`    meta mark { ${tp.outbound_mark}, ${tp.dns_mark} } accept`);
    lines.push('    meta l4proto { tcp, udp } goto lan_filter');
    lines.push('  }');
    lines.push('}');
    return { backend, rules: lines.join('\n') + '\n', changes };
  }

  // fw3 iptables
  changes.push({
    scope: 'iptables',
    action: 'create',
    target: tp.tproxy_mode === 'redirect' ? 'nat/AIOS_REDIRECT' : 'mangle/AIOS_PREROUTING + AIOS_OUTPUT (IPv4 & IPv6)',
    detail: `仅挂接独立 AIOS_* 链，清理时不 flush 全局表`
  });
  changes.push({
    scope: 'ipset',
    action: 'create',
    target: 'aios_reserved_v4/v6, aios_bp_v4/v6',
    detail: '保留网段与 WAN 直连绕过集合'
  });

  const iptLines =
    tp.tproxy_mode === 'redirect'
      ? [
          '# Expected legacy firewall3 (iptables nat REDIRECT)',
          `iptables -t nat -N AIOS_REDIRECT`,
          `iptables -t nat -A AIOS_REDIRECT -m mark --mark ${tp.outbound_mark} -j RETURN`,
          `iptables -t nat -A AIOS_REDIRECT -m set --match-set aios_reserved_v4 dst -j RETURN`,
          `iptables -t nat -A AIOS_REDIRECT -p tcp -j REDIRECT --to-ports ${tp.tproxy_port_tcp_v4}`,
          `iptables -t nat -A PREROUTING -p tcp -j AIOS_REDIRECT`
        ]
      : [
          '# Expected legacy firewall3 (iptables + ip6tables mangle TPROXY)',
          `ip rule add fwmark ${tp.tproxy_mark} lookup ${tp.route_table}`,
          `iptables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port ${tp.tproxy_port_tcp_v4} --tproxy-mark ${tp.tproxy_mark}`,
          `iptables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port ${tp.tproxy_port_udp_v4} --tproxy-mark ${tp.tproxy_mark}`,
          `ip6tables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port ${tp.tproxy_port_tcp_v6} --tproxy-mark ${tp.tproxy_mark}`,
          `ip6tables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port ${tp.tproxy_port_udp_v6} --tproxy-mark ${tp.tproxy_mark}`
        ];

  return { backend, rules: iptLines.join('\n') + '\n', changes };
}

export function computeLineDiff(beforeText: string, afterText: string): DiffLine[] {
  const a = beforeText.trim() ? beforeText.trim().split('\n') : [];
  const b = afterText.trim() ? afterText.trim().split('\n') : [];
  const aSet = new Set(a);
  const bSet = new Set(b);
  const out: DiffLine[] = [];

  for (const line of a) {
    if (!bSet.has(line)) out.push({ kind: 'del', text: line });
  }
  for (const line of b) {
    if (aSet.has(line)) out.push({ kind: 'same', text: line });
    else out.push({ kind: 'add', text: line });
  }
  return out;
}
