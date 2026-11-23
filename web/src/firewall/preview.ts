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

  if (tp.tproxy_mode !== 'redirect') {
    changes.push({
      scope: 'ip-rule',
      action: 'create',
      target: `fwmark ${tp.tproxy_mark} -> table ${tp.route_table}`,
      detail: `IPv4 / IPv6 策略路由：local default dev lo table ${tp.route_table}`
    });
  }

  if (tp.dnsmasq_enabled) {
    changes.push({
      scope: 'dnsmasq',
      action: 'create',
      target:
        tp.dnsmasq_integration_mode === 'per_instance'
          ? `/tmp/dnsmasq.<inst>.d/aios.conf (${tp.dnsmasq_instances.join(', ') || '未指定'})`
          : '/tmp/dnsmasq.d/aios.conf',
      detail: `转发至 127.0.0.1#${tp.dnsmasq_port_start}..${tp.dnsmasq_port_start + Math.max(1, tp.dnsmasq_port_count) - 1}`
    });
  }

  if (backend === 'nftables') {
    const baseChains =
      tp.tproxy_mode === 'redirect'
        ? 'redirect_filter, nat_prerouting, nat_output'
        : 'tproxy_prerouting, prerouting, output, lan_filter';
    changes.push({
      scope: 'nftables',
      action: 'create',
      target: 'table inet aios (独立表，不修改 table inet fw4)',
      detail: `chains: ${baseChains}${tp.fakedns_enabled && tp.fakedns_ping_response ? ', fakedns_ping_prerouting, fakedns_ping_output' : ''}`
    });
    if (tp.dynamic_direct_enabled) {
      changes.push({
        scope: 'nftables',
        action: 'create',
        target: 'sets: aios_dd_v4, aios_dd_v6',
        detail: `Dynamic Direct 内核态动态直连，超时 ${tp.dynamic_direct_timeout}s，ct mark ${tp.ct_direct_mark}`
      });
    }

    const prio = tp.firewall_priority >= 0 ? `+${tp.firewall_priority}` : `${tp.firewall_priority}`;
    const bpV4 = tp.wan_bp_ips.filter((v) => !v.includes(':'));
    const bpV6 = tp.wan_bp_ips.filter((v) => v.includes(':'));
    const fwV4 = tp.wan_fw_ips.filter((v) => !v.includes(':'));
    const fwV6 = tp.wan_fw_ips.filter((v) => v.includes(':'));
    const macBpV4 = cfg.lan_hosts.filter((h) => h.macaddr && h.strategy_v4 === 'bypass').map((h) => h.macaddr);
    const macBpV6 = cfg.lan_hosts.filter((h) => h.macaddr && h.strategy_v6 === 'bypass').map((h) => h.macaddr);
    const macTpV4 = cfg.lan_hosts.filter((h) => h.macaddr && h.strategy_v4 === 'tproxy').map((h) => h.macaddr);
    const macTpV6 = cfg.lan_hosts.filter((h) => h.macaddr && h.strategy_v6 === 'tproxy').map((h) => h.macaddr);
    const fTcp4 = tp.fakedns_port_tcp_v4 || tp.tproxy_port_tcp_v4;
    const fTcp6 = tp.fakedns_port_tcp_v6 || tp.tproxy_port_tcp_v6;
    const fUdp4 = tp.fakedns_port_udp_v4 || tp.tproxy_port_udp_v4;
    const fUdp6 = tp.fakedns_port_udp_v6 || tp.tproxy_port_udp_v6;
    const v4Protos = [tp.tproxy_port_tcp_v4 > 0 ? 'tcp' : '', tp.tproxy_port_udp_v4 > 0 ? 'udp' : ''].filter(Boolean);
    const v6Protos = [tp.tproxy_port_tcp_v6 > 0 ? 'tcp' : '', tp.tproxy_port_udp_v6 > 0 ? 'udp' : ''].filter(Boolean);
    const fv4Protos = [fTcp4 > 0 ? 'tcp' : '', fUdp4 > 0 ? 'udp' : ''].filter(Boolean);
    const fv6Protos = [fTcp6 > 0 ? 'tcp' : '', fUdp6 > 0 ? 'udp' : ''].filter(Boolean);
    const v4Expr = v4Protos.length === 2 ? '{ tcp, udp }' : v4Protos[0] || '';
    const v6Expr = v6Protos.length === 2 ? '{ tcp, udp }' : v6Protos[0] || '';
    const fv4Expr = fv4Protos.length === 2 ? '{ tcp, udp }' : fv4Protos[0] || '';
    const fv6Expr = fv6Protos.length === 2 ? '{ tcp, udp }' : fv6Protos[0] || '';

    const lines: string[] = [
      '# Isolated nftables table managed exclusively by luci-app-aios',
      'table inet aios {',
      `  # Mode: ${tp.tproxy_mode} | Marks: tproxy=${tp.tproxy_mark}, dd=${tp.dynamic_direct_mark}, outbound=${tp.outbound_mark}, dns=${tp.dns_mark}, ct_dd=${tp.ct_direct_mark}`,
      '  set aios_reserved_v4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 224.0.0.0/3 } }',
      '  set aios_reserved_v6 { type ipv6_addr; flags interval; elements = { ::, ::1, ::ffff:0.0.0.0/96, 64:ff9b::/96, 100::/64, 2001::/32, 2001:db8::/32, 2002::/16, fc00::/7, fe80::/10, ff00::/8 } }',
      '  set aios_gateway_v4  { type ipv4_addr; flags interval; auto-merge; }',
      '  set aios_gateway_v6  { type ipv6_addr; flags interval; auto-merge; }'
    ];
    if (bpV4.length > 0) lines.push(`  set aios_bp_v4 { type ipv4_addr; flags interval; elements = { ${bpV4.join(', ')} } }`);
    if (bpV6.length > 0) lines.push(`  set aios_bp_v6 { type ipv6_addr; flags interval; elements = { ${bpV6.join(', ')} } }`);
    if (fwV4.length > 0) lines.push(`  set aios_fw_v4 { type ipv4_addr; flags interval; elements = { ${fwV4.join(', ')} } }`);
    if (fwV6.length > 0) lines.push(`  set aios_fw_v6 { type ipv6_addr; flags interval; elements = { ${fwV6.join(', ')} } }`);
    if (tp.dynamic_direct_enabled) {
      lines.push(`  set aios_dd_v4 { type ipv4_addr; flags dynamic,timeout; timeout ${tp.dynamic_direct_timeout}s; }`);
      lines.push(`  set aios_dd_v6 { type ipv6_addr; flags dynamic,timeout; timeout ${tp.dynamic_direct_timeout}s; }`);
    }
    if (macBpV4.length > 0) lines.push(`  set aios_mac_bp_v4 { type ether_addr; elements = { ${macBpV4.join(', ')} } }`);
    if (macBpV6.length > 0) lines.push(`  set aios_mac_bp_v6 { type ether_addr; elements = { ${macBpV6.join(', ')} } }`);
    if (macTpV4.length > 0) lines.push(`  set aios_mac_tp_v4 { type ether_addr; elements = { ${macTpV4.join(', ')} } }`);
    if (macTpV6.length > 0) lines.push(`  set aios_mac_tp_v6 { type ether_addr; elements = { ${macTpV6.join(', ')} } }`);

    if (tp.tproxy_mode === 'redirect') {
      lines.push('  chain redirect_filter {');
      lines.push('    fib daddr type local return');
      if (tp.fakedns_enabled && fTcp4 > 0) {
        lines.push(`    ip protocol tcp ip daddr ${tp.fakedns_pool_v4} redirect to :${fTcp4}`);
      }
      if (tp.fakedns_enabled && fTcp6 > 0) {
        lines.push(`    ip6 nexthdr tcp ip6 daddr ${tp.fakedns_pool_v6} redirect to :${fTcp6}`);
      }
      if (fwV4.length > 0 && tp.tproxy_port_tcp_v4 > 0) {
        lines.push(`    ip protocol tcp ip daddr @aios_fw_v4 redirect to :${tp.tproxy_port_tcp_v4}`);
      }
      if (fwV6.length > 0 && tp.tproxy_port_tcp_v6 > 0) {
        lines.push(`    ip6 nexthdr tcp ip6 daddr @aios_fw_v6 redirect to :${tp.tproxy_port_tcp_v6}`);
      }
      lines.push('    ip daddr @aios_gateway_v4 return');
      lines.push('    ip6 daddr @aios_gateway_v6 return');
      if (bpV4.length > 0) lines.push('    ip daddr @aios_bp_v4 return');
      if (bpV6.length > 0) lines.push('    ip6 daddr @aios_bp_v6 return');
      lines.push('    ip daddr @aios_reserved_v4 return');
      lines.push('    ip6 daddr @aios_reserved_v6 return');
      if (tp.tproxy_port_tcp_v4 > 0) lines.push(`    ip protocol tcp redirect to :${tp.tproxy_port_tcp_v4}`);
      if (tp.tproxy_port_tcp_v6 > 0) lines.push(`    ip6 nexthdr tcp redirect to :${tp.tproxy_port_tcp_v6}`);
      lines.push('  }');
      lines.push('  chain nat_prerouting {');
      lines.push(`    type nat hook prerouting priority dstnat ${prio}; policy accept;`);
      if (tp.bypass_ifaces_v4.length > 0) {
        lines.push(`    ip protocol tcp iifname { "${tp.bypass_ifaces_v4.join('", "')}" } return`);
      }
      if (tp.bypass_ifaces_v6.length > 0) {
        lines.push(`    ip6 nexthdr tcp iifname { "${tp.bypass_ifaces_v6.join('", "')}" } return`);
      }
      if (macBpV4.length > 0) lines.push('    ip protocol tcp ether saddr @aios_mac_bp_v4 return');
      if (macBpV6.length > 0) lines.push('    ip6 nexthdr tcp ether saddr @aios_mac_bp_v6 return');
      if (macTpV4.length > 0 && tp.tproxy_port_tcp_v4 > 0) lines.push('    ip protocol tcp ether saddr @aios_mac_tp_v4 goto redirect_filter');
      if (macTpV6.length > 0 && tp.tproxy_port_tcp_v6 > 0) lines.push('    ip6 nexthdr tcp ether saddr @aios_mac_tp_v6 goto redirect_filter');
      if (tp.tproxy_ifaces_v4.length > 0 && tp.tproxy_port_tcp_v4 > 0) {
        lines.push(`    ip protocol tcp iifname { "${tp.tproxy_ifaces_v4.join('", "')}" } goto redirect_filter`);
      }
      if (tp.tproxy_ifaces_v6.length > 0 && tp.tproxy_port_tcp_v6 > 0) {
        lines.push(`    ip6 nexthdr tcp iifname { "${tp.tproxy_ifaces_v6.join('", "')}" } goto redirect_filter`);
      }
      lines.push('  }');
      lines.push('  chain nat_output {');
      lines.push(`    type nat hook output priority dstnat ${prio}; policy accept;`);
      lines.push(`    meta mark { ${tp.outbound_mark}, ${tp.dns_mark} } return`);
      lines.push('    meta l4proto tcp jump redirect_filter');
      lines.push('  }');
    } else {
      lines.push('  chain tproxy_prerouting {');
      lines.push(`    type filter hook prerouting priority filter ${prio}; policy accept;`);
      lines.push(`    meta mark != ${tp.tproxy_mark} accept`);
      lines.push('    fib daddr type local accept');
      if (tp.fakedns_enabled) {
        if (fTcp4 > 0) lines.push(`    ip protocol tcp ip daddr ${tp.fakedns_pool_v4} tproxy ip to :${fTcp4} accept`);
        if (fUdp4 > 0) lines.push(`    ip protocol udp ip daddr ${tp.fakedns_pool_v4} tproxy ip to :${fUdp4} accept`);
        if (fTcp6 > 0) lines.push(`    ip6 nexthdr tcp ip6 daddr ${tp.fakedns_pool_v6} tproxy ip6 to :${fTcp6} accept`);
        if (fUdp6 > 0) lines.push(`    ip6 nexthdr udp ip6 daddr ${tp.fakedns_pool_v6} tproxy ip6 to :${fUdp6} accept`);
      }
      if (tp.tproxy_port_tcp_v4 > 0) lines.push(`    ip protocol tcp tproxy ip to :${tp.tproxy_port_tcp_v4} accept`);
      if (tp.tproxy_port_udp_v4 > 0) lines.push(`    ip protocol udp tproxy ip to :${tp.tproxy_port_udp_v4} accept`);
      if (tp.tproxy_port_tcp_v6 > 0) lines.push(`    ip6 nexthdr tcp tproxy ip6 to :${tp.tproxy_port_tcp_v6} accept`);
      if (tp.tproxy_port_udp_v6 > 0) lines.push(`    ip6 nexthdr udp tproxy ip6 to :${tp.tproxy_port_udp_v6} accept`);
      lines.push('    accept');
      lines.push('  }');
      lines.push('  chain prerouting {');
      lines.push(`    type filter hook prerouting priority mangle ${prio}; policy accept;`);
      lines.push('    fib daddr type local accept');
      if (tp.dynamic_direct_enabled) {
        lines.push(`    ip protocol { tcp, udp } ct mark ${tp.ct_direct_mark} update @aios_dd_v4 { ip daddr timeout ${tp.dynamic_direct_timeout}s } accept`);
        lines.push(`    ip6 nexthdr { tcp, udp } ct mark ${tp.ct_direct_mark} update @aios_dd_v6 { ip6 daddr timeout ${tp.dynamic_direct_timeout}s } accept`);
      }
      lines.push(`    meta mark ${tp.tproxy_mark} accept`);
      if (tp.fakedns_enabled) {
        if (fv4Expr) lines.push(`    ip protocol ${fv4Expr} ip daddr ${tp.fakedns_pool_v4} meta mark set ${tp.tproxy_mark} accept`);
        if (fv6Expr) lines.push(`    ip6 nexthdr ${fv6Expr} ip6 daddr ${tp.fakedns_pool_v6} meta mark set ${tp.tproxy_mark} accept`);
      }
      if (tp.bypass_ifaces_v4.length > 0 && v4Expr) {
        lines.push(`    ip protocol ${v4Expr} iifname { "${tp.bypass_ifaces_v4.join('", "')}" } accept`);
      }
      if (tp.bypass_ifaces_v6.length > 0 && v6Expr) {
        lines.push(`    ip6 nexthdr ${v6Expr} iifname { "${tp.bypass_ifaces_v6.join('", "')}" } accept`);
      }
      if (macBpV4.length > 0 && v4Expr) lines.push(`    ip protocol ${v4Expr} ether saddr @aios_mac_bp_v4 accept`);
      if (macBpV6.length > 0 && v6Expr) lines.push(`    ip6 nexthdr ${v6Expr} ether saddr @aios_mac_bp_v6 accept`);
      if (macTpV4.length > 0 && v4Expr) lines.push(`    ip protocol ${v4Expr} ether saddr @aios_mac_tp_v4 goto lan_filter`);
      if (macTpV6.length > 0 && v6Expr) lines.push(`    ip6 nexthdr ${v6Expr} ether saddr @aios_mac_tp_v6 goto lan_filter`);
      if (tp.tproxy_ifaces_v4.length > 0 && v4Expr) {
        lines.push(`    ip protocol ${v4Expr} iifname { "${tp.tproxy_ifaces_v4.join('", "')}" } goto lan_filter`);
      }
      if (tp.tproxy_ifaces_v6.length > 0 && v6Expr) {
        lines.push(`    ip6 nexthdr ${v6Expr} iifname { "${tp.tproxy_ifaces_v6.join('", "')}" } goto lan_filter`);
      }
      lines.push('  }');
      lines.push('  chain output {');
      lines.push(`    type route hook output priority mangle ${prio}; policy accept;`);
      lines.push('    ct direction reply accept');
      lines.push('    fib daddr type local accept');
      if (tp.dynamic_direct_enabled) {
        lines.push(`    ip protocol { tcp, udp } meta mark ${tp.dynamic_direct_mark} update @aios_dd_v4 { ip daddr timeout ${tp.dynamic_direct_timeout}s } accept`);
        lines.push(`    ip6 nexthdr { tcp, udp } meta mark ${tp.dynamic_direct_mark} update @aios_dd_v6 { ip6 daddr timeout ${tp.dynamic_direct_timeout}s } accept`);
      }
      lines.push(`    meta mark { ${tp.outbound_mark}, ${tp.dns_mark} } accept`);
      if (tp.fakedns_enabled) {
        if (fv4Expr) lines.push(`    ip protocol ${fv4Expr} ip daddr ${tp.fakedns_pool_v4} meta mark set ${tp.tproxy_mark} accept`);
        if (fv6Expr) lines.push(`    ip6 nexthdr ${fv6Expr} ip6 daddr ${tp.fakedns_pool_v6} meta mark set ${tp.tproxy_mark} accept`);
      }
      if (v4Expr) lines.push(`    ip protocol ${v4Expr} goto lan_filter`);
      if (v6Expr) lines.push(`    ip6 nexthdr ${v6Expr} goto lan_filter`);
      lines.push('  }');
      lines.push('  chain lan_filter {');
      if (fwV4.length > 0) lines.push(`    ip daddr @aios_fw_v4 meta mark set ${tp.tproxy_mark} accept`);
      if (fwV6.length > 0) lines.push(`    ip6 daddr @aios_fw_v6 meta mark set ${tp.tproxy_mark} accept`);
      lines.push('    ip daddr @aios_gateway_v4 accept');
      lines.push('    ip6 daddr @aios_gateway_v6 accept');
      if (bpV4.length > 0) lines.push('    ip daddr @aios_bp_v4 accept');
      if (bpV6.length > 0) lines.push('    ip6 daddr @aios_bp_v6 accept');
      lines.push('    ip daddr @aios_reserved_v4 accept');
      lines.push('    ip6 daddr @aios_reserved_v6 accept');
      if (tp.dynamic_direct_enabled) {
        lines.push(`    ip daddr @aios_dd_v4 ct mark set ${tp.ct_direct_mark} accept`);
        lines.push(`    ip6 daddr @aios_dd_v6 ct mark set ${tp.ct_direct_mark} accept`);
      }
      lines.push(`    meta mark set ${tp.tproxy_mark} accept`);
      lines.push('  }');
    }
    if (tp.fakedns_enabled && tp.fakedns_ping_response) {
      lines.push(
        `  chain fakedns_ping_prerouting { type nat hook prerouting priority dstnat ${prio}; policy accept;`,
        `    ip daddr ${tp.fakedns_pool_v4} icmp type echo-request redirect`,
        `    ip6 daddr ${tp.fakedns_pool_v6} icmpv6 type echo-request redirect`,
        '  }',
        `  chain fakedns_ping_output { type nat hook output priority dstnat ${prio}; policy accept;`,
        `    ip daddr ${tp.fakedns_pool_v4} icmp type echo-request redirect`,
        `    ip6 daddr ${tp.fakedns_pool_v6} icmpv6 type echo-request redirect`,
        '  }'
      );
    }
    lines.push('}');
    return { backend, rules: lines.join('\n') + '\n', changes };
  }

  // fw3 iptables
  changes.push({
    scope: 'iptables',
    action: 'create',
    target:
      tp.tproxy_mode === 'redirect'
        ? 'nat/AIOS_REDIRECT + AIOS_REDIRECT_PRE'
        : 'mangle/AIOS_PREROUTING + AIOS_OUTPUT (IPv4 & IPv6)',
    detail: '仅挂接独立 AIOS_* 链，清理时不 flush 全局表'
  });
  changes.push({
    scope: 'ipset',
    action: 'create',
    target: 'aios_reserved_v4/v6, aios_bp_v4/v6, aios_fw_v4/v6',
    detail: '保留网段、WAN 直连绕过与强制代理集合'
  });

  const iptLines: string[] = [];
  if (tp.tproxy_mode === 'redirect') {
    iptLines.push(
      '# Expected legacy firewall3 (iptables nat REDIRECT)',
      'iptables -t nat -N AIOS_REDIRECT',
      'iptables -t nat -A AIOS_REDIRECT -m addrtype --dst-type LOCAL -j RETURN',
      `iptables -t nat -A AIOS_REDIRECT -m mark --mark ${tp.outbound_mark} -j RETURN`,
      `iptables -t nat -A AIOS_REDIRECT -m mark --mark ${tp.dns_mark} -j RETURN`
    );
    if (tp.tproxy_port_tcp_v4 > 0) {
      iptLines.push(
        `iptables -t nat -A AIOS_REDIRECT -p tcp -m set --match-set aios_fw_v4 dst -j REDIRECT --to-ports ${tp.tproxy_port_tcp_v4}`
      );
    }
    iptLines.push(
      'iptables -t nat -A AIOS_REDIRECT -m set --match-set aios_reserved_v4 dst -j RETURN',
      'iptables -t nat -A AIOS_REDIRECT -m set --match-set aios_bp_v4 dst -j RETURN'
    );
    if (tp.tproxy_port_tcp_v4 > 0) {
      iptLines.push(`iptables -t nat -A AIOS_REDIRECT -p tcp -j REDIRECT --to-ports ${tp.tproxy_port_tcp_v4}`);
    }
    iptLines.push('iptables -t nat -N AIOS_REDIRECT_PRE');
    for (const iface of tp.bypass_ifaces_v4) {
      iptLines.push(`iptables -t nat -A AIOS_REDIRECT_PRE -i ${iface} -j RETURN`);
    }
    iptLines.push('iptables -t nat -A AIOS_REDIRECT_PRE -j AIOS_REDIRECT');
    if (tp.tproxy_ifaces_v4.length > 0) {
      for (const iface of tp.tproxy_ifaces_v4) {
        iptLines.push(`iptables -t nat -A PREROUTING -i ${iface} -p tcp -j AIOS_REDIRECT_PRE`);
      }
    } else {
      iptLines.push('iptables -t nat -A PREROUTING -p tcp -j AIOS_REDIRECT_PRE');
    }
    iptLines.push('iptables -t nat -A OUTPUT -p tcp -j AIOS_REDIRECT');
  } else {
    iptLines.push(
      '# Expected legacy firewall3 (iptables + ip6tables mangle TPROXY)',
      `ip rule add fwmark ${tp.tproxy_mark} lookup ${tp.route_table}`,
      `ip route add local default dev lo table ${tp.route_table}`,
      `ip -6 rule add fwmark ${tp.tproxy_mark} lookup ${tp.route_table}`,
      `ip -6 route add local default dev lo table ${tp.route_table}`
    );
    if (tp.tproxy_port_tcp_v4 > 0 || tp.tproxy_port_udp_v4 > 0) {
      iptLines.push(
        'iptables -t mangle -N AIOS_PREROUTING_LOCAL',
        'iptables -t mangle -A AIOS_PREROUTING_LOCAL -m addrtype --dst-type LOCAL -j RETURN'
      );
      if (tp.tproxy_port_tcp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_PREROUTING_LOCAL -p tcp -j TPROXY --on-port ${tp.tproxy_port_tcp_v4} --tproxy-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_PREROUTING_LOCAL -p udp -j TPROXY --on-port ${tp.tproxy_port_udp_v4} --tproxy-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(
        'iptables -t mangle -N AIOS_PREROUTING',
        'iptables -t mangle -A AIOS_PREROUTING -m addrtype --dst-type LOCAL -j RETURN'
      );
      for (const iface of tp.bypass_ifaces_v4) {
        iptLines.push(`iptables -t mangle -A AIOS_PREROUTING -i ${iface} -j RETURN`);
      }
      if (tp.tproxy_port_tcp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_PREROUTING -p tcp -m set --match-set aios_fw_v4 dst -j TPROXY --on-port ${tp.tproxy_port_tcp_v4} --tproxy-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_PREROUTING -p udp -m set --match-set aios_fw_v4 dst -j TPROXY --on-port ${tp.tproxy_port_udp_v4} --tproxy-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(
        'iptables -t mangle -A AIOS_PREROUTING -m set --match-set aios_reserved_v4 dst -j RETURN',
        'iptables -t mangle -A AIOS_PREROUTING -m set --match-set aios_bp_v4 dst -j RETURN'
      );
      if (tp.tproxy_port_tcp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port ${tp.tproxy_port_tcp_v4} --tproxy-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port ${tp.tproxy_port_udp_v4} --tproxy-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(
        'iptables -t mangle -N AIOS_OUTPUT',
        'iptables -t mangle -A AIOS_OUTPUT -m conntrack --ctdir REPLY -j RETURN',
        'iptables -t mangle -A AIOS_OUTPUT -m addrtype --dst-type LOCAL -j RETURN',
        `iptables -t mangle -A AIOS_OUTPUT -m mark --mark ${tp.outbound_mark} -j RETURN`,
        `iptables -t mangle -A AIOS_OUTPUT -m mark --mark ${tp.dns_mark} -j RETURN`
      );
      if (tp.tproxy_port_tcp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_OUTPUT -p tcp -m set --match-set aios_fw_v4 dst -j MARK --set-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_OUTPUT -p udp -m set --match-set aios_fw_v4 dst -j MARK --set-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(
        'iptables -t mangle -A AIOS_OUTPUT -m set --match-set aios_reserved_v4 dst -j RETURN',
        'iptables -t mangle -A AIOS_OUTPUT -m set --match-set aios_bp_v4 dst -j RETURN'
      );
      if (tp.tproxy_port_tcp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_OUTPUT -p tcp -j MARK --set-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v4 > 0) {
        iptLines.push(`iptables -t mangle -A AIOS_OUTPUT -p udp -j MARK --set-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(`iptables -t mangle -A PREROUTING -m mark --mark ${tp.tproxy_mark} -j AIOS_PREROUTING_LOCAL`);
      if (tp.tproxy_ifaces_v4.length > 0) {
        for (const iface of tp.tproxy_ifaces_v4) {
          iptLines.push(`iptables -t mangle -A PREROUTING -i ${iface} -j AIOS_PREROUTING`);
        }
      } else {
        iptLines.push('iptables -t mangle -A PREROUTING -j AIOS_PREROUTING');
      }
      iptLines.push('iptables -t mangle -A OUTPUT -j AIOS_OUTPUT');
    }
    if (tp.tproxy_port_tcp_v6 > 0 || tp.tproxy_port_udp_v6 > 0) {
      iptLines.push(
        'ip6tables -t mangle -N AIOS_PREROUTING_LOCAL',
        'ip6tables -t mangle -A AIOS_PREROUTING_LOCAL -m addrtype --dst-type LOCAL -j RETURN'
      );
      if (tp.tproxy_port_tcp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_PREROUTING_LOCAL -p tcp -j TPROXY --on-port ${tp.tproxy_port_tcp_v6} --tproxy-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_PREROUTING_LOCAL -p udp -j TPROXY --on-port ${tp.tproxy_port_udp_v6} --tproxy-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(
        'ip6tables -t mangle -N AIOS_PREROUTING',
        'ip6tables -t mangle -A AIOS_PREROUTING -m addrtype --dst-type LOCAL -j RETURN'
      );
      for (const iface of tp.bypass_ifaces_v6) {
        iptLines.push(`ip6tables -t mangle -A AIOS_PREROUTING -i ${iface} -j RETURN`);
      }
      if (tp.tproxy_port_tcp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_PREROUTING -p tcp -m set --match-set aios_fw_v6 dst -j TPROXY --on-port ${tp.tproxy_port_tcp_v6} --tproxy-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_PREROUTING -p udp -m set --match-set aios_fw_v6 dst -j TPROXY --on-port ${tp.tproxy_port_udp_v6} --tproxy-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(
        'ip6tables -t mangle -A AIOS_PREROUTING -m set --match-set aios_reserved_v6 dst -j RETURN',
        'ip6tables -t mangle -A AIOS_PREROUTING -m set --match-set aios_bp_v6 dst -j RETURN'
      );
      if (tp.tproxy_port_tcp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port ${tp.tproxy_port_tcp_v6} --tproxy-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port ${tp.tproxy_port_udp_v6} --tproxy-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(
        'ip6tables -t mangle -N AIOS_OUTPUT',
        'ip6tables -t mangle -A AIOS_OUTPUT -m conntrack --ctdir REPLY -j RETURN',
        'ip6tables -t mangle -A AIOS_OUTPUT -m addrtype --dst-type LOCAL -j RETURN',
        `ip6tables -t mangle -A AIOS_OUTPUT -m mark --mark ${tp.outbound_mark} -j RETURN`,
        `ip6tables -t mangle -A AIOS_OUTPUT -m mark --mark ${tp.dns_mark} -j RETURN`
      );
      if (tp.tproxy_port_tcp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_OUTPUT -p tcp -m set --match-set aios_fw_v6 dst -j MARK --set-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_OUTPUT -p udp -m set --match-set aios_fw_v6 dst -j MARK --set-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(
        'ip6tables -t mangle -A AIOS_OUTPUT -m set --match-set aios_reserved_v6 dst -j RETURN',
        'ip6tables -t mangle -A AIOS_OUTPUT -m set --match-set aios_bp_v6 dst -j RETURN'
      );
      if (tp.tproxy_port_tcp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_OUTPUT -p tcp -j MARK --set-mark ${tp.tproxy_mark}`);
      }
      if (tp.tproxy_port_udp_v6 > 0) {
        iptLines.push(`ip6tables -t mangle -A AIOS_OUTPUT -p udp -j MARK --set-mark ${tp.tproxy_mark}`);
      }
      iptLines.push(`ip6tables -t mangle -A PREROUTING -m mark --mark ${tp.tproxy_mark} -j AIOS_PREROUTING_LOCAL`);
      if (tp.tproxy_ifaces_v6.length > 0) {
        for (const iface of tp.tproxy_ifaces_v6) {
          iptLines.push(`ip6tables -t mangle -A PREROUTING -i ${iface} -j AIOS_PREROUTING`);
        }
      } else {
        iptLines.push('ip6tables -t mangle -A PREROUTING -j AIOS_PREROUTING');
      }
      iptLines.push('ip6tables -t mangle -A OUTPUT -j AIOS_OUTPUT');
    }
  }

  return { backend, rules: iptLines.join('\n') + '\n', changes };
}

export function computeLineDiff(beforeText: string, afterText: string): DiffLine[] {
  const a = beforeText.trim() ? beforeText.trim().split('\n') : [];
  const b = afterText.trim() ? afterText.trim().split('\n') : [];
  const m = a.length;
  const n = b.length;

  if (m === 0) return b.map((text) => ({ kind: 'add', text }));
  if (n === 0) return a.map((text) => ({ kind: 'del', text }));

  if (m * n > 2_000_000) {
    const bCounts = new Map<string, number>();
    for (const line of b) bCounts.set(line, (bCounts.get(line) || 0) + 1);
    const aCounts = new Map<string, number>();
    for (const line of a) aCounts.set(line, (aCounts.get(line) || 0) + 1);
    const out: DiffLine[] = [];
    for (const line of a) {
      const rem = bCounts.get(line) || 0;
      if (rem > 0) bCounts.set(line, rem - 1);
      else out.push({ kind: 'del', text: line });
    }
    for (const line of b) {
      const rem = aCounts.get(line) || 0;
      if (rem > 0) {
        aCounts.set(line, rem - 1);
        out.push({ kind: 'same', text: line });
      } else {
        out.push({ kind: 'add', text: line });
      }
    }
    return out;
  }

  const dp: Uint32Array[] = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      if (a[i] === b[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = dp[i + 1][j] >= dp[i][j + 1] ? dp[i + 1][j] : dp[i][j + 1];
      }
    }
  }

  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) {
      out.push({ kind: 'same', text: a[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ kind: 'del', text: a[i] });
      i++;
    } else {
      out.push({ kind: 'add', text: b[j] });
      j++;
    }
  }
  while (i < m) out.push({ kind: 'del', text: a[i++] });
  while (j < n) out.push({ kind: 'add', text: b[j++] });
  return out;
}
