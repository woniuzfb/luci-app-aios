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
    const v4Protos = [tp.tproxy_port_tcp_v4 > 0 ? 'tcp' : '', tp.tproxy_port_udp_v4 > 0 ? 'udp' : ''].filter(Boolean);
    const v6Protos = [tp.tproxy_port_tcp_v6 > 0 ? 'tcp' : '', tp.tproxy_port_udp_v6 > 0 ? 'udp' : ''].filter(Boolean);
    const v4Expr = v4Protos.length === 2 ? '{ tcp, udp }' : v4Protos[0] || '';
    const v6Expr = v6Protos.length === 2 ? '{ tcp, udp }' : v6Protos[0] || '';

    const lines: string[] = [
      '# Isolated nftables table managed exclusively by luci-app-aios',
      'table inet aios {',
      `  # Mode: ${tp.tproxy_mode} | Marks: tproxy=${tp.tproxy_mark}, dd=${tp.dynamic_direct_mark}, outbound=${tp.outbound_mark}, dns=${tp.dns_mark}, ct_dd=${tp.ct_direct_mark}`,
      '  set aios_reserved_v4 { type ipv4_addr; flags interval; }',
      '  set aios_reserved_v6 { type ipv6_addr; flags interval; }',
      '  set aios_gateway_v4  { type ipv4_addr; flags interval; }',
      '  set aios_gateway_v6  { type ipv6_addr; flags interval; }'
    ];
    if (bpV4.length > 0) lines.push(`  set aios_bp_v4 { type ipv4_addr; flags interval; elements = { ${bpV4.join(', ')} } }`);
    if (bpV6.length > 0) lines.push(`  set aios_bp_v6 { type ipv6_addr; flags interval; elements = { ${bpV6.join(', ')} } }`);
    if (fwV4.length > 0) lines.push(`  set aios_fw_v4 { type ipv4_addr; flags interval; elements = { ${fwV4.join(', ')} } }`);
    if (fwV6.length > 0) lines.push(`  set aios_fw_v6 { type ipv6_addr; flags interval; elements = { ${fwV6.join(', ')} } }`);
    if (tp.dynamic_direct_enabled) {
      lines.push(`  set aios_dd_v4 { type ipv4_addr; flags dynamic,timeout; timeout ${tp.dynamic_direct_timeout}s; }`);
      lines.push(`  set aios_dd_v6 { type ipv6_addr; flags dynamic,timeout; timeout ${tp.dynamic_direct_timeout}s; }`);
    }
    if (tp.tproxy_mode === 'redirect') {
      lines.push('  chain redirect_filter {');
      lines.push('    fib daddr type local return');
      if (tp.tproxy_port_tcp_v4 > 0) lines.push(`    ip protocol tcp redirect to :${tp.tproxy_port_tcp_v4}`);
      if (tp.tproxy_port_tcp_v6 > 0) lines.push(`    ip6 nexthdr tcp redirect to :${tp.tproxy_port_tcp_v6}`);
      lines.push('  }');
      lines.push('  chain nat_prerouting {');
      lines.push(`    type nat hook prerouting priority dstnat ${prio}; policy accept;`);
      if (tp.tproxy_ifaces_v4.length > 0 && tp.tproxy_port_tcp_v4 > 0) {
        lines.push(`    ip protocol tcp iifname { "${tp.tproxy_ifaces_v4.join('", "')}" } jump redirect_filter`);
      }
      if (tp.tproxy_ifaces_v6.length > 0 && tp.tproxy_port_tcp_v6 > 0) {
        lines.push(`    ip6 nexthdr tcp iifname { "${tp.tproxy_ifaces_v6.join('", "')}" } jump redirect_filter`);
      }
      lines.push('  }');
    } else {
      lines.push('  chain tproxy_prerouting {');
      lines.push(`    type filter hook prerouting priority filter ${prio}; policy accept;`);
      lines.push(`    meta mark != ${tp.tproxy_mark} accept`);
      lines.push('    fib daddr type local accept');
      if (tp.fakedns_enabled) {
        if (tp.fakedns_port_tcp_v4 > 0) lines.push(`    ip protocol tcp ip daddr ${tp.fakedns_pool_v4} tproxy ip to :${tp.fakedns_port_tcp_v4} accept`);
        if (tp.fakedns_port_udp_v4 > 0) lines.push(`    ip protocol udp ip daddr ${tp.fakedns_pool_v4} tproxy ip to :${tp.fakedns_port_udp_v4} accept`);
        if (tp.fakedns_port_tcp_v6 > 0) lines.push(`    ip6 nexthdr tcp ip6 daddr ${tp.fakedns_pool_v6} tproxy ip6 to :${tp.fakedns_port_tcp_v6} accept`);
        if (tp.fakedns_port_udp_v6 > 0) lines.push(`    ip6 nexthdr udp ip6 daddr ${tp.fakedns_pool_v6} tproxy ip6 to :${tp.fakedns_port_udp_v6} accept`);
      }
      if (tp.tproxy_port_tcp_v4 > 0) lines.push(`    ip protocol tcp tproxy ip to :${tp.tproxy_port_tcp_v4} accept`);
      if (tp.tproxy_port_udp_v4 > 0) lines.push(`    ip protocol udp tproxy ip to :${tp.tproxy_port_udp_v4} accept`);
      if (tp.tproxy_port_tcp_v6 > 0) lines.push(`    ip6 nexthdr tcp tproxy ip6 to :${tp.tproxy_port_tcp_v6} accept`);
      if (tp.tproxy_port_udp_v6 > 0) lines.push(`    ip6 nexthdr udp tproxy ip6 to :${tp.tproxy_port_udp_v6} accept`);
      lines.push('  }');
      lines.push('  chain prerouting {');
      lines.push(`    type filter hook prerouting priority mangle ${prio}; policy accept;`);
      lines.push('    fib daddr type local accept');
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
      lines.push(`    meta mark { ${tp.outbound_mark}, ${tp.dns_mark} } accept`);
      if (v4Expr) lines.push(`    ip protocol ${v4Expr} goto lan_filter`);
      if (v6Expr) lines.push(`    ip6 nexthdr ${v6Expr} goto lan_filter`);
      lines.push('  }');
      lines.push('  chain lan_filter {');
      lines.push('    ip daddr @aios_gateway_v4 accept');
      lines.push('    ip6 daddr @aios_gateway_v6 accept');
      lines.push('    ip daddr @aios_reserved_v4 accept');
      lines.push('    ip6 daddr @aios_reserved_v6 accept');
      lines.push(`    meta mark set ${tp.tproxy_mark} accept`);
      lines.push('  }');
    }
    if (tp.fakedns_enabled && tp.fakedns_ping_response) {
      lines.push(`  chain fakedns_ping_prerouting { type nat hook prerouting priority dstnat ${prio}; policy accept; }`);
      lines.push('  chain fakedns_ping_output { type nat hook output priority -100; policy accept; }');
    }
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
      'iptables -t nat -A AIOS_REDIRECT -m set --match-set aios_reserved_v4 dst -j RETURN',
      `iptables -t nat -A AIOS_REDIRECT -p tcp -j REDIRECT --to-ports ${tp.tproxy_port_tcp_v4}`
    );
  } else {
    iptLines.push(
      '# Expected legacy firewall3 (iptables + ip6tables mangle TPROXY)',
      `ip rule add fwmark ${tp.tproxy_mark} lookup ${tp.route_table}`,
      `ip -6 rule add fwmark ${tp.tproxy_mark} lookup ${tp.route_table}`
    );
    if (tp.tproxy_port_tcp_v4 > 0) {
      iptLines.push(`iptables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port ${tp.tproxy_port_tcp_v4} --tproxy-mark ${tp.tproxy_mark}`);
      iptLines.push(`iptables -t mangle -A AIOS_OUTPUT -p tcp -j MARK --set-mark ${tp.tproxy_mark}`);
    }
    if (tp.tproxy_port_udp_v4 > 0) {
      iptLines.push(`iptables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port ${tp.tproxy_port_udp_v4} --tproxy-mark ${tp.tproxy_mark}`);
      iptLines.push(`iptables -t mangle -A AIOS_OUTPUT -p udp -j MARK --set-mark ${tp.tproxy_mark}`);
    }
    if (tp.tproxy_port_tcp_v6 > 0) {
      iptLines.push(`ip6tables -t mangle -A AIOS_PREROUTING -p tcp -j TPROXY --on-port ${tp.tproxy_port_tcp_v6} --tproxy-mark ${tp.tproxy_mark}`);
      iptLines.push(`ip6tables -t mangle -A AIOS_OUTPUT -p tcp -j MARK --set-mark ${tp.tproxy_mark}`);
    }
    if (tp.tproxy_port_udp_v6 > 0) {
      iptLines.push(`ip6tables -t mangle -A AIOS_PREROUTING -p udp -j TPROXY --on-port ${tp.tproxy_port_udp_v6} --tproxy-mark ${tp.tproxy_mark}`);
      iptLines.push(`ip6tables -t mangle -A AIOS_OUTPUT -p udp -j MARK --set-mark ${tp.tproxy_mark}`);
    }
  }

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
