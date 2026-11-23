import type { AiosConfig, AiosPreset } from '@/schema/types';

export interface PresetDiffEntry {
  section: string;
  before: string;
  after: string;
}

export function cloneConfig(cfg: AiosConfig): AiosConfig {
  return JSON.parse(JSON.stringify(cfg)) as AiosConfig;
}

export function slugifyPresetId(name: string): string {
  const base = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fa5_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  const ascii = base.replace(/[^a-z0-9_-]/g, '');
  const stamp = Date.now().toString(36);
  return `user-${ascii ? ascii.slice(0, 32) : 'preset'}-${stamp}`;
}

export function createUserPresetFromConfig(
  current: AiosConfig,
  meta: { name: string; description?: string; tags?: string[] }
): AiosPreset {
  const now = new Date().toISOString();
  return {
    id: slugifyPresetId(meta.name),
    name: meta.name.trim(),
    description: (meta.description || '从当前配置保存的自定义预设').trim(),
    builtin: false,
    recommendedCore: current.general.core_type,
    createdAt: now,
    updatedAt: now,
    tags: meta.tags && meta.tags.length > 0 ? meta.tags : ['custom', current.general.core_type],
    config: cloneConfig(current)
  };
}

export function computePresetDiff(current: AiosConfig, target: AiosConfig): PresetDiffEntry[] {
  const diffs: PresetDiffEntry[] = [];

  if (current.general.core_type !== target.general.core_type) {
    diffs.push({
      section: '核心类型 (core_type)',
      before: current.general.core_type,
      after: target.general.core_type
    });
  }
  if (current.transparent_proxy.enabled !== target.transparent_proxy.enabled) {
    diffs.push({
      section: '透明代理开关',
      before: current.transparent_proxy.enabled ? '启用' : '关闭',
      after: target.transparent_proxy.enabled ? '启用' : '关闭'
    });
  }
  if (current.transparent_proxy.fakedns_enabled !== target.transparent_proxy.fakedns_enabled) {
    diffs.push({
      section: 'FakeDNS',
      before: current.transparent_proxy.fakedns_enabled ? '启用' : '关闭',
      after: target.transparent_proxy.fakedns_enabled ? '启用' : '关闭'
    });
  }
  if (
    current.transparent_proxy.dynamic_direct_enabled !==
    target.transparent_proxy.dynamic_direct_enabled
  ) {
    diffs.push({
      section: 'Dynamic Direct 动态直连',
      before: current.transparent_proxy.dynamic_direct_enabled ? '启用' : '关闭',
      after: target.transparent_proxy.dynamic_direct_enabled ? '启用' : '关闭'
    });
  }
  if (current.inbounds.length !== target.inbounds.length) {
    diffs.push({
      section: '入站规则数量 (Inbounds)',
      before: `${current.inbounds.length} 条`,
      after: `${target.inbounds.length} 条`
    });
  }
  if (current.outbounds.length !== target.outbounds.length) {
    diffs.push({
      section: '出站节点数量 (Outbounds)',
      before: `${current.outbounds.length} 条`,
      after: `${target.outbounds.length} 条`
    });
  }
  if (current.routing_rules.length !== target.routing_rules.length) {
    diffs.push({
      section: '路由规则数量 (Routing Rules)',
      before: `${current.routing_rules.length} 条`,
      after: `${target.routing_rules.length} 条`
    });
  }
  if (current.dns_servers.length !== target.dns_servers.length) {
    diffs.push({
      section: 'DNS 服务器数量',
      before: `${current.dns_servers.length} 个`,
      after: `${target.dns_servers.length} 个`
    });
  }

  return diffs;
}

export function applyPresetToConfig(
  current: AiosConfig,
  preset: AiosPreset,
  options: { preserveOutbounds?: boolean } = {}
): AiosConfig {
  const next = cloneConfig(preset.config);
  // Preserve host runtime & multi-version environment fields so applying a preset
  // never wipes the user's selected binary slot, storage dir, or target version.
  next.general.core_bin = current.general.core_bin;
  next.general.bins_dir = current.general.bins_dir;
  next.general.asset_location = current.general.asset_location;
  next.general.target_version = current.general.target_version;
  next.general.v2ray_format = current.general.v2ray_format;
  if (preset.recommendedCore === 'auto') {
    next.general.core_type = current.general.core_type;
  }

  if (options.preserveOutbounds) {
    const userProxyOutbounds = current.outbounds.filter(
      (o) => !['freedom', 'blackhole', 'dns', 'loopback'].includes(o.protocol)
    );
    const existingTags = new Set(next.outbounds.map((o) => o.tag));
    const preserved = userProxyOutbounds
      .filter((ob) => !existingTags.has(ob.tag))
      .map((ob) => JSON.parse(JSON.stringify(ob)));
    next.outbounds = [...preserved, ...next.outbounds];
  }
  return next;
}
