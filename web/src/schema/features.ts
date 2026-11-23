import coreFeaturesSpec from '../../../packages/luci-app-aios/root/usr/share/aios/common/core_features.json';
import type { CoreType } from './types';
import type { V2RayFormat } from './capabilities';

export interface VersionFeatureRule {
  since?: string;
  removedIn?: string;
}

export interface VersionPreset {
  id: string;
  label: string;
  version: string;
}

export interface ResolvedXrayFeatures {
  core: 'xray';
  version: string;
  versionFallback: boolean;
  streamMethodKey: 'method' | 'network';
  flatOutbounds: boolean;
  inboundUsersKey: 'users' | 'legacy';
  hasLegacyReverse: boolean;
  hasTunInbound: boolean;
  hasHysteria: boolean;
  hasMasque: boolean;
}

export interface ResolvedV2RayFeatures {
  core: 'v2ray';
  format: V2RayFormat;
  version: string;
  versionFallback: boolean;
  hasJsonV5: boolean;
  hasV5ServicesTun: boolean;
  hasV4Services: boolean;
  hasShadowsocks2022: boolean;
  hasHysteria2: boolean;
  hasPacketEncodingStream: boolean;
}

export type ResolvedCoreFeatures = ResolvedXrayFeatures | ResolvedV2RayFeatures;

export const CORE_FEATURES_SPEC = coreFeaturesSpec;

export function parseCoreVersion(raw?: string | null): [number, number, number] | null {
  if (!raw || raw === 'auto') return null;
  const m = String(raw).match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

export function compareSemver(a: string, b: string): number {
  const pa = parseCoreVersion(a);
  const pb = parseCoreVersion(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

function evalRule(rule: VersionFeatureRule | undefined, ver: string): boolean {
  if (!rule) return false;
  if (rule.since && compareSemver(ver, rule.since) < 0) return false;
  if (rule.removedIn && compareSemver(ver, rule.removedIn) >= 0) return false;
  return true;
}

export function resolveCoreFeatures(
  core: 'xray',
  format?: V2RayFormat,
  version?: string | null
): ResolvedXrayFeatures;
export function resolveCoreFeatures(
  core: 'v2ray',
  format?: V2RayFormat,
  version?: string | null
): ResolvedV2RayFeatures;
export function resolveCoreFeatures(
  core: CoreType,
  format?: V2RayFormat,
  version?: string | null
): ResolvedCoreFeatures;
export function resolveCoreFeatures(
  core: CoreType,
  format: V2RayFormat = 'jsonv4',
  version?: string | null
): ResolvedCoreFeatures {
  if (core === 'xray') {
    const spec = coreFeaturesSpec.xray;
    const parsed = parseCoreVersion(version);
    const effective = parsed ? `${parsed[0]}.${parsed[1]}.${parsed[2]}` : spec.defaultVersion;
    const f = spec.features;
    return {
      core: 'xray',
      version: effective,
      versionFallback: !parsed,
      streamMethodKey: evalRule(f.streamMethodKey, effective) ? 'method' : 'network',
      flatOutbounds: evalRule(f.flatOutbounds, effective),
      inboundUsersKey: evalRule(f.inboundUsersKey, effective) ? 'users' : 'legacy',
      hasLegacyReverse: evalRule(f.legacyReverse, effective),
      hasTunInbound: evalRule(f.tunInbound, effective),
      hasHysteria: evalRule(f.hysteria, effective),
      hasMasque: evalRule(f.masque, effective)
    };
  }

  const spec = coreFeaturesSpec.v2ray;
  const parsed = parseCoreVersion(version);
  const effective = parsed ? `${parsed[0]}.${parsed[1]}.${parsed[2]}` : spec.defaultVersion;
  const f = spec.features;
  return {
    core: 'v2ray',
    format,
    version: effective,
    versionFallback: !parsed,
    hasJsonV5: evalRule(f.jsonv5, effective),
    hasV5ServicesTun: evalRule(f.v5ServicesTun, effective),
    hasV4Services: evalRule(f.v4Services, effective),
    hasShadowsocks2022: evalRule(f.shadowsocks2022, effective),
    hasHysteria2: evalRule(f.hysteria2, effective),
    hasPacketEncodingStream: evalRule(f.packetEncodingStream, effective)
  };
}

export function getVersionPresets(core: CoreType): VersionPreset[] {
  return core === 'xray' ? coreFeaturesSpec.xray.presets : coreFeaturesSpec.v2ray.presets;
}
