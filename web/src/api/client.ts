import type { AiosConfig, AiosPreset, CoreType } from '@/schema/types';
import { createDefaultConfig } from '@/schema/defaults';
import { parseUciDump, serializeConfigToUci, type UciRawDump } from '@/schema/uci';
import { renderExpectedFirewallRules } from '@/firewall/preview';

export interface CoreInfo {
  core_bin: string;
  binary_exists: boolean;
  core_type: CoreType | 'auto';
  version: string;
  core_version?: string;
  asset_location: string;
  has_geoip: boolean;
  has_geosite: boolean;
  has_ucode: boolean;
  detected_firewall: 'nftables' | 'iptables' | 'none';
}

export interface ServiceStatus {
  running: boolean;
  pid: string;
  rss_kb: number;
}

export interface PreflightResult {
  warnings: string[];
  route_table: string;
  tproxy_mark: string;
}

export interface FirewallStatus {
  backend: 'nftables' | 'iptables' | 'none';
  active: boolean;
  table_present: boolean;
  route_table: string;
  tproxy_mark: string;
  dynamic_direct_v4_count: number;
  dynamic_direct_v6_count: number;
  live_rules: string;
  rendered_file: string;
  ip_rules: string;
  ip_routes: string;
}

export interface ValidateResult {
  ok: boolean;
  output: string;
}

export interface StatsResponse {
  source: 'metrics' | 'api' | 'none';
  core: string;
  data: Record<string, unknown>;
}

export interface CoreSlot {
  id: string;
  source: 'system' | 'managed';
  core: CoreType;
  tag: string;
  version: string;
  path: string;
  active: boolean;
  removable: boolean;
}

export interface CoreListResult {
  bins_dir: string;
  active_bin: string;
  active_real: string;
  arch: string;
  avail_kb: number;
  has_unzip: boolean;
  has_sha256: boolean;
  has_downloader: boolean;
  slots: CoreSlot[];
}

export interface InstallCoreStatus {
  job_id?: string;
  state: 'idle' | 'queued' | 'running' | 'done' | 'error';
  core?: CoreType;
  tag?: string;
  progress: number;
  message: string;
  updated_at?: number;
}

export interface SwitchCoreResult {
  ok: boolean;
  core?: CoreType;
  version?: string;
  core_bin?: string;
  rolled_back?: boolean;
  error?: string;
}

export interface AiosApiClient {
  mode: 'ubus' | 'mock';
  getCoreInfo(): Promise<CoreInfo>;
  getServiceStatus(): Promise<ServiceStatus>;
  preflightCheck(): Promise<PreflightResult>;
  getFirewallStatus(): Promise<FirewallStatus>;
  firewallAction(action: 'apply' | 'flush' | 'refresh_gateway'): Promise<void>;
  validateConfig(configJson: string): Promise<ValidateResult>;
  getStats(): Promise<StatsResponse>;
  keyGen(kind: 'uuid' | 'x25519' | 'mldsa65' | 'vlessenc' | 'wg'): Promise<string>;
  loadConfig(): Promise<AiosConfig>;
  saveConfig(cfg: AiosConfig, compiledJson: string): Promise<void>;
  serviceAction(action: 'start' | 'stop' | 'restart' | 'reload'): Promise<void>;
  listUserPresets(): Promise<AiosPreset[]>;
  saveUserPreset(preset: AiosPreset): Promise<void>;
  deleteUserPreset(id: string): Promise<void>;
  readLog(): Promise<string>;
  listCores(): Promise<CoreListResult>;
  installCore(core: CoreType, tag: string, mirror?: string): Promise<{ ok: boolean; job_id?: string; error?: string }>;
  installStatus(): Promise<InstallCoreStatus>;
  switchCore(path: string, compiledJson?: string): Promise<SwitchCoreResult>;
  removeCore(id: string): Promise<{ ok: boolean; id?: string; error?: string }>;
}

const STORAGE_CONFIG_KEY = 'aios_mock_config_v3';
const STORAGE_PRESETS_KEY = 'aios_mock_presets_v3';

function getSessionFromUrl(): string {
  const hash = window.location.hash || '';
  const match = hash.match(/ubus_session=([^&]+)/);
  if (match) return decodeURIComponent(match[1]);
  return localStorage.getItem('aios_ubus_session') || '';
}

class UbusApiClient implements AiosApiClient {
  mode: 'ubus' = 'ubus';
  private rpcId = 1;
  constructor(private sessionId: string) {}

  private async call<T>(object: string, method: string, params: Record<string, unknown> = {}): Promise<T> {
    const res = await fetch('/ubus', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: this.rpcId++,
        method: 'call',
        params: [this.sessionId, object, method, params]
      })
    });
    const body = (await res.json()) as { result?: [number, T]; error?: { message: string } };
    if (body.error) throw new Error(body.error.message);
    if (!body.result || body.result[0] !== 0) {
      throw new Error(`ubus ${object}.${method} failed (code ${body.result?.[0] ?? -1})`);
    }
    return body.result[1];
  }

  getCoreInfo() {
    return this.call<CoreInfo>('luci.aios', 'coreInfo');
  }
  getServiceStatus() {
    return this.call<ServiceStatus>('luci.aios', 'serviceStatus');
  }
  preflightCheck() {
    return this.call<PreflightResult>('luci.aios', 'preflightCheck');
  }
  getFirewallStatus() {
    return this.call<FirewallStatus>('luci.aios', 'firewallInspect');
  }
  async firewallAction(action: 'apply' | 'flush' | 'refresh_gateway') {
    await this.call('luci.aios', 'firewallAction', { action });
  }
  validateConfig(configJson: string) {
    return this.call<ValidateResult>('luci.aios', 'validateConfig', { config: configJson });
  }
  getStats() {
    return this.call<StatsResponse>('luci.aios', 'stats');
  }
  async keyGen(kind: 'uuid' | 'x25519' | 'mldsa65' | 'vlessenc' | 'wg') {
    const res = await this.call<{ output: string }>('luci.aios', 'keyGen', { kind });
    return res.output || '';
  }

  /** Full bidirectional read from /etc/config/aios via ubus uci.get */
  async loadConfig(): Promise<AiosConfig> {
    const res = await this.call<{ values?: UciRawDump }>('uci', 'get', { config: 'aios' });
    if (res && res.values && Object.keys(res.values).length > 0) {
      return parseUciDump(res.values);
    }
    return createDefaultConfig();
  }

  /** Full bidirectional sync to /etc/config/aios (all sections) + precompiled JSON fallback */
  async saveConfig(cfg: AiosConfig, compiledJson: string): Promise<void> {
    const existing = await this.call<{ values?: UciRawDump }>('uci', 'get', { config: 'aios' });
    const existingNames = Object.keys(existing.values || {});
    const targetSections = serializeConfigToUci(cfg);
    const targetNames = new Set(targetSections.map((s) => s.name));

    // 1. Delete removed sections from /etc/config/aios
    for (const oldName of existingNames) {
      if (!targetNames.has(oldName)) {
        await this.call('uci', 'delete', { config: 'aios', section: oldName });
      }
    }

    // 2. Recreate/update all sections with full values
    for (const sec of targetSections) {
      if (existingNames.includes(sec.name)) {
        await this.call('uci', 'delete', { config: 'aios', section: sec.name });
      }
      await this.call('uci', 'add', {
        config: 'aios',
        type: sec.type,
        name: sec.name,
        values: sec.values
      });
    }

    // 3. Commit UCI and write precompiled JSON fallback for non-ucode legacy OpenWrt
    await this.call('uci', 'commit', { config: 'aios' });
    await this.call('luci.aios', 'writeCompiledConfig', { content: compiledJson });
  }

  async serviceAction(action: 'start' | 'stop' | 'restart' | 'reload') {
    await this.call('luci.aios', 'serviceAction', { action });
  }
  async listUserPresets(): Promise<AiosPreset[]> {
    const res = await this.call<{ presets: AiosPreset[] }>('luci.aios', 'listPresets');
    return res.presets || [];
  }
  async saveUserPreset(preset: AiosPreset): Promise<void> {
    await this.call('luci.aios', 'savePreset', {
      id: preset.id,
      payload: JSON.stringify(preset)
    });
  }
  async deleteUserPreset(id: string): Promise<void> {
    await this.call('luci.aios', 'deletePreset', { id });
  }
  async readLog(): Promise<string> {
    const res = await this.call<{ content: string }>('luci.aios', 'readLog');
    return res.content || '';
  }
  listCores(): Promise<CoreListResult> {
    return this.call<CoreListResult>('luci.aios', 'listCores');
  }
  installCore(core: CoreType, tag: string, mirror = ''): Promise<{ ok: boolean; job_id?: string; error?: string }> {
    return this.call<{ ok: boolean; job_id?: string; error?: string }>('luci.aios', 'installCore', {
      core,
      tag,
      mirror
    });
  }
  installStatus(): Promise<InstallCoreStatus> {
    return this.call<InstallCoreStatus>('luci.aios', 'installStatus');
  }
  switchCore(path: string, compiledJson = ''): Promise<SwitchCoreResult> {
    return this.call<SwitchCoreResult>('luci.aios', 'switchCore', {
      path,
      compiled_json: compiledJson
    });
  }
  removeCore(id: string): Promise<{ ok: boolean; id?: string; error?: string }> {
    return this.call<{ ok: boolean; id?: string; error?: string }>('luci.aios', 'removeCore', { id });
  }
}

class LocalMockApiClient implements AiosApiClient {
  mode: 'mock' = 'mock';
  private running = true;
  private fwApplied = false;
  private fwLiveRules = '';

  async getCoreInfo(): Promise<CoreInfo> {
    return {
      core_bin: '/usr/bin/xray',
      binary_exists: true,
      core_type: 'xray',
      version: 'Xray 26.9.8 (local preview mode)',
      asset_location: '/usr/share/xray',
      has_geoip: true,
      has_geosite: true,
      has_ucode: true,
      detected_firewall: 'nftables'
    };
  }
  async getServiceStatus(): Promise<ServiceStatus> {
    return { running: this.running, pid: this.running ? '14820' : '', rss_kb: this.running ? 24576 : 0 };
  }
  async preflightCheck(): Promise<PreflightResult> {
    return { warnings: [], route_table: '166', tproxy_mark: '0x3a01' };
  }
  async getFirewallStatus(): Promise<FirewallStatus> {
    const cfg = await this.loadConfig();
    const tp = cfg.transparent_proxy;
    const active = this.fwApplied || (this.running && tp.enabled);
    const rendered = renderExpectedFirewallRules(cfg, 'nftables').rules;
    const live = active ? this.fwLiveRules || rendered : '';
    return {
      backend: tp.firewall_backend === 'auto' ? 'nftables' : tp.firewall_backend,
      active,
      table_present: active,
      route_table: String(tp.route_table),
      tproxy_mark: tp.tproxy_mark,
      dynamic_direct_v4_count: active && tp.dynamic_direct_enabled ? 42 : 0,
      dynamic_direct_v6_count: active && tp.dynamic_direct_enabled ? 9 : 0,
      live_rules: live,
      rendered_file: live,
      ip_rules: active
        ? `0:\tfrom all lookup local\n32765:\tfrom all fwmark ${tp.tproxy_mark} lookup ${tp.route_table}\n32766:\tfrom all lookup main`
        : `0:\tfrom all lookup local\n32766:\tfrom all lookup main`,
      ip_routes: active ? `local default dev lo scope host` : ''
    };
  }
  async firewallAction(action: 'apply' | 'flush' | 'refresh_gateway'): Promise<void> {
    if (action === 'flush') {
      this.fwApplied = false;
      this.fwLiveRules = '';
    } else if (action === 'apply') {
      const cfg = await this.loadConfig();
      this.fwApplied = true;
      this.fwLiveRules = renderExpectedFirewallRules(cfg, 'nftables').rules;
    }
  }
  async validateConfig(configJson: string): Promise<ValidateResult> {
    try {
      JSON.parse(configJson);
      return { ok: true, output: 'Configuration JSON syntax valid (local preview).' };
    } catch (e) {
      return { ok: false, output: String(e) };
    }
  }
  async getStats(): Promise<StatsResponse> {
    return {
      source: 'metrics',
      core: 'xray',
      data: {
        stats: {
          outbound: {
            direct: { uplink: 12485760, downlink: 184549376 },
            proxy: { uplink: 48234496, downlink: 892348224 }
          }
        }
      }
    };
  }
  async keyGen(kind: 'uuid' | 'x25519' | 'mldsa65' | 'vlessenc' | 'wg'): Promise<string> {
    if (kind === 'uuid' && typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
      return crypto.randomUUID();
    }
    return `[${kind}] 需在 OpenWrt 路由器上连接内核二进制生成`;
  }
  async loadConfig(): Promise<AiosConfig> {
    try {
      const raw = localStorage.getItem(STORAGE_CONFIG_KEY);
      if (raw) return JSON.parse(raw) as AiosConfig;
    } catch {
      // ignore
    }
    return createDefaultConfig();
  }
  async saveConfig(cfg: AiosConfig): Promise<void> {
    localStorage.setItem(STORAGE_CONFIG_KEY, JSON.stringify(cfg));
    if (cfg.transparent_proxy.enabled) {
      this.fwApplied = true;
      this.fwLiveRules = renderExpectedFirewallRules(cfg, 'nftables').rules;
    }
  }
  async serviceAction(action: 'start' | 'stop' | 'restart' | 'reload'): Promise<void> {
    this.running = action !== 'stop';
    if (!this.running) {
      this.fwApplied = false;
      this.fwLiveRules = '';
    }
  }
  async listUserPresets(): Promise<AiosPreset[]> {
    try {
      const raw = localStorage.getItem(STORAGE_PRESETS_KEY);
      return raw ? (JSON.parse(raw) as AiosPreset[]) : [];
    } catch {
      return [];
    }
  }
  async saveUserPreset(preset: AiosPreset): Promise<void> {
    const list = await this.listUserPresets();
    const idx = list.findIndex((p) => p.id === preset.id);
    if (idx >= 0) list[idx] = preset;
    else list.unshift(preset);
    localStorage.setItem(STORAGE_PRESETS_KEY, JSON.stringify(list));
  }
  async deleteUserPreset(id: string): Promise<void> {
    const list = (await this.listUserPresets()).filter((p) => p.id !== id);
    localStorage.setItem(STORAGE_PRESETS_KEY, JSON.stringify(list));
  }
  private mockActivePath = '/usr/bin/aios-xray';
  private mockSlots: CoreSlot[] = [
    {
      id: 'system:aios-xray',
      source: 'system',
      core: 'xray',
      tag: 'system',
      version: '26.11.9',
      path: '/usr/bin/aios-xray',
      active: true,
      removable: false
    },
    {
      id: 'system:aios-v2ray',
      source: 'system',
      core: 'v2ray',
      tag: 'system',
      version: '5.56.0',
      path: '/usr/bin/aios-v2ray',
      active: false,
      removable: false
    }
  ];
  private mockInstallStatus: InstallCoreStatus = { state: 'idle', progress: 0, message: '' };

  async readLog(): Promise<string> {
    return '[info] AIOS local preview mode — connect to OpenWrt /ubus for live logs.';
  }
  async listCores(): Promise<CoreListResult> {
    const cfg = await this.loadConfig();
    return {
      bins_dir: cfg.general.bins_dir || '',
      active_bin: this.mockActivePath,
      active_real: this.mockActivePath,
      arch: 'x86_64',
      avail_kb: 262144,
      has_unzip: true,
      has_sha256: true,
      has_downloader: true,
      slots: this.mockSlots.map((s) => ({
        ...s,
        active: s.path === this.mockActivePath,
        removable: s.source === 'managed' && s.path !== this.mockActivePath
      }))
    };
  }
  async installCore(core: CoreType, tag: string): Promise<{ ok: boolean; job_id?: string; error?: string }> {
    const cfg = await this.loadConfig();
    if (!cfg.general.bins_dir) {
      return { ok: false, error: 'bins_dir is not configured (local preview)' };
    }
    const id = `${core}-${tag}`;
    const ver = tag.replace(/^v/, '');
    const path = `${cfg.general.bins_dir}/${id}/${core}`;
    if (!this.mockSlots.some((s) => s.id === id)) {
      this.mockSlots.push({
        id,
        source: 'managed',
        core,
        tag,
        version: ver,
        path,
        active: false,
        removable: true
      });
    }
    this.mockInstallStatus = {
      job_id: `mock-${Date.now()}`,
      state: 'done',
      core,
      tag,
      progress: 100,
      message: `已模拟安装 ${core} ${tag} 至 ${path}`
    };
    return { ok: true, job_id: this.mockInstallStatus.job_id };
  }
  async installStatus(): Promise<InstallCoreStatus> {
    return this.mockInstallStatus;
  }
  async switchCore(path: string): Promise<SwitchCoreResult> {
    const slot = this.mockSlots.find((s) => s.path === path);
    if (!slot) return { ok: false, error: 'Slot not found (local preview)' };
    this.mockActivePath = slot.path;
    return { ok: true, core: slot.core, version: slot.version, core_bin: slot.path };
  }
  async removeCore(id: string): Promise<{ ok: boolean; id?: string; error?: string }> {
    const slot = this.mockSlots.find((s) => s.id === id);
    if (!slot) return { ok: false, error: 'Slot not found' };
    if (slot.path === this.mockActivePath) return { ok: false, error: 'Cannot remove active slot' };
    this.mockSlots = this.mockSlots.filter((s) => s.id !== id);
    return { ok: true, id };
  }
}

export function createApiClient(): AiosApiClient {
  const sid = typeof window !== 'undefined' ? getSessionFromUrl() : '';
  if (sid) {
    localStorage.setItem('aios_ubus_session', sid);
    return new UbusApiClient(sid);
  }
  return new LocalMockApiClient();
}
