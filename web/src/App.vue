<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import type { AiosConfig, AiosPreset } from '@/schema/types';
import { createDefaultConfig } from '@/schema/defaults';
import { resolveEffectiveCore } from '@/schema/capabilities';
import { getVersionPresets } from '@/schema/features';
import { compileConfig } from '@/compiler';
import { createUserPresetFromConfig } from '@/presets/manager';
import {
  createApiClient,
  type CoreInfo,
  type PreflightResult,
  type ServiceStatus
} from '@/api/client';

import ToggleSwitch from '@/components/ui/ToggleSwitch.vue';
import KeyValueInput from '@/components/ui/KeyValueInput.vue';
import PresetsPanel from '@/components/PresetsPanel.vue';
import InboundsPanel from '@/components/InboundsPanel.vue';
import OutboundsPanel from '@/components/OutboundsPanel.vue';
import RoutingDnsPanel from '@/components/RoutingDnsPanel.vue';
import TproxyPanel from '@/components/TproxyPanel.vue';
import FirewallPanel from '@/components/FirewallPanel.vue';
import PreviewToolsPanel from '@/components/PreviewToolsPanel.vue';
import CoreManagerPanel from '@/components/CoreManagerPanel.vue';

type TabKey = 'general' | 'presets' | 'inbounds' | 'outbounds' | 'routing' | 'tproxy' | 'firewall' | 'tools';

const api = createApiClient();
const activeTab = ref<TabKey>('general');
const config = ref<AiosConfig>(createDefaultConfig());
const userPresets = ref<AiosPreset[]>([]);
const coreInfo = ref<CoreInfo | null>(null);
const serviceStatus = ref<ServiceStatus | null>(null);
const preflight = ref<PreflightResult | null>(null);
const toast = ref('');
const theme = ref<'dark' | 'light'>(
  (localStorage.getItem('aios_theme') as 'dark' | 'light') || 'dark'
);

// Quick "Save Current Config as Preset" modal from topbar
const showQuickSavePreset = ref(false);
const quickPresetName = ref('');
const quickPresetDesc = ref('');

const effectiveCore = computed(() =>
  resolveEffectiveCore(
    config.value.general.core_type,
    coreInfo.value?.core_type === 'auto' ? undefined : coreInfo.value?.core_type,
    config.value.general.core_bin
  )
);

const versionPresets = computed(() => getVersionPresets(effectiveCore.value));

const resolvedTargetVersion = computed(() => {
  const configured = config.value.general.target_version;
  if (configured && configured !== 'auto') return configured;
  return coreInfo.value?.core_version || undefined;
});

const compiled = computed(() =>
  compileConfig(config.value, {
    core: effectiveCore.value,
    version: resolvedTargetVersion.value
  })
);

function applyTheme(t: 'dark' | 'light') {
  theme.value = t;
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('aios_theme', t);
}

function toggleTheme() {
  applyTheme(theme.value === 'dark' ? 'light' : 'dark');
}

function notify(msg: string) {
  toast.value = msg;
  setTimeout(() => {
    if (toast.value === msg) toast.value = '';
  }, 4000);
}

async function refreshSystem() {
  try {
    const [ci, st, pf] = await Promise.all([
      api.getCoreInfo(),
      api.getServiceStatus(),
      api.preflightCheck()
    ]);
    coreInfo.value = ci;
    serviceStatus.value = st;
    preflight.value = pf;
  } catch (e) {
    notify(`状态刷新失败: ${String(e)}`);
  }
}

async function handleSaveAndApply() {
  const errors = compiled.value.diagnostics.filter((d) => d.level === 'error');
  if (errors.length > 0) {
    notify(`存在 ${errors.length} 个配置错误，已阻止保存与重启：${errors[0].path} — ${errors[0].message}`);
    activeTab.value = 'tools';
    return;
  }
  try {
    const compiledText = JSON.stringify(compiled.value.json, null, 2);
    await api.saveConfig(config.value, compiledText);
    if (config.value.general.enabled) {
      await api.serviceAction('restart');
    }
    await refreshSystem();
    notify('配置已保存并同步至路由器（含预编译 JSON 兜底）。');
  } catch (e) {
    notify(`保存失败: ${String(e)}`);
  }
}

async function handleServiceAction(action: 'start' | 'stop' | 'restart') {
  try {
    await api.serviceAction(action);
    await refreshSystem();
    notify(`已执行服务操作: ${action}`);
  } catch (e) {
    notify(`服务操作失败: ${String(e)}`);
  }
}

async function handleSavePreset(preset: AiosPreset) {
  await api.saveUserPreset(preset);
  userPresets.value = await api.listUserPresets();
  notify(`已将当前设置保存为预设「${preset.name}」`);
}

async function handleQuickSavePreset() {
  if (!quickPresetName.value.trim()) return;
  const preset = createUserPresetFromConfig(config.value, {
    name: quickPresetName.value,
    description: quickPresetDesc.value
  });
  await handleSavePreset(preset);
  quickPresetName.value = '';
  quickPresetDesc.value = '';
  showQuickSavePreset.value = false;
}

async function handleDeletePreset(id: string) {
  await api.deleteUserPreset(id);
  userPresets.value = await api.listUserPresets();
  notify('已删除自定义预设');
}

function handleApplyPreset(nextConfig: AiosConfig, presetName: string) {
  config.value = nextConfig;
  notify(`已应用预设「${presetName}」（请点击右上角“保存并应用”生效）`);
}

onMounted(async () => {
  applyTheme(theme.value);
  config.value = await api.loadConfig();
  userPresets.value = await api.listUserPresets();
  await refreshSystem();
});
</script>

<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="brand-box">
        <div class="brand">
          <span class="brand-dot" />
          <span>AIOS Console</span>
        </div>
        <div class="brand-sub">Xray-core &amp; V2Ray · Vue 3</div>
      </div>

      <div class="nav-section-label">核心控制台</div>
      <button class="nav-btn" :class="{ active: activeTab === 'general' }" @click="activeTab = 'general'">
        <span>总览与核心</span>
        <span class="badge badge-primary">{{ effectiveCore }}</span>
      </button>
      <button class="nav-btn" :class="{ active: activeTab === 'presets' }" @click="activeTab = 'presets'">
        <span>预设快捷键</span>
        <span class="badge">{{ userPresets.length }}</span>
      </button>

      <div class="nav-section-label">配置拼装</div>
      <button class="nav-btn" :class="{ active: activeTab === 'inbounds' }" @click="activeTab = 'inbounds'">
        <span>入站 (Inbounds)</span>
        <span class="badge">{{ config.inbounds.length }}</span>
      </button>
      <button class="nav-btn" :class="{ active: activeTab === 'outbounds' }" @click="activeTab = 'outbounds'">
        <span>出站 (Outbounds)</span>
        <span class="badge">{{ config.outbounds.length }}</span>
      </button>
      <button class="nav-btn" :class="{ active: activeTab === 'routing' }" @click="activeTab = 'routing'">
        <span>DNS 与路由</span>
        <span class="badge">{{ config.routing_rules.length }}</span>
      </button>
      <button class="nav-btn" :class="{ active: activeTab === 'tproxy' }" @click="activeTab = 'tproxy'">
        <span>透明代理与隔离</span>
        <span class="badge" :class="config.transparent_proxy.enabled ? 'badge-ok' : ''">
          {{ config.transparent_proxy.enabled ? '开' : '关' }}
        </span>
      </button>

      <div class="nav-section-label">诊断与工具</div>
      <button class="nav-btn" :class="{ active: activeTab === 'firewall' }" @click="activeTab = 'firewall'">
        <span>防火墙状态与改动</span>
        <span class="badge" :class="config.transparent_proxy.enabled ? 'badge-ok' : ''">
          {{ coreInfo?.detected_firewall || 'auto' }}
        </span>
      </button>
      <button class="nav-btn" :class="{ active: activeTab === 'tools' }" @click="activeTab = 'tools'">
        <span>预览 / Geo / 日志</span>
        <span v-if="compiled.diagnostics.length > 0" class="badge badge-warn">{{ compiled.diagnostics.length }}</span>
      </button>
    </aside>

    <main class="main">
      <header class="topbar">
        <div class="row-nowrap">
          <span class="badge" :class="serviceStatus?.running ? 'badge-ok' : 'badge-err'">
            {{ serviceStatus?.running ? `运行中 · PID ${serviceStatus.pid}` : '已停止' }}
          </span>
          <span class="badge badge-primary">{{ effectiveCore.toUpperCase() }}</span>
          <span class="badge">{{ api.mode === 'ubus' ? 'OpenWrt ubus' : '本地预览' }}</span>
        </div>
        <div class="row-nowrap">
          <button class="btn btn-sm" title="切换深色/浅色主题" @click="toggleTheme">
            {{ theme === 'dark' ? '☀ 浅色' : '☾ 深色' }}
          </button>
          <button class="btn btn-sm" @click="showQuickSavePreset = true">★ 保存为预设</button>
          <button
            v-if="serviceStatus?.running"
            class="btn btn-sm"
            @click="handleServiceAction('restart')"
          >
            重启
          </button>
          <button
            v-if="serviceStatus?.running"
            class="btn btn-sm btn-danger"
            @click="handleServiceAction('stop')"
          >
            停止
          </button>
          <button
            v-else
            class="btn btn-sm btn-success"
            @click="handleServiceAction('start')"
          >
            启动
          </button>
          <button class="btn btn-sm btn-primary" @click="handleSaveAndApply">保存并应用</button>
        </div>
      </header>

      <div class="content-scroll">
        <section class="content">
          <div v-if="toast" class="alert alert-ok">{{ toast }}</div>

          <!-- General Tab -->
          <div v-if="activeTab === 'general'">
            <div v-if="coreInfo" class="grid-3" style="margin-bottom: 16px">
              <div class="stat-tile">
                <div class="stat-tile-label">核心版本</div>
                <div class="stat-tile-value">{{ coreInfo.version || '未检测到二进制' }}</div>
              </div>
              <div class="stat-tile">
                <div class="stat-tile-label">防火墙后端 / ucode</div>
                <div class="stat-tile-value">{{ coreInfo.detected_firewall }} · {{ coreInfo.has_ucode ? 'ucode 原生' : '预编译 JSON' }}</div>
              </div>
              <div class="stat-tile">
                <div class="stat-tile-label">GeoData 资产</div>
                <div class="stat-tile-value">
                  geoip: {{ coreInfo.has_geoip ? '✓' : '✗' }} · geosite: {{ coreInfo.has_geosite ? '✓' : '✗' }}
                </div>
              </div>
            </div>

            <div class="card">
              <div class="card-header">
                <h3 class="card-title">核心运行设置 (/etc/config/aios)</h3>
                <ToggleSwitch v-model="config.general.enabled" label="开机自启 / 允许运行 (enabled)" />
              </div>
              <p class="section-desc">
                对应 UCI 的 <code>aios.main.enabled</code>：开启后路由器开机自动启动，且点击「保存并应用」会自动重启生效；关闭则仅保存配置不拉起进程。临时启停请直接用右上角「启动 / 停止」。
              </p>

              <div class="grid-3">
                <div class="field">
                  <label>目标内核 (core_type)</label>
                  <select v-model="config.general.core_type">
                    <option value="auto">auto（自动识别）</option>
                    <option value="xray">Xray-core</option>
                    <option value="v2ray">V2Ray (v2fly)</option>
                  </select>
                </div>
                <div class="field">
                  <label>目标版本基线 (target_version)</label>
                  <select v-model="config.general.target_version">
                    <option value="auto">
                      auto（{{ coreInfo?.core_version ? `已探测 v${coreInfo.core_version}` : `默认 v${compiled.version}` }}）
                    </option>
                    <option v-for="vp in versionPresets" :key="vp.id" :value="vp.version">
                      {{ vp.label }} (v{{ vp.version }})
                    </option>
                  </select>
                </div>
                <div v-if="effectiveCore === 'v2ray'" class="field">
                  <label>V2Ray 配置格式 (v2ray_format)</label>
                  <select v-model="config.general.v2ray_format">
                    <option value="jsonv4">jsonv4（经典稳定，默认）</option>
                    <option value="jsonv5">jsonv5（支持 SS2022 / uTLS / HTTPUpgrade / services.tun）</option>
                  </select>
                </div>
                <div class="field">
                  <label>可执行文件路径 (core_bin)</label>
                  <input v-model="config.general.core_bin" type="text" placeholder="留空自动探测 /usr/bin/aios-xray 等" />
                </div>
                <div class="field">
                  <label>多版本存储目录 (bins_dir，可选)</label>
                  <input v-model="config.general.bins_dir" type="text" placeholder="外置存储，如 /mnt/sda1/aios/bins" />
                </div>
                <div class="field">
                  <label>GeoData 资产目录</label>
                  <input v-model="config.general.asset_location" type="text" placeholder="留空自动探测 /usr/share/aios/geodata 等" />
                </div>
                <div class="field">
                  <label>日志级别 (log_level)</label>
                  <select v-model="config.general.log_level">
                    <option value="debug">debug</option>
                    <option value="info">info</option>
                    <option value="warning">warning</option>
                    <option value="error">error</option>
                    <option value="none">none</option>
                  </select>
                </div>
                <div class="field">
                  <label>GOMEMLIMIT (小内存路由器推荐，如 64MiB)</label>
                  <input v-model="config.general.go_memlimit" type="text" placeholder="留空不限制" />
                </div>
                <div class="field">
                  <label>最大文件句柄 (rlimit_nofile)</label>
                  <input v-model="config.general.rlimit_nofile" type="text" placeholder="102400" />
                </div>
              </div>

              <div class="row" style="margin-top: 14px">
                <ToggleSwitch v-model="config.general.stats_enabled" label="流量统计 (stats)" />
                <ToggleSwitch v-model="config.general.api_enabled" label="gRPC API" />
                <ToggleSwitch v-if="effectiveCore === 'xray'" v-model="config.general.metrics_enabled" label="Xray Metrics (/debug/vars)" />
                <ToggleSwitch v-if="effectiveCore === 'xray'" v-model="config.general.dns_log" label="DNS 日志 (dnsLog)" />
              </div>

              <div v-if="effectiveCore === 'xray'" class="card-subtle" style="margin-top: 16px; display: flex; flex-direction: column; gap: 12px">
                <strong style="font-size: 13px">Xray 顶层扩展 (env / geodata / version)</strong>
                <div class="grid-3">
                  <div class="field">
                    <label>GeoData 自动重载间隔 (geodata.reloadInterval)</label>
                    <input v-model="config.general.geodata_reload_interval" type="text" placeholder="如 1h / 24h" />
                  </div>
                  <div class="field">
                    <label>最低内核版本要求 (version.min)</label>
                    <input v-model="config.general.min_version" type="text" placeholder="如 25.1.1" />
                  </div>
                  <div class="field">
                    <label>最高内核版本要求 (version.max)</label>
                    <input v-model="config.general.max_version" type="text" placeholder="可选" />
                  </div>
                </div>
                <KeyValueInput
                  v-model="config.general.inline_env"
                  label="内联环境变量 (env)"
                  key-placeholder="XRAY_CONE_DISABLED"
                  value-placeholder="true"
                />
              </div>
            </div>

            <CoreManagerPanel
              :api="api"
              :config="config"
              :core-info="coreInfo"
              @switched="refreshSystem"
              @notify="notify"
            />
          </div>

          <PresetsPanel
            v-else-if="activeTab === 'presets'"
            :config="config"
            :user-presets="userPresets"
            @apply="handleApplyPreset"
            @save-preset="handleSavePreset"
            @delete-preset="handleDeletePreset"
          />

          <InboundsPanel
            v-else-if="activeTab === 'inbounds'"
            :inbounds="config.inbounds"
            :core="effectiveCore"
            :v2ray-format="config.general.v2ray_format"
          />

          <OutboundsPanel
            v-else-if="activeTab === 'outbounds'"
            :outbounds="config.outbounds"
            :core="effectiveCore"
            :v2ray-format="config.general.v2ray_format"
          />

          <RoutingDnsPanel
            v-else-if="activeTab === 'routing'"
            :config="config"
            :core="effectiveCore"
            :v2ray-format="config.general.v2ray_format"
          />

          <TproxyPanel
            v-else-if="activeTab === 'tproxy'"
            :config="config"
            :preflight="preflight"
            :detected-firewall="coreInfo?.detected_firewall || 'auto'"
            @run-preflight="refreshSystem"
          />

          <FirewallPanel
            v-else-if="activeTab === 'firewall'"
            :config="config"
            :api="api"
            :preflight="preflight"
            :detected-firewall="coreInfo?.detected_firewall || 'nftables'"
            @notify="notify"
            @refresh-preflight="refreshSystem"
          />

          <PreviewToolsPanel
            v-else-if="activeTab === 'tools'"
            :compiled="compiled"
            :api="api"
          />
        </section>
      </div>
    </main>

    <!-- Quick Save Current Config as Preset Modal -->
    <div v-if="showQuickSavePreset" class="modal-backdrop" @click.self="showQuickSavePreset = false">
      <div class="modal">
        <div class="modal-header">
          <h3 class="modal-title">将当前完整设置保存为预设</h3>
          <button class="btn btn-sm" @click="showQuickSavePreset = false">关闭</button>
        </div>
        <div class="field" style="margin-bottom: 12px">
          <label>预设名称 *</label>
          <input v-model="quickPresetName" type="text" placeholder="例如：办公室 V2Ray 分流方案" />
        </div>
        <div class="field" style="margin-bottom: 16px">
          <label>备注说明</label>
          <input v-model="quickPresetDesc" type="text" placeholder="可选，说明核心/网络环境" />
        </div>
        <div class="row" style="justify-content: flex-end">
          <button class="btn" @click="showQuickSavePreset = false">取消</button>
          <button class="btn btn-primary" :disabled="!quickPresetName.trim()" @click="handleQuickSavePreset">
            保存预设
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
