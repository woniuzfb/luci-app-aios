<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import type {
  AiosApiClient,
  CoreInfo,
  CoreListResult,
  CoreSlot,
  InstallCoreStatus
} from '@/api/client';
import type { AiosConfig, CoreType } from '@/schema/types';
import { compileConfig } from '@/compiler';

const props = defineProps<{
  api: AiosApiClient;
  config: AiosConfig;
  coreInfo: CoreInfo | null;
}>();

const emit = defineEmits<{
  (e: 'switched'): void;
  (e: 'notify', message: string): void;
}>();

const loading = ref(false);
const switchingPath = ref('');
const removingId = ref('');
const coreList = ref<CoreListResult | null>(null);
const installCoreType = ref<CoreType>('xray');
const installTag = ref('v26.11.9');
const installMirror = ref('');
const installStatus = ref<InstallCoreStatus | null>(null);
const errorMsg = ref('');

let pollTimer: number | null = null;

const availMb = computed(() => Math.floor((coreList.value?.avail_kb || 0) / 1024));
const canInstall = computed(() => {
  const c = coreList.value;
  if (!c) return false;
  return Boolean(c.bins_dir) && c.avail_kb >= 70000 && c.has_unzip && c.has_sha256 && c.has_downloader;
});

const installDisabledReason = computed(() => {
  const c = coreList.value;
  if (!c) return '正在检测路由器存储与工具环境...';
  if (!c.bins_dir) return '请先在上方填写并保存「内核多版本目录 (bins_dir)」（建议外接 U 盘/大容量 overlay，如 /mnt/sda1/aios/bins）';
  if (c.avail_kb < 70000) return `目录剩余空间不足（当前 ${availMb.value} MB，需要至少 70 MB）`;
  if (!c.has_unzip || !c.has_sha256 || !c.has_downloader) {
    const missing: string[] = [];
    if (!c.has_downloader) missing.push('curl/wget');
    if (!c.has_unzip) missing.push('unzip');
    if (!c.has_sha256) missing.push('sha256sum');
    return `路由器缺少必要工具：${missing.join('、')}`;
  }
  return '';
});

const isInstalling = computed(
  () => installStatus.value?.state === 'queued' || installStatus.value?.state === 'running'
);

function stopPolling() {
  if (pollTimer !== null) {
    window.clearInterval(pollTimer);
    pollTimer = null;
  }
}

async function pollInstallStatus() {
  try {
    const st = await props.api.installStatus();
    installStatus.value = st;
    if (st.state === 'done') {
      stopPolling();
      emit('notify', st.message || '内核安装完成');
      await refresh();
    } else if (st.state === 'error' || st.state === 'idle') {
      stopPolling();
    }
  } catch (e) {
    stopPolling();
    errorMsg.value = String(e);
  }
}

function startPolling() {
  stopPolling();
  pollTimer = window.setInterval(() => {
    void pollInstallStatus();
  }, 1500);
}

async function refresh() {
  loading.value = true;
  errorMsg.value = '';
  try {
    coreList.value = await props.api.listCores();
    const st = await props.api.installStatus();
    installStatus.value = st;
    if (st.state === 'queued' || st.state === 'running') {
      startPolling();
    }
  } catch (e) {
    errorMsg.value = String(e);
  } finally {
    loading.value = false;
  }
}

async function handleInstall() {
  errorMsg.value = '';
  const tag = installTag.value.trim();
  if (!tag) {
    errorMsg.value = '请填写版本号 Tag（如 v26.11.9 或 v5.56.0）';
    return;
  }
  try {
    const res = await props.api.installCore(installCoreType.value, tag, installMirror.value.trim());
    if (!res.ok) {
      errorMsg.value = res.error || '启动安装任务失败';
      return;
    }
    installStatus.value = {
      job_id: res.job_id,
      state: 'queued',
      core: installCoreType.value,
      tag,
      progress: 5,
      message: '已提交后台安装任务...'
    };
    startPolling();
  } catch (e) {
    errorMsg.value = String(e);
  }
}

async function handleSwitch(slot: CoreSlot) {
  errorMsg.value = '';
  switchingPath.value = slot.path;
  try {
    let precompiled: string | undefined;
    // 无 ucode 的旧版 OpenWrt：由前端 TS 编译器按目标内核和目标版本预编译 JSON，传递给路由器做 -test 与原子切换
    if (!props.coreInfo?.has_ucode) {
      const targetVersion = slot.version && slot.version !== 'unknown' ? slot.version : undefined;
      const targetCfg: AiosConfig = {
        ...props.config,
        general: { ...props.config.general, core_type: slot.core }
      };
      const compiled = compileConfig(targetCfg, { core: slot.core, version: targetVersion });
      const errDiag = compiled.diagnostics.find((d) => d.level === 'error');
      if (errDiag) {
        errorMsg.value = `目标版本编译阻断：${errDiag.message}`;
        return;
      }
      precompiled = JSON.stringify(compiled.json, null, 2);
    }
    const res = await props.api.switchCore(slot.path, precompiled);
    if (!res.ok) {
      errorMsg.value = res.rolled_back
        ? `切换后看门狗检测异常，已自动回滚：${res.error || ''}`
        : `切换失败：${res.error || '未知错误'}`;
      return;
    }
    emit('notify', `已安全切换至 ${slot.core} v${res.version || slot.version}（已通过 -test 门禁）`);
    await refresh();
    emit('switched');
  } catch (e) {
    errorMsg.value = String(e);
  } finally {
    switchingPath.value = '';
  }
}

async function handleRemove(slot: CoreSlot) {
  errorMsg.value = '';
  removingId.value = slot.id;
  try {
    const res = await props.api.removeCore(slot.id);
    if (!res.ok) {
      errorMsg.value = res.error || '删除失败';
      return;
    }
    emit('notify', `已删除内核槽位 ${slot.id}`);
    await refresh();
  } catch (e) {
    errorMsg.value = String(e);
  } finally {
    removingId.value = '';
  }
}

onMounted(() => {
  void refresh();
});

onBeforeUnmount(() => {
  stopPolling();
});
</script>

<template>
  <div class="card" style="margin-top: 16px">
    <div class="card-header">
      <h3 class="card-title">多版本内核管理（安全切换与热回滚）</h3>
      <button class="btn btn-sm" :disabled="loading" @click="refresh">
        {{ loading ? '刷新中...' : '刷新槽位' }}
      </button>
    </div>
    <p class="section-desc" style="margin-bottom: 16px">
      支持检测系统预装（<code>/usr/bin/aios-*</code> / <code>/usr/bin/xray</code> / <code>/usr/bin/v2ray</code>）与自定义目录多版本槽位。切换前自动按目标版本编译并执行离线 <code>-test</code>，重启后看门狗失败将自动回滚。
    </p>

    <div v-if="errorMsg" class="alert alert-err" style="margin-bottom: 16px">{{ errorMsg }}</div>

    <div v-if="coreList" class="row" style="margin-bottom: 16px; gap: 8px 10px; font-size: 12px">
      <span class="badge">架构: {{ coreList.arch }}</span>
      <span class="badge">存储目录: {{ coreList.bins_dir || '未配置' }}</span>
      <span v-if="coreList.bins_dir" class="badge" :class="coreList.avail_kb >= 70000 ? 'badge-ok' : 'badge-warn'">
        可用空间: {{ availMb }} MB
      </span>
      <span class="badge" :class="coreList.has_downloader ? 'badge-ok' : 'badge-warn'">
        下载器: {{ coreList.has_downloader ? '✓' : '✗' }}
      </span>
      <span class="badge" :class="coreList.has_unzip ? 'badge-ok' : 'badge-warn'">
        unzip: {{ coreList.has_unzip ? '✓' : '✗' }}
      </span>
      <span class="badge" :class="coreList.has_sha256 ? 'badge-ok' : 'badge-warn'">
        sha256sum: {{ coreList.has_sha256 ? '✓' : '✗' }}
      </span>
    </div>

    <div v-if="coreList && coreList.slots.length > 0" class="table-wrap" style="margin-bottom: 18px">
      <table class="table">
        <thead>
          <tr>
            <th>来源</th>
            <th>内核</th>
            <th>版本</th>
            <th>路径</th>
            <th>状态</th>
            <th class="col-actions">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="slot in coreList.slots" :key="slot.id">
            <td style="white-space: nowrap; color: var(--text-secondary)">
              {{ slot.source === 'system' ? '系统' : '托管槽位' }}
            </td>
            <td>{{ slot.core }}</td>
            <td><code>v{{ slot.version }}</code></td>
            <td><code style="font-size: 12px">{{ slot.path }}</code></td>
            <td>
              <span v-if="slot.active" class="badge badge-ok">当前启用</span>
              <span v-else class="badge">待命</span>
            </td>
            <td class="col-actions">
              <div class="table-actions">
                <button
                  v-if="!slot.active"
                  class="btn btn-sm btn-primary"
                  :disabled="Boolean(switchingPath)"
                  @click="handleSwitch(slot)"
                >
                  {{ switchingPath === slot.path ? '切换校验中...' : '安全切换' }}
                </button>
                <button
                  v-if="slot.removable && !slot.active"
                  class="btn btn-sm"
                  :disabled="removingId === slot.id"
                  @click="handleRemove(slot)"
                >
                  {{ removingId === slot.id ? '删除中...' : '删除' }}
                </button>
                <span v-if="slot.active" class="field-hint">—</span>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="coreList" class="alert" style="margin-bottom: 18px">
      未检测到可用内核二进制。可通过 opkg/apk 安装 <code>aios-xray</code> / <code>aios-v2ray</code>，或在下方配置外置存储下载。
    </div>

    <div class="card-subtle" style="padding: 16px 18px; display: flex; flex-direction: column; gap: 14px">
      <div style="display: flex; flex-direction: column; gap: 4px">
        <strong style="font-size: 13.5px">在线安装多版本槽位（官方 Release + SHA256 校验）</strong>
        <div v-if="installDisabledReason" class="field-hint" style="font-size: 12px">
          {{ installDisabledReason }}
        </div>
      </div>
      <div class="grid-3">
        <div class="field">
          <label>内核类型</label>
          <select
            v-model="installCoreType"
            :disabled="!canInstall || isInstalling"
            @change="installTag = installCoreType === 'xray' ? 'v26.11.9' : 'v5.56.0'"
          >
            <option value="xray">Xray-core (XTLS/Xray-core)</option>
            <option value="v2ray">V2Ray (v2fly/v2ray-core)</option>
          </select>
        </div>
        <div class="field">
          <label>Release Tag</label>
          <input
            v-model="installTag"
            type="text"
            :disabled="!canInstall || isInstalling"
            placeholder="例如 v26.11.9 或 v5.56.0"
          />
        </div>
        <div class="field">
          <label>下载镜像前缀（可选）</label>
          <input
            v-model="installMirror"
            type="text"
            :disabled="!canInstall || isInstalling"
            placeholder="留空直连 GitHub，如 https://ghproxy.net/"
          />
        </div>
      </div>
      <div class="row" style="align-items: center; gap: 12px; padding-top: 2px">
        <button
          class="btn btn-sm btn-primary"
          :disabled="!canInstall || isInstalling"
          @click="handleInstall"
        >
          {{ isInstalling ? `安装中 (${installStatus?.progress || 0}%)...` : '后台下载并安装' }}
        </button>
        <span v-if="installStatus && installStatus.state !== 'idle'" style="font-size: 12px">
          [{{ installStatus.state }} · {{ installStatus.progress }}%] {{ installStatus.message }}
        </span>
      </div>
    </div>
  </div>
</template>
