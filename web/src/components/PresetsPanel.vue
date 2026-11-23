<script setup lang="ts">
import { computed, ref } from 'vue';
import type { AiosConfig, AiosPreset } from '@/schema/types';
import { BUILTIN_PRESETS } from '@/presets/builtin';
import {
  applyPresetToConfig,
  computePresetDiff,
  createUserPresetFromConfig,
  type PresetDiffEntry
} from '@/presets/manager';
import ArrayInput from '@/components/ui/ArrayInput.vue';
import ToggleSwitch from '@/components/ui/ToggleSwitch.vue';

const props = defineProps<{
  config: AiosConfig;
  userPresets: AiosPreset[];
}>();

const emit = defineEmits<{
  (e: 'apply', nextConfig: AiosConfig, presetName: string): void;
  (e: 'save-preset', preset: AiosPreset): void;
  (e: 'delete-preset', id: string): void;
}>();

const saveName = ref('');
const saveDesc = ref('');
const saveTags = ref<string[]>([]);
const preserveOutbounds = ref(true);
const importError = ref('');

const previewPreset = ref<AiosPreset | null>(null);
const previewDiffs = computed<PresetDiffEntry[]>(() =>
  previewPreset.value
    ? computePresetDiff(
        props.config,
        applyPresetToConfig(props.config, previewPreset.value, {
          preserveOutbounds: preserveOutbounds.value
        })
      )
    : []
);

function handleSaveCurrent() {
  if (!saveName.value.trim()) return;
  const preset = createUserPresetFromConfig(props.config, {
    name: saveName.value,
    description: saveDesc.value,
    tags: saveTags.value
  });
  emit('save-preset', preset);
  saveName.value = '';
  saveDesc.value = '';
  saveTags.value = [];
}

function confirmApply() {
  if (!previewPreset.value) return;
  const next = applyPresetToConfig(props.config, previewPreset.value, {
    preserveOutbounds: preserveOutbounds.value
  });
  emit('apply', next, previewPreset.value.name);
  previewPreset.value = null;
}

function exportPreset(preset: AiosPreset) {
  const blob = new Blob([JSON.stringify(preset, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${preset.id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function handleImportFile(event: Event) {
  importError.value = '';
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(String(reader.result)) as AiosPreset;
      if (!parsed.name || !parsed.config || !parsed.config.general) {
        importError.value = '无效的预设 JSON 文件结构。';
        return;
      }
      parsed.builtin = false;
      parsed.id = parsed.id || `user-import-${Date.now().toString(36)}`;
      emit('save-preset', parsed);
    } catch (e) {
      importError.value = `解析失败: ${String(e)}`;
    }
  };
  reader.readAsText(file);
  input.value = '';
}
</script>

<template>
  <div>
    <!-- Save current config as preset -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">将当前设置保存为预设</h3>
        <label class="btn btn-sm" style="cursor: pointer">
          导入预设 JSON
          <input type="file" accept=".json" style="display: none" @change="handleImportFile" />
        </label>
      </div>
      <p class="section-desc">
        将当前完整配置（含入站、出站、DNS、路由与透明代理）保存为独立快照至 <code>/etc/aios/presets/</code>，支持一键切换、Diff 预览与跨设备导出。
      </p>
      <div v-if="importError" class="alert alert-err">{{ importError }}</div>
      <div class="grid-2" style="margin-bottom: 12px">
        <div class="field">
          <label>预设名称 *</label>
          <input v-model="saveName" type="text" placeholder="例如：家庭双栈 Xray + Reality 主力方案" />
        </div>
        <div class="field">
          <label>说明备注</label>
          <input v-model="saveDesc" type="text" placeholder="记录适用场景或网络环境" />
        </div>
      </div>
      <ArrayInput
        v-model="saveTags"
        label="标签 (tags[])"
        :suggestions="['home', 'office', 'xray', 'v2ray', 'reality', 'tproxy']"
        placeholder="输入标签回车添加"
      />
      <div class="row" style="margin-top: 14px">
        <button class="btn btn-primary" :disabled="!saveName.trim()" @click="handleSaveCurrent">
          保存当前配置为预设
        </button>
      </div>
    </div>

    <!-- User saved presets -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">我的自定义预设 ({{ userPresets.length }})</h3>
      </div>
      <div v-if="userPresets.length === 0" class="field-hint">
        暂无自定义预设。你可以在上方或右上角随时将当前设置保存为预设。
      </div>
      <div v-else class="grid-2">
        <div v-for="p in userPresets" :key="p.id" class="card-subtle" style="display: flex; flex-direction: column; gap: 10px">
          <div class="row-nowrap" style="justify-content: space-between">
            <strong style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap" :title="p.name">{{ p.name }}</strong>
            <span class="badge badge-primary">{{ p.recommendedCore || 'auto' }}</span>
          </div>
          <p style="margin: 0; color: var(--text-secondary); font-size: 12.5px">{{ p.description }}</p>
          <div class="row">
            <span v-for="t in p.tags" :key="t" class="badge">{{ t }}</span>
          </div>
          <div class="row" style="margin-top: auto; padding-top: 4px">
            <button class="btn btn-sm btn-primary" @click="previewPreset = p">预览差异并应用</button>
            <button class="btn btn-sm" @click="exportPreset(p)">导出 JSON</button>
            <button class="btn btn-sm btn-danger" @click="emit('delete-preset', p.id)">删除</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Built-in presets -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">推荐设置快捷键 ({{ BUILTIN_PRESETS.length }})</h3>
      </div>
      <div class="grid-2">
        <div
          v-for="p in BUILTIN_PRESETS"
          :key="p.id"
          class="card-subtle"
          style="display: flex; flex-direction: column; gap: 10px"
        >
          <div class="row-nowrap" style="justify-content: space-between">
            <strong style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap" :title="p.name">{{ p.name }}</strong>
            <span class="badge badge-ok">{{ p.recommendedCore || 'auto' }}</span>
          </div>
          <p style="margin: 0; color: var(--text-secondary); font-size: 12.5px">{{ p.description }}</p>
          <div class="row">
            <span v-for="t in p.tags" :key="t" class="badge">{{ t }}</span>
          </div>
          <div class="row" style="margin-top: auto; padding-top: 4px">
            <button class="btn btn-sm btn-primary" @click="previewPreset = p">预览差异并应用</button>
            <button class="btn btn-sm" @click="exportPreset(p)">导出 JSON</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Diff Modal with strict non-wrapping header -->
    <div v-if="previewPreset" class="modal-backdrop" @click.self="previewPreset = null">
      <div class="modal">
        <div class="modal-header">
          <h3 class="modal-title" :title="`应用预设前差异预览：${previewPreset.name}`">
            应用预设前差异预览：{{ previewPreset.name }}
          </h3>
          <button class="btn btn-sm" @click="previewPreset = null">关闭</button>
        </div>

        <div style="margin-bottom: 14px">
          <ToggleSwitch
            v-model="preserveOutbounds"
            label="保留当前已配置的代理出站节点（推荐，避免覆盖手工导入的节点）"
          />
        </div>

        <table v-if="previewDiffs.length > 0" class="table" style="margin-bottom: 16px">
          <thead>
            <tr>
              <th>配置项</th>
              <th>当前值</th>
              <th>应用后</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in previewDiffs" :key="d.section">
              <td>{{ d.section }}</td>
              <td style="color: var(--muted)">{{ d.before }}</td>
              <td style="color: var(--success); font-weight: 500">{{ d.after }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="alert alert-ok">关键结构与当前配置一致，应用将同步其余细项参数。</div>

        <div class="row" style="justify-content: flex-end">
          <button class="btn" @click="previewPreset = null">取消</button>
          <button class="btn btn-primary" @click="confirmApply">确认应用预设</button>
        </div>
      </div>
    </div>
  </div>
</template>
