<script setup lang="ts">
import { ref } from 'vue';
import type { CompileResult } from '@/compiler';
import type { AiosApiClient, StatsResponse, ValidateResult } from '@/api/client';
import { parseGeoDatIndex, type GeoCategorySummary } from '@/geodata/parser';

const props = defineProps<{
  compiled: CompileResult;
  api: AiosApiClient;
}>();

const validateRes = ref<ValidateResult | null>(null);
const keyOutput = ref('');
const logContent = ref('');
const statsData = ref<StatsResponse | null>(null);
const geoCategories = ref<GeoCategorySummary[]>([]);
const geoSearch = ref('');

async function runValidate() {
  validateRes.value = await props.api.validateConfig(JSON.stringify(props.compiled.json, null, 2));
}

async function runKeyGen(kind: 'uuid' | 'x25519' | 'mldsa65' | 'vlessenc' | 'wg') {
  keyOutput.value = await props.api.keyGen(kind);
}

async function refreshLog() {
  logContent.value = await props.api.readLog();
}

async function refreshStats() {
  statsData.value = await props.api.getStats();
}

async function handleGeoUpload(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  const buf = await file.arrayBuffer();
  geoCategories.value = parseGeoDatIndex(buf);
}
</script>

<template>
  <div>
    <!-- Diagnostics & Compiled JSON -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">实时编译配置预览（目标内核：{{ compiled.core.toUpperCase() }}）</h3>
        <button class="btn btn-primary" @click="runValidate">调用内核校验 (-test)</button>
      </div>

      <div v-if="compiled.diagnostics.length > 0" class="alert alert-warn">
        <strong>双核兼容性自动适配提示：</strong>
        <ul style="margin: 6px 0 0 18px; padding: 0">
          <li v-for="(d, idx) in compiled.diagnostics" :key="idx">
            [{{ d.level.toUpperCase() }}] {{ d.path }}: {{ d.message }}
          </li>
        </ul>
      </div>

      <div v-if="validateRes" class="alert" :class="validateRes.ok ? 'alert-ok' : 'alert-err'">
        {{ validateRes.ok ? '校验通过' : '校验失败' }}：{{ validateRes.output }}
      </div>

      <pre class="code-block">{{ JSON.stringify(compiled.json, null, 2) }}</pre>
    </div>

    <!-- KeyGen & GeoData -->
    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">密钥与工具箱</h3>
        </div>
        <div class="row" style="margin-bottom: 10px">
          <button class="btn" @click="runKeyGen('uuid')">生成 UUID</button>
          <button class="btn" @click="runKeyGen('x25519')">X25519 (REALITY)</button>
          <button class="btn" @click="runKeyGen('mldsa65')">ML-DSA-65</button>
          <button class="btn" @click="runKeyGen('vlessenc')">VLESS Enc</button>
          <button class="btn" @click="runKeyGen('wg')">WireGuard Key</button>
        </div>
        <pre v-if="keyOutput" class="code-block" style="max-height: 180px">{{ keyOutput }}</pre>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="card-title">纯前端 GeoData (.dat) 浏览器</h3>
          <label class="btn" style="cursor: pointer">
            加载 geoip.dat / geosite.dat
            <input type="file" accept=".dat" style="display: none" @change="handleGeoUpload" />
          </label>
        </div>
        <input v-if="geoCategories.length > 0" v-model="geoSearch" type="text" placeholder="搜索分类代码，如 cn / google / ads" />
        <div v-if="geoCategories.length > 0" style="max-height: 180px; overflow: auto; margin-top: 8px">
          <table class="table">
            <tbody>
              <tr
                v-for="c in geoCategories.filter((x) => !geoSearch || x.code.includes(geoSearch.toLowerCase())).slice(0, 60)"
                :key="c.code"
              >
                <td>{{ c.code }}</td>
                <td>{{ c.count }} 条目</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else style="color: var(--muted); font-size: 12.5px">
          纯浏览器端 Protobuf 解码，零后端依赖。支持直接检查本地或路由器导出的 geoip.dat / geosite.dat。
        </div>
      </div>
    </div>

    <!-- Stats & Logs -->
    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">运行统计 (Metrics / API)</h3>
          <button class="btn" @click="refreshStats">刷新统计</button>
        </div>
        <pre v-if="statsData" class="code-block" style="max-height: 220px">{{ JSON.stringify(statsData, null, 2) }}</pre>
        <div v-else style="color: var(--muted); font-size: 12.5px">点击刷新拉取 Xray Metrics (/debug/vars) 或 V2Ray StatsService。</div>
      </div>
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">错误日志</h3>
          <button class="btn" @click="refreshLog">读取日志</button>
        </div>
        <pre v-if="logContent" class="code-block" style="max-height: 220px">{{ logContent }}</pre>
        <div v-else style="color: var(--muted); font-size: 12.5px">点击读取日志查看最新 200 行内核日志。</div>
      </div>
    </div>
  </div>
</template>
