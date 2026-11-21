<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import type { AiosConfig } from '@/schema/types';
import type { AiosApiClient, FirewallStatus, PreflightResult } from '@/api/client';
import { computeLineDiff, renderExpectedFirewallRules } from '@/firewall/preview';

const props = defineProps<{
  config: AiosConfig;
  api: AiosApiClient;
  preflight: PreflightResult | null;
  detectedFirewall: 'nftables' | 'iptables' | 'none';
}>();

const emit = defineEmits<{
  (e: 'notify', msg: string): void;
  (e: 'refresh-preflight'): void;
}>();

const fwTab = ref<'changes' | 'live' | 'diff'>('changes');
const status = ref<FirewallStatus | null>(null);
const loading = ref(false);

const expected = computed(() =>
  renderExpectedFirewallRules(props.config, props.detectedFirewall)
);

const diffLines = computed(() =>
  computeLineDiff(status.value?.live_rules || '', expected.value.rules)
);

const diffStats = computed(() => {
  let added = 0;
  let removed = 0;
  for (const d of diffLines.value) {
    if (d.kind === 'add') added++;
    else if (d.kind === 'del') removed++;
  }
  return { added, removed };
});

async function refreshStatus() {
  loading.value = true;
  try {
    status.value = await props.api.getFirewallStatus();
  } catch (e) {
    emit('notify', `读取防火墙状态失败: ${String(e)}`);
  } finally {
    loading.value = false;
  }
}

async function runAction(action: 'apply' | 'flush' | 'refresh_gateway') {
  loading.value = true;
  try {
    await props.api.firewallAction(action);
    await refreshStatus();
    emit('refresh-preflight');
    const labels = {
      apply: '已独立应用 AIOS 防火墙规则（未触碰其他插件）',
      flush: '已清空 AIOS 独立防火墙表与策略路由',
      refresh_gateway: '已刷新默认网关与 IPv6 PD 绕过集合'
    };
    emit('notify', labels[action]);
  } catch (e) {
    emit('notify', `防火墙操作失败: ${String(e)}`);
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  refreshStatus();
});
</script>

<template>
  <div>
    <!-- Real-time status overview tiles -->
    <div class="grid-3" style="margin-bottom: 16px">
      <div class="stat-tile">
        <div class="stat-tile-label">当前防火墙后端与隔离表</div>
        <div class="stat-tile-value">
          {{ status?.backend || detectedFirewall }} ·
          <span :style="{ color: status?.table_present ? 'var(--success)' : 'var(--muted)' }">
            {{ status?.table_present ? '已挂载 (table inet aios / AIOS_*)' : '未挂载' }}
          </span>
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile-label">策略路由与标记</div>
        <div class="stat-tile-value">
          fwmark {{ status?.tproxy_mark || config.transparent_proxy.tproxy_mark }} → table {{ status?.route_table || config.transparent_proxy.route_table }}
        </div>
      </div>
      <div class="stat-tile">
        <div class="stat-tile-label">Dynamic Direct 动态直连命中</div>
        <div class="stat-tile-value">
          IPv4: {{ status?.dynamic_direct_v4_count ?? 0 }} · IPv6: {{ status?.dynamic_direct_v6_count ?? 0 }}
        </div>
      </div>
    </div>

    <div v-if="preflight && preflight.warnings.length > 0" class="alert alert-warn">
      <strong>共存插件与路由冲突提醒：</strong>
      <ul style="margin: 6px 0 0 18px; padding: 0">
        <li v-for="w in preflight.warnings" :key="w">{{ w }}</li>
      </ul>
    </div>

    <!-- Action Bar -->
    <div class="card">
      <div class="card-header" style="margin-bottom: 0">
        <div class="tabs" style="margin-bottom: 0">
          <button class="tab-btn" :class="{ active: fwTab === 'changes' }" @click="fwTab = 'changes'">
            改动清单与预期规则 ({{ expected.changes.length }})
          </button>
          <button class="tab-btn" :class="{ active: fwTab === 'live' }" @click="fwTab = 'live'">
            实时生效规则 (Live)
          </button>
          <button class="tab-btn" :class="{ active: fwTab === 'diff' }" @click="fwTab = 'diff'">
            规则差异对比 (+{{ diffStats.added }} / -{{ diffStats.removed }})
          </button>
        </div>

        <div class="row-nowrap">
          <button class="btn btn-sm" :disabled="loading" @click="refreshStatus">刷新状态</button>
          <button class="btn btn-sm" :disabled="loading" @click="runAction('refresh_gateway')">刷新网关绕过</button>
          <button class="btn btn-sm btn-primary" :disabled="loading" @click="runAction('apply')">仅应用防火墙</button>
          <button class="btn btn-sm btn-danger" :disabled="loading" @click="runAction('flush')">清空 AIOS 规则</button>
        </div>
      </div>
    </div>

    <!-- Tab 1: Structured Changes & Expected Rules -->
    <div v-if="fwTab === 'changes'">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">AIOS 对系统防火墙与路由的改动清单</h3>
          <span class="badge badge-primary">目标后端: {{ expected.backend }}</span>
        </div>
        <table class="table">
          <thead>
            <tr>
              <th>范围</th>
              <th>动作</th>
              <th>目标对象</th>
              <th>详细说明</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(c, idx) in expected.changes" :key="idx">
              <td><span class="badge">{{ c.scope }}</span></td>
              <td>
                <span
                  class="badge"
                  :class="c.action === 'delete' ? 'badge-err' : 'badge-ok'"
                >
                  {{ c.action === 'create' ? '创建/覆盖' : c.action === 'delete' ? '清理移除' : '修改' }}
                </span>
              </td>
              <td><code>{{ c.target }}</code></td>
              <td style="color: var(--text-secondary)">{{ c.detail }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="card-title">预期将应用的完整规则预览</h3>
        </div>
        <pre class="code-block">{{ expected.rules }}</pre>
      </div>
    </div>

    <!-- Tab 2: Live Router Rules -->
    <div v-else-if="fwTab === 'live'">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">路由器实时生效规则（nft list table inet aios / iptables AIOS_*）</h3>
          <span class="badge" :class="status?.table_present ? 'badge-ok' : 'badge-warn'">
            {{ status?.table_present ? '规则已生效' : '当前无 AIOS 规则' }}
          </span>
        </div>
        <pre class="code-block">{{ status?.live_rules || '# 当前路由器未挂载 table inet aios 或 AIOS_* 链。' }}</pre>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="card-header"><h3 class="card-title">实时策略路由 (ip rule)</h3></div>
          <pre class="code-block" style="max-height: 220px">{{ status?.ip_rules || '(无输出)' }}</pre>
        </div>
        <div class="card">
          <div class="card-header"><h3 class="card-title">AIOS 路由表 (table {{ status?.route_table || config.transparent_proxy.route_table }})</h3></div>
          <pre class="code-block" style="max-height: 220px">{{ status?.ip_routes || '(空路由表)' }}</pre>
        </div>
      </div>
    </div>

    <!-- Tab 3: Live vs Pending Diff -->
    <div v-else-if="fwTab === 'diff'" class="card">
      <div class="card-header">
        <h3 class="card-title">实时生效规则 vs 当前配置预期规则（Diff）</h3>
        <div class="row-nowrap">
          <span class="badge badge-ok">+{{ diffStats.added }} 新增</span>
          <span class="badge badge-err">-{{ diffStats.removed }} 移除</span>
        </div>
      </div>
      <div class="code-block" style="white-space: pre; padding: 10px 0">
        <div
          v-for="(line, idx) in diffLines"
          :key="idx"
          :style="{
            padding: '1px 14px',
            background:
              line.kind === 'add'
                ? 'rgba(16, 185, 129, 0.14)'
                : line.kind === 'del'
                  ? 'rgba(239, 68, 68, 0.14)'
                  : 'transparent',
            color:
              line.kind === 'add'
                ? '#6ee7b7'
                : line.kind === 'del'
                  ? '#fca5a5'
                  : 'var(--text-secondary)'
          }"
        >
          {{ line.kind === 'add' ? '+ ' : line.kind === 'del' ? '- ' : '  ' }}{{ line.text }}
        </div>
      </div>
    </div>
  </div>
</template>
