<script setup lang="ts">
import { computed, ref } from 'vue';
import type { CoreType, OutboundConfig } from '@/schema/types';
import { CORE_CAPABILITIES } from '@/schema/capabilities';
import { parseShareUriList } from '@/importers/uri';
import ArrayInput from '@/components/ui/ArrayInput.vue';
import ToggleSwitch from '@/components/ui/ToggleSwitch.vue';
import StreamEditor from '@/components/StreamEditor.vue';

const props = defineProps<{
  outbounds: OutboundConfig[];
  core: CoreType;
}>();

const cap = computed(() => CORE_CAPABILITIES[props.core]);
const selectedId = ref<string>(props.outbounds[0]?.id || '');
const subTab = ref<'basic' | 'stream' | 'advanced'>('basic');
const selected = computed(() => props.outbounds.find((o) => o.id === selectedId.value) || null);

const showImport = ref(false);
const importText = ref('');
const importResult = ref('');

function addOutbound() {
  const id = `out_${Date.now().toString(36)}`;
  const item: OutboundConfig = {
    id,
    enabled: true,
    alias: 'New Proxy Outbound',
    tag: id,
    protocol: props.core === 'xray' ? 'vless' : 'vmess',
    address: '',
    port: 443,
    uuid: '',
    encryption: 'none',
    transport: props.core === 'xray' ? 'raw' : 'tcp',
    security: 'tls',
    tls_fingerprint: 'chrome',
    tls_alpn: []
  };
  props.outbounds.unshift(item);
  selectedId.value = id;
  subTab.value = 'basic';
}

function cloneOutbound(src: OutboundConfig) {
  const copy = JSON.parse(JSON.stringify(src)) as OutboundConfig;
  copy.id = `out_${Date.now().toString(36)}`;
  copy.tag = `${src.tag}-copy`;
  copy.alias = `${src.alias} (副本)`;
  props.outbounds.unshift(copy);
  selectedId.value = copy.id;
}

function removeOutbound(id: string) {
  const idx = props.outbounds.findIndex((o) => o.id === id);
  if (idx >= 0) props.outbounds.splice(idx, 1);
  if (selectedId.value === id) selectedId.value = props.outbounds[0]?.id || '';
}

function addWgPeer() {
  if (!selected.value) return;
  if (!selected.value.wg_peers) selected.value.wg_peers = [];
  selected.value.wg_peers.unshift({ publicKey: '', endpoint: '', allowedIPs: ['0.0.0.0/0', '::/0'], keepAlive: 25 });
}

function handleImport() {
  const parsed = parseShareUriList(importText.value);
  if (parsed.length === 0) {
    importResult.value = '未解析到有效节点链接（支持 vless://, vmess://, trojan://, ss://, hy2://）。';
    return;
  }
  for (const item of parsed.reverse()) {
    props.outbounds.unshift(item);
  }
  selectedId.value = parsed[0].id;
  importResult.value = `已成功导入 ${parsed.length} 个出站节点。`;
  importText.value = '';
}
</script>

<template>
  <div>
    <div v-if="showImport" class="card">
      <div class="card-header">
        <h3 class="card-title">批量导入分享链接（vless / vmess / trojan / ss / hy2）</h3>
        <button class="btn btn-sm" @click="showImport = false">收起</button>
      </div>
      <textarea
        v-model="importText"
        rows="4"
        placeholder="每行粘贴一条分享链接：vless://... / vmess://... / trojan://... / ss://... / hy2://..."
      />
      <div class="row" style="margin-top: 10px">
        <button class="btn btn-primary" @click="handleImport">解析并导入</button>
        <span v-if="importResult" style="font-size: 12.5px; color: var(--success)">{{ importResult }}</span>
      </div>
    </div>

    <div class="split-pane">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">出站列表 ({{ outbounds.length }})</h3>
          <div class="row-nowrap">
            <button class="btn btn-sm" @click="showImport = !showImport">导入</button>
            <button class="btn btn-sm btn-primary" @click="addOutbound">+ 新增</button>
          </div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 4px">
          <button
            v-for="item in outbounds"
            :key="item.id"
            class="nav-btn"
            :class="{ active: item.id === selectedId }"
            @click="selectedId = item.id"
          >
            <div style="min-width: 0; overflow: hidden">
              <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{{ item.alias || item.tag }}</div>
              <div style="font-size: 11px; color: var(--muted)">
                {{ item.protocol }} · {{ item.address ? `${item.address}:${item.port}` : item.tag }}
              </div>
            </div>
            <span class="badge" :class="item.enabled ? 'badge-ok' : ''">{{ item.enabled ? '开' : '关' }}</span>
          </button>
        </div>
      </div>

      <div v-if="selected" class="card">
        <div class="card-header">
          <h3 class="card-title">编辑出站：{{ selected.alias || selected.tag }}</h3>
          <div class="row-nowrap">
            <ToggleSwitch v-model="selected.enabled" label="启用" />
            <button class="btn btn-sm" @click="cloneOutbound(selected)">克隆</button>
            <button class="btn btn-sm btn-danger" @click="removeOutbound(selected.id)">删除</button>
          </div>
        </div>

        <div class="tabs">
          <button class="tab-btn" :class="{ active: subTab === 'basic' }" @click="subTab = 'basic'">基础与协议</button>
          <button class="tab-btn" :class="{ active: subTab === 'stream' }" @click="subTab = 'stream'">传输与安全 (Stream)</button>
          <button class="tab-btn" :class="{ active: subTab === 'advanced' }" @click="subTab = 'advanced'">Mux 与高级覆写</button>
        </div>

        <!-- Tab 1: Basic & Protocol -->
        <div v-if="subTab === 'basic'" style="display: flex; flex-direction: column; gap: 14px">
          <div class="grid-3">
            <div class="field"><label>别名 (Alias)</label><input v-model="selected.alias" type="text" /></div>
            <div class="field"><label>标识 (Tag)</label><input v-model="selected.tag" type="text" /></div>
            <div class="field">
              <label>协议 (Protocol — {{ cap.label }})</label>
              <select v-model="selected.protocol">
                <option v-for="p in cap.outboundProtocols" :key="p" :value="p">{{ p }}</option>
              </select>
            </div>
            <div
              v-if="!['freedom', 'blackhole', 'dns', 'loopback', 'wireguard'].includes(selected.protocol)"
              class="field"
            >
              <label>服务器地址 (Address)</label>
              <input v-model="selected.address" type="text" placeholder="example.com" />
            </div>
            <div
              v-if="!['freedom', 'blackhole', 'dns', 'loopback', 'wireguard'].includes(selected.protocol)"
              class="field"
            >
              <label>端口 (Port)</label>
              <input v-model.number="selected.port" type="number" />
            </div>
            <div class="field">
              <label>前置链式代理 ({{ core === 'xray' ? 'sockopt.dialerProxy' : 'proxySettings.tag' }})</label>
              <input v-model="selected.dialer_proxy" type="text" placeholder="可选，填写前置 outbound tag" />
            </div>
            <div class="field">
              <label>出口源地址 (sendThrough)</label>
              <input v-model="selected.send_through" type="text" placeholder="可选，如 0.0.0.0 或 IPv6 CIDR" />
            </div>
          </div>

          <!-- VLESS / VMess -->
          <div v-if="selected.protocol === 'vless' || selected.protocol === 'vmess'" class="card-subtle grid-3">
            <div class="field"><label>UUID</label><input v-model="selected.uuid" type="text" /></div>
            <div v-if="selected.protocol === 'vless' && cap.supportsVlessFlow" class="field">
              <label>Flow (Xray)</label>
              <select v-model="selected.flow">
                <option value="">无</option>
                <option value="xtls-rprx-vision">xtls-rprx-vision</option>
                <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
              </select>
            </div>
            <div v-if="selected.protocol === 'vless' && cap.supportsVlessEncryption" class="field">
              <label>Encryption (VLESS Encryption)</label>
              <input v-model="selected.encryption" type="text" placeholder="none 或 mlkem768..." />
            </div>
            <div v-if="selected.protocol === 'vmess'" class="field">
              <label>加密算法 (Security)</label>
              <select v-model="selected.security_cipher">
                <option value="auto">auto</option>
                <option value="aes-128-gcm">aes-128-gcm</option>
                <option value="chacha20-poly1305">chacha20-poly1305</option>
                <option value="none">none</option>
                <option value="zero">zero</option>
              </select>
            </div>
            <div v-if="selected.protocol === 'vmess' && core === 'v2ray'" class="field">
              <label>AlterID (V2Ray 建议 0 启用 AEAD)</label>
              <input v-model.number="selected.alter_id" type="number" />
            </div>
          </div>

          <!-- Trojan / Shadowsocks / Hysteria -->
          <div
            v-if="['trojan', 'shadowsocks', 'shadowsocks2022', 'hysteria', 'hysteria2'].includes(selected.protocol)"
            class="card-subtle"
            style="display: flex; flex-direction: column; gap: 12px"
          >
            <div class="grid-3">
              <div class="field"><label>密码 / Auth</label><input v-model="selected.password" type="password" /></div>
              <div v-if="selected.protocol.startsWith('shadowsocks')" class="field">
                <label>加密方式 (Method)</label>
                <input v-model="selected.method" type="text" placeholder="2022-blake3-aes-128-gcm / aes-256-gcm" />
              </div>
              <div v-if="selected.protocol === 'hysteria' || selected.protocol === 'hysteria2'" class="field">
                <label>上行带宽 (Mbps, Brutal)</label>
                <input v-model.number="selected.hysteria_up_mbps" type="number" placeholder="50" />
              </div>
              <div v-if="selected.protocol === 'hysteria' || selected.protocol === 'hysteria2'" class="field">
                <label>下行带宽 (Mbps, Brutal)</label>
                <input v-model.number="selected.hysteria_down_mbps" type="number" placeholder="200" />
              </div>
              <div v-if="core === 'xray' && selected.protocol === 'hysteria'" class="field">
                <label>Salamander 混淆密码 (FinalMask)</label>
                <input v-model="selected.hysteria_obfs_password" type="text" />
              </div>
              <div v-if="core === 'xray' && selected.protocol === 'hysteria'" class="field">
                <label>UDP 端口跳跃 (如 20000-50000)</label>
                <input v-model="selected.hysteria_udphop_port" type="text" />
              </div>
            </div>
            <div v-if="selected.protocol.startsWith('shadowsocks')" class="row">
              <ToggleSwitch v-if="core === 'xray'" v-model="selected.ss_uot" label="UDP over TCP (uot)" />
              <ToggleSwitch v-if="core === 'v2ray'" v-model="selected.ss_iv_check" label="ivCheck (防重放)" />
            </div>
          </div>

          <!-- WireGuard (Xray) -->
          <div v-if="selected.protocol === 'wireguard' && core === 'xray'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
            <div class="grid-3">
              <div class="field"><label>Secret Key</label><input v-model="selected.wg_secret_key" type="password" /></div>
              <div class="field"><label>MTU</label><input v-model.number="selected.wg_mtu" type="number" placeholder="1420" /></div>
              <div class="field" style="justify-content: flex-end">
                <ToggleSwitch v-model="selected.wg_no_kernel_tun" label="用户态 noKernelTun" />
              </div>
            </div>
            <div class="grid-2">
              <ArrayInput v-model="selected.wg_address" label="本机隧道地址 (address[])" placeholder="回车添加，如 172.16.0.2/32" />
              <ArrayInput v-model="selected.wg_reserved" label="Reserved 字节数组 (reserved[])" placeholder="如 12, 34, 56" />
            </div>
            <div class="row-nowrap" style="justify-content: space-between">
              <strong style="font-size: 12.5px">WireGuard Peers 列表 (peers[])</strong>
              <button class="btn btn-sm" @click="addWgPeer">+ 添加 Peer</button>
            </div>
            <div v-for="(peer, idx) in selected.wg_peers || []" :key="idx" class="card-subtle" style="display: flex; flex-direction: column; gap: 8px">
              <div class="grid-3">
                <div class="field"><label>Peer PublicKey</label><input v-model="peer.publicKey" type="text" /></div>
                <div class="field"><label>Endpoint</label><input v-model="peer.endpoint" type="text" placeholder="engage.cloudflareclient.com:2408" /></div>
                <div class="row-nowrap" style="align-items: end">
                  <div class="field" style="flex: 1"><label>KeepAlive (s)</label><input v-model.number="peer.keepAlive" type="number" /></div>
                  <button class="btn btn-sm btn-danger" @click="selected.wg_peers?.splice(idx, 1)">删</button>
                </div>
              </div>
              <ArrayInput v-model="peer.allowedIPs" label="allowedIPs[]" :suggestions="['0.0.0.0/0', '::/0']" />
            </div>
          </div>

          <!-- Freedom / Blackhole / DNS / Loopback -->
          <div v-if="selected.protocol === 'freedom'" class="card-subtle grid-2">
            <div class="field"><label>重定向目标 (redirect)</label><input v-model="selected.freedom_redirect" type="text" placeholder="可选，如 127.0.0.1:80" /></div>
            <div class="field">
              <label>域名解析策略 (domainStrategy)</label>
              <select v-model="selected.domain_strategy">
                <option value="AsIs">AsIs</option>
                <option value="UseIP">UseIP</option>
                <option value="UseIPv4">UseIPv4</option>
                <option value="UseIPv6">UseIPv6</option>
              </select>
            </div>
          </div>
          <div v-if="selected.protocol === 'dns'" class="card-subtle grid-3">
            <div class="field"><label>network</label><input v-model="selected.dns_network" type="text" placeholder="udp / tcp" /></div>
            <div class="field"><label>address</label><input v-model="selected.dns_address" type="text" placeholder="可选" /></div>
            <div v-if="core === 'xray'" class="field">
              <label>nonIPQuery (Xray)</label>
              <select v-model="selected.dns_non_ip_query">
                <option value="">默认</option>
                <option value="skip">skip</option>
                <option value="drop">drop</option>
              </select>
            </div>
          </div>
        </div>

        <!-- Tab 2: Stream & Security -->
        <StreamEditor v-else-if="subTab === 'stream'" :model="selected" :core="core" :is-inbound="false" />

        <!-- Tab 3: Mux & Custom JSON -->
        <div v-else-if="subTab === 'advanced'" style="display: flex; flex-direction: column; gap: 14px">
          <div class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
            <ToggleSwitch v-model="selected.mux_enabled" label="启用多路复用 (Mux)" />
            <div class="grid-3">
              <div class="field">
                <label>concurrency (-1 禁用 / 1-1024)</label>
                <input v-model.number="selected.mux_concurrency" type="number" placeholder="8" />
              </div>
              <div v-if="core === 'xray'" class="field">
                <label>xudpConcurrency (Xray)</label>
                <input v-model.number="selected.mux_xudp_concurrency" type="number" placeholder="16" />
              </div>
              <div v-if="core === 'xray'" class="field">
                <label>xudpProxyUDP443 (Xray)</label>
                <select v-model="selected.mux_xudp_proxy_udp443">
                  <option value="">默认</option>
                  <option value="reject">reject</option>
                  <option value="allow">allow</option>
                  <option value="skip">skip</option>
                </select>
              </div>
            </div>
          </div>

          <div class="field">
            <label>高级自定义覆写 JSON (custom_config)</label>
            <textarea v-model="selected.custom_config" rows="3" placeholder='{"targetStrategy":"UseIP"}' />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
