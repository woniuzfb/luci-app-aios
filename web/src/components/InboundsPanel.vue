<script setup lang="ts">
import { computed, ref } from 'vue';
import type { CoreType, InboundConfig } from '@/schema/types';
import { getCoreCapabilities, type V2RayFormat } from '@/schema/capabilities';
import ArrayInput from '@/components/ui/ArrayInput.vue';
import KeyValueInput from '@/components/ui/KeyValueInput.vue';
import ToggleSwitch from '@/components/ui/ToggleSwitch.vue';
import StreamEditor from '@/components/StreamEditor.vue';

const props = defineProps<{
  inbounds: InboundConfig[];
  core: CoreType;
  v2rayFormat?: V2RayFormat;
}>();

const cap = computed(() => getCoreCapabilities(props.core, props.v2rayFormat || 'jsonv4'));
const selectedId = ref<string>(props.inbounds[0]?.id || '');
const subTab = ref<'basic' | 'users' | 'stream' | 'advanced'>('basic');

const selected = computed(() => props.inbounds.find((i) => i.id === selectedId.value) || null);

function addInbound() {
  const id = `in_${Date.now().toString(36)}`;
  const item: InboundConfig = {
    id,
    enabled: true,
    alias: 'New Inbound',
    tag: id,
    listen: '127.0.0.1',
    port: 10810 + props.inbounds.length,
    protocol: 'socks',
    transport: props.core === 'xray' ? 'raw' : 'tcp',
    security: 'none',
    socks_auth: 'noauth',
    socks_udp: true,
    sniffing_enabled: true,
    sniffing_dest_override: ['http', 'tls'],
    sniffing_domains_excluded: [],
    users: [],
    fallbacks: []
  };
  props.inbounds.unshift(item);
  selectedId.value = id;
  subTab.value = 'basic';
}

function cloneInbound(src: InboundConfig) {
  const copy = JSON.parse(JSON.stringify(src)) as InboundConfig;
  copy.id = `in_${Date.now().toString(36)}`;
  copy.tag = `${src.tag}-copy`;
  copy.alias = `${src.alias} (副本)`;
  copy.port = (src.port || 10800) + 1;
  props.inbounds.unshift(copy);
  selectedId.value = copy.id;
}

function removeInbound(id: string) {
  const idx = props.inbounds.findIndex((i) => i.id === id);
  if (idx >= 0) props.inbounds.splice(idx, 1);
  if (selectedId.value === id) selectedId.value = props.inbounds[0]?.id || '';
}

function addUser() {
  if (!selected.value) return;
  if (!selected.value.users) selected.value.users = [];
  selected.value.users.unshift({ id: '', username: '', password: '', auth: '', flow: '', alterId: 0, email: '', level: 0 });
}

function addWgPeer() {
  if (!selected.value) return;
  if (!selected.value.wg_peers) selected.value.wg_peers = [];
  selected.value.wg_peers.unshift({ publicKey: '', preSharedKey: '', endpoint: '', allowedIPs: ['10.0.0.2/32'], keepAlive: 25 });
}

function addFallback() {
  if (!selected.value) return;
  if (!selected.value.fallbacks) selected.value.fallbacks = [];
  selected.value.fallbacks.unshift({ name: '', alpn: '', path: '', dest: '80', xver: 0 });
}
</script>

<template>
  <div class="split-pane">
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">入站列表 ({{ inbounds.length }})</h3>
        <button class="btn btn-sm btn-primary" @click="addInbound">+ 新增</button>
      </div>
      <div style="display: flex; flex-direction: column; gap: 4px">
        <button
          v-for="item in inbounds"
          :key="item.id"
          class="nav-btn"
          :class="{ active: item.id === selectedId }"
          @click="selectedId = item.id"
        >
          <div style="min-width: 0; overflow: hidden">
            <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{{ item.alias || item.tag }}</div>
            <div style="font-size: 11px; color: var(--muted)">
              {{ item.protocol }} · {{ item.protocol === 'tun' ? (item.tun_name || 'tun0') : `${item.listen}:${item.port}` }}
            </div>
          </div>
          <span class="badge" :class="item.enabled ? 'badge-ok' : ''">{{ item.enabled ? '开' : '关' }}</span>
        </button>
      </div>
    </div>

    <div v-if="selected" class="card">
      <div class="card-header">
        <h3 class="card-title">编辑入站：{{ selected.alias || selected.tag }}</h3>
        <div class="row-nowrap">
          <ToggleSwitch v-model="selected.enabled" label="启用" />
          <button class="btn btn-sm" @click="cloneInbound(selected)">克隆</button>
          <button class="btn btn-sm btn-danger" @click="removeInbound(selected.id)">删除</button>
        </div>
      </div>

      <div class="tabs">
        <button class="tab-btn" :class="{ active: subTab === 'basic' }" @click="subTab = 'basic'">基础与协议</button>
        <button class="tab-btn" :class="{ active: subTab === 'users' }" @click="subTab = 'users'">多用户与回落</button>
        <button class="tab-btn" :class="{ active: subTab === 'stream' }" @click="subTab = 'stream'">传输与安全 (Stream)</button>
        <button class="tab-btn" :class="{ active: subTab === 'advanced' }" @click="subTab = 'advanced'">嗅探 / 分配 / 覆写</button>
      </div>

      <!-- Tab 1: Basic & Protocol -->
      <div v-if="subTab === 'basic'" style="display: flex; flex-direction: column; gap: 14px">
        <div class="grid-3">
          <div class="field"><label>别名 (Alias)</label><input v-model="selected.alias" type="text" /></div>
          <div class="field"><label>标识 (Tag)</label><input v-model="selected.tag" type="text" /></div>
          <div class="field">
            <label>协议 (Protocol — {{ cap.label }})</label>
            <select v-model="selected.protocol">
              <option v-for="p in cap.inboundProtocols" :key="p" :value="p">{{ p }}</option>
            </select>
          </div>
          <div v-if="selected.protocol !== 'tun'" class="field">
            <label>监听地址 (IP 或 Unix Socket 路径)</label>
            <input v-model="selected.listen" type="text" placeholder="0.0.0.0 或 @abstract" />
          </div>
          <div v-if="selected.protocol !== 'tun'" class="field">
            <label>端口 (Port)</label>
            <input v-model.number="selected.port" type="number" />
          </div>
        </div>

        <div v-if="selected.protocol === 'socks'" class="card-subtle grid-3" style="align-items: end">
          <div class="field">
            <label>认证方式 (auth)</label>
            <select v-model="selected.socks_auth">
              <option value="noauth">noauth（无认证）</option>
              <option value="password">password（账号密码）</option>
            </select>
          </div>
          <div class="field"><label>UDP 绑定 IP (ip)</label><input v-model="selected.socks_ip" type="text" placeholder="127.0.0.1" /></div>
          <div v-if="core === 'v2ray'" class="field">
            <label>UDP 封包编码 (packetEncoding, V2Ray)</label>
            <select v-model="selected.packet_encoding">
              <option value="">默认</option>
              <option value="None">None</option>
              <option value="Packet">Packet</option>
            </select>
          </div>
          <ToggleSwitch v-model="selected.socks_udp" label="启用 UDP 转发" />
        </div>

        <div v-if="selected.protocol === 'http'" class="card-subtle grid-2" style="align-items: end">
          <div class="field">
            <label>连接超时 (timeout, 秒)</label>
            <input v-model.number="selected.http_timeout" type="number" placeholder="300" />
          </div>
          <ToggleSwitch v-model="selected.http_allow_transparent" label="允许透明代理 (allowTransparent)" />
        </div>

        <div v-if="selected.protocol === 'dokodemo-door' || selected.protocol === 'tunnel'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
          <div class="grid-3">
            <div class="field"><label>网络 (network / allowedNetwork)</label><input v-model="selected.dokodemo_network" type="text" placeholder="tcp,udp" /></div>
            <div class="field"><label>转发目标地址 (address / rewriteAddress)</label><input v-model="selected.dokodemo_address" type="text" placeholder="可选，用于 DNS/端口转发" /></div>
            <div class="field"><label>转发目标端口 (port / rewritePort)</label><input v-model.number="selected.dokodemo_port" type="number" /></div>
            <div v-if="core === 'xray'" class="field"><label>用户等级 (userLevel, Xray)</label><input v-model.number="selected.tunnel_user_level" type="number" placeholder="0" /></div>
          </div>
          <KeyValueInput v-if="core === 'xray'" v-model="selected.tunnel_port_map" label="多端口映射表 (portMap, Xray)" key-placeholder="5555" value-placeholder="1.1.1.1:7777" />
          <div class="row">
            <ToggleSwitch v-model="selected.dokodemo_follow_redirect" label="followRedirect（透明代理必填）" />
            <ToggleSwitch v-if="core === 'xray'" v-model="selected.use_tunnel" label="使用 Xray 新版 tunnel 协议名" />
          </div>
        </div>

        <div v-if="selected.protocol === 'vless' || selected.protocol === 'vmess'" class="card-subtle grid-3">
          <div class="field"><label>默认用户 UUID（多用户请切到「多用户与回落」）</label><input v-model="selected.uuid" type="text" /></div>
          <div v-if="selected.protocol === 'vless' && cap.supportsVlessFlow" class="field">
            <label>Flow (Xray)</label>
            <input v-model="selected.flow" type="text" placeholder="xtls-rprx-vision" />
          </div>
          <div v-if="selected.protocol === 'vless' && cap.supportsVlessEncryption" class="field">
            <label>Decryption (VLESS Encryption)</label>
            <input v-model="selected.decryption" type="text" placeholder="none" />
          </div>
        </div>

        <div v-if="selected.protocol === 'trojan' || selected.protocol === 'shadowsocks'" class="card-subtle grid-3">
          <div class="field"><label>密码 (Password)</label><input v-model="selected.password" type="password" /></div>
          <div v-if="selected.protocol === 'shadowsocks'" class="field">
            <label>加密方式 (Method)</label>
            <input v-model="selected.method" type="text" placeholder="2022-blake3-aes-128-gcm / aes-256-gcm" />
          </div>
          <div v-if="selected.protocol === 'shadowsocks'" class="field">
            <label>网络 (network)</label>
            <input v-model="selected.ss_network" type="text" placeholder="tcp,udp" />
          </div>
          <div v-if="core === 'v2ray'" class="field">
            <label>UDP 封包编码 (packetEncoding, V2Ray)</label>
            <select v-model="selected.packet_encoding">
              <option value="">默认</option>
              <option value="None">None</option>
              <option value="Packet">Packet</option>
            </select>
          </div>
        </div>

        <div v-if="selected.protocol === 'hysteria' || selected.protocol === 'hysteria2'" class="card-subtle grid-3">
          <div class="field"><label>单用户认证密码 (auth / password)</label><input v-model="selected.password" type="password" placeholder="多用户请切到「多用户与回落」" /></div>
          <div class="field"><label>上行带宽上限 (Mbps)</label><input v-model.number="selected.hysteria_up_mbps" type="number" placeholder="100" /></div>
          <div class="field"><label>下行带宽上限 (Mbps)</label><input v-model.number="selected.hysteria_down_mbps" type="number" placeholder="500" /></div>
        </div>

        <div v-if="selected.protocol === 'wireguard' && core === 'xray'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
          <div class="grid-2">
            <div class="field"><label>服务端私钥 (secretKey)</label><input v-model="selected.wg_secret_key" type="password" /></div>
            <div class="field"><label>MTU</label><input v-model.number="selected.wg_mtu" type="number" placeholder="1420" /></div>
          </div>
          <ArrayInput v-model="selected.wg_address" label="服务端隧道地址 (address[])" placeholder="回车添加，如 10.0.0.1/24" />
          <div class="row-nowrap" style="justify-content: space-between">
            <strong style="font-size: 12.5px">允许接入的 Peers 列表 (peers[])</strong>
            <button class="btn btn-sm" @click="addWgPeer">+ 添加 Peer</button>
          </div>
          <div v-for="(peer, idx) in selected.wg_peers || []" :key="idx" class="card-subtle" style="display: flex; flex-direction: column; gap: 8px">
            <div class="grid-3">
              <div class="field"><label>Peer PublicKey</label><input v-model="peer.publicKey" type="text" /></div>
              <div class="field"><label>PreSharedKey (可选)</label><input v-model="peer.preSharedKey" type="password" /></div>
              <div class="row-nowrap" style="align-items: end">
                <div class="field" style="flex: 1"><label>KeepAlive (s)</label><input v-model.number="peer.keepAlive" type="number" /></div>
                <button class="btn btn-sm btn-danger" @click="selected.wg_peers?.splice(idx, 1)">删</button>
              </div>
            </div>
            <ArrayInput v-model="peer.allowedIPs" label="allowedIPs[]" :suggestions="['10.0.0.2/32', '0.0.0.0/0', '::/0']" />
          </div>
        </div>

        <div v-if="selected.protocol === 'masque' && core === 'xray'" class="card-subtle" style="display: flex; flex-direction: column; gap: 10px">
          <div class="grid-2">
            <ArrayInput v-model="selected.masque_address" label="MASQUE 隧道地址池 (address[])" placeholder="回车添加，如 10.0.0.1/24" />
            <div class="field"><label>隧道 MTU (1280-65535)</label><input v-model.number="selected.masque_mtu" type="number" placeholder="1280" /></div>
          </div>
          <div class="field-hint">请在「多用户与回落」标签页配置 MASQUE 用户（email + password），未配置用户时所有连接都会被拒绝。</div>
        </div>

        <div v-if="selected.protocol === 'tun'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
          <div class="grid-3">
            <div class="field"><label>TUN 网卡名</label><input v-model="selected.tun_name" type="text" placeholder="aios0" /></div>
            <div class="field"><label>MTU</label><input v-model.number="selected.tun_mtu" type="number" placeholder="1500" /></div>
            <div v-if="core === 'xray'" class="field"><label>自动绑定出口网卡 (autoOutboundsInterface)</label><input v-model="selected.tun_auto_outbounds_interface" type="text" placeholder="auto" /></div>
          </div>
          <div v-if="core === 'xray'" class="grid-3">
            <ArrayInput v-model="selected.tun_gateway" label="TUN 网关地址前缀 (gateway[])" placeholder="如 10.0.0.1/16" />
            <ArrayInput v-model="selected.tun_dns" label="TUN DNS 列表 (dns[])" placeholder="如 1.1.1.1" />
            <ArrayInput v-model="selected.tun_auto_routing_table" label="自动系统路由表 (autoSystemRoutingTable[])" :suggestions="['0.0.0.0/0', '::/0']" />
          </div>
          <div v-if="core === 'v2ray'" class="grid-2">
            <ArrayInput v-model="selected.tun_ips" label="TUN IP 地址段 (ips[])" placeholder="如 10.0.0.1/24" />
            <ArrayInput v-model="selected.tun_routes" label="TUN 路由表 (routes[])" :suggestions="['0.0.0.0/0']" />
          </div>
          <div v-if="core === 'v2ray'" class="row">
            <ToggleSwitch v-model="selected.tun_promiscuous" label="enablePromiscuousMode" />
            <ToggleSwitch v-model="selected.tun_spoofing" label="enableSpoofing" />
          </div>
        </div>
      </div>

      <!-- Tab 2: Multi-Users & Fallbacks -->
      <div v-else-if="subTab === 'users'" style="display: flex; flex-direction: column; gap: 16px">
        <div class="card-subtle">
          <div class="card-header" style="margin-bottom: 10px">
            <strong style="font-size: 13px">多用户列表 (users[] / clients[] / accounts[])</strong>
            <button class="btn btn-sm btn-primary" @click="addUser">+ 添加用户</button>
          </div>
          <div v-if="!selected.users || selected.users.length === 0" class="field-hint">
            未添加多用户时，将自动使用基础页中的单用户字段。点击「+ 添加用户」可连续配置任意数量用户。
          </div>
          <div v-else style="display: flex; flex-direction: column; gap: 8px">
            <div v-for="(u, idx) in selected.users" :key="idx" class="grid-3" style="align-items: end">
              <div v-if="selected.protocol === 'vless' || selected.protocol === 'vmess'" class="field">
                <label>UUID</label><input v-model="u.id" type="text" />
              </div>
              <div v-if="selected.protocol === 'socks' || selected.protocol === 'http'" class="field">
                <label>Username</label><input v-model="u.username" type="text" />
              </div>
              <div v-if="['socks', 'http', 'trojan', 'shadowsocks'].includes(selected.protocol)" class="field">
                <label>Password</label><input v-model="u.password" type="password" />
              </div>
              <div v-if="selected.protocol === 'hysteria' || selected.protocol === 'hysteria2'" class="field">
                <label>Auth 密钥</label><input v-model="u.auth" type="password" />
              </div>
              <div v-if="selected.protocol === 'vless' && cap.supportsVlessFlow" class="field">
                <label>Flow</label><input v-model="u.flow" type="text" placeholder="xtls-rprx-vision" />
              </div>
              <div class="row-nowrap">
                <input v-model="u.email" type="text" placeholder="email 统计标识（可选）" />
                <button class="btn btn-sm btn-danger" @click="selected.users?.splice(idx, 1)">删</button>
              </div>
            </div>
          </div>
        </div>

        <div class="card-subtle">
          <div class="card-header" style="margin-bottom: 10px">
            <strong style="font-size: 13px">回落分流列表 (fallbacks[] — VLESS / Trojan)</strong>
            <button class="btn btn-sm btn-primary" @click="addFallback">+ 添加回落</button>
          </div>
          <div v-if="!selected.fallbacks || selected.fallbacks.length === 0" class="field-hint">
            无回落配置。可用于同端口分流 Web / WebSocket / gRPC 后端服务。
          </div>
          <div v-else style="display: flex; flex-direction: column; gap: 8px">
            <div v-for="(fb, idx) in selected.fallbacks" :key="idx" class="grid-3" style="align-items: end">
              <div class="field"><label>目标 dest *</label><input v-model="fb.dest" type="text" placeholder="127.0.0.1:8080" /></div>
              <div class="field"><label>path / alpn / name</label><input v-model="fb.path" type="text" placeholder="/ws（留空匹配默认）" /></div>
              <div class="row-nowrap">
                <input v-model="fb.alpn" type="text" placeholder="alpn 如 h2" />
                <input v-model.number="fb.xver" type="number" style="width: 72px" placeholder="xver" />
                <button class="btn btn-sm btn-danger" @click="selected.fallbacks?.splice(idx, 1)">删</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 3: Stream & Security -->
      <StreamEditor v-else-if="subTab === 'stream'" :model="selected" :core="core" :v2ray-format="v2rayFormat" :is-inbound="true" />

      <!-- Tab 4: Sniffing / Allocate / Custom JSON -->
      <div v-else-if="subTab === 'advanced'" style="display: flex; flex-direction: column; gap: 14px">
        <div class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
          <div class="row">
            <ToggleSwitch v-model="selected.sniffing_enabled" label="启用流量嗅探 (sniffing)" />
            <ToggleSwitch v-model="selected.sniffing_metadata_only" label="metadataOnly (仅元数据)" />
            <ToggleSwitch v-if="core === 'xray'" v-model="selected.sniffing_route_only" label="routeOnly (仅用于路由)" />
          </div>
          <ArrayInput
            v-model="selected.sniffing_dest_override"
            label="嗅探目标协议 (destOverride[])"
            :suggestions="core === 'xray' ? ['http', 'tls', 'quic', 'fakedns'] : ['http', 'tls', 'quic', 'fakedns', 'fakedns+others']"
          />
          <div class="grid-2">
            <ArrayInput
              v-model="selected.sniffing_domains_excluded"
              label="排除嗅探域名 (domainsExcluded[])"
              placeholder="回车添加域名，如 courier.push.apple.com"
            />
            <ArrayInput
              v-if="core === 'xray'"
              v-model="selected.sniffing_ips_excluded"
              label="排除嗅探 IP (ipsExcluded[], Xray)"
              placeholder="回车添加 CIDR 或 IP"
            />
          </div>
        </div>

        <div class="card-subtle grid-3">
          <div class="field">
            <label>端口分配策略 (allocate.strategy)</label>
            <select v-model="selected.allocate_strategy">
              <option value="">不启用</option>
              <option value="always">always</option>
              <option value="random">random</option>
            </select>
          </div>
          <div class="field"><label>刷新间隔 (refresh, 分钟)</label><input v-model.number="selected.allocate_refresh" type="number" placeholder="5" /></div>
          <div class="field"><label>并发端口数 (concurrency)</label><input v-model.number="selected.allocate_concurrency" type="number" placeholder="3" /></div>
        </div>

        <div class="field">
          <label>高级自定义覆写 JSON (custom_config，递归合并到当前入站对象)</label>
          <textarea v-model="selected.custom_config" rows="3" placeholder='{"tag":"override"}' />
        </div>
      </div>
    </div>
  </div>
</template>
