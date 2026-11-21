<script setup lang="ts">
import { computed, ref } from 'vue';
import type { AiosConfig, CoreType } from '@/schema/types';
import { CORE_CAPABILITIES } from '@/schema/capabilities';
import ArrayInput from '@/components/ui/ArrayInput.vue';
import ToggleSwitch from '@/components/ui/ToggleSwitch.vue';

const props = defineProps<{
  config: AiosConfig;
  core: CoreType;
}>();

const cap = computed(() => CORE_CAPABILITIES[props.core]);
const subTab = ref<'dns' | 'routing' | 'balancers' | 'policy'>('dns');

function addDnsServer() {
  props.config.dns_servers.unshift({
    id: `dns_${Date.now().toString(36)}`,
    enabled: true,
    alias: 'New DNS',
    address: '8.8.8.8',
    port: 53,
    skip_fallback: false,
    domains: [],
    expect_ips: [],
    unexpected_ips: []
  });
}

function addHostEntry() {
  if (!props.config.dns.host_entries) props.config.dns.host_entries = [];
  props.config.dns.host_entries.unshift({ domain: '', addresses: [] });
}

function addRoutingRule() {
  props.config.routing_rules.unshift({
    id: `rule_${Date.now().toString(36)}`,
    enabled: true,
    alias: 'New Routing Rule',
    domain: [],
    ip: [],
    source: [],
    local_ip: [],
    user: [],
    inbound_tag: [],
    protocol: [],
    process: [],
    outbound_tag: 'direct'
  });
}

function addBalancer() {
  props.config.balancers.unshift({
    id: `bal_${Date.now().toString(36)}`,
    tag: `balancer-${props.config.balancers.length + 1}`,
    selector: [],
    strategy: 'random',
    fallback_tag: ''
  });
}

function addFakeDns() {
  props.config.fakedns.unshift({
    id: `fake_${Date.now().toString(36)}`,
    ip_pool: '198.18.0.0/15',
    pool_size: 65535
  });
}
</script>

<template>
  <div>
    <div class="tabs">
      <button class="tab-btn" :class="{ active: subTab === 'dns' }" @click="subTab = 'dns'">
        DNS &amp; FakeDNS ({{ config.dns_servers.length }})
      </button>
      <button class="tab-btn" :class="{ active: subTab === 'routing' }" @click="subTab = 'routing'">
        路由规则 ({{ config.routing_rules.length }})
      </button>
      <button class="tab-btn" :class="{ active: subTab === 'balancers' }" @click="subTab = 'balancers'">
        负载均衡 &amp; 观测 ({{ config.balancers.length }})
      </button>
      <button class="tab-btn" :class="{ active: subTab === 'policy' }" @click="subTab = 'policy'">
        本地策略 &amp; 反向代理
      </button>
    </div>

    <!-- Tab 1: DNS & FakeDNS -->
    <div v-if="subTab === 'dns'">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">内置 DNS 全局设置</h3>
          <ToggleSwitch v-model="config.dns.enabled" label="启用内置 DNS" />
        </div>

        <div class="grid-3">
          <div class="field"><label>DNS Tag</label><input v-model="config.dns.tag" type="text" /></div>
          <div class="field">
            <label>查询策略 (queryStrategy)</label>
            <select v-model="config.dns.query_strategy">
              <option value="UseIP">UseIP</option>
              <option value="UseIPv4">UseIPv4</option>
              <option value="UseIPv6">UseIPv6</option>
              <option v-if="core === 'xray'" value="UseSystem">UseSystem (Xray)</option>
            </select>
          </div>
          <div class="field"><label>全局 ECS (clientIp)</label><input v-model="config.dns.client_ip" type="text" placeholder="可选" /></div>
        </div>

        <div class="row" style="margin-top: 12px">
          <ToggleSwitch v-model="config.dns.disable_cache" label="disableCache" />
          <ToggleSwitch v-model="config.dns.disable_fallback" label="disableFallback" />
          <ToggleSwitch v-model="config.dns.disable_fallback_if_match" label="disableFallbackIfMatch" />
          <ToggleSwitch v-if="cap.supportsServeStale" v-model="config.dns.serve_stale" label="serveStale (Xray)" />
          <ToggleSwitch v-if="cap.supportsServeStale" v-model="config.dns.enable_parallel_query" label="enableParallelQuery (Xray)" />
        </div>
      </div>

      <!-- DNS Servers (Card list with real ArrayInputs) -->
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">DNS 服务器列表 ({{ config.dns_servers.length }})</h3>
          <button class="btn btn-sm btn-primary" @click="addDnsServer">+ 添加 DNS 服务器</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px">
          <div v-for="(srv, idx) in config.dns_servers" :key="srv.id" class="card-subtle" style="display: flex; flex-direction: column; gap: 10px">
            <div class="row-nowrap" style="justify-content: space-between">
              <div class="row">
                <ToggleSwitch v-model="srv.enabled" />
                <strong>{{ srv.alias || srv.address }}</strong>
              </div>
              <div class="row-nowrap">
                <ToggleSwitch v-model="srv.skip_fallback" label="skipFallback" />
                <button class="btn btn-sm btn-danger" @click="config.dns_servers.splice(idx, 1)">删除</button>
              </div>
            </div>
            <div class="grid-3">
              <div class="field"><label>别名</label><input v-model="srv.alias" type="text" /></div>
              <div class="field"><label>地址 (IP / https:// / tls:// / quic+local:// / fakedns)</label><input v-model="srv.address" type="text" /></div>
              <div class="field"><label>端口 (可选)</label><input v-model.number="srv.port" type="number" placeholder="53" /></div>
            </div>
            <div class="grid-2">
              <ArrayInput
                v-model="srv.domains"
                label="匹配域名列表 (domains[])"
                :suggestions="['geosite:cn', 'geosite:geolocation-!cn']"
              />
              <ArrayInput
                v-model="srv.expect_ips"
                :label="`期望 IP 列表 (${core === 'xray' ? 'expectedIPs[]' : 'expectIPs[]'})`"
                :suggestions="['geoip:cn', 'geoip:!cn']"
              />
            </div>
            <div v-if="cap.supportsUnexpectedIps" class="grid-2">
              <ArrayInput v-model="srv.unexpected_ips" label="排除 IP 列表 (unexpectedIPs[], Xray)" :suggestions="['geoip:cn']" />
              <div class="field"><label>独立 ECS (clientIP)</label><input v-model="srv.client_ip" type="text" placeholder="可选" /></div>
            </div>
          </div>
        </div>
      </div>

      <!-- Static Hosts & FakeDNS -->
      <div class="grid-2">
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">静态 Hosts 映射 (支持多 IP 数组)</h3>
            <button class="btn btn-sm" @click="addHostEntry">+ 添加映射</button>
          </div>
          <div v-if="!config.dns.host_entries || config.dns.host_entries.length === 0" class="field-hint">
            支持单域名映射到多个 IPv4/IPv6 地址，如 example.com → [1.1.1.1, 2606:4700::1]。
          </div>
          <div v-else style="display: flex; flex-direction: column; gap: 10px">
            <div v-for="(h, idx) in config.dns.host_entries" :key="idx" class="card-subtle" style="display: flex; flex-direction: column; gap: 8px">
              <div class="row-nowrap">
                <input v-model="h.domain" type="text" placeholder="domain:example.com 或 geosite:category-ads" />
                <button class="btn btn-sm btn-danger" @click="config.dns.host_entries?.splice(idx, 1)">删</button>
              </div>
              <ArrayInput v-model="h.addresses" label="目标 IP / 域名数组" placeholder="回车添加 IPv4 / IPv6" />
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">FakeDNS 地址池 ({{ config.fakedns.length }})</h3>
            <button class="btn btn-sm" @click="addFakeDns">+ 添加地址池</button>
          </div>
          <div v-if="config.fakedns.length === 0" class="field-hint">
            尚未配置 FakeDNS 池。透明代理启用 FakeDNS 时建议配置 IPv4 (198.18.0.0/15) 与 IPv6 (2001:2::/48)。
          </div>
          <div v-else style="display: flex; flex-direction: column; gap: 8px">
            <div v-for="(f, idx) in config.fakedns" :key="f.id" class="row-nowrap">
              <input v-model="f.ip_pool" type="text" placeholder="198.18.0.0/15" />
              <input v-model.number="f.pool_size" type="number" style="width: 110px" placeholder="65535" />
              <button class="btn btn-sm btn-danger" @click="config.fakedns.splice(idx, 1)">删</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Tab 2: Routing Rules -->
    <div v-else-if="subTab === 'routing'">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">路由全局参数</h3>
          <div class="row-nowrap">
            <ToggleSwitch v-model="config.routing.enabled" label="启用路由" />
            <button class="btn btn-sm btn-primary" @click="addRoutingRule">+ 新增路由规则</button>
          </div>
        </div>
        <div class="grid-2">
          <div class="field">
            <label>domainStrategy</label>
            <select v-model="config.routing.domain_strategy">
              <option value="AsIs">AsIs</option>
              <option value="IPIfNonMatch">IPIfNonMatch</option>
              <option value="IPOnDemand">IPOnDemand</option>
            </select>
          </div>
          <div class="field">
            <label>domainMatcher</label>
            <select v-model="config.routing.domain_matcher">
              <option value="hybrid">hybrid (Xray)</option>
              <option value="linear">linear</option>
              <option value="mph">mph</option>
            </select>
          </div>
        </div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 12px">
        <div v-for="(rr, idx) in config.routing_rules" :key="rr.id" class="card" style="margin: 0">
          <div class="card-header" style="margin-bottom: 10px">
            <div class="row">
              <ToggleSwitch v-model="rr.enabled" />
              <strong>#{{ idx + 1 }} {{ rr.alias || 'Unnamed Rule' }}</strong>
            </div>
            <button class="btn btn-sm btn-danger" @click="config.routing_rules.splice(idx, 1)">删除规则</button>
          </div>

          <div class="grid-3" style="margin-bottom: 10px">
            <div class="field"><label>规则别名</label><input v-model="rr.alias" type="text" /></div>
            <div class="field"><label>目标 Outbound Tag</label><input v-model="rr.outbound_tag" type="text" placeholder="direct / block / proxy" /></div>
            <div class="field"><label>或目标 Balancer Tag</label><input v-model="rr.balancer_tag" type="text" placeholder="优先于 outboundTag" /></div>
            <div class="field"><label>目标端口 (port)</label><input v-model="rr.port" type="text" placeholder="53,80,443,1000-2000" /></div>
            <div class="field"><label>来源端口 (sourcePort)</label><input v-model="rr.source_port" type="text" /></div>
            <div class="field">
              <label>传输协议 (network)</label>
              <select v-model="rr.network">
                <option value="">不限</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="tcp,udp">tcp,udp</option>
              </select>
            </div>
          </div>

          <div class="grid-2" style="margin-bottom: 10px">
            <ArrayInput
              v-model="rr.domain"
              :label="`域名匹配 (${core === 'xray' ? 'domain[]' : 'domains[]'})`"
              :suggestions="['geosite:cn', 'geosite:category-ads-all', 'geosite:geolocation-!cn']"
            />
            <ArrayInput
              v-model="rr.ip"
              label="目标 IP 匹配 (ip[])"
              :suggestions="['geoip:private', 'geoip:cn']"
            />
            <ArrayInput v-model="rr.inbound_tag" label="入站标签 (inboundTag[])" placeholder="如 socks-in, tproxy-tcp4" />
            <ArrayInput
              v-model="rr.protocol"
              label="嗅探协议 (protocol[])"
              :suggestions="core === 'xray' ? ['http', 'tls', 'bittorrent', 'quic'] : ['http', 'tls', 'bittorrent']"
            />
            <ArrayInput v-model="rr.source" label="来源 IP (source[])" placeholder="如 192.168.1.0/24" />
            <ArrayInput v-model="rr.user" label="用户邮箱 (user[])" placeholder="匹配入站用户 email" />
          </div>

          <div v-if="core === 'xray'" class="grid-2">
            <ArrayInput v-model="rr.local_ip" label="本地目标 IP (localIP[], Xray)" />
            <ArrayInput v-model="rr.process" label="进程名匹配 (process[], Xray)" />
          </div>
        </div>
      </div>
    </div>

    <!-- Tab 3: Balancers & Observatory -->
    <div v-else-if="subTab === 'balancers'" style="display: flex; flex-direction: column; gap: 16px">
      <div class="card" style="margin: 0">
        <div class="card-header">
          <h3 class="card-title">负载均衡器 (Balancers)</h3>
          <button class="btn btn-sm btn-primary" @click="addBalancer">+ 新增均衡器</button>
        </div>
        <div v-if="config.balancers.length === 0" class="field-hint">暂无负载均衡器。</div>
        <div v-else style="display: flex; flex-direction: column; gap: 10px">
          <div v-for="(b, idx) in config.balancers" :key="b.id" class="card-subtle" style="display: flex; flex-direction: column; gap: 10px">
            <div class="grid-3" style="align-items: end">
              <div class="field"><label>Balancer Tag</label><input v-model="b.tag" type="text" /></div>
              <div class="field">
                <label>调度策略 (strategy — {{ cap.label }})</label>
                <select v-model="b.strategy">
                  <option v-for="st in cap.balancerStrategies" :key="st" :value="st">{{ st }}</option>
                </select>
              </div>
              <div class="row-nowrap">
                <div v-if="core === 'xray'" class="field" style="flex: 1">
                  <label>回退节点 (fallbackTag)</label>
                  <input v-model="b.fallback_tag" type="text" placeholder="direct" />
                </div>
                <button class="btn btn-sm btn-danger" @click="config.balancers.splice(idx, 1)">删除</button>
              </div>
            </div>
            <ArrayInput v-model="b.selector" label="节点标签前缀列表 (selector[])" placeholder="回车添加出站 tag 前缀" />
          </div>
        </div>
      </div>

      <div class="card" style="margin: 0">
        <div class="card-header">
          <h3 class="card-title">连接观测 (Observatory)</h3>
          <ToggleSwitch v-model="config.observatory.enabled" label="启用连接观测" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px">
          <ArrayInput v-model="config.observatory.subject_selector" label="观测节点前缀列表 (subjectSelector[])" />
          <div class="grid-3" style="align-items: end">
            <div class="field"><label>探测 URL ({{ core === 'xray' ? 'probeUrl' : 'probeURL' }})</label><input v-model="config.observatory.probe_url" type="text" /></div>
            <div class="field"><label>探测周期 (probeInterval)</label><input v-model="config.observatory.probe_interval" type="text" placeholder="1m" /></div>
            <ToggleSwitch v-if="core === 'xray'" v-model="config.observatory.enable_concurrency" label="并发探测 (enableConcurrency)" />
          </div>
        </div>
      </div>
    </div>

    <!-- Tab 4: Policy & Reverse -->
    <div v-else-if="subTab === 'policy'" class="grid-2">
      <div class="card" style="margin: 0">
        <div class="card-header">
          <h3 class="card-title">本地策略 (Policy)</h3>
          <ToggleSwitch v-model="config.policy.enabled" label="启用" />
        </div>
        <div class="grid-2" style="margin-bottom: 12px">
          <div class="field"><label>handshake (s)</label><input v-model.number="config.policy.handshake" type="number" /></div>
          <div class="field"><label>connIdle (s)</label><input v-model.number="config.policy.conn_idle" type="number" /></div>
          <div class="field"><label>uplinkOnly (s)</label><input v-model.number="config.policy.uplink_only" type="number" /></div>
          <div class="field"><label>downlinkOnly (s)</label><input v-model.number="config.policy.downlink_only" type="number" /></div>
          <div class="field"><label>bufferSize (KB)</label><input v-model.number="config.policy.buffer_size" type="number" /></div>
        </div>
        <div class="row">
          <ToggleSwitch v-model="config.policy.stats_inbound_uplink" label="statsInboundUplink" />
          <ToggleSwitch v-model="config.policy.stats_inbound_downlink" label="statsInboundDownlink" />
          <ToggleSwitch v-model="config.policy.stats_outbound_uplink" label="statsOutboundUplink" />
          <ToggleSwitch v-model="config.policy.stats_outbound_downlink" label="statsOutboundDownlink" />
        </div>
      </div>

      <div class="card" style="margin: 0">
        <div class="card-header">
          <h3 class="card-title">反向代理 (Reverse Bridges / Portals)</h3>
          <ToggleSwitch v-model="config.reverse.enabled" label="启用" />
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px">
          <ArrayInput
            v-model="config.reverse.bridges"
            label="Bridges 列表（格式 tag|domain）"
            placeholder="例如 bridge|private.example.com"
          />
          <ArrayInput
            v-model="config.reverse.portals"
            label="Portals 列表（格式 tag|domain）"
            placeholder="例如 portal|private.example.com"
          />
        </div>
      </div>
    </div>
  </div>
</template>
