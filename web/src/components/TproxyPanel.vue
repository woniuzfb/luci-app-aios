<script setup lang="ts">
import type { AiosConfig } from '@/schema/types';
import type { PreflightResult } from '@/api/client';
import ArrayInput from '@/components/ui/ArrayInput.vue';
import ToggleSwitch from '@/components/ui/ToggleSwitch.vue';

const props = defineProps<{
  config: AiosConfig;
  preflight: PreflightResult | null;
  detectedFirewall: string;
}>();

const emit = defineEmits<{
  (e: 'run-preflight'): void;
}>();

function addLanHost() {
  props.config.lan_hosts.unshift({
    id: `lan_${Date.now().toString(36)}`,
    alias: 'LAN Device',
    macaddr: '',
    strategy_v4: 'default',
    strategy_v6: 'default'
  });
}
</script>

<template>
  <div>
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">透明代理与防冲突隔离（支持 fw4 nftables &amp; fw3 iptables）</h3>
        <div class="row-nowrap">
          <span class="badge">检测到防火墙: {{ detectedFirewall }}</span>
          <button class="btn btn-sm" @click="emit('run-preflight')">冲突预检</button>
          <ToggleSwitch v-model="config.transparent_proxy.enabled" label="启用" />
        </div>
      </div>

      <div v-if="preflight && preflight.warnings.length > 0" class="alert alert-warn">
        <strong>冲突预检发现提醒：</strong>
        <ul style="margin: 6px 0 0 18px; padding: 0">
          <li v-for="w in preflight.warnings" :key="w">{{ w }}</li>
        </ul>
      </div>

      <div class="grid-3">
        <div class="field">
          <label>防火墙后端 (firewall_backend)</label>
          <select v-model="config.transparent_proxy.firewall_backend">
            <option value="auto">auto（自动选择 fw4 / fw3）</option>
            <option value="nftables">nftables（OpenWrt 22.03+ 独立 table inet aios）</option>
            <option value="iptables">iptables + ipset（OpenWrt 19.07/21.02 AIOS_* 链）</option>
            <option value="none">none（禁用防火墙规则，适合 TUN 模式）</option>
          </select>
        </div>
        <div class="field">
          <label>拦截模式 (fw3 生效)</label>
          <select v-model="config.transparent_proxy.tproxy_mode">
            <option value="tproxy">TPROXY（TCP + UDP 双栈）</option>
            <option value="redirect">REDIRECT（仅 TCP IPv4）</option>
          </select>
        </div>
        <div class="field">
          <label>冲突处理策略 (conflict_policy)</label>
          <select v-model="config.general.conflict_policy">
            <option value="warn">仅记录告警并继续</option>
            <option value="block">检测到冲突时阻止启动</option>
            <option value="ignore">忽略</option>
          </select>
        </div>
      </div>

      <!-- Isolated marks & route table -->
      <div class="grid-3" style="margin-top: 12px">
        <div class="field">
          <label>独立路由表号 (默认 166，避开 100/251)</label>
          <input v-model.number="config.transparent_proxy.route_table" type="number" />
        </div>
        <div class="field">
          <label>TProxy fwmark (默认 0x3a01)</label>
          <input v-model="config.transparent_proxy.tproxy_mark" type="text" />
        </div>
        <div class="field">
          <label>出站防回环 mark (默认 0x3a03)</label>
          <input v-model="config.transparent_proxy.outbound_mark" type="text" />
        </div>
      </div>

      <!-- TProxy ports -->
      <div class="grid-3" style="margin-top: 12px">
        <div class="field"><label>TCP IPv4 TProxy 端口</label><input v-model.number="config.transparent_proxy.tproxy_port_tcp_v4" type="number" /></div>
        <div class="field"><label>TCP IPv6 TProxy 端口</label><input v-model.number="config.transparent_proxy.tproxy_port_tcp_v6" type="number" /></div>
        <div class="field"><label>UDP IPv4 TProxy 端口</label><input v-model.number="config.transparent_proxy.tproxy_port_udp_v4" type="number" /></div>
        <div class="field"><label>UDP IPv6 TProxy 端口</label><input v-model.number="config.transparent_proxy.tproxy_port_udp_v6" type="number" /></div>
      </div>

      <div class="grid-2" style="margin-top: 14px">
        <ArrayInput
          v-model="config.transparent_proxy.tproxy_ifaces_v4"
          label="接管 LAN 接口 IPv4 (tproxy_ifaces_v4[])"
          :suggestions="['br-lan', 'lan']"
        />
        <ArrayInput
          v-model="config.transparent_proxy.tproxy_ifaces_v6"
          label="接管 LAN 接口 IPv6 (tproxy_ifaces_v6[])"
          :suggestions="['br-lan', 'lan']"
        />
        <ArrayInput
          v-model="config.transparent_proxy.bypass_ifaces_v4"
          label="绕过接口 IPv4 (bypass_ifaces_v4[])"
        />
        <ArrayInput
          v-model="config.transparent_proxy.bypass_ifaces_v6"
          label="绕过接口 IPv6 (bypass_ifaces_v6[])"
        />
        <ArrayInput
          v-model="config.transparent_proxy.wan_bp_ips"
          label="WAN 直连绕过 IP/CIDR (wan_bp_ips[])"
          placeholder="回车添加 IPv4 / IPv6 / CIDR"
        />
        <ArrayInput
          v-model="config.transparent_proxy.wan_fw_ips"
          label="WAN 强制代理 IP/CIDR (wan_fw_ips[])"
          placeholder="回车添加 IPv4 / IPv6 / CIDR"
        />
      </div>

      <div class="row" style="margin-top: 14px">
        <ToggleSwitch v-model="config.transparent_proxy.fakedns_enabled" label="FakeDNS 透明劫持" />
        <ToggleSwitch v-model="config.transparent_proxy.fakedns_ping_response" label="FakeDNS ICMP Ping 响应" />
        <ToggleSwitch v-model="config.transparent_proxy.dynamic_direct_enabled" label="Dynamic Direct (fw4 内核态直连卸载)" />
        <ToggleSwitch v-model="config.transparent_proxy.dnsmasq_enabled" label="Dnsmasq 多端口转发集成" />
      </div>

      <div v-if="config.transparent_proxy.dnsmasq_enabled" class="card-subtle grid-2" style="margin-top: 12px">
        <div class="field">
          <label>Dnsmasq 集成模式</label>
          <select v-model="config.transparent_proxy.dnsmasq_integration_mode">
            <option value="global">global（所有实例）</option>
            <option value="per_instance">per_instance（OpenWrt 24.10+ 指定实例）</option>
          </select>
        </div>
        <ArrayInput
          v-if="config.transparent_proxy.dnsmasq_integration_mode === 'per_instance'"
          v-model="config.transparent_proxy.dnsmasq_instances"
          label="Dnsmasq 实例列表 (dnsmasq_instances[])"
          placeholder="如 cfg01411c"
        />
      </div>
    </div>

    <!-- LAN Host MAC ACL -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">LAN 设备 MAC 访问控制 ({{ config.lan_hosts.length }})</h3>
        <button class="btn btn-sm btn-primary" @click="addLanHost">+ 添加设备规则</button>
      </div>
      <table v-if="config.lan_hosts.length > 0" class="table">
        <thead>
          <tr>
            <th>备注</th>
            <th>MAC 地址</th>
            <th>IPv4 策略</th>
            <th>IPv6 策略</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(h, idx) in config.lan_hosts" :key="h.id">
            <td><input v-model="h.alias" type="text" /></td>
            <td><input v-model="h.macaddr" type="text" placeholder="aa:bb:cc:dd:ee:ff" /></td>
            <td>
              <select v-model="h.strategy_v4">
                <option value="default">跟随接口默认</option>
                <option value="tproxy">强制透明代理</option>
                <option value="bypass">直连绕过</option>
              </select>
            </td>
            <td>
              <select v-model="h.strategy_v6">
                <option value="default">跟随接口默认</option>
                <option value="tproxy">强制透明代理</option>
                <option value="bypass">直连绕过</option>
              </select>
            </td>
            <td><button class="btn btn-sm btn-danger" @click="config.lan_hosts.splice(idx, 1)">删</button></td>
          </tr>
        </tbody>
      </table>
      <div v-else class="field-hint">未配置单独设备策略，所有设备将按接口规则处理。</div>
    </div>
  </div>
</template>
