<script setup lang="ts">
import { computed } from 'vue';
import type { CoreType, StreamFields, TlsCertificate } from '@/schema/types';
import { getCoreCapabilities, type V2RayFormat } from '@/schema/capabilities';
import ArrayInput from '@/components/ui/ArrayInput.vue';
import KeyValueInput from '@/components/ui/KeyValueInput.vue';
import ToggleSwitch from '@/components/ui/ToggleSwitch.vue';

const props = defineProps<{
  model: StreamFields;
  core: CoreType;
  v2rayFormat?: V2RayFormat;
  isInbound?: boolean;
}>();

const cap = computed(() => getCoreCapabilities(props.core, props.v2rayFormat || 'jsonv4'));

function ensureCerts(): TlsCertificate[] {
  if (!props.model.tls_certificates) {
    props.model.tls_certificates = [];
  }
  return props.model.tls_certificates;
}

function addCert() {
  ensureCerts().unshift({ certificateFile: '', keyFile: '', usage: 'encipherment' });
}

function removeCert(idx: number) {
  ensureCerts().splice(idx, 1);
}
</script>

<template>
  <div style="display: flex; flex-direction: column; gap: 16px">
    <!-- Transport & Security selector -->
    <div class="grid-3">
      <div class="field">
        <label>传输层 (Transport)</label>
        <select v-model="model.transport">
          <option v-for="t in cap.transports" :key="t" :value="t">{{ t }}</option>
        </select>
      </div>
      <div class="field">
        <label>安全层 (Security)</label>
        <select v-model="model.security">
          <option v-for="s in cap.securities" :key="s" :value="s">{{ s }}</option>
        </select>
      </div>
      <div v-if="!isInbound" class="field">
        <label>域名解析策略 (domainStrategy)</label>
        <select v-model="model.domain_strategy">
          <option value="">默认</option>
          <option value="UseIP">UseIP</option>
          <option value="UseIPv4">UseIPv4</option>
          <option value="UseIPv6">UseIPv6</option>
          <option value="UseIPv4v6">UseIPv4v6 (Xray)</option>
          <option value="AsIs">AsIs</option>
        </select>
      </div>
      <div v-else class="field">
        <label>透明代理模式 (sockopt.tproxy)</label>
        <select v-model="model.sockopt_tproxy">
          <option value="off">off</option>
          <option value="tproxy">tproxy</option>
          <option value="redirect">redirect</option>
        </select>
      </div>
    </div>

    <!-- TLS Settings -->
    <div v-if="model.security === 'tls' || model.security === 'utls'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <div class="row-nowrap" style="justify-content: space-between">
        <strong style="font-size: 13px">{{ model.security === 'utls' ? 'uTLS 安全配置 (V2Ray v5)' : 'TLS 安全配置' }}</strong>
        <div class="row">
          <ToggleSwitch v-model="model.tls_allow_insecure" label="allowInsecure" />
          <ToggleSwitch v-if="core === 'v2ray'" v-model="model.tls_verify_client" label="verifyClientCertificate (mTLS)" />
        </div>
      </div>

      <div class="grid-3">
        <div class="field">
          <label>SNI (serverName)</label>
          <input v-model="model.tls_server_name" type="text" placeholder="example.com" />
        </div>
        <div v-if="core === 'xray' || model.security === 'utls'" class="field">
          <label>uTLS Fingerprint</label>
          <input v-model="model.tls_fingerprint" type="text" placeholder="chrome / firefox / safari / randomized" />
        </div>
        <div v-if="core === 'xray'" class="field">
          <label>域前置校验证书名 (verifyPeerCertByName)</label>
          <input v-model="model.tls_verify_peer_name" type="text" placeholder="可选" />
        </div>
        <div v-if="core === 'xray'" class="field">
          <label>ECH Config List</label>
          <input v-model="model.tls_ech_config" type="text" placeholder="base64 或 dns+https://..." />
        </div>
        <div v-if="core === 'xray' && isInbound" class="field">
          <label>ECH Server Keys (echServerKeys)</label>
          <input v-model="model.tls_ech_server_keys" type="password" placeholder="可选" />
        </div>
        <div v-if="core === 'xray'" class="field">
          <label>最小 TLS 版本 (minVersion)</label>
          <input v-model="model.tls_min_version" type="text" placeholder="1.2 / 1.3" />
        </div>
        <div v-if="core === 'xray'" class="field">
          <label>最大 TLS 版本 (maxVersion)</label>
          <input v-model="model.tls_max_version" type="text" placeholder="1.3" />
        </div>
        <div v-if="core === 'xray'" class="field">
          <label>加密套件 (cipherSuites)</label>
          <input v-model="model.tls_cipher_suites" type="text" placeholder="冒号分隔" />
        </div>
      </div>

      <div v-if="core === 'xray'" class="row">
        <ToggleSwitch v-if="isInbound" v-model="model.tls_reject_unknown_sni" label="rejectUnknownSni" />
        <ToggleSwitch v-model="model.tls_use_system_ca" label="useSystemCA" />
        <ToggleSwitch v-model="model.tls_disable_system_root" label="disableSystemRoot" />
        <ToggleSwitch v-model="model.tls_enable_session_resumption" label="enableSessionResumption" />
      </div>

      <div class="grid-2">
        <ArrayInput
          v-model="model.tls_alpn"
          label="ALPN 协议列表 (alpn[])"
          :suggestions="['h2', 'http/1.1', 'h3']"
          placeholder="回车添加 ALPN"
        />
        <ArrayInput
          v-model="model.tls_pinned_sha256"
          :label="core === 'xray' ? '证书固定 SHA256 (pinnedPeerCertSha256)' : '证书链固定 Base64 (pinnedPeerCertificateChainSha256[])'"
          placeholder="回车添加多个证书指纹"
        />
      </div>

      <ArrayInput
        v-if="core === 'xray'"
        v-model="model.tls_curve_preferences"
        label="椭圆曲线偏好 (curvePreferences[])"
        :suggestions="['X25519MLKEM768', 'X25519', 'CurveP256']"
      />

      <!-- Inbound Certificates Array -->
      <div v-if="isInbound" style="display: flex; flex-direction: column; gap: 8px">
        <div class="row-nowrap" style="justify-content: space-between">
          <label style="font-size: 12px; color: var(--text-secondary)">服务端证书列表 (certificates[])</label>
          <button type="button" class="btn btn-sm" @click="addCert">+ 添加证书</button>
        </div>
        <div v-for="(cert, idx) in model.tls_certificates || []" :key="idx" class="grid-3" style="align-items: end">
          <div class="field">
            <label>证书路径 (certificateFile)</label>
            <input v-model="cert.certificateFile" type="text" placeholder="/etc/ssl/certs/fullchain.pem" />
          </div>
          <div class="field">
            <label>私钥路径 (keyFile)</label>
            <input v-model="cert.keyFile" type="text" placeholder="/etc/ssl/private/privkey.pem" />
          </div>
          <div class="row-nowrap">
            <select v-model="cert.usage">
              <option value="encipherment">encipherment</option>
              <option value="verify">verify</option>
              <option value="issue">issue</option>
              <option value="verifyclient">verifyclient</option>
            </select>
            <button type="button" class="btn btn-sm btn-danger" @click="removeCert(idx)">删</button>
          </div>
        </div>
      </div>
    </div>

    <!-- REALITY Settings (Xray) -->
    <div v-if="model.security === 'reality' && core === 'xray'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <div class="row-nowrap" style="justify-content: space-between">
        <strong style="font-size: 13px">REALITY 安全配置 (Xray)</strong>
        <ToggleSwitch v-model="model.reality_show" label="调试输出 (show)" />
      </div>

      <template v-if="isInbound">
        <div class="grid-3">
          <div class="field">
            <label>回落目标 (target / dest)</label>
            <input v-model="model.reality_target" type="text" placeholder="www.apple.com:443" />
          </div>
          <div class="field">
            <label>私钥 (privateKey)</label>
            <input v-model="model.reality_private_key" type="password" />
          </div>
          <div class="field">
            <label>PROXY Protocol 版本 (xver)</label>
            <input v-model.number="model.reality_xver" type="number" placeholder="0" />
          </div>
          <div class="field">
            <label>后量子签名种子 (mldsa65Seed)</label>
            <input v-model="model.reality_mldsa65_seed" type="password" placeholder="可选" />
          </div>
          <div class="field">
            <label>最低客户端版本 (minClientVer)</label>
            <input v-model="model.reality_min_client_ver" type="text" placeholder="如 1.8.0" />
          </div>
          <div class="field">
            <label>最高客户端版本 (maxClientVer)</label>
            <input v-model="model.reality_max_client_ver" type="text" placeholder="可选" />
          </div>
          <div class="field">
            <label>最大时间差 (maxTimeDiff, ms)</label>
            <input v-model.number="model.reality_max_time_diff" type="number" placeholder="0" />
          </div>
        </div>
        <div class="grid-2">
          <ArrayInput
            v-model="model.reality_server_names"
            label="允许的 SNI 列表 (serverNames[])"
            placeholder="回车添加，如 www.apple.com"
          />
          <ArrayInput
            v-model="model.reality_short_ids"
            label="Short ID 列表 (shortIds[])"
            placeholder="回车添加，如 0123456789abcdef"
          />
        </div>
      </template>

      <template v-else>
        <div class="grid-3">
          <div class="field">
            <label>SNI (serverName)</label>
            <input v-model="model.reality_server_name" type="text" placeholder="www.apple.com" />
          </div>
          <div class="field">
            <label>Public Key / Password</label>
            <input v-model="model.reality_public_key" type="text" />
          </div>
          <div class="field">
            <label>Short ID</label>
            <input v-model="model.reality_short_id" type="text" />
          </div>
          <div class="field">
            <label>uTLS Fingerprint</label>
            <input v-model="model.reality_fingerprint" type="text" placeholder="chrome" />
          </div>
          <div class="field">
            <label>SpiderX</label>
            <input v-model="model.reality_spider_x" type="text" placeholder="/" />
          </div>
          <div class="field">
            <label>ML-DSA-65 Verify (后量子)</label>
            <input v-model="model.reality_mldsa65_verify" type="text" placeholder="可选" />
          </div>
        </div>
      </template>
    </div>

    <!-- Transport Specifics -->
    <div v-if="model.transport === 'raw' || model.transport === 'tcp'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <div class="grid-2">
        <div class="field">
          <label>TCP 伪装类型 (header.type)</label>
          <select v-model="model.tcp_header_type">
            <option value="none">none（不伪装）</option>
            <option value="http">http（HTTP 头部伪装）</option>
          </select>
        </div>
        <div class="field" style="justify-content: flex-end">
          <ToggleSwitch v-model="model.tcp_accept_proxy_protocol" label="acceptProxyProtocol" />
        </div>
      </div>
      <div v-if="model.tcp_header_type === 'http'" class="grid-2">
        <KeyValueInput
          v-model="model.tcp_request_headers"
          label="HTTP 请求头 (request.headers)"
          key-placeholder="Host / User-Agent"
        />
        <KeyValueInput
          v-model="model.tcp_response_headers"
          label="HTTP 响应头 (response.headers)"
          key-placeholder="Content-Type"
        />
      </div>
    </div>

    <div v-else-if="model.transport === 'websocket' || model.transport === 'ws'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <div class="grid-3">
        <div class="field"><label>WebSocket Path</label><input v-model="model.ws_path" type="text" placeholder="/" /></div>
        <div class="field"><label>WebSocket Host</label><input v-model="model.ws_host" type="text" placeholder="example.com" /></div>
        <div v-if="core === 'xray'" class="field">
          <label>心跳间隔 (heartbeatPeriod, 秒)</label>
          <input v-model.number="model.ws_heartbeat_period" type="number" placeholder="0" />
        </div>
        <div v-if="core === 'v2ray'" class="field">
          <label>Early Data 最大字节 (maxEarlyData)</label>
          <input v-model.number="model.ws_max_early_data" type="number" placeholder="2048" />
        </div>
        <div v-if="core === 'v2ray'" class="field">
          <label>Early Data Header 名</label>
          <input v-model="model.ws_early_data_header" type="text" placeholder="Sec-WebSocket-Protocol" />
        </div>
      </div>
      <KeyValueInput v-model="model.ws_headers" label="自定义 WebSocket Headers" />
    </div>

    <div v-else-if="model.transport === 'grpc'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <div class="grid-3">
        <div class="field"><label>serviceName</label><input v-model="model.grpc_service_name" type="text" /></div>
        <div v-if="core === 'xray'" class="field"><label>authority</label><input v-model="model.grpc_authority" type="text" /></div>
        <div v-if="core === 'xray'" class="field"><label>initial_windows_size</label><input v-model.number="model.grpc_initial_windows_size" type="number" /></div>
        <div v-if="core === 'xray'" class="field"><label>idle_timeout (s)</label><input v-model.number="model.grpc_idle_timeout" type="number" /></div>
        <div v-if="core === 'xray'" class="field"><label>health_check_timeout (s)</label><input v-model.number="model.grpc_health_check_timeout" type="number" /></div>
      </div>
      <div v-if="core === 'xray'" class="row">
        <ToggleSwitch v-model="model.grpc_multi_mode" label="multiMode" />
        <ToggleSwitch v-model="model.grpc_permit_without_stream" label="permit_without_stream" />
      </div>
    </div>

    <div v-else-if="(model.transport === 'xhttp' || model.transport === 'splithttp') && core === 'xray'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <div class="grid-3">
        <div class="field"><label>XHTTP Path</label><input v-model="model.xhttp_path" type="text" placeholder="/" /></div>
        <div class="field"><label>XHTTP Host</label><input v-model="model.xhttp_host" type="text" /></div>
        <div class="field">
          <label>XHTTP Mode</label>
          <select v-model="model.xhttp_mode">
            <option value="auto">auto</option>
            <option value="packet-up">packet-up</option>
            <option value="stream-up">stream-up</option>
            <option value="stream-one">stream-one</option>
          </select>
        </div>
      </div>
      <div class="field">
        <label>XHTTP extra JSON（上下行分离 downloadSettings / xmux 等）</label>
        <textarea v-model="model.xhttp_extra" rows="2" placeholder='{"scMaxEachPostBytes":1000000}' />
      </div>
    </div>

    <div v-else-if="model.transport === 'httpupgrade'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <div class="grid-2">
        <div class="field"><label>HTTPUpgrade Path</label><input v-model="model.httpupgrade_path" type="text" placeholder="/" /></div>
        <div class="field"><label>HTTPUpgrade Host</label><input v-model="model.httpupgrade_host" type="text" /></div>
      </div>
      <KeyValueInput v-model="model.httpupgrade_headers" label="自定义 HTTPUpgrade Headers" />
    </div>

    <div v-else-if="(model.transport === 'http' || model.transport === 'h2') && core === 'v2ray'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <div class="grid-2">
        <div class="field"><label>HTTP/2 Path</label><input v-model="model.h2_path" type="text" placeholder="/" /></div>
        <div class="field"><label>HTTP Method</label><input v-model="model.h2_method" type="text" placeholder="PUT" /></div>
      </div>
      <ArrayInput v-model="model.h2_host" label="HTTP/2 Host 列表 (host[])" placeholder="回车添加多个域名" />
      <KeyValueInput v-model="model.h2_headers" label="自定义 HTTP/2 Headers" />
    </div>

    <div v-else-if="model.transport === 'mkcp' || model.transport === 'kcp'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <div class="grid-3">
        <div class="field"><label>MTU</label><input v-model.number="model.mkcp_mtu" type="number" placeholder="1350" /></div>
        <div class="field"><label>TTI (ms)</label><input v-model.number="model.mkcp_tti" type="number" placeholder="50" /></div>
        <div class="field"><label>上行容量 (MB/s)</label><input v-model.number="model.mkcp_uplink_capacity" type="number" placeholder="5" /></div>
        <div class="field"><label>下行容量 (MB/s)</label><input v-model.number="model.mkcp_downlink_capacity" type="number" placeholder="20" /></div>
        <div v-if="core === 'xray'" class="field"><label>拥塞窗口倍数 (cwndMultiplier)</label><input v-model.number="model.mkcp_cwnd_multiplier" type="number" placeholder="2" /></div>
        <div v-if="core === 'xray'" class="field"><label>最大发送窗口 (maxSendingWindow)</label><input v-model.number="model.mkcp_max_sending_window" type="number" placeholder="2097152" /></div>
        <div v-if="core === 'v2ray'" class="field"><label>混淆 Seed</label><input v-model="model.mkcp_seed" type="text" /></div>
        <div v-if="core === 'v2ray'" class="field">
          <label>伪装类型 (header.type)</label>
          <select v-model="model.mkcp_header_type">
            <option value="none">none</option>
            <option value="srtp">srtp</option>
            <option value="utp">utp</option>
            <option value="wechat-video">wechat-video</option>
            <option value="dtls">dtls</option>
            <option value="wireguard">wireguard</option>
          </select>
        </div>
      </div>
      <ToggleSwitch v-if="core === 'v2ray'" v-model="model.mkcp_congestion" label="启用拥塞控制 (congestion)" />
    </div>

    <div v-else-if="model.transport === 'quic' && core === 'v2ray'" class="card-subtle">
      <div class="grid-3">
        <div class="field">
          <label>QUIC 加密 (security)</label>
          <select v-model="model.quic_security">
            <option value="none">none</option>
            <option value="aes-128-gcm">aes-128-gcm</option>
            <option value="chacha20-poly1305">chacha20-poly1305</option>
          </select>
        </div>
        <div class="field"><label>QUIC Key</label><input v-model="model.quic_key" type="text" /></div>
        <div class="field"><label>伪装类型</label><input v-model="model.quic_header_type" type="text" placeholder="none / srtp / utp" /></div>
      </div>
    </div>

    <div v-else-if="model.transport === 'domainsocket' && core === 'v2ray'" class="card-subtle">
      <div class="grid-3" style="align-items: end">
        <div class="field"><label>Unix Socket Path</label><input v-model="model.ds_path" type="text" placeholder="/var/run/v2ray.sock" /></div>
        <ToggleSwitch v-model="model.ds_abstract" label="abstract" />
        <ToggleSwitch v-model="model.ds_padding" label="padding" />
      </div>
    </div>

    <div v-else-if="model.transport === 'hysteria' || model.transport === 'hysteria2'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <strong style="font-size: 13px">Hysteria 传输层参数</strong>
      <div class="grid-3">
        <div class="field"><label>认证密钥 (auth)</label><input v-model="model.hysteria_auth" type="password" placeholder="留空则沿用密码字段" /></div>
        <div v-if="core === 'xray'" class="field"><label>UDP 空闲超时 (udpIdleTimeout, 秒)</label><input v-model.number="model.hysteria_udp_idle_timeout" type="number" placeholder="60" /></div>
        <div v-if="core === 'xray'" class="field">
          <label>HTTP/3 伪装类型 (masquerade.type)</label>
          <select v-model="model.hysteria_masquerade_type">
            <option value="">默认 404</option>
            <option value="proxy">proxy（反代）</option>
            <option value="file">file（静态目录）</option>
            <option value="string">string（自定义内容）</option>
          </select>
        </div>
        <div v-if="core === 'xray' && model.hysteria_masquerade_type === 'proxy'" class="field"><label>伪装反代 URL (masquerade.url)</label><input v-model="model.hysteria_masquerade_url" type="text" placeholder="https://example.com" /></div>
        <div v-if="core === 'xray' && model.hysteria_masquerade_type === 'file'" class="field"><label>静态文件目录 (masquerade.dir)</label><input v-model="model.hysteria_masquerade_dir" type="text" placeholder="/var/www" /></div>
        <div v-if="core === 'xray' && model.hysteria_masquerade_type === 'string'" class="field"><label>自定义响应内容 (masquerade.content)</label><input v-model="model.hysteria_masquerade_content" type="text" placeholder="OK" /></div>
        <div v-if="core === 'xray' && model.hysteria_masquerade_type === 'string'" class="field"><label>响应状态码 (statusCode)</label><input v-model.number="model.hysteria_masquerade_status_code" type="number" placeholder="200" /></div>
        <div v-if="core === 'xray'" class="field"><label>UDP 端口跳跃 (udpHop.ports)</label><input v-model="model.hysteria_udphop_port" type="text" placeholder="20000-50000" /></div>
        <div v-if="core === 'xray'" class="field"><label>跳跃间隔 (udpHop.interval, 秒)</label><input v-model.number="model.hysteria_udphop_interval" type="number" placeholder="30" /></div>
        <div v-if="core === 'xray'" class="field"><label>Salamander 混淆密码</label><input v-model="model.hysteria_obfs_password" type="password" /></div>
      </div>
      <div class="row">
        <ToggleSwitch v-if="core === 'v2ray'" v-model="model.hysteria_udp_extension" label="启用 UDP 扩展 (use_udp_extension)" />
        <ToggleSwitch v-if="core === 'xray' && model.hysteria_masquerade_type === 'proxy'" v-model="model.hysteria_masquerade_rewrite_host" label="rewriteHost" />
        <ToggleSwitch v-if="core === 'xray' && model.hysteria_masquerade_type === 'proxy'" v-model="model.hysteria_masquerade_insecure" label="insecure" />
      </div>
    </div>

    <div v-else-if="model.transport === 'masque' && core === 'xray'" class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <strong style="font-size: 13px">MASQUE 传输层参数 (Xray)</strong>
      <div class="grid-3">
        <div v-if="!isInbound" class="field"><label>Authority Host (host)</label><input v-model="model.masque_host" type="text" placeholder="example.com" /></div>
        <div class="field"><label>URI 模板路径 (path)</label><input v-model="model.masque_path" type="text" placeholder="/.well-known/masque/ip/{target}/{ipproto}/" /></div>
        <div v-if="!isInbound" class="field"><label>HTTP Basic 用户名 (user)</label><input v-model="model.masque_user" type="text" placeholder="可选" /></div>
        <div v-if="!isInbound" class="field"><label>HTTP Basic 密码 (pass)</label><input v-model="model.masque_pass" type="password" placeholder="可选" /></div>
      </div>
      <KeyValueInput v-if="!isInbound" v-model="model.masque_headers" label="自定义 MASQUE Headers" />
      <div v-if="!isInbound" class="field">
        <label>Cloudflare WARP JSON (warp，可选)</label>
        <textarea v-model="model.masque_warp_json" rows="2" placeholder='{"address":["172.16.0.2/32"],"privateKey":"..."}' />
      </div>
    </div>

    <!-- Sockopt & FinalMask -->
    <div class="card-subtle" style="display: flex; flex-direction: column; gap: 12px">
      <strong style="font-size: 13px">底层 Socket 选项 (sockopt)</strong>
      <div class="grid-3">
        <div class="field"><label>出站网卡 ({{ core === 'xray' ? 'interface' : 'bindToDevice' }})</label><input v-model="model.sockopt_interface" type="text" placeholder="如 eth0 / wan" /></div>
        <div class="field"><label>KeepAlive 间隔 (秒)</label><input v-model.number="model.sockopt_tcp_keepalive_interval" type="number" placeholder="0" /></div>
        <div v-if="core === 'xray'" class="field"><label>KeepAlive 空闲阈值 (tcpKeepAliveIdle, s)</label><input v-model.number="model.sockopt_tcp_keepalive_idle" type="number" placeholder="300" /></div>
        <div v-if="core === 'xray'" class="field"><label>TCP 拥塞控制 (tcpcongestion)</label><input v-model="model.sockopt_tcp_congestion" type="text" placeholder="bbr / cubic" /></div>
        <div v-if="core === 'xray'" class="field"><label>TCP MaxSeg (tcpMaxSeg)</label><input v-model.number="model.sockopt_tcp_max_seg" type="number" placeholder="0" /></div>
        <div v-if="core === 'xray'" class="field"><label>TCP UserTimeout (ms)</label><input v-model.number="model.sockopt_tcp_user_timeout" type="number" placeholder="10000" /></div>
        <div v-if="core === 'xray'" class="field"><label>SRV/TXT 策略 (addressPortStrategy)</label><input v-model="model.sockopt_address_port_strategy" type="text" placeholder="none / SrvPortAndAddress" /></div>
      </div>
      <div class="row">
        <ToggleSwitch v-model="model.sockopt_tcp_fast_open" label="TCP Fast Open" />
        <ToggleSwitch v-model="model.sockopt_mptcp" :label="core === 'xray' ? 'tcpMptcp' : 'mptcp'" />
        <ToggleSwitch v-if="core === 'xray'" v-model="model.sockopt_v6_only" label="V6Only" />
      </div>
      <div v-if="core === 'xray' && !isInbound" class="grid-3">
        <div class="field"><label>HappyEyeballs tryDelayMs</label><input v-model.number="model.sockopt_happy_eyeballs_try_delay_ms" type="number" placeholder="250" /></div>
        <div class="field"><label>HappyEyeballs interleave</label><input v-model.number="model.sockopt_happy_eyeballs_interleave" type="number" placeholder="1" /></div>
        <div class="field"><label>HappyEyeballs maxConcurrentTry</label><input v-model.number="model.sockopt_happy_eyeballs_max_concurrent_try" type="number" placeholder="4" /></div>
      </div>
      <ToggleSwitch v-if="core === 'xray' && !isInbound" v-model="model.sockopt_happy_eyeballs_prioritize_ipv6" label="HappyEyeballs prioritizeIPv6" />
      <div v-if="core === 'xray'" class="field">
        <label>FinalMask JSON (Xray 专属：fragment / salamander / noise / quicParams)</label>
        <textarea v-model="model.finalmask_json" rows="2" placeholder='{"tcp":[{"type":"fragment","settings":{"packets":"tlshello"}}]}' />
      </div>
    </div>
  </div>
</template>
