import type { AiosConfig, InboundConfig, OutboundConfig, StreamFields } from '@/schema/types';
import { validateStreamCombination } from '@/schema/capabilities';
import { CORE_FEATURES_SPEC, type ResolvedV2RayFeatures } from '@/schema/features';
import type { CompileDiagnostic, CompileResult } from './index';

function toV5LogLevel(level?: string): string {
  switch ((level || 'warning').toLowerCase()) {
    case 'debug':
      return 'Debug';
    case 'info':
      return 'Info';
    case 'error':
      return 'Error';
    case 'none':
      return 'None';
    default:
      return 'Warning';
  }
}

function toV5QueryStrategy(qs?: string): string {
  switch (qs) {
    case 'UseIPv4':
    case 'USE_IP4':
      return 'USE_IP4';
    case 'UseIPv6':
    case 'USE_IP6':
      return 'USE_IP6';
    default:
      return 'USE_IP';
  }
}

function toV5OutboundDomainStrategy(ds?: string): string | undefined {
  if (!ds) return undefined;
  switch (ds) {
    case 'UseIPv4':
    case 'UseIP4':
    case 'ForceIPv4':
      return 'UseIP4';
    case 'UseIPv6':
    case 'UseIP6':
    case 'ForceIPv6':
      return 'UseIP6';
    case 'UseIP':
    case 'UseIPv4v6':
    case 'UseIPv6v4':
    case 'ForceIP':
      return 'UseIP';
    case 'AsIs':
      return 'AsIs';
    default:
      return 'AsIs';
  }
}

function toV5RouterDomainStrategy(ds?: string): string {
  if (ds === 'IPIfNonMatch' || ds === 'IpIfNonMatch') return 'IpIfNonMatch';
  if (ds === 'IPOnDemand' || ds === 'IpOnDemand') return 'IpOnDemand';
  if (ds === 'UseIp') return 'UseIp';
  return 'AsIs';
}

function toV5QuicSecurity(sec?: string): string {
  switch ((sec || 'none').toLowerCase()) {
    case 'aes-128-gcm':
    case 'aes128_gcm':
      return 'AES128_GCM';
    case 'chacha20-poly1305':
    case 'chacha20_poly1305':
      return 'CHACHA20_POLY1305';
    case 'auto':
      return 'AUTO';
    case 'zero':
      return 'ZERO';
    default:
      return 'NONE';
  }
}

export function parseDurationToNs(val: string | number | undefined, fallbackNs: number): number {
  if (val === undefined || val === '') return fallbackNs;
  if (typeof val === 'number') return Number.isFinite(val) && val > 0 ? Math.round(val) : fallbackNs;
  const s = val.trim().toLowerCase();
  if (/^\d+$/.test(s)) return Number(s);
  const m = s.match(/^(\d+(?:\.\d+)?)(ns|us|ms|s|m|h)$/);
  if (!m) return fallbackNs;
  const n = Number(m[1]);
  switch (m[2]) {
    case 'ns':
      return Math.round(n);
    case 'us':
      return Math.round(n * 1e3);
    case 'ms':
      return Math.round(n * 1e6);
    case 's':
      return Math.round(n * 1e9);
    case 'm':
      return Math.round(n * 60 * 1e9);
    case 'h':
      return Math.round(n * 3600 * 1e9);
    default:
      return fallbackNs;
  }
}

function parseJsonObjectChecked(
  str: string | undefined,
  diagnostics: CompileDiagnostic[],
  path: string
): Record<string, unknown> | null {
  if (!str || !str.trim()) return null;
  try {
    const parsed = JSON.parse(str);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    diagnostics.push({ level: 'error', path, message: 'JSON 必须为对象（Object）格式。' });
    return null;
  } catch (e) {
    diagnostics.push({ level: 'error', path, message: `JSON 解析失败: ${String(e)}` });
    return null;
  }
}

function deepMerge(
  target: Record<string, unknown>,
  source: Record<string, unknown>
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...target };
  for (const key of Object.keys(source)) {
    const sv = source[key];
    const tv = out[key];
    if (
      sv &&
      tv &&
      typeof sv === 'object' &&
      typeof tv === 'object' &&
      !Array.isArray(sv) &&
      !Array.isArray(tv)
    ) {
      out[key] = deepMerge(tv as Record<string, unknown>, sv as Record<string, unknown>);
    } else {
      out[key] = sv;
    }
  }
  return out;
}

const V2RAY_V5_SS_ALLOWED_METHODS = new Set([
  'aes-128-gcm',
  'aes_128_gcm',
  'aead_aes_128_gcm',
  'aes-256-gcm',
  'aes_256_gcm',
  'aead_aes_256_gcm',
  'chacha20-poly1305',
  'chacha20_poly1305',
  'aead_chacha20_poly1305',
  'chacha20-ietf-poly1305',
  'none',
  'plain'
]);

function isIpLiteral(val: string): boolean {
  if (!val) return false;
  if (val.includes(':')) return parseIpv6ToBytes(val) !== null;
  const parts = val.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isValidBase64Pin(val: string): boolean {
  const s = val.trim();
  if (s.length < 4 || s.length % 4 !== 0) return false;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

function parseIpv6ToBytes(ip: string): number[] | null {
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing <= 0) return null;
  const groups = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
  if (groups.length !== 8) return null;
  const bytes: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const val = Number.parseInt(g, 16);
    bytes.push((val >> 8) & 0xff, val & 0xff);
  }
  return bytes;
}

function parseCidrToBytes(cidr: string): { ip: number[]; prefix: number } | null {
  const [addr, prefixStr] = cidr.trim().split('/');
  if (!addr) return null;
  if (addr.includes(':')) {
    const bytes = parseIpv6ToBytes(addr);
    if (prefixStr !== undefined && prefixStr !== '' && !/^\d+$/.test(prefixStr)) return null;
    const prefix = prefixStr !== undefined && prefixStr !== '' ? Number(prefixStr) : 128;
    if (bytes && Number.isFinite(prefix) && prefix >= 0 && prefix <= 128) {
      return { ip: bytes, prefix };
    }
    return null;
  }
  const parts = addr.split('.');
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p))) {
    const bytes = parts.map((p) => Number(p));
    if (prefixStr !== undefined && prefixStr !== '' && !/^\d+$/.test(prefixStr)) return null;
    const prefix = prefixStr !== undefined && prefixStr !== '' ? Number(prefixStr) : 32;
    if (bytes.every((b) => b >= 0 && b <= 255) && Number.isFinite(prefix) && prefix >= 0 && prefix <= 32) {
      return { ip: bytes, prefix };
    }
  }
  return null;
}

function parseGeoIpEntry(raw: string): Record<string, unknown> {
  let item = raw.trim();
  let inverseMatch = false;
  if (item.startsWith('!')) {
    inverseMatch = true;
    item = item.slice(1).trim();
  }
  if (item.startsWith('geoip:')) {
    let code = item.slice('geoip:'.length).trim();
    if (code.startsWith('!')) {
      inverseMatch = true;
      code = code.slice(1).trim();
    }
    const obj: Record<string, unknown> = { filePath: 'geoip.dat', code };
    if (inverseMatch) obj.inverseMatch = true;
    return obj;
  }
  if (item.startsWith('ext:') || item.startsWith('ext-ip:')) {
    const rest = item.startsWith('ext-ip:') ? item.slice(7) : item.slice(4);
    const idx = rest.indexOf(':');
    const filePath = idx >= 0 ? rest.slice(0, idx) : 'geoip.dat';
    let code = idx >= 0 ? rest.slice(idx + 1) : rest;
    if (code.startsWith('!')) {
      inverseMatch = true;
      code = code.slice(1).trim();
    }
    const obj: Record<string, unknown> = { filePath, code };
    if (inverseMatch) obj.inverseMatch = true;
    return obj;
  }
  const [ipAddr, prefixStr] = item.split('/');
  const defaultPrefix = ipAddr.includes(':') ? 128 : 32;
  const prefix = prefixStr !== undefined && prefixStr !== '' ? Number(prefixStr) : defaultPrefix;
  const obj: Record<string, unknown> = {
    cidr: [{ ipAddr, prefix: Number.isFinite(prefix) ? prefix : defaultPrefix }]
  };
  if (inverseMatch) obj.inverseMatch = true;
  return obj;
}

function parsePriorityDomain(raw: string): Record<string, unknown> {
  const s = raw.trim();
  if (s.startsWith('full:')) return { type: 'Full', domain: s.slice(5) };
  if (s.startsWith('domain:')) return { type: 'Subdomain', domain: s.slice(7) };
  if (s.startsWith('regexp:')) return { type: 'Regex', domain: s.slice(7) };
  if (s.startsWith('keyword:')) return { type: 'Keyword', domain: s.slice(8) };
  return { type: 'Subdomain', domain: s };
}

function parseRouterDomains(rawList: string[]): {
  domains: Record<string, unknown>[];
  geoDomains: Record<string, unknown>[];
} {
  const domains: Record<string, unknown>[] = [];
  const geoDomains: Record<string, unknown>[] = [];
  for (const raw of rawList) {
    const s = raw.trim();
    if (!s) continue;
    if (s.startsWith('geosite:')) {
      geoDomains.push({ filePath: 'geosite.dat', code: s.slice('geosite:'.length) });
    } else if (s.startsWith('ext:') || s.startsWith('ext-domain:')) {
      const rest = s.startsWith('ext-domain:') ? s.slice(11) : s.slice(4);
      const idx = rest.indexOf(':');
      geoDomains.push({
        filePath: idx >= 0 ? rest.slice(0, idx) : 'geosite.dat',
        code: idx >= 0 ? rest.slice(idx + 1) : rest
      });
    } else if (s.startsWith('full:')) {
      domains.push({ type: 'Full', value: s.slice(5) });
    } else if (s.startsWith('domain:')) {
      domains.push({ type: 'RootDomain', value: s.slice(7) });
    } else if (s.startsWith('regexp:')) {
      domains.push({ type: 'Regex', value: s.slice(7) });
    } else if (s.startsWith('keyword:')) {
      domains.push({ type: 'Plain', value: s.slice(8) });
    } else {
      domains.push({ type: 'Plain', value: s });
    }
  }
  return { domains, geoDomains };
}

function buildStaticHostEntry(domainRaw: string, targets: string[]): Record<string, unknown> | null {
  const s = domainRaw.trim();
  if (!s) return null;
  let type = 'Full';
  let domain = s;
  if (s.startsWith('full:')) {
    type = 'Full';
    domain = s.slice(5);
  } else if (s.startsWith('domain:')) {
    type = 'Subdomain';
    domain = s.slice(7);
  } else if (s.startsWith('regexp:')) {
    type = 'Regex';
    domain = s.slice(7);
  } else if (s.startsWith('keyword:')) {
    type = 'Keyword';
    domain = s.slice(8);
  }
  const cleaned = targets.map((t) => t.trim()).filter(Boolean);
  if (cleaned.length === 0) return null;
  const ips = cleaned.filter((t) => isIpLiteral(t));
  const proxied = cleaned.find((t) => !isIpLiteral(t));
  if (proxied) {
    return { type, domain, proxiedDomain: proxied };
  }
  if (ips.length === 0) return null;
  return { type, domain, ip: ips };
}

function buildV5Stream(
  item: StreamFields & { password?: string },
  protocol: string,
  isInbound: boolean,
  defaultMark: number | null,
  diagnostics: CompileDiagnostic[],
  pathPrefix: string
): Record<string, unknown> {
  let transport = item.transport || 'tcp';
  if (transport === 'raw') transport = 'tcp';
  if (transport === 'websocket') transport = 'ws';
  if (transport === 'mkcp') transport = 'kcp';
  if (transport === 'h2') transport = 'http';
  if (transport === 'hysteria') transport = 'hysteria2';
  if (transport === 'xhttp' || transport === 'splithttp' || transport === 'masque') {
    diagnostics.push({
      level: 'error',
      path: `${pathPrefix}.transport`,
      message: `V2Ray jsonv5 不支持传输层 "${transport}"。`
    });
    transport = 'tcp';
  }

  let security = item.security || 'none';
  if (security === 'reality') {
    diagnostics.push({
      level: 'error',
      path: `${pathPrefix}.security`,
      message: 'V2Ray jsonv5 不支持 REALITY 安全层，请改用 tls 或 utls。'
    });
    security = 'none';
  }

  for (const issue of validateStreamCombination(
    'v2ray',
    'jsonv5',
    protocol,
    transport,
    security,
    isInbound ? 'inbound' : 'outbound'
  )) {
    diagnostics.push({ level: issue.level, path: `${pathPrefix}.streamSettings`, message: issue.message });
  }

  let transportSettings: Record<string, unknown> = {};
  if (transport === 'tcp') {
    if (isInbound && item.tcp_accept_proxy_protocol) {
      transportSettings = { acceptProxyProtocol: true };
    }
  } else if (transport === 'ws') {
    const wsHeaders: Array<{ key: string; value: string }> = (item.ws_headers || [])
      .filter((h) => h.key.trim())
      .map((h) => ({ key: h.key.trim(), value: h.value }));
    if (item.ws_host && !wsHeaders.some((h) => h.key.toLowerCase() === 'host')) {
      wsHeaders.unshift({ key: 'Host', value: item.ws_host });
    }
    transportSettings = {
      path: item.ws_path || '/',
      header: wsHeaders.length > 0 ? wsHeaders : undefined,
      acceptProxyProtocol: isInbound && item.tcp_accept_proxy_protocol ? true : undefined,
      maxEarlyData: item.ws_max_early_data || undefined,
      earlyDataHeaderName: item.ws_early_data_header || undefined
    };
  } else if (transport === 'grpc') {
    transportSettings = { serviceName: item.grpc_service_name || '' };
  } else if (transport === 'httpupgrade') {
    const headers = (item.httpupgrade_headers || [])
      .filter((h) => h.key.trim())
      .map((h) => ({ key: h.key.trim(), value: h.value }));
    transportSettings = {
      path: item.httpupgrade_path || '/',
      host: item.httpupgrade_host || '',
      header: headers.length > 0 ? headers : undefined,
      maxEarlyData: item.ws_max_early_data || undefined,
      earlyDataHeaderName: item.ws_early_data_header || undefined
    };
  } else if (transport === 'kcp') {
    transportSettings = {
      mtu: { value: item.mkcp_mtu || 1350 },
      tti: { value: item.mkcp_tti || 50 },
      uplinkCapacity: { value: item.mkcp_uplink_capacity || 5 },
      downlinkCapacity: { value: item.mkcp_downlink_capacity || 20 },
      congestion: !!item.mkcp_congestion
    };
    if (item.mkcp_seed) transportSettings.seed = { seed: item.mkcp_seed };
  } else if (transport === 'quic') {
    transportSettings = {
      security: { type: toV5QuicSecurity(item.quic_security) },
      key: item.quic_key || ''
    };
  } else if (transport === 'hysteria2') {
    transportSettings = {
      password: item.hysteria_auth || item.password || '',
      use_udp_extension: item.hysteria_udp_extension !== false,
      congestion:
        item.hysteria_up_mbps || item.hysteria_down_mbps
          ? {
              type: 'brutal',
              up_mbps: item.hysteria_up_mbps || 50,
              down_mbps: item.hysteria_down_mbps || 100
            }
          : { type: 'bbr' }
    };
  }

  let securitySettings: Record<string, unknown> | undefined;
  if (security === 'tls') {
    const tls: Record<string, unknown> = {};
    if (item.tls_server_name) tls.serverName = item.tls_server_name;
    if (item.tls_alpn && item.tls_alpn.length > 0) tls.nextProtocol = item.tls_alpn;
    if (item.tls_disable_system_root) tls.disableSystemRoot = true;
    const pinned = (item.tls_pinned_sha256 || []).filter(Boolean);
    if (pinned.length > 0) {
      const validPins: string[] = [];
      for (const p of pinned) {
        const s = p.trim();
        if (!s) continue;
        if (!isValidBase64Pin(s)) {
          diagnostics.push({
            level: 'error',
            path: `${pathPrefix}.tls_pinned_sha256`,
            message: `V2Ray jsonv5 tls_pinned_sha256 必须为合法 Base64 编码，已跳过无效条目: "${s}"。`
          });
          continue;
        }
        validPins.push(s);
      }
      if (validPins.length > 0) {
        tls.pinnedPeerCertificateChainSha256 = validPins;
        if (item.tls_allow_insecure) tls.allowInsecureIfPinnedPeerCertificate = true;
      }
    }
    if (item.tls_ech_config && item.tls_ech_config.trim()) {
      const ech = item.tls_ech_config.trim();
      if (!isValidBase64Pin(ech)) {
        diagnostics.push({
          level: 'error',
          path: `${pathPrefix}.tls_ech_config`,
          message: `V2Ray jsonv5 tls_ech_config 必须为合法标准 Base64 编码，已跳过无效配置。`
        });
      } else {
        tls.echConfig = ech;
      }
    }
    if (isInbound) {
      const usageMap: Record<string, string> = {
        encipherment: 'ENCIPHERMENT',
        verify: 'AUTHORITY_VERIFY',
        verifyclient: 'AUTHORITY_VERIFY_CLIENT',
        issue: 'AUTHORITY_ISSUE'
      };
      if (item.tls_certificates && item.tls_certificates.length > 0) {
        tls.certificate = item.tls_certificates
          .filter((c) => c.certificateFile && c.keyFile)
          .map((c) => {
            const out: Record<string, unknown> = {
              certificateFile: c.certificateFile,
              keyFile: c.keyFile
            };
            if (c.usage) {
              out.usage = usageMap[c.usage.toLowerCase()] || c.usage.toUpperCase();
            }
            return out;
          });
      } else if (item.tls_cert_file && item.tls_key_file) {
        tls.certificate = [{ certificateFile: item.tls_cert_file, keyFile: item.tls_key_file }];
      }
    }
    securitySettings = tls;
  } else if (security === 'utls') {
    const tlsCfg: Record<string, unknown> = {};
    if (item.tls_server_name) tlsCfg.serverName = item.tls_server_name;
    if (item.tls_alpn && item.tls_alpn.length > 0) tlsCfg.nextProtocol = item.tls_alpn;
    if (item.tls_disable_system_root) tlsCfg.disableSystemRoot = true;
    securitySettings = {
      tlsConfig: tlsCfg,
      imitate: item.tls_fingerprint || 'chrome_auto'
    };
  }

  const socketSettings: Record<string, unknown> = {};
  const mark = item.sockopt_mark ?? defaultMark;
  if (mark !== null && mark > 0) socketSettings.mark = mark;
  if (item.sockopt_tproxy && item.sockopt_tproxy !== 'off') socketSettings.tproxy = item.sockopt_tproxy;
  if (item.sockopt_tcp_fast_open) socketSettings.tcpFastOpen = true;
  if (item.sockopt_mptcp) socketSettings.mptcp = true;
  if (item.sockopt_interface) socketSettings.bindToDevice = item.sockopt_interface;

  const ss: Record<string, unknown> = {
    transport,
    transportSettings,
    security
  };
  if (securitySettings) ss.securitySettings = securitySettings;
  if (Object.keys(socketSettings).length > 0) ss.socketSettings = socketSettings;
  return ss;
}

function compileV5Inbound(
  item: InboundConfig,
  diagnostics: CompileDiagnostic[],
  v2rayFeatures?: ResolvedV2RayFeatures
): Record<string, unknown> | null {
  if (item.protocol === 'tun') return null; // Mapped to services.tun
  if (item.protocol === 'wireguard' || item.protocol === 'masque') {
    diagnostics.push({
      level: 'error',
      path: `inbounds.${item.tag}`,
      message: `V2Ray jsonv5 入站协议不支持 "${item.protocol}"。`
    });
    return null;
  }
  const proto = item.protocol === 'tunnel' ? 'dokodemo-door' : item.protocol === 'hysteria' ? 'hysteria2' : item.protocol;
  const vfSpec = CORE_FEATURES_SPEC.v2ray.features;
  if (v2rayFeatures) {
    if (proto === 'hysteria2' && !v2rayFeatures.hasHysteria2) {
      diagnostics.push({
        level: 'error',
        path: `inbounds.${item.tag}`,
        message: `V2Ray ${v2rayFeatures.version} 不支持 hysteria2 入站协议（需 >= ${vfSpec.hysteria2.since}）。`
      });
      return null;
    }
    if (item.packet_encoding === 'Stream' && !v2rayFeatures.hasPacketEncodingStream) {
      diagnostics.push({
        level: 'error',
        path: `inbounds.${item.tag}.packet_encoding`,
        message: `V2Ray ${v2rayFeatures.version} 不支持 packetEncoding="Stream"（需 >= ${vfSpec.packetEncodingStream.since}）。`
      });
    }
  }
  const settings: Record<string, unknown> = {};
  if (proto === 'socks') {
    if (item.socks_ip) settings.address = item.socks_ip;
    settings.udpEnabled = !!item.socks_udp;
    if (item.packet_encoding) settings.packetEncoding = item.packet_encoding;
  } else if (proto === 'http') {
    // Simplified v5 inbound.http has empty settings object
  } else if (proto === 'dokodemo-door') {
    settings.networks = (item.dokodemo_network || 'tcp,udp').toLowerCase();
    settings.followRedirect = !!item.dokodemo_follow_redirect;
    if (item.dokodemo_address) settings.address = item.dokodemo_address;
    if (item.dokodemo_port) settings.port = item.dokodemo_port;
  } else if (proto === 'vmess' || proto === 'vless') {
    settings.users =
      item.users && item.users.length > 0
        ? item.users.map((u) => u.id || '').filter(Boolean)
        : item.uuid
          ? [item.uuid]
          : [];
  } else if (proto === 'trojan') {
    settings.users =
      item.users && item.users.length > 0
        ? item.users.map((u) => u.password || '').filter(Boolean)
        : item.password
          ? [item.password]
          : [];
    if (item.packet_encoding) settings.packetEncoding = item.packet_encoding;
  } else if (proto === 'shadowsocks') {
    const method = item.method || 'aes-256-gcm';
    const methodLower = method.toLowerCase();
    if (!V2RAY_V5_SS_ALLOWED_METHODS.has(methodLower)) {
      diagnostics.push({
        level: 'error',
        path: `inbounds.${item.tag}.method`,
        message: `V2Ray jsonv5 的 shadowsocks 入站不支持 "${method}"。`
      });
      return null;
    }
    settings.method = method;
    settings.password = item.password || '';
    settings.networks = (item.ss_network || 'tcp,udp').toLowerCase();
    if (item.packet_encoding) settings.packetEncoding = item.packet_encoding;
  } else if (proto === 'hysteria2') {
    if (item.packet_encoding) settings.packetEncoding = item.packet_encoding;
  }

  const obj: Record<string, unknown> = {
    tag: item.tag || item.id,
    listen: item.listen || '0.0.0.0',
    port: item.port,
    protocol: proto,
    settings,
    streamSettings: buildV5Stream(item, proto, true, null, diagnostics, `inbounds.${item.tag}`)
  };
  if (item.sniffing_enabled) {
    obj.sniffing = {
      enabled: true,
      destOverride:
        item.sniffing_dest_override && item.sniffing_dest_override.length > 0
          ? item.sniffing_dest_override
          : ['http', 'tls'],
      metadataOnly: !!item.sniffing_metadata_only
    };
  }
  const custom = parseJsonObjectChecked(item.custom_config, diagnostics, `inbounds.${item.tag}.custom_config`);
  return custom ? deepMerge(obj, custom) : obj;
}

function compileV5Outbound(
  item: OutboundConfig,
  defaultMark: number | null,
  diagnostics: CompileDiagnostic[],
  v2rayFeatures?: ResolvedV2RayFeatures
): Record<string, unknown> | null {
  if (item.protocol === 'wireguard' || item.protocol === 'masque') {
    diagnostics.push({
      level: 'error',
      path: `outbounds.${item.tag}`,
      message: `V2Ray jsonv5 不支持出站协议 "${item.protocol}"。`
    });
    return null;
  }

  const proto = item.protocol === 'hysteria' ? 'hysteria2' : item.protocol;
  const vfSpec = CORE_FEATURES_SPEC.v2ray.features;
  if (v2rayFeatures) {
    if (proto === 'shadowsocks2022' && !v2rayFeatures.hasShadowsocks2022) {
      diagnostics.push({
        level: 'error',
        path: `outbounds.${item.tag}`,
        message: `V2Ray ${v2rayFeatures.version} 不支持 shadowsocks2022 出站协议（需 >= ${vfSpec.shadowsocks2022.since}）。`
      });
      return null;
    }
    if (proto === 'hysteria2' && !v2rayFeatures.hasHysteria2) {
      diagnostics.push({
        level: 'error',
        path: `outbounds.${item.tag}`,
        message: `V2Ray ${v2rayFeatures.version} 不支持 hysteria2 出站协议（需 >= ${vfSpec.hysteria2.since}）。`
      });
      return null;
    }
  }
  let settings: Record<string, unknown> = {};

  if (proto === 'shadowsocks2022') {
    settings = {
      address: item.address || '',
      port: item.port || 8388,
      method: item.method || '2022-blake3-aes-128-gcm',
      psk: item.password || ''
    };
    if (item.ss_ipsk && item.ss_ipsk.length > 0) settings.ipsk = item.ss_ipsk;
  } else if (proto === 'vmess' || proto === 'vless') {
    settings = {
      address: item.address || '',
      port: item.port || 443,
      uuid: item.uuid || ''
    };
  } else if (proto === 'trojan') {
    settings = {
      address: item.address || '',
      port: item.port || 443,
      password: item.password || ''
    };
  } else if (proto === 'shadowsocks') {
    const method = item.method || 'aes-256-gcm';
    const methodLower = method.toLowerCase();
    if (!V2RAY_V5_SS_ALLOWED_METHODS.has(methodLower)) {
      diagnostics.push({
        level: 'error',
        path: `outbounds.${item.tag}.method`,
        message: `V2Ray jsonv5 的 shadowsocks 协议不支持 "${method}"。`
      });
      return null;
    }
    settings = {
      address: item.address || '',
      port: item.port || 8388,
      method,
      password: item.password || ''
    };
  } else if (proto === 'hysteria2') {
    settings = {
      server: [{ address: item.address || '', port: item.port || 443 }]
    };
  } else if (proto === 'freedom' || proto === 'blackhole' || proto === 'dns') {
    settings = {};
  } else if (proto === 'loopback') {
    settings = { inboundTag: item.loopback_inbound_tag || '' };
  } else if (proto === 'socks' || proto === 'http') {
    settings = {
      address: item.address || '',
      port: item.port || (proto === 'http' ? 8080 : 1080)
    };
  }

  const obj: Record<string, unknown> = {
    tag: item.tag || item.id,
    protocol: proto,
    settings,
    streamSettings: buildV5Stream(item, proto, false, proto === 'dns' ? null : defaultMark, diagnostics, `outbounds.${item.tag}`)
  };
  if (item.send_through) obj.sendThrough = item.send_through;
  const ds = toV5OutboundDomainStrategy(item.domain_strategy);
  if (ds) obj.domainStrategy = ds;
  if (item.dialer_proxy) {
    obj.proxySettings = { tag: item.dialer_proxy, transportLayer: true };
  }
  if (item.mux_enabled) {
    obj.mux = {
      enabled: true,
      concurrency: item.mux_concurrency ?? 8
    };
  }
  const custom = parseJsonObjectChecked(item.custom_config, diagnostics, `outbounds.${item.tag}.custom_config`);
  return custom ? deepMerge(obj, custom) : obj;
}

export function compileV2RayV5(
  cfg: AiosConfig,
  v2rayFeatures?: ResolvedV2RayFeatures
): CompileResult {
  const diagnostics: CompileDiagnostic[] = [];
  const vfSpec = CORE_FEATURES_SPEC.v2ray.features;
  if (v2rayFeatures && !v2rayFeatures.hasJsonV5) {
    diagnostics.push({
      level: 'error',
      path: 'general.v2ray_format',
      message: `V2Ray ${v2rayFeatures.version} 不支持 jsonv5 格式（需 >= ${vfSpec.jsonv5.since}）。`
    });
  }
  const outMark = cfg.transparent_proxy.enabled
    ? Number.parseInt(cfg.transparent_proxy.outbound_mark, 16) || null
    : null;

  const services: Record<string, unknown> = {};
  if (cfg.general.stats_enabled) services.stats = {};
  if (cfg.general.api_enabled) {
    diagnostics.push({
      level: 'warning',
      path: 'general.api_enabled',
      message: 'V2Ray jsonv5 未注册 services.api 别名，已跳过生成 services.api。'
    });
  }
  if (cfg.observatory.enabled) {
    services.backgroundObservatory = {
      subjectSelector: cfg.observatory.subject_selector,
      probeUrl: cfg.observatory.probe_url || 'https://www.google.com/generate_204',
      probeInterval: parseDurationToNs(cfg.observatory.probe_interval, 60e9)
    };
  }
  if (cfg.burst_observatory?.enabled) {
    services.burstObservatory = {
      subjectSelector: cfg.burst_observatory.subject_selector,
      pingConfig: {
        destination: cfg.burst_observatory.destination || 'https://www.google.com/generate_204',
        connectivity: cfg.burst_observatory.connectivity || undefined,
        interval: parseDurationToNs(cfg.burst_observatory.interval, 60e9),
        samplingCount: cfg.burst_observatory.sampling || 3,
        timeout: parseDurationToNs(cfg.burst_observatory.timeout, 5e9)
      }
    };
  }
  if (cfg.browser_forwarder?.enabled) {
    services.browser = {
      listenAddr: cfg.browser_forwarder.listen_addr || '127.0.0.1',
      listenPort: cfg.browser_forwarder.listen_port || 8088
    };
  }
  if (cfg.reverse.enabled) {
    const mapPair = (arr: string[]) =>
      arr
        .map((s) => s.split('|'))
        .filter((p) => p.length === 2 && p[0].trim() && p[1].trim())
        .map(([tag, domain]) => ({ tag: tag.trim(), domain: domain.trim() }));
    services.reverse = {
      bridgeConfig: mapPair(cfg.reverse.bridges),
      portalConfig: mapPair(cfg.reverse.portals)
    };
  }
  if (cfg.policy.enabled) {
    const levelMap: Record<string, Record<string, unknown>> = {};
    const levels = cfg.policy.levels && cfg.policy.levels.length > 0
      ? cfg.policy.levels
      : [
          {
            level: '0',
            handshake: cfg.policy.handshake,
            conn_idle: cfg.policy.conn_idle,
            uplink_only: cfg.policy.uplink_only,
            downlink_only: cfg.policy.downlink_only,
            buffer_size: cfg.policy.buffer_size,
            stats_user_uplink: true,
            stats_user_downlink: true
          }
        ];
    for (const lv of levels) {
      levelMap[lv.level || '0'] = {
        timeout: {
          handshake: { value: lv.handshake },
          connectionIdle: { value: lv.conn_idle },
          uplinkOnly: { value: lv.uplink_only },
          downlinkOnly: { value: lv.downlink_only }
        },
        stats: {
          userUplink: lv.stats_user_uplink,
          userDownlink: lv.stats_user_downlink
        },
        buffer: {
          connection: lv.buffer_size < 0 ? -1 : lv.buffer_size * 1024
        }
      };
    }
    services.policy = {
      level: levelMap,
      system: {
        stats: {
          inboundUplink: cfg.policy.stats_inbound_uplink,
          inboundDownlink: cfg.policy.stats_inbound_downlink,
          outboundUplink: cfg.policy.stats_outbound_uplink,
          outboundDownlink: cfg.policy.stats_outbound_downlink
        }
      }
    };
  }

  // Convert any TUN inbound into V2Ray v5 services.tun
  const tunInbound = cfg.inbounds.find((i) => i.enabled && i.protocol === 'tun');
  if (tunInbound) {
    if (v2rayFeatures && !v2rayFeatures.hasV5ServicesTun) {
      diagnostics.push({
        level: 'error',
        path: `inbounds.${tunInbound.tag}`,
        message: `V2Ray ${v2rayFeatures.version} 不支持 services.tun（需 >= ${vfSpec.v5ServicesTun.since}）。`
      });
    } else {
      if (v2rayFeatures && tunInbound.packet_encoding === 'Stream' && !v2rayFeatures.hasPacketEncodingStream) {
        diagnostics.push({
          level: 'error',
          path: `inbounds.${tunInbound.tag}.packet_encoding`,
          message: `V2Ray ${v2rayFeatures.version} 不支持 packetEncoding="Stream"（需 >= ${vfSpec.packetEncodingStream.since}）。`
        });
      }
      const parsedIps = (tunInbound.tun_ips || [])
        .map(parseCidrToBytes)
        .filter((x): x is { ip: number[]; prefix: number } => x !== null);
      const parsedRoutes = (tunInbound.tun_routes || [])
        .map(parseCidrToBytes)
        .filter((x): x is { ip: number[]; prefix: number } => x !== null);
      const tunSvc: Record<string, unknown> = {
        name: tunInbound.tun_name || 'aios0',
        mtu: tunInbound.tun_mtu || 1500,
        tag: tunInbound.tag || 'tun-in',
        ips: parsedIps.length > 0 ? parsedIps : [{ ip: [10, 0, 0, 1], prefix: 24 }],
        routes: parsedRoutes.length > 0 ? parsedRoutes : [{ ip: [0, 0, 0, 0], prefix: 0 }],
        enablePromiscuousMode: tunInbound.tun_promiscuous !== false,
        enableSpoofing: tunInbound.tun_spoofing !== false
      };
      if (tunInbound.packet_encoding) tunSvc.packetEncoding = tunInbound.packet_encoding;
      if (tunInbound.sniffing_enabled) {
        tunSvc.sniffingSettings = {
          enabled: true,
          destinationOverride:
            tunInbound.sniffing_dest_override && tunInbound.sniffing_dest_override.length > 0
              ? tunInbound.sniffing_dest_override
              : ['http', 'tls'],
          metadataOnly: !!tunInbound.sniffing_metadata_only
        };
      }
      services.tun = tunSvc;
    }
  }

  const inbounds = cfg.inbounds
    .filter((i) => i.enabled)
    .map((i) => compileV5Inbound(i, diagnostics, v2rayFeatures))
    .filter((x): x is Record<string, unknown> => x !== null);

  const outbounds = cfg.outbounds
    .filter((o) => o.enabled)
    .map((o) => compileV5Outbound(o, outMark, diagnostics, v2rayFeatures))
    .filter((x): x is Record<string, unknown> => x !== null);

  let dnsObj: Record<string, unknown> | undefined;
  if (cfg.dns.enabled || cfg.fakedns.length > 0) {
    const hostsMap = new Map<string, string[]>();
    for (const [domain, addrs] of Object.entries(cfg.dns.hosts || {})) {
      const key = domain.trim();
      const cleaned = (Array.isArray(addrs) ? addrs : [String(addrs)])
        .map((x) => String(x).trim())
        .filter(Boolean);
      if (key && cleaned.length > 0) {
        hostsMap.set(key, cleaned);
      }
    }
    for (const h of cfg.dns.host_entries || []) {
      const key = h.domain.trim();
      const cleaned = (h.addresses || []).map((x) => String(x).trim()).filter(Boolean);
      if (key && cleaned.length > 0) {
        hostsMap.set(key, cleaned);
      }
    }
    const staticHosts: Record<string, unknown>[] = [];
    for (const [domain, targets] of hostsMap.entries()) {
      const entry = buildStaticHostEntry(domain, targets);
      if (entry) staticHosts.push(entry);
    }
    dnsObj = {
      tag: cfg.dns.tag || 'dns-in',
      queryStrategy: toV5QueryStrategy(cfg.dns.query_strategy),
      cacheStrategy: cfg.dns.disable_cache ? 'CacheDisabled' : 'CacheEnabled',
      fallbackStrategy: cfg.dns.disable_fallback
        ? 'Disabled'
        : cfg.dns.disable_fallback_if_match
          ? 'DisabledIfAnyMatch'
          : 'Enabled',
      domainMatcher: cfg.routing.domain_matcher === 'mph' ? 'mph' : 'linear',
      clientIp: cfg.dns.client_ip || undefined,
      staticHosts: staticHosts.length > 0 ? staticHosts : undefined,
      fakeDns:
        cfg.fakedns.length > 0
          ? {
              pools: cfg.fakedns.map((f) => ({
                ipPool: f.ip_pool || '198.18.0.0/15',
                lruSize: f.pool_size || 65535
              }))
            }
          : undefined,
      nameServer: cfg.dns_servers
        .filter((s) => s.enabled)
        .map((s) => {
          const endpoint: Record<string, unknown> = { address: s.address };
          if (s.port) endpoint.port = s.port;
          const ns: Record<string, unknown> = { address: endpoint };
          if (s.client_ip) ns.clientIp = s.client_ip;
          if (s.skip_fallback) ns.skipFallback = true;
          if (s.domains && s.domains.length > 0) {
            const pDomains: Record<string, unknown>[] = [];
            const gDomains: Record<string, unknown>[] = [];
            for (const rawDom of s.domains) {
              const trimmed = rawDom.trim();
              if (!trimmed) continue;
              if (trimmed.startsWith('geosite:')) {
                gDomains.push({ filePath: 'geosite.dat', code: trimmed.slice(8) });
              } else if (trimmed.startsWith('ext:') || trimmed.startsWith('ext-domain:')) {
                const rest = trimmed.startsWith('ext-domain:') ? trimmed.slice(11) : trimmed.slice(4);
                const colon = rest.indexOf(':');
                gDomains.push({
                  filePath: colon >= 0 ? rest.slice(0, colon) : 'geosite.dat',
                  code: colon >= 0 ? rest.slice(colon + 1) : rest
                });
              } else {
                pDomains.push(parsePriorityDomain(trimmed));
              }
            }
            if (pDomains.length > 0) ns.prioritizedDomain = pDomains;
            if (gDomains.length > 0) ns.geoDomain = gDomains;
          }
          if (s.expect_ips && s.expect_ips.length > 0) {
            ns.geoip = s.expect_ips.map(parseGeoIpEntry);
          }
          if (s.tag) ns.tag = s.tag;
          if (s.query_strategy) {
            ns.queryStrategy = toV5QueryStrategy(s.query_strategy);
          }
          return ns;
        })
    };
  }

  const hasAccessLog = !!cfg.general.access_log && cfg.general.access_log !== 'none' && cfg.general.access_log !== '/dev/null';
  const errLogRaw = (cfg.general.error_log || '').trim();
  const errLogObj =
    errLogRaw === 'none' || errLogRaw === '/dev/null'
      ? { type: 'None', level: toV5LogLevel(cfg.general.log_level) }
      : errLogRaw
        ? { type: 'File', path: errLogRaw, level: toV5LogLevel(cfg.general.log_level) }
        : { type: 'Console', level: toV5LogLevel(cfg.general.log_level) };
  const doc: Record<string, unknown> = {
    log: {
      access: hasAccessLog
        ? { type: 'File', path: cfg.general.access_log }
        : { type: 'None' },
      error: errLogObj
    },
    dns: dnsObj,
    inbounds,
    outbounds,
    router: cfg.routing.enabled
      ? {
          domainStrategy: toV5RouterDomainStrategy(cfg.routing.domain_strategy),
          rule: cfg.routing_rules
            .filter((r) => r.enabled)
            .map((r) => {
              const { domains, geoDomains } = parseRouterDomains(r.domain || []);
              const ruleObj: Record<string, unknown> = {
                domain: domains.length > 0 ? domains : undefined,
                geoDomain: geoDomains.length > 0 ? geoDomains : undefined,
                geoip: r.ip && r.ip.length > 0 ? r.ip.map(parseGeoIpEntry) : undefined,
                portList: r.port || undefined,
                sourcePortList: r.source_port || undefined,
                networks: r.network || undefined,
                sourceGeoip: r.source && r.source.length > 0 ? r.source.map(parseGeoIpEntry) : undefined,
                userEmail: r.user && r.user.length > 0 ? r.user : undefined,
                inboundTag: r.inbound_tag && r.inbound_tag.length > 0 ? r.inbound_tag : undefined,
                protocol: r.protocol && r.protocol.length > 0 ? r.protocol : undefined,
                domainMatcher: cfg.routing.domain_matcher === 'mph' ? 'mph' : 'linear',
                attributes: r.attrs || undefined,
                tag: r.balancer_tag ? undefined : r.outbound_tag || undefined,
                balancingTag: r.balancer_tag || undefined
              };
              return ruleObj;
            }),
          balancingRule: cfg.balancers.map((b) => {
            let strategy = 'random';
            if (b.strategy === 'leastPing') strategy = 'leastping';
            else if (b.strategy === 'leastLoad') strategy = 'leastload';
            const br: Record<string, unknown> = {
              tag: b.tag,
              outboundSelector: b.selector,
              strategy
            };
            if (b.fallback_tag) br.fallbackTag = b.fallback_tag;
            return br;
          })
        }
      : undefined,
    services: Object.keys(services).length > 0 ? services : undefined
  };

  return { core: 'v2ray', json: doc, diagnostics };
}
