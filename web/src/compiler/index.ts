import type {
  AiosConfig,
  CoreType,
  InboundConfig,
  KeyValuePair,
  OutboundConfig,
  StreamFields
} from '@/schema/types';
import { resolveEffectiveCore, validateStreamCombination } from '@/schema/capabilities';
import {
  CORE_FEATURES_SPEC,
  resolveCoreFeatures,
  type ResolvedCoreFeatures,
  type ResolvedV2RayFeatures,
  type ResolvedXrayFeatures
} from '@/schema/features';
import { compileV2RayV5, parseDurationToNs } from './v2ray_v5';

export interface CompileDiagnostic {
  level: 'warning' | 'error';
  path: string;
  message: string;
}

export interface CompileResult {
  core: CoreType;
  version?: string;
  features?: ResolvedCoreFeatures;
  json: Record<string, unknown>;
  diagnostics: CompileDiagnostic[];
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

function parseJsonArrayChecked(
  str: string | undefined,
  diagnostics: CompileDiagnostic[],
  path: string
): unknown[] | null {
  if (!str || !str.trim()) return null;
  try {
    const parsed = JSON.parse(str);
    if (Array.isArray(parsed)) return parsed;
    diagnostics.push({ level: 'error', path, message: 'JSON 必须为数组（Array）格式。' });
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

function parseHexOrInt(value: string | number | undefined): number | null {
  if (value === undefined || value === '') return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const parsed = Number.parseInt(value, value.startsWith('0x') ? 16 : 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseSecondsNumber(value: number | string | undefined): number | null {
  if (value === undefined || value === '') return null;
  if (typeof value === 'number') return Number.isFinite(value) && value > 0 ? value : null;
  const cleaned = value.trim().replace(/s$/i, '');
  const n = Number(cleaned);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function parseCidrToBytes(cidr: string): { ip: number[]; prefix: number } | null {
  const [addr, prefixStr] = cidr.trim().split('/');
  if (!addr) return null;
  const parts = addr.split('.');
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p))) {
    const bytes = parts.map((p) => Number(p));
    const prefix = prefixStr !== undefined ? Number(prefixStr) : 32;
    if (bytes.every((b) => b >= 0 && b <= 255) && Number.isFinite(prefix)) {
      return { ip: bytes, prefix };
    }
  }
  return null;
}

function kvToMap(pairs?: KeyValuePair[]): Record<string, string> | null {
  if (!pairs || pairs.length === 0) return null;
  const out: Record<string, string> = {};
  for (const p of pairs) {
    if (p.key.trim()) out[p.key.trim()] = p.value;
  }
  return Object.keys(out).length > 0 ? out : null;
}

function buildStreamSettings(
  item: StreamFields & { tag?: string; password?: string },
  core: CoreType,
  protocol: string,
  isInbound: boolean,
  defaultMark: number | null,
  diagnostics: CompileDiagnostic[],
  pathPrefix: string,
  xrayFeatures?: ResolvedXrayFeatures
): Record<string, unknown> {
  const isXray = core === 'xray';
  let net = item.transport || (isXray ? 'raw' : 'tcp');

  if (isXray) {
    if (net === 'tcp') net = 'raw';
    if (net === 'ws') net = 'websocket';
    if (net === 'hysteria2') net = 'hysteria';
    if (net === 'splithttp') net = 'xhttp';
    if (net === 'h2' || net === 'http' || net === 'quic') {
      diagnostics.push({
        level: 'warning',
        path: `${pathPrefix}.transport`,
        message: `Xray 新版已将 ${net} 合并/引导至 xhttp，建议迁移为 xhttp。`
      });
    }
  } else {
    if (net === 'raw') net = 'tcp';
    if (net === 'websocket') net = 'ws';
    if (net === 'mkcp') net = 'kcp';
    if (net === 'h2') net = 'http';
    if (net === 'hysteria') net = 'hysteria2';
    if (net === 'xhttp' || net === 'splithttp' || net === 'httpupgrade' || net === 'masque') {
      diagnostics.push({
        level: 'error',
        path: `${pathPrefix}.transport`,
        message: `V2Ray jsonv4 不支持传输层 "${net}"（httpupgrade 请切换 jsonv5）。`
      });
      net = 'tcp';
    }
  }

  let security = item.security || 'none';
  if (!isXray && security === 'reality') {
    diagnostics.push({
      level: 'error',
      path: `${pathPrefix}.security`,
      message: 'V2Ray 不支持 REALITY 安全层。'
    });
    security = 'tls';
  }
  if (!isXray && security === 'utls') {
    diagnostics.push({
      level: 'error',
      path: `${pathPrefix}.security`,
      message: 'V2Ray jsonv4 不支持独立 uTLS 安全层（请切换 jsonv5 或改用 tls）。'
    });
    security = 'tls';
  }

  for (const issue of validateStreamCombination(core, 'jsonv4', protocol, net, security)) {
    diagnostics.push({ level: issue.level, path: `${pathPrefix}.streamSettings`, message: issue.message });
  }

  const streamKey = isXray ? xrayFeatures?.streamMethodKey || 'method' : 'network';
  const ss: Record<string, unknown> = { [streamKey]: net };
  ss.security = security;

  if (security === 'tls') {
    const tls: Record<string, unknown> = {};
    if (item.tls_server_name) tls.serverName = item.tls_server_name;
    if (item.tls_allow_insecure) tls.allowInsecure = true;
    if (item.tls_alpn && item.tls_alpn.length > 0) tls.alpn = item.tls_alpn;

    const pinned = Array.isArray(item.tls_pinned_sha256)
      ? item.tls_pinned_sha256.filter(Boolean)
      : item.tls_pinned_sha256
        ? [String(item.tls_pinned_sha256)]
        : [];

    if (isXray) {
      if (item.tls_fingerprint) tls.fingerprint = item.tls_fingerprint;
      if (pinned.length > 0) tls.pinnedPeerCertSha256 = pinned.join(',');
      if (item.tls_ech_config) tls.echConfigList = item.tls_ech_config;
      if (item.tls_ech_server_keys) tls.echServerKeys = item.tls_ech_server_keys;
      const echSock = parseJsonObjectChecked(item.tls_ech_sockopt_json, diagnostics, `${pathPrefix}.tls_ech_sockopt_json`);
      if (echSock) tls.echSockopt = echSock;
      if (item.tls_verify_peer_name) tls.verifyPeerCertByName = item.tls_verify_peer_name;
      if (item.tls_min_version) tls.minVersion = item.tls_min_version;
      if (item.tls_max_version) tls.maxVersion = item.tls_max_version;
      if (item.tls_cipher_suites) tls.cipherSuites = item.tls_cipher_suites;
      if (item.tls_reject_unknown_sni) tls.rejectUnknownSni = true;
      if (item.tls_use_system_ca) tls.useSystemCA = true;
      if (item.tls_disable_system_root) tls.disableSystemRoot = true;
      if (item.tls_enable_session_resumption) tls.enableSessionResumption = true;
      if (item.tls_curve_preferences && item.tls_curve_preferences.length > 0) {
        tls.curvePreferences = item.tls_curve_preferences;
      }
    } else {
      if (pinned.length > 0) tls.pinnedPeerCertificateChainSha256 = pinned;
      if (item.tls_verify_client) tls.verifyClientCertificate = true;
      if (item.tls_disable_system_root) tls.disableSystemRoot = true;
    }

    if (isInbound) {
      if (item.tls_certificates && item.tls_certificates.length > 0) {
        tls.certificates = item.tls_certificates.filter((c) => c.certificateFile && c.keyFile);
      } else if (item.tls_cert_file && item.tls_key_file) {
        tls.certificates = [
          { certificateFile: item.tls_cert_file, keyFile: item.tls_key_file }
        ];
      }
    }
    ss.tlsSettings = tls;
  } else if (security === 'reality' && isXray) {
    if (isInbound) {
      const rs: Record<string, unknown> = {
        show: !!item.reality_show,
        target: item.reality_target || '',
        xver: item.reality_xver || 0,
        serverNames: item.reality_server_names || [],
        privateKey: item.reality_private_key || '',
        shortIds: item.reality_short_ids || []
      };
      if (item.reality_mldsa65_seed) rs.mldsa65Seed = item.reality_mldsa65_seed;
      if (item.reality_min_client_ver) rs.minClientVer = item.reality_min_client_ver;
      if (item.reality_max_client_ver) rs.maxClientVer = item.reality_max_client_ver;
      if (item.reality_max_time_diff) rs.maxTimeDiff = item.reality_max_time_diff;
      ss.realitySettings = rs;
    } else {
      const rs: Record<string, unknown> = {
        show: !!item.reality_show,
        fingerprint: item.reality_fingerprint || 'chrome',
        serverName: item.reality_server_name || '',
        password: item.reality_public_key || '',
        publicKey: item.reality_public_key || '',
        shortId: item.reality_short_id || '',
        spiderX: item.reality_spider_x || '/'
      };
      if (item.reality_mldsa65_verify) rs.mldsa65Verify = item.reality_mldsa65_verify;
      ss.realitySettings = rs;
    }
  }

  // Transport specific objects
  if (net === 'raw' || net === 'tcp') {
    const tcp: Record<string, unknown> = {};
    if (item.tcp_accept_proxy_protocol) tcp.acceptProxyProtocol = true;
    if (item.tcp_header_type && item.tcp_header_type !== 'none') {
      const header: Record<string, unknown> = { type: item.tcp_header_type };
      const reqHeaders = kvToMap(item.tcp_request_headers);
      if (reqHeaders) header.request = { headers: reqHeaders };
      const respHeaders = kvToMap(item.tcp_response_headers);
      if (respHeaders) header.response = { headers: respHeaders };
      tcp.header = header;
    }
    if (Object.keys(tcp).length > 0) {
      ss[isXray ? 'rawSettings' : 'tcpSettings'] = tcp;
    }
  } else if (net === 'websocket' || net === 'ws') {
    const ws: Record<string, unknown> = { path: item.ws_path || '/' };
    const headers = kvToMap(item.ws_headers) || {};
    if (item.ws_host) {
      if (isXray) ws.host = item.ws_host;
      else headers.Host = item.ws_host;
    }
    if (Object.keys(headers).length > 0) ws.headers = headers;
    if (isXray && item.ws_heartbeat_period) ws.heartbeatPeriod = item.ws_heartbeat_period;
    if (!isXray && item.ws_max_early_data) {
      ws.maxEarlyData = item.ws_max_early_data;
      if (item.ws_early_data_header) ws.earlyDataHeaderName = item.ws_early_data_header;
    }
    ss.wsSettings = ws;
  } else if (net === 'grpc') {
    const grpc: Record<string, unknown> = { serviceName: item.grpc_service_name || '' };
    if (isXray) {
      if (item.grpc_authority) grpc.authority = item.grpc_authority;
      if (item.grpc_multi_mode) grpc.multiMode = true;
      if (item.grpc_idle_timeout) grpc.idle_timeout = item.grpc_idle_timeout;
      if (item.grpc_health_check_timeout) grpc.health_check_timeout = item.grpc_health_check_timeout;
      if (item.grpc_permit_without_stream) grpc.permit_without_stream = true;
      if (item.grpc_initial_windows_size) grpc.initial_windows_size = item.grpc_initial_windows_size;
    }
    ss.grpcSettings = grpc;
  } else if (net === 'xhttp' && isXray) {
    const xhttp: Record<string, unknown> = {
      path: item.xhttp_path || '/',
      mode: item.xhttp_mode || 'auto'
    };
    if (item.xhttp_host) xhttp.host = item.xhttp_host;
    const extra = parseJsonObjectChecked(item.xhttp_extra, diagnostics, `${pathPrefix}.xhttp_extra`);
    if (extra) xhttp.extra = extra;
    ss.xhttpSettings = xhttp;
  } else if (net === 'httpupgrade' && isXray) {
    const hu: Record<string, unknown> = { path: item.httpupgrade_path || '/' };
    if (item.httpupgrade_host) hu.host = item.httpupgrade_host;
    const headers = kvToMap(item.httpupgrade_headers);
    if (headers) hu.headers = headers;
    ss.httpupgradeSettings = hu;
  } else if (net === 'http' && !isXray) {
    const h2: Record<string, unknown> = {
      path: item.h2_path || '/',
      host: item.h2_host || []
    };
    if (item.h2_method) h2.method = item.h2_method;
    const headers = kvToMap(item.h2_headers);
    if (headers) h2.headers = headers;
    ss.httpSettings = h2;
  } else if (net === 'kcp' || net === 'mkcp') {
    const kcp: Record<string, unknown> = {
      mtu: item.mkcp_mtu || 1350,
      tti: item.mkcp_tti || 50,
      uplinkCapacity: item.mkcp_uplink_capacity || 5,
      downlinkCapacity: item.mkcp_downlink_capacity || 20
    };
    if (isXray) {
      if (item.mkcp_cwnd_multiplier) kcp.cwndMultiplier = item.mkcp_cwnd_multiplier;
      if (item.mkcp_max_sending_window) kcp.maxSendingWindow = item.mkcp_max_sending_window;
    } else {
      kcp.congestion = !!item.mkcp_congestion;
      if (item.mkcp_seed) kcp.seed = item.mkcp_seed;
      if (item.mkcp_header_type) kcp.header = { type: item.mkcp_header_type };
    }
    ss.kcpSettings = kcp;
  } else if (net === 'quic' && !isXray) {
    ss.quicSettings = {
      security: item.quic_security || 'none',
      key: item.quic_key || '',
      header: { type: item.quic_header_type || 'none' }
    };
  } else if (net === 'domainsocket' && !isXray) {
    ss.dsSettings = {
      path: item.ds_path || '',
      abstract: !!item.ds_abstract,
      padding: !!item.ds_padding
    };
  } else if (net === 'hysteria' && isXray) {
    const hy: Record<string, unknown> = {
      version: 2,
      auth: item.hysteria_auth || item.password || ''
    };
    const idleSec = parseSecondsNumber(item.hysteria_udp_idle_timeout);
    if (idleSec !== null) hy.udpIdleTimeout = idleSec;
    if (item.hysteria_masquerade_type) {
      const masq: Record<string, unknown> = { type: item.hysteria_masquerade_type };
      if (item.hysteria_masquerade_type === 'file' && item.hysteria_masquerade_dir) {
        masq.dir = item.hysteria_masquerade_dir;
      } else if (item.hysteria_masquerade_type === 'proxy') {
        if (item.hysteria_masquerade_url) masq.url = item.hysteria_masquerade_url;
        if (item.hysteria_masquerade_rewrite_host) masq.rewriteHost = true;
        if (item.hysteria_masquerade_insecure) masq.insecure = true;
      } else if (item.hysteria_masquerade_type === 'string') {
        if (item.hysteria_masquerade_content) masq.content = item.hysteria_masquerade_content;
        const mHeaders = kvToMap(item.hysteria_masquerade_headers);
        if (mHeaders) masq.headers = mHeaders;
        if (item.hysteria_masquerade_status_code) masq.statusCode = item.hysteria_masquerade_status_code;
      }
      hy.masquerade = masq;
    } else if (item.hysteria_masquerade && item.hysteria_masquerade.trim()) {
      const rawMasq = item.hysteria_masquerade.trim();
      if (rawMasq.startsWith('{')) {
        const parsedMasq = parseJsonObjectChecked(rawMasq, diagnostics, `${pathPrefix}.hysteria_masquerade`);
        if (parsedMasq) hy.masquerade = parsedMasq;
      } else {
        hy.masquerade = { type: 'proxy', url: rawMasq };
      }
    }
    ss.hysteriaSettings = hy;
  } else if (net === 'hysteria2' && !isXray) {
    const hy2: Record<string, unknown> = {
      password: item.hysteria_auth || item.password || '',
      use_udp_extension: item.hysteria_udp_extension !== false
    };
    if (item.hysteria_up_mbps || item.hysteria_down_mbps) {
      hy2.congestion = {
        type: 'brutal',
        up_mbps: item.hysteria_up_mbps || 50,
        down_mbps: item.hysteria_down_mbps || 100
      };
    }
    ss.hysteria2Settings = hy2;
  } else if (net === 'masque' && isXray) {
    const mq: Record<string, unknown> = {};
    const path = item.masque_path || item.masque_uri;
    if (path) mq.path = path;
    if (!isInbound) {
      if (item.masque_host) mq.host = item.masque_host;
      if (item.masque_user) mq.user = item.masque_user;
      if (item.masque_pass) mq.pass = item.masque_pass;
      const headers = kvToMap(item.masque_headers);
      if (headers) mq.headers = headers;
      const warp = parseJsonObjectChecked(item.masque_warp_json, diagnostics, `${pathPrefix}.masque_warp_json`);
      if (warp) mq.warp = warp;
    }
    ss.masqueSettings = mq;
  }

  // FinalMask (Xray only)
  if (isXray) {
    let fm = parseJsonObjectChecked(item.finalmask_json, diagnostics, `${pathPrefix}.finalmask_json`);
    if (
      !fm &&
      net === 'hysteria' &&
      (item.hysteria_up_mbps ||
        item.hysteria_down_mbps ||
        item.hysteria_udphop_port ||
        item.hysteria_obfs_password)
    ) {
      fm = {};
      if (item.hysteria_obfs_password) {
        fm.udp = [{ type: 'salamander', settings: { password: item.hysteria_obfs_password } }];
      }
      const qp: Record<string, unknown> = {};
      if (item.hysteria_up_mbps || item.hysteria_down_mbps) {
        qp.congestion = 'brutal';
        if (item.hysteria_up_mbps) qp.brutalUp = `${item.hysteria_up_mbps} mbps`;
        if (item.hysteria_down_mbps) qp.brutalDown = `${item.hysteria_down_mbps} mbps`;
      }
      if (item.hysteria_udphop_port) {
        qp.udpHop = {
          ports: item.hysteria_udphop_port,
          interval: item.hysteria_udphop_interval || 30
        };
      }
      if (Object.keys(qp).length > 0) fm.quicParams = qp;
    }
    if (fm) ss.finalmask = fm;
  }

  // Sockopt
  const sockopt: Record<string, unknown> = {};
  const mark = item.sockopt_mark ?? defaultMark;
  if (mark !== null && mark > 0) sockopt.mark = mark;
  if (item.sockopt_tproxy && item.sockopt_tproxy !== 'off') sockopt.tproxy = item.sockopt_tproxy;
  if (item.sockopt_tcp_fast_open) {
    sockopt.tcpFastOpen =
      isXray && item.sockopt_tcp_fast_open_queue_length
        ? item.sockopt_tcp_fast_open_queue_length
        : true;
    if (!isXray && item.sockopt_tcp_fast_open_queue_length) {
      sockopt.tcpFastOpenQueueLength = item.sockopt_tcp_fast_open_queue_length;
    }
  }
  if (item.sockopt_mptcp) sockopt[isXray ? 'tcpMptcp' : 'mptcp'] = true;
  if (item.sockopt_interface) sockopt[isXray ? 'interface' : 'bindToDevice'] = item.sockopt_interface;
  if (item.sockopt_tcp_keepalive_interval) sockopt.tcpKeepAliveInterval = item.sockopt_tcp_keepalive_interval;
  if (isXray) {
    if (item.sockopt_tcp_max_seg) sockopt.tcpMaxSeg = item.sockopt_tcp_max_seg;
    if (item.sockopt_tcp_keepalive_idle) sockopt.tcpKeepAliveIdle = item.sockopt_tcp_keepalive_idle;
    if (item.sockopt_tcp_user_timeout) sockopt.tcpUserTimeout = item.sockopt_tcp_user_timeout;
    if (item.sockopt_tcp_congestion) sockopt.tcpcongestion = item.sockopt_tcp_congestion;
    if (item.sockopt_v6_only) sockopt.V6Only = true;
    if (item.sockopt_tcp_window_clamp) sockopt.tcpWindowClamp = item.sockopt_tcp_window_clamp;
    if (item.sockopt_address_port_strategy) sockopt.addressPortStrategy = item.sockopt_address_port_strategy;
    if (item.sockopt_trusted_xff && item.sockopt_trusted_xff.length > 0) {
      sockopt.trustedXForwardedFor = item.sockopt_trusted_xff;
    }
    const customSock = parseJsonArrayChecked(item.sockopt_custom_json, diagnostics, `${pathPrefix}.sockopt_custom_json`);
    if (customSock) sockopt.customSockopt = customSock;
    if (
      item.sockopt_happy_eyeballs_try_delay_ms ||
      item.sockopt_happy_eyeballs_prioritize_ipv6 ||
      item.sockopt_happy_eyeballs_interleave ||
      item.sockopt_happy_eyeballs_max_concurrent_try
    ) {
      const he: Record<string, unknown> = {};
      if (item.sockopt_happy_eyeballs_try_delay_ms !== undefined) {
        he.tryDelayMs = item.sockopt_happy_eyeballs_try_delay_ms;
      }
      if (item.sockopt_happy_eyeballs_prioritize_ipv6) he.prioritizeIPv6 = true;
      if (item.sockopt_happy_eyeballs_interleave !== undefined) {
        he.interleave = item.sockopt_happy_eyeballs_interleave;
      }
      if (item.sockopt_happy_eyeballs_max_concurrent_try !== undefined) {
        he.maxConcurrentTry = item.sockopt_happy_eyeballs_max_concurrent_try;
      }
      sockopt.happyEyeballs = he;
    }
    if (item.domain_strategy) sockopt.domainStrategy = item.domain_strategy;
    if (item.dialer_proxy) sockopt.dialerProxy = item.dialer_proxy;
  }
  if (Object.keys(sockopt).length > 0) ss.sockopt = sockopt;

  return ss;
}

function compileInbound(
  item: InboundConfig,
  core: CoreType,
  diagnostics: CompileDiagnostic[],
  xrayFeatures?: ResolvedXrayFeatures,
  v2rayFeatures?: ResolvedV2RayFeatures
): Record<string, unknown> | null {
  const isXray = core === 'xray';
  const useInboundUsers = isXray && (!xrayFeatures || xrayFeatures.inboundUsersKey === 'users');
  if (!isXray && item.protocol === 'tun') {
    return null; // Handled via v4 services.tun
  }
  if (!isXray && (item.protocol === 'wireguard' || item.protocol === 'masque')) {
    diagnostics.push({
      level: 'error',
      path: `inbounds.${item.tag}`,
      message: `V2Ray jsonv4 不支持入站协议 "${item.protocol}"。`
    });
    return null;
  }
  if (!isXray && v2rayFeatures) {
    const vfSpec = CORE_FEATURES_SPEC.v2ray.features;
    if ((item.protocol === 'hysteria' || item.protocol === 'hysteria2') && !v2rayFeatures.hasHysteria2) {
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
  if (isXray && xrayFeatures) {
    const xfSpec = CORE_FEATURES_SPEC.xray.features;
    if (item.protocol === 'masque' && !xrayFeatures.hasMasque) {
      diagnostics.push({
        level: 'error',
        path: `inbounds.${item.tag}`,
        message: `Xray ${xrayFeatures.version} 不支持 masque 入站协议（需 >= ${xfSpec.masque.since}）。`
      });
      return null;
    }
    if ((item.protocol === 'hysteria' || item.protocol === 'hysteria2') && !xrayFeatures.hasHysteria) {
      diagnostics.push({
        level: 'error',
        path: `inbounds.${item.tag}`,
        message: `Xray ${xrayFeatures.version} 不支持 hysteria 入站协议（需 >= ${xfSpec.hysteria.since}）。`
      });
      return null;
    }
    if (item.protocol === 'tun' && !xrayFeatures.hasTunInbound) {
      diagnostics.push({
        level: 'error',
        path: `inbounds.${item.tag}`,
        message: `Xray ${xrayFeatures.version} 不支持 tun 入站协议（需 >= ${xfSpec.tunInbound.since}）。`
      });
      return null;
    }
  }

  let proto = item.protocol || 'socks';
  if (isXray && proto === 'dokodemo-door' && item.use_tunnel) proto = 'tunnel';
  if (!isXray && proto === 'tunnel') proto = 'dokodemo-door';
  if (!isXray && proto === 'hysteria') proto = 'hysteria2';

  const obj: Record<string, unknown> = {
    tag: item.tag || item.id,
    listen: item.listen || '0.0.0.0',
    port: item.port,
    protocol: proto,
    settings: {}
  };

  const userList = item.users && item.users.length > 0 ? item.users : null;

  if (proto === 'socks') {
    const s: Record<string, unknown> = {
      auth: item.socks_auth || 'noauth',
      udp: !!item.socks_udp
    };
    if (item.socks_ip) s.ip = item.socks_ip;
    if (!isXray && item.packet_encoding) s.packetEncoding = item.packet_encoding;
    if (item.socks_auth === 'password') {
      const creds = userList
        ? userList.map((u) => ({ user: u.username || '', pass: u.password || '' }))
        : item.username
          ? [{ user: item.username, pass: item.password || '' }]
          : [];
      if (creds.length > 0) {
        s[useInboundUsers ? 'users' : 'accounts'] = creds;
      }
    }
    obj.settings = s;
  } else if (proto === 'http') {
    const s: Record<string, unknown> = {};
    const creds = userList
      ? userList.map((u) => ({ user: u.username || '', pass: u.password || '' }))
      : item.username
        ? [{ user: item.username, pass: item.password || '' }]
        : [];
    if (creds.length > 0) {
      s[useInboundUsers ? 'users' : 'accounts'] = creds;
    }
    if (item.http_allow_transparent) s.allowTransparent = true;
    if (!isXray && item.http_timeout) s.timeout = item.http_timeout;
    obj.settings = s;
  } else if (proto === 'dokodemo-door') {
    const s: Record<string, unknown> = {
      network: item.dokodemo_network || 'tcp,udp',
      followRedirect: !!item.dokodemo_follow_redirect
    };
    if (item.dokodemo_address) s.address = item.dokodemo_address;
    if (item.dokodemo_port) s.port = item.dokodemo_port;
    obj.settings = s;
  } else if (proto === 'tunnel') {
    const s: Record<string, unknown> = {
      allowedNetwork: item.dokodemo_network || 'tcp,udp',
      followRedirect: !!item.dokodemo_follow_redirect
    };
    if (item.dokodemo_address) s.rewriteAddress = item.dokodemo_address;
    if (item.dokodemo_port) s.rewritePort = item.dokodemo_port;
    const portMap = kvToMap(item.tunnel_port_map);
    if (portMap) s.portMap = portMap;
    if (item.tunnel_user_level !== undefined) s.userLevel = item.tunnel_user_level;
    obj.settings = s;
  } else if (proto === 'vless') {
    const entries = userList
      ? userList.map((u) =>
          isXray
            ? { id: u.id || '', flow: u.flow || '', email: u.email || undefined, level: u.level ?? 0 }
            : { id: u.id || '', email: u.email || undefined, level: u.level ?? 0 }
        )
      : [isXray ? { id: item.uuid || '', flow: item.flow || '' } : { id: item.uuid || '' }];
    const s: Record<string, unknown> = {
      [useInboundUsers ? 'users' : 'clients']: entries,
      decryption: isXray ? item.decryption || 'none' : 'none'
    };
    if (item.fallbacks && item.fallbacks.length > 0) s.fallbacks = item.fallbacks;
    obj.settings = s;
  } else if (proto === 'vmess') {
    const entries = userList
      ? userList.map((u) =>
          isXray
            ? { id: u.id || '', email: u.email || undefined, level: u.level ?? 0 }
            : { id: u.id || '', alterId: u.alterId ?? 0, email: u.email || undefined, level: u.level ?? 0 }
        )
      : [
          isXray
            ? { id: item.uuid || '' }
            : { id: item.uuid || '', alterId: item.alter_id || 0 }
        ];
    obj.settings = { [useInboundUsers ? 'users' : 'clients']: entries };
  } else if (proto === 'trojan') {
    const entries = userList
      ? userList.map((u) => ({ password: u.password || '', email: u.email || undefined, level: u.level ?? 0 }))
      : [{ password: item.password || '' }];
    const s: Record<string, unknown> = { [useInboundUsers ? 'users' : 'clients']: entries };
    if (item.fallbacks && item.fallbacks.length > 0) s.fallbacks = item.fallbacks;
    if (!isXray && item.packet_encoding) s.packetEncoding = item.packet_encoding;
    obj.settings = s;
  } else if (proto === 'shadowsocks') {
    const s: Record<string, unknown> = {
      method: item.method || 'aes-256-gcm',
      password: item.password || '',
      network: item.ss_network || 'tcp,udp'
    };
    if (!isXray && item.packet_encoding) s.packetEncoding = item.packet_encoding;
    obj.settings = s;
  } else if (proto === 'hysteria' && isXray) {
    const users = userList
      ? userList.map((u) => ({ auth: u.auth || u.password || '', email: u.email || undefined, level: u.level ?? 0 }))
      : [{ auth: item.hysteria_auth || item.password || '' }];
    obj.settings = { version: 2, users };
  } else if (proto === 'hysteria2' && !isXray) {
    const s: Record<string, unknown> = {};
    if (item.packet_encoding) s.packetEncoding = item.packet_encoding;
    obj.settings = s;
  } else if (proto === 'wireguard' && isXray) {
    obj.settings = {
      secretKey: item.wg_secret_key || '',
      address: item.wg_address || [],
      peers: item.wg_peers || [],
      mtu: item.wg_mtu || 1420
    };
  } else if (proto === 'masque' && isXray) {
    const users = userList
      ? userList.map((u) => ({
          email: u.email || u.username || '',
          pass: u.password || u.auth || '',
          level: u.level ?? 0
        }))
      : item.username || item.password
        ? [{ email: item.username || '', pass: item.password || '', level: 0 }]
        : [];
    if (users.length === 0) {
      diagnostics.push({
        level: 'warning',
        path: `inbounds.${item.tag}.users`,
        message: 'Xray MASQUE 入站未配置 users，所有连接将被拒绝。'
      });
    }
    obj.settings = {
      users,
      address: item.masque_address && item.masque_address.length > 0 ? item.masque_address : ['10.0.0.1/24'],
      mtu: item.masque_mtu || 1280
    };
  } else if (proto === 'tun' && isXray) {
    delete obj.listen;
    delete obj.port;
    const tunSettings: Record<string, unknown> = {
      name: item.tun_name || 'xray0',
      mtu: item.tun_mtu || 1500
    };
    if (item.tun_desc) tunSettings.desc = item.tun_desc;
    if (item.tun_gateway && item.tun_gateway.length > 0) tunSettings.gateway = item.tun_gateway;
    if (item.tun_dns && item.tun_dns.length > 0) tunSettings.dns = item.tun_dns;
    if (item.tun_user_level !== undefined) tunSettings.userLevel = item.tun_user_level;
    if (item.tun_auto_routing_table && item.tun_auto_routing_table.length > 0) {
      tunSettings.autoSystemRoutingTable = item.tun_auto_routing_table;
    }
    if (item.tun_auto_outbounds_interface) {
      tunSettings.autoOutboundsInterface = item.tun_auto_outbounds_interface;
    }
    if (item.tun_auto_dns_to_gateway) tunSettings.autoSystemDnsToGateway = true;
    if (item.tun_auto_wfp_block_leak && item.tun_auto_wfp_block_leak.length > 0) {
      tunSettings.autoSystemWfpBlockLeak = item.tun_auto_wfp_block_leak;
    }
    obj.settings = tunSettings;
  }

  if (item.sniffing_enabled) {
    const sn: Record<string, unknown> = {
      enabled: true,
      destOverride: item.sniffing_dest_override || ['http', 'tls'],
      metadataOnly: !!item.sniffing_metadata_only
    };
    if (item.sniffing_domains_excluded && item.sniffing_domains_excluded.length > 0) {
      sn.domainsExcluded = item.sniffing_domains_excluded;
    }
    if (isXray) {
      sn.routeOnly = !!item.sniffing_route_only;
      if (item.sniffing_ips_excluded && item.sniffing_ips_excluded.length > 0) {
        sn.ipsExcluded = item.sniffing_ips_excluded;
      }
    }
    obj.sniffing = sn;
  }

  if (item.allocate_strategy) {
    obj.allocate = {
      strategy: item.allocate_strategy,
      refresh: item.allocate_refresh || 5,
      concurrency: item.allocate_concurrency || 3
    };
  }

  if (
    proto !== 'tun' &&
    proto !== 'wireguard' &&
    (item.transport || item.security !== 'none' || (item.sockopt_tproxy && item.sockopt_tproxy !== 'off'))
  ) {
    obj.streamSettings = buildStreamSettings(item, core, proto, true, null, diagnostics, `inbounds.${item.tag}`, xrayFeatures);
  }

  const custom = parseJsonObjectChecked(item.custom_config, diagnostics, `inbounds.${item.tag}.custom_config`);
  return custom ? deepMerge(obj, custom) : obj;
}

function compileOutbound(
  item: OutboundConfig,
  core: CoreType,
  defaultMark: number | null,
  diagnostics: CompileDiagnostic[],
  xrayFeatures?: ResolvedXrayFeatures,
  v2rayFeatures?: ResolvedV2RayFeatures
): Record<string, unknown> | null {
  const isXray = core === 'xray';
  const useFlatOutbounds = !xrayFeatures || xrayFeatures.flatOutbounds;
  if (!isXray && (item.protocol === 'wireguard' || item.protocol === 'masque')) {
    diagnostics.push({
      level: 'error',
      path: `outbounds.${item.tag}`,
      message: `V2Ray 不支持出站协议 "${item.protocol}"。`
    });
    return null;
  }
  if (!isXray && item.protocol === 'shadowsocks2022') {
    diagnostics.push({
      level: 'error',
      path: `outbounds.${item.tag}`,
      message: 'V2Ray jsonv4 不支持 shadowsocks2022，请将 V2Ray 格式切换为 jsonv5 或改用 Xray-core。'
    });
    return null;
  }
  if (!isXray && v2rayFeatures && (item.protocol === 'hysteria' || item.protocol === 'hysteria2') && !v2rayFeatures.hasHysteria2) {
    diagnostics.push({
      level: 'error',
      path: `outbounds.${item.tag}`,
      message: `V2Ray ${v2rayFeatures.version} 不支持 hysteria2 出站协议（需 >= ${CORE_FEATURES_SPEC.v2ray.features.hysteria2.since}）。`
    });
    return null;
  }
  if (isXray && xrayFeatures) {
    const xfSpec = CORE_FEATURES_SPEC.xray.features;
    if (item.protocol === 'masque' && !xrayFeatures.hasMasque) {
      diagnostics.push({
        level: 'error',
        path: `outbounds.${item.tag}`,
        message: `Xray ${xrayFeatures.version} 不支持 masque 出站协议（需 >= ${xfSpec.masque.since}）。`
      });
      return null;
    }
    if ((item.protocol === 'hysteria' || item.protocol === 'hysteria2') && !xrayFeatures.hasHysteria) {
      diagnostics.push({
        level: 'error',
        path: `outbounds.${item.tag}`,
        message: `Xray ${xrayFeatures.version} 不支持 hysteria 出站协议（需 >= ${xfSpec.hysteria.since}）。`
      });
      return null;
    }
  }

  let proto = item.protocol || 'freedom';
  if (isXray && proto === 'hysteria2') proto = 'hysteria';
  if (!isXray && proto === 'hysteria') proto = 'hysteria2';

  const obj: Record<string, unknown> = {
    tag: item.tag || item.id,
    protocol: proto,
    settings: {}
  };
  if (item.send_through) obj.sendThrough = item.send_through;
  if (isXray && item.target_strategy) obj.targetStrategy = item.target_strategy;

  if (proto === 'freedom') {
    const s: Record<string, unknown> = {};
    if (!isXray && item.domain_strategy) s.domainStrategy = item.domain_strategy;
    if (item.freedom_redirect) s.redirect = item.freedom_redirect;
    if (isXray && item.user_level !== undefined) s.userLevel = item.user_level;
    if (isXray && item.freedom_proxy_protocol) s.proxyProtocol = item.freedom_proxy_protocol;
    if (isXray && item.freedom_final_rules_json) {
      const fr = parseJsonArrayChecked(item.freedom_final_rules_json, diagnostics, `outbounds.${item.tag}.freedom_final_rules_json`);
      if (fr) s.finalRules = fr;
    }
    obj.settings = s;
  } else if (proto === 'blackhole') {
    obj.settings = { response: { type: item.blackhole_response || 'none' } };
  } else if (proto === 'dns') {
    const s: Record<string, unknown> = {};
    if (isXray) {
      if (item.dns_network) s.rewriteNetwork = item.dns_network;
      if (item.dns_address) s.rewriteAddress = item.dns_address;
      if (item.dns_port) s.rewritePort = item.dns_port;
      if (item.dns_non_ip_query) s.nonIPQuery = item.dns_non_ip_query;
      const rules = parseJsonArrayChecked(item.dns_rules_json, diagnostics, `outbounds.${item.tag}.dns_rules_json`);
      if (rules) s.rules = rules;
    } else {
      if (item.dns_network) s.network = item.dns_network;
      if (item.dns_address) s.address = item.dns_address;
      if (item.dns_port) s.port = item.dns_port;
    }
    obj.settings = s;
  } else if (proto === 'loopback') {
    const s: Record<string, unknown> = { inboundTag: item.loopback_inbound_tag || '' };
    if (isXray && item.loopback_sniffing_enabled) {
      const sn: Record<string, unknown> = {
        enabled: true,
        destOverride: item.loopback_sniffing_dest_override || ['http', 'tls'],
        metadataOnly: !!item.loopback_sniffing_metadata_only,
        routeOnly: !!item.loopback_sniffing_route_only
      };
      if (item.loopback_sniffing_domains_excluded && item.loopback_sniffing_domains_excluded.length > 0) {
        sn.domainsExcluded = item.loopback_sniffing_domains_excluded;
      }
      if (item.loopback_sniffing_ips_excluded && item.loopback_sniffing_ips_excluded.length > 0) {
        sn.ipsExcluded = item.loopback_sniffing_ips_excluded;
      }
      s.sniffing = sn;
    }
    obj.settings = s;
  } else if (proto === 'vless') {
    if (!isXray && item.flow) {
      diagnostics.push({
        level: 'warning',
        path: `outbounds.${item.tag}.flow`,
        message: 'V2Ray 不支持 VLESS flow (xtls-rprx-vision)，已自动忽略。'
      });
    }
    if (isXray && useFlatOutbounds) {
      const s: Record<string, unknown> = {
        address: item.address || '',
        port: item.port || 443,
        id: item.uuid || '',
        encryption: item.encryption || 'none'
      };
      if (item.flow) s.flow = item.flow;
      if (item.user_level !== undefined) s.level = item.user_level;
      if (item.vless_reverse_tag) s.reverse = { tag: item.vless_reverse_tag };
      obj.settings = s;
    } else if (isXray) {
      const u: Record<string, unknown> = { id: item.uuid || '', encryption: item.encryption || 'none' };
      if (item.flow) u.flow = item.flow;
      if (item.user_level !== undefined) u.level = item.user_level;
      obj.settings = { vnext: [{ address: item.address || '', port: item.port || 443, users: [u] }] };
    } else {
      obj.settings = {
        vnext: [
          {
            address: item.address || '',
            port: item.port || 443,
            users: [{ id: item.uuid || '', encryption: 'none' }]
          }
        ]
      };
    }
  } else if (proto === 'vmess') {
    if (isXray && useFlatOutbounds) {
      const s: Record<string, unknown> = {
        address: item.address || '',
        port: item.port || 443,
        id: item.uuid || '',
        security: item.security_cipher || 'auto'
      };
      if (item.user_level !== undefined) s.level = item.user_level;
      if (item.vmess_experiments) s.experiments = item.vmess_experiments;
      obj.settings = s;
    } else if (isXray) {
      const u: Record<string, unknown> = { id: item.uuid || '', security: item.security_cipher || 'auto' };
      if (item.user_level !== undefined) u.level = item.user_level;
      if (item.vmess_experiments) u.experiments = item.vmess_experiments;
      obj.settings = { vnext: [{ address: item.address || '', port: item.port || 443, users: [u] }] };
    } else {
      obj.settings = {
        vnext: [
          {
            address: item.address || '',
            port: item.port || 443,
            users: [
              {
                id: item.uuid || '',
                alterId: item.alter_id || 0,
                security: item.security_cipher || 'auto'
              }
            ]
          }
        ]
      };
    }
  } else if (proto === 'trojan') {
    if (isXray && useFlatOutbounds) {
      const s: Record<string, unknown> = {
        address: item.address || '',
        port: item.port || 443,
        password: item.password || ''
      };
      if (item.email) s.email = item.email;
      if (item.user_level !== undefined) s.level = item.user_level;
      obj.settings = s;
    } else {
      const srv: Record<string, unknown> = {
        address: item.address || '',
        port: item.port || 443,
        password: item.password || ''
      };
      if (isXray && item.email) srv.email = item.email;
      if (isXray && item.user_level !== undefined) srv.level = item.user_level;
      obj.settings = { servers: [srv] };
    }
  } else if (proto === 'shadowsocks') {
    if (isXray && useFlatOutbounds) {
      const s: Record<string, unknown> = {
        address: item.address || '',
        port: item.port || 8388,
        method: item.method || 'aes-256-gcm',
        password: item.password || ''
      };
      if (item.email) s.email = item.email;
      if (item.user_level !== undefined) s.level = item.user_level;
      if (item.ss_uot) s.uot = true;
      if (item.ss_uot_version) s.UoTVersion = item.ss_uot_version;
      obj.settings = s;
    } else {
      const srv: Record<string, unknown> = {
        address: item.address || '',
        port: item.port || 8388,
        method: item.method || 'aes-256-gcm',
        password: item.password || ''
      };
      if (!isXray && item.ss_iv_check) srv.ivCheck = true;
      if (isXray && item.ss_uot) srv.uot = true;
      if (isXray && item.ss_uot_version) srv.UoTVersion = item.ss_uot_version;
      obj.settings = { servers: [srv] };
    }
  } else if (proto === 'hysteria') {
    obj.settings = { version: 2, address: item.address || '', port: item.port || 443 };
  } else if (proto === 'hysteria2') {
    obj.settings = { servers: [{ address: item.address || '', port: item.port || 443 }] };
  } else if (proto === 'socks') {
    if (isXray && useFlatOutbounds) {
      const s: Record<string, unknown> = {
        address: item.address || '',
        port: item.port || 1080
      };
      if (item.username) {
        s.user = item.username;
        s.pass = item.password || '';
        if (item.email) s.email = item.email;
        if (item.user_level !== undefined) s.level = item.user_level;
      }
      obj.settings = s;
    } else {
      const srv: Record<string, unknown> = { address: item.address || '', port: item.port || 1080 };
      if (item.username) srv.users = [{ user: item.username, pass: item.password || '' }];
      const s: Record<string, unknown> = { servers: [srv] };
      if (!isXray && item.socks_version) s.version = item.socks_version;
      obj.settings = s;
    }
  } else if (proto === 'http') {
    if (isXray && useFlatOutbounds) {
      const s: Record<string, unknown> = {
        address: item.address || '',
        port: item.port || 8080
      };
      if (item.username) {
        s.user = item.username;
        s.pass = item.password || '';
        if (item.email) s.email = item.email;
        if (item.user_level !== undefined) s.level = item.user_level;
      }
      const headers = kvToMap(item.http_headers);
      if (headers) s.headers = headers;
      obj.settings = s;
    } else {
      const srv: Record<string, unknown> = { address: item.address || '', port: item.port || 8080 };
      if (item.username) srv.users = [{ user: item.username, pass: item.password || '' }];
      obj.settings = { servers: [srv] };
    }
  } else if (proto === 'wireguard' && isXray) {
    const peers =
      item.wg_peers && item.wg_peers.length > 0
        ? item.wg_peers
        : [{ publicKey: item.wg_peer_public_key || '', endpoint: item.wg_endpoint || '' }];
    const wg: Record<string, unknown> = {
      secretKey: item.wg_secret_key || '',
      address: item.wg_address || [],
      peers,
      mtu: item.wg_mtu || 1420,
      noKernelTun: item.wg_no_kernel_tun === true
    };
    if (item.wg_reserved && item.wg_reserved.length > 0) {
      wg.reserved = item.wg_reserved.map((n) => Number(n)).filter((n) => Number.isFinite(n));
    }
    if (item.wg_remote_dns && item.wg_remote_dns.length > 0) {
      wg.remoteDNS = item.wg_remote_dns;
    }
    obj.settings = wg;
  } else if (proto === 'masque' && isXray) {
    const mq: Record<string, unknown> = {
      address: item.address || '',
      port: item.port || 443
    };
    if (item.masque_remote_dns && item.masque_remote_dns.length > 0) {
      mq.remoteDNS = item.masque_remote_dns;
    }
    obj.settings = mq;
  }

  if (!isXray && item.dialer_proxy) {
    obj.proxySettings = { tag: item.dialer_proxy, transportLayer: true };
  }

  const mark = proto === 'dns' ? null : defaultMark;
  if (proto !== 'wireguard') {
    obj.streamSettings = buildStreamSettings(item, core, proto, false, mark, diagnostics, `outbounds.${item.tag}`, xrayFeatures);
  } else {
    const wgSock: Record<string, unknown> = {};
    const m = item.sockopt_mark ?? mark;
    if (m !== null && m > 0) wgSock.mark = m;
    if (item.sockopt_interface) wgSock.interface = item.sockopt_interface;
    if (item.domain_strategy) wgSock.domainStrategy = item.domain_strategy;
    if (item.dialer_proxy) wgSock.dialerProxy = item.dialer_proxy;
    if (Object.keys(wgSock).length > 0) obj.streamSettings = { sockopt: wgSock };
  }

  if (item.mux_enabled) {
    if (isXray && proto === 'masque') {
      diagnostics.push({
        level: 'warning',
        path: `outbounds.${item.tag}.mux`,
        message: 'Xray MASQUE 出站不支持 Mux。'
      });
    }
    const concurrency = item.mux_concurrency ?? 8;
    if (isXray && concurrency > 128) {
      diagnostics.push({
        level: 'warning',
        path: `outbounds.${item.tag}.mux.concurrency`,
        message: `Xray mux.concurrency 最大值为 128（当前 ${concurrency}，超过 128 核心按 128 处理）。`
      });
    }
    const mux: Record<string, unknown> = {
      enabled: true,
      concurrency: isXray && concurrency > 128 ? 128 : concurrency
    };
    if (isXray) {
      if (item.mux_xudp_concurrency) mux.xudpConcurrency = item.mux_xudp_concurrency;
      if (item.mux_xudp_proxy_udp443) mux.xudpProxyUDP443 = item.mux_xudp_proxy_udp443;
    }
    obj.mux = mux;
  }

  const custom = parseJsonObjectChecked(item.custom_config, diagnostics, `outbounds.${item.tag}.custom_config`);
  return custom ? deepMerge(obj, custom) : obj;
}

export interface CompileOptions {
  core?: CoreType;
  version?: string | null;
}

export function compileConfig(
  cfg: AiosConfig,
  detectedCoreOrOpts?: CoreType | CompileOptions
): CompileResult {
  const opts: CompileOptions =
    typeof detectedCoreOrOpts === 'string'
      ? { core: detectedCoreOrOpts }
      : detectedCoreOrOpts || {};
  const core = resolveEffectiveCore(cfg.general.core_type, opts.core, cfg.general.core_bin);
  const requestedVersion =
    opts.version ||
    (cfg.general.target_version && cfg.general.target_version !== 'auto'
      ? cfg.general.target_version
      : undefined);
  const features = resolveCoreFeatures(core, cfg.general.v2ray_format, requestedVersion);

  if (core === 'v2ray' && cfg.general.v2ray_format === 'jsonv5') {
    const v5Res = compileV2RayV5(cfg, features.core === 'v2ray' ? features : undefined);
    return { ...v5Res, version: features.version, features };
  }
  const isXray = core === 'xray';
  const xrayFeatures = features.core === 'xray' ? features : undefined;
  const v2rayFeatures = features.core === 'v2ray' ? features : undefined;
  const diagnostics: CompileDiagnostic[] = [];
  const outMark = cfg.transparent_proxy.enabled
    ? parseHexOrInt(cfg.transparent_proxy.outbound_mark)
    : null;

  const log: Record<string, unknown> = {
    loglevel: cfg.general.log_level || 'warning',
    access: cfg.general.access_log || 'none',
    error: cfg.general.error_log || ''
  };
  if (isXray) {
    log.dnsLog = !!cfg.general.dns_log;
    if (cfg.general.mask_address) log.maskAddress = cfg.general.mask_address;
  }

  const doc: Record<string, unknown> = {
    log,
    inbounds: [] as Record<string, unknown>[],
    outbounds: [] as Record<string, unknown>[]
  };

  // Xray top-level extensions: env, geodata, version
  if (isXray) {
    const envMap = kvToMap(cfg.general.inline_env);
    if (envMap) doc.env = envMap;
    if (cfg.general.geodata_reload_interval) {
      doc.geodata = { reloadInterval: cfg.general.geodata_reload_interval };
    }
    if (cfg.general.min_version || cfg.general.max_version) {
      const ver: Record<string, string> = {};
      if (cfg.general.min_version) ver.min = cfg.general.min_version;
      if (cfg.general.max_version) ver.max = cfg.general.max_version;
      doc.version = ver;
    }
  }

  if (cfg.general.stats_enabled) doc.stats = {};

  let v2rayApiRule: Record<string, unknown> | null = null;
  if (cfg.general.api_enabled) {
    const apiPort = cfg.general.api_port || 18080;
    if (isXray) {
      doc.api = {
        tag: 'api',
        listen: `127.0.0.1:${apiPort}`,
        services: ['HandlerService', 'LoggerService', 'StatsService', 'RoutingService']
      };
    } else {
      const v2ApiServices = ['HandlerService', 'LoggerService'];
      if (cfg.general.stats_enabled) v2ApiServices.push('StatsService');
      if (cfg.observatory.enabled) v2ApiServices.push('ObservatoryService');
      doc.api = {
        tag: 'api',
        services: v2ApiServices
      };
      (doc.inbounds as Record<string, unknown>[]).push({
        tag: 'api-in',
        listen: '127.0.0.1',
        port: apiPort,
        protocol: 'dokodemo-door',
        settings: { address: '127.0.0.1' }
      });
      v2rayApiRule = { type: 'field', inboundTag: ['api-in'], outboundTag: 'api' };
    }
  }

  if (cfg.general.metrics_enabled && isXray) {
    doc.metrics = { tag: 'metrics', listen: `127.0.0.1:${cfg.general.metrics_port || 18888}` };
  }

  for (const ib of cfg.inbounds) {
    if (!ib.enabled) continue;
    const compiled = compileInbound(ib, core, diagnostics, xrayFeatures, v2rayFeatures);
    if (compiled) (doc.inbounds as Record<string, unknown>[]).push(compiled);
  }

  for (const ob of cfg.outbounds) {
    if (!ob.enabled) continue;
    const compiled = compileOutbound(ob, core, outMark, diagnostics, xrayFeatures, v2rayFeatures);
    if (compiled) (doc.outbounds as Record<string, unknown>[]).push(compiled);
  }

  // DNS
  if (cfg.dns.enabled) {
    const servers = cfg.dns_servers
      .filter((s) => s.enabled)
      .map((s) => {
        const srv: Record<string, unknown> = { address: s.address };
        if (isXray && s.server_id) srv.id = s.server_id;
        if (s.port) srv.port = s.port;
        if (s.skip_fallback) srv.skipFallback = true;
        if (s.domains && s.domains.length > 0) srv.domains = s.domains;
        if (s.expect_ips && s.expect_ips.length > 0) {
          srv[isXray ? 'expectedIPs' : 'expectIPs'] = s.expect_ips;
        }
        if (isXray && s.unexpected_ips && s.unexpected_ips.length > 0) {
          srv.unexpectedIPs = s.unexpected_ips;
        }
        if (s.client_ip) srv[isXray ? 'clientIP' : 'clientIp'] = s.client_ip;
        if (isXray) {
          if (s.query_strategy) srv.queryStrategy = s.query_strategy;
          if (s.disable_cache) srv.disableCache = true;
          if (s.serve_stale) srv.serveStale = true;
          if (s.serve_expired_ttl) srv.serveExpiredTTL = s.serve_expired_ttl;
          if (s.timeout_ms) srv.timeoutMs = s.timeout_ms;
          if (s.final_query) srv.finalQuery = true;
          if (s.tag) srv.tag = s.tag;
        }
        return srv;
      });

    const dnsObj: Record<string, unknown> = {
      tag: cfg.dns.tag || 'dns-in',
      queryStrategy:
        !isXray && cfg.dns.query_strategy === 'UseSystem' ? 'UseIP' : cfg.dns.query_strategy,
      disableCache: cfg.dns.disable_cache,
      disableFallback: cfg.dns.disable_fallback,
      disableFallbackIfMatch: cfg.dns.disable_fallback_if_match,
      servers
    };
    if (isXray) {
      if (cfg.dns.script) dnsObj.script = cfg.dns.script;
      dnsObj.serveStale = cfg.dns.serve_stale;
      if (cfg.dns.serve_expired_ttl) dnsObj.serveExpiredTTL = cfg.dns.serve_expired_ttl;
      dnsObj.enableParallelQuery = cfg.dns.enable_parallel_query;
      if (cfg.dns.use_system_hosts) dnsObj.useSystemHosts = true;
    }
    if (cfg.dns.client_ip) dnsObj.clientIp = cfg.dns.client_ip;

    const hostsMap: Record<string, string[] | string> = { ...(cfg.dns.hosts || {}) };
    for (const h of cfg.dns.host_entries || []) {
      if (h.domain.trim() && h.addresses.length > 0) {
        hostsMap[h.domain.trim()] = h.addresses.length === 1 ? h.addresses[0] : h.addresses;
      }
    }
    if (Object.keys(hostsMap).length > 0) dnsObj.hosts = hostsMap;
    doc.dns = dnsObj;
  }

  // FakeDNS (always array for dual-core safety)
  if (cfg.fakedns.length > 0) {
    doc.fakedns = cfg.fakedns.map((f) => ({ ipPool: f.ip_pool, poolSize: f.pool_size }));
  }

  // Routing
  if (cfg.routing.enabled || v2rayApiRule) {
    const rules: Record<string, unknown>[] = [];
    if (v2rayApiRule) rules.push(v2rayApiRule);
    for (const rr of cfg.routing_rules) {
      if (!rr.enabled) continue;
      const rule: Record<string, unknown> = { type: 'field' };
      if (rr.domain && rr.domain.length > 0) {
        rule[isXray ? 'domain' : 'domains'] = rr.domain;
      }
      if (rr.ip && rr.ip.length > 0) rule.ip = rr.ip;
      if (rr.port) rule.port = rr.port;
      if (rr.source_port) rule.sourcePort = rr.source_port;
      if (isXray && rr.local_port) rule.localPort = rr.local_port;
      if (rr.network) rule.network = rr.network;
      if (rr.source && rr.source.length > 0) rule.source = rr.source;
      if (isXray && rr.local_ip && rr.local_ip.length > 0) rule.localIP = rr.local_ip;
      if (rr.user && rr.user.length > 0) rule.user = rr.user;
      if (rr.inbound_tag && rr.inbound_tag.length > 0) rule.inboundTag = rr.inbound_tag;
      if (isXray && rr.process && rr.process.length > 0) rule.process = rr.process;
      if (rr.protocol && rr.protocol.length > 0) {
        const protos = isXray ? rr.protocol : rr.protocol.filter((p) => p !== 'quic');
        if (protos.length > 0) rule.protocol = protos;
      }
      if (isXray && rr.vless_route) rule.vlessRoute = rr.vless_route;
      if (isXray && rr.rule_tag) rule.ruleTag = rr.rule_tag;
      if (isXray && rr.webhook_url) {
        const wh: Record<string, unknown> = { url: rr.webhook_url };
        if (rr.webhook_deduplication) wh.deduplication = rr.webhook_deduplication;
        const whHeaders = kvToMap(rr.webhook_headers);
        if (whHeaders) wh.headers = whHeaders;
        rule.webhook = wh;
      }
      if (rr.attrs && rr.attrs.trim()) {
        if (isXray) {
          const parsedAttrs = parseJsonObjectChecked(rr.attrs, diagnostics, `routing_rules.${rr.id}.attrs`);
          if (parsedAttrs) rule.attrs = parsedAttrs;
        } else {
          rule.attrs = rr.attrs;
        }
      }
      if (rr.balancer_tag) rule.balancerTag = rr.balancer_tag;
      else if (rr.outbound_tag) rule.outboundTag = rr.outbound_tag;
      rules.push(rule);
    }

    const balancers = cfg.balancers.map((b) => {
      let strat = b.strategy;
      if (!isXray) {
        if (strat === 'roundRobin') {
          strat = 'random';
          diagnostics.push({
            level: 'warning',
            path: `balancers.${b.tag}`,
            message: 'V2Ray 不支持 roundRobin，已自动降级为 random。'
          });
        } else if (strat === 'leastLoad') {
          strat = 'leastPing';
          diagnostics.push({
            level: 'warning',
            path: `balancers.${b.tag}`,
            message: 'V2Ray jsonv4 不支持 leastLoad，已自动降级为 leastPing。'
          });
        }
      }
      const strategyObj: Record<string, unknown> = { type: strat };
      if (isXray && strat === 'leastLoad') {
        const stSettings: Record<string, unknown> = {};
        if (b.strategy_expected !== undefined) stSettings.expected = b.strategy_expected;
        if (b.strategy_max_rtt) stSettings.maxRTT = b.strategy_max_rtt;
        if (b.strategy_tolerance !== undefined) stSettings.tolerance = b.strategy_tolerance;
        if (b.strategy_baselines && b.strategy_baselines.length > 0) stSettings.baselines = b.strategy_baselines;
        const costs = parseJsonArrayChecked(b.strategy_costs_json, diagnostics, `balancers.${b.tag}.strategy_costs_json`);
        if (costs) stSettings.costs = costs;
        if (Object.keys(stSettings).length > 0) strategyObj.settings = stSettings;
      }
      const out: Record<string, unknown> = {
        tag: b.tag,
        selector: b.selector,
        strategy: strategyObj
      };
      if (isXray && b.fallback_tag) out.fallbackTag = b.fallback_tag;
      return out;
    });

    const routingObj: Record<string, unknown> = {
      domainStrategy: cfg.routing.domain_strategy,
      domainMatcher: !isXray && cfg.routing.domain_matcher === 'hybrid' ? 'linear' : cfg.routing.domain_matcher,
      rules,
      balancers
    };
    if (isXray && cfg.routing.script) routingObj.script = cfg.routing.script;
    doc.routing = routingObj;
  }

  // Observatory
  if (cfg.observatory.enabled) {
    const obs: Record<string, unknown> = {
      subjectSelector: cfg.observatory.subject_selector,
      probeInterval: cfg.observatory.probe_interval || '1m'
    };
    if (isXray) {
      obs.probeUrl = cfg.observatory.probe_url;
      obs.enableConcurrency = cfg.observatory.enable_concurrency;
    } else {
      obs.probeURL = cfg.observatory.probe_url;
    }
    doc.observatory = obs;
  }

  // BurstObservatory (Xray top-level)
  if (isXray && cfg.burst_observatory?.enabled) {
    doc.burstObservatory = {
      subjectSelector: cfg.burst_observatory.subject_selector,
      pingConfig: {
        destination: cfg.burst_observatory.destination || 'https://www.google.com/generate_204',
        connectivity: cfg.burst_observatory.connectivity || undefined,
        interval: cfg.burst_observatory.interval || '1m',
        sampling: cfg.burst_observatory.sampling || 3,
        timeout: cfg.burst_observatory.timeout || '5s'
      }
    };
  }

  // V2Ray jsonv4 services: burstObservatory, tun
  if (!isXray) {
    const vfSpec = CORE_FEATURES_SPEC.v2ray.features;
    const v4Services: Record<string, unknown> = {};
    if (cfg.burst_observatory?.enabled) {
      if (v2rayFeatures && !v2rayFeatures.hasV4Services) {
        diagnostics.push({
          level: 'error',
          path: 'burst_observatory',
          message: `V2Ray ${v2rayFeatures.version} jsonv4 不支持 services.burstObservatory（需 >= ${vfSpec.v4Services.since}）。`
        });
      } else {
        v4Services.burstObservatory = {
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
    }
    const tunInbound = cfg.inbounds.find((i) => i.enabled && i.protocol === 'tun');
    if (tunInbound) {
      if (v2rayFeatures && !v2rayFeatures.hasV4Services) {
        diagnostics.push({
          level: 'error',
          path: `inbounds.${tunInbound.tag}`,
          message: `V2Ray ${v2rayFeatures.version} jsonv4 不支持 services.tun（需 >= ${vfSpec.v4Services.since}）。`
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
        v4Services.tun = tunSvc;
      }
    }
    if (Object.keys(v4Services).length > 0) doc.services = v4Services;
  }

  // BrowserForwarder (V2Ray jsonv4 top-level)
  if (!isXray && cfg.browser_forwarder?.enabled) {
    doc.browserForwarder = {
      listenAddr: cfg.browser_forwarder.listen_addr || '127.0.0.1',
      listenPort: cfg.browser_forwarder.listen_port || 8088
    };
  }

  // Policy (multi-level)
  if (cfg.policy.enabled) {
    const levelsMap: Record<string, Record<string, unknown>> = {};
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
      levelsMap[lv.level || '0'] = {
        handshake: lv.handshake,
        connIdle: lv.conn_idle,
        uplinkOnly: lv.uplink_only,
        downlinkOnly: lv.downlink_only,
        bufferSize: lv.buffer_size,
        statsUserUplink: lv.stats_user_uplink,
        statsUserDownlink: lv.stats_user_downlink
      };
    }
    doc.policy = {
      levels: levelsMap,
      system: {
        statsInboundUplink: cfg.policy.stats_inbound_uplink,
        statsInboundDownlink: cfg.policy.stats_inbound_downlink,
        statsOutboundUplink: cfg.policy.stats_outbound_uplink,
        statsOutboundDownlink: cfg.policy.stats_outbound_downlink
      }
    };
  }

  // Reverse (Xray removed legacy top-level reverse in v26.4.25 in favor of VLESS Reverse Proxy)
  if (cfg.reverse.enabled) {
    if (isXray && !xrayFeatures?.hasLegacyReverse) {
      diagnostics.push({
        level: 'warning',
        path: 'reverse',
        message: `Xray ${features.version} 已移除顶层 legacy reverse，请改用 VLESS 入出站 reverse 配置，已跳过生成顶层 reverse。`
      });
    } else {
      const mapPair = (arr: string[]) =>
        arr
          .map((s) => s.split('|'))
          .filter((p) => p.length === 2 && p[0].trim() && p[1].trim())
          .map(([tag, domain]) => ({ tag: tag.trim(), domain: domain.trim() }));
      doc.reverse = {
        bridges: mapPair(cfg.reverse.bridges),
        portals: mapPair(cfg.reverse.portals)
      };
    }
  }

  return { core, version: features.version, features, json: doc, diagnostics };
}
