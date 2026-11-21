import type {
  AiosConfig,
  CoreType,
  InboundConfig,
  KeyValuePair,
  OutboundConfig,
  StreamFields
} from '@/schema/types';
import { resolveEffectiveCore } from '@/schema/capabilities';
import { compileV2RayV5 } from './v2ray_v5';

export interface CompileDiagnostic {
  level: 'warning' | 'error';
  path: string;
  message: string;
}

export interface CompileResult {
  core: CoreType;
  json: Record<string, unknown>;
  diagnostics: CompileDiagnostic[];
}

function parseJsonSafe(str?: string): Record<string, unknown> | null {
  if (!str || !str.trim()) return null;
  try {
    const parsed = JSON.parse(str);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
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
  isInbound: boolean,
  defaultMark: number | null,
  diagnostics: CompileDiagnostic[],
  pathPrefix: string
): Record<string, unknown> {
  const isXray = core === 'xray';
  let net = item.transport || (isXray ? 'raw' : 'tcp');

  if (isXray) {
    if (net === 'tcp') net = 'raw';
    if (net === 'ws') net = 'websocket';
    if (net === 'hysteria2') net = 'hysteria';
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
        message: `V2Ray jsonv4 不支持传输层 "${net}"，已降级为 tcp。`
      });
      net = 'tcp';
    }
  }

  const ss: Record<string, unknown> = { network: net };

  let security = item.security || 'none';
  if (!isXray && security === 'reality') {
    diagnostics.push({
      level: 'error',
      path: `${pathPrefix}.security`,
      message: 'V2Ray 不支持 REALITY，已自动降级为 tls。'
    });
    security = 'tls';
  }
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
      if (item.tls_verify_peer_name) tls.verifyPeerCertByName = item.tls_verify_peer_name;
      if (item.tls_curve_preferences && item.tls_curve_preferences.length > 0) {
        tls.curvePreferences = item.tls_curve_preferences;
      }
    } else {
      if (pinned.length > 0) tls.pinnedPeerCertificateChainSha256 = pinned;
      if (item.tls_verify_client) tls.verifyClientCertificate = true;
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
  } else if ((net === 'xhttp' || net === 'splithttp') && isXray) {
    const xhttp: Record<string, unknown> = {
      path: item.xhttp_path || '/',
      mode: item.xhttp_mode || 'auto'
    };
    if (item.xhttp_host) xhttp.host = item.xhttp_host;
    const extra = parseJsonSafe(item.xhttp_extra);
    if (extra) xhttp.extra = extra;
    ss[net === 'splithttp' ? 'splithttpSettings' : 'xhttpSettings'] = xhttp;
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
    if (!isXray) {
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
    if (item.hysteria_udp_idle_timeout) hy.udpIdleTimeout = item.hysteria_udp_idle_timeout;
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
  }

  // FinalMask (Xray only)
  if (isXray) {
    let fm = parseJsonSafe(item.finalmask_json);
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
    if (item.sockopt_tcp_congestion) sockopt.tcpcongestion = item.sockopt_tcp_congestion;
    if (item.domain_strategy) sockopt.domainStrategy = item.domain_strategy;
    if (item.dialer_proxy) sockopt.dialerProxy = item.dialer_proxy;
  }
  if (Object.keys(sockopt).length > 0) ss.sockopt = sockopt;

  return ss;
}

function compileInbound(
  item: InboundConfig,
  core: CoreType,
  diagnostics: CompileDiagnostic[]
): Record<string, unknown> | null {
  const isXray = core === 'xray';
  if (!isXray && (item.protocol === 'tun' || item.protocol === 'wireguard' || item.protocol === 'masque')) {
    diagnostics.push({
      level: 'warning',
      path: `inbounds.${item.tag}`,
      message: `V2Ray jsonv4 不支持入站协议 "${item.protocol}"，已跳过该入站。`
    });
    return null;
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
    if (item.socks_auth === 'password') {
      if (userList) {
        s.accounts = userList.map((u) => ({ user: u.username || '', pass: u.password || '' }));
      } else if (item.username) {
        s.accounts = [{ user: item.username, pass: item.password || '' }];
      }
    }
    obj.settings = s;
  } else if (proto === 'http') {
    if (userList) {
      obj.settings = {
        accounts: userList.map((u) => ({ user: u.username || '', pass: u.password || '' }))
      };
    } else if (item.username) {
      obj.settings = { accounts: [{ user: item.username, pass: item.password || '' }] };
    }
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
    obj.settings = s;
  } else if (proto === 'vless') {
    const clients = userList
      ? userList.map((u) =>
          isXray
            ? { id: u.id || '', flow: u.flow || '', email: u.email || undefined, level: u.level ?? 0 }
            : { id: u.id || '', email: u.email || undefined, level: u.level ?? 0 }
        )
      : [isXray ? { id: item.uuid || '', flow: item.flow || '' } : { id: item.uuid || '' }];
    const s: Record<string, unknown> = {
      clients,
      decryption: isXray ? item.decryption || 'none' : 'none'
    };
    if (item.fallbacks && item.fallbacks.length > 0) s.fallbacks = item.fallbacks;
    obj.settings = s;
  } else if (proto === 'vmess') {
    const clients = userList
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
    obj.settings = { clients };
  } else if (proto === 'trojan') {
    const clients = userList
      ? userList.map((u) => ({ password: u.password || '', email: u.email || undefined, level: u.level ?? 0 }))
      : [{ password: item.password || '' }];
    const s: Record<string, unknown> = { clients };
    if (item.fallbacks && item.fallbacks.length > 0) s.fallbacks = item.fallbacks;
    obj.settings = s;
  } else if (proto === 'shadowsocks') {
    obj.settings = {
      method: item.method || 'aes-256-gcm',
      password: item.password || '',
      network: item.ss_network || 'tcp,udp'
    };
  } else if (proto === 'tun' && isXray) {
    delete obj.listen;
    delete obj.port;
    obj.settings = {
      name: item.tun_name || 'xray0',
      MTU: item.tun_mtu || 1500
    };
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

  if (item.transport || item.security !== 'none' || (item.sockopt_tproxy && item.sockopt_tproxy !== 'off')) {
    obj.streamSettings = buildStreamSettings(item, core, true, null, diagnostics, `inbounds.${item.tag}`);
  }

  const custom = parseJsonSafe(item.custom_config);
  return custom ? deepMerge(obj, custom) : obj;
}

function compileOutbound(
  item: OutboundConfig,
  core: CoreType,
  defaultMark: number | null,
  diagnostics: CompileDiagnostic[]
): Record<string, unknown> | null {
  const isXray = core === 'xray';
  if (!isXray && (item.protocol === 'wireguard' || item.protocol === 'masque')) {
    diagnostics.push({
      level: 'warning',
      path: `outbounds.${item.tag}`,
      message: `V2Ray 不支持出站协议 "${item.protocol}"，已跳过。`
    });
    return null;
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

  if (proto === 'freedom') {
    const s: Record<string, unknown> = {};
    if (!isXray && item.domain_strategy) s.domainStrategy = item.domain_strategy;
    if (item.freedom_redirect) s.redirect = item.freedom_redirect;
    obj.settings = s;
  } else if (proto === 'blackhole') {
    obj.settings = { response: { type: item.blackhole_response || 'none' } };
  } else if (proto === 'dns') {
    const s: Record<string, unknown> = {};
    if (item.dns_network) s.network = item.dns_network;
    if (item.dns_address) s.address = item.dns_address;
    if (item.dns_port) s.port = item.dns_port;
    if (isXray && item.dns_non_ip_query) s.nonIPQuery = item.dns_non_ip_query;
    obj.settings = s;
  } else if (proto === 'loopback') {
    obj.settings = { inboundTag: item.loopback_inbound_tag || '' };
  } else if (proto === 'vless') {
    if (!isXray && item.flow) {
      diagnostics.push({
        level: 'warning',
        path: `outbounds.${item.tag}.flow`,
        message: 'V2Ray 不支持 VLESS flow (xtls-rprx-vision)，已自动忽略。'
      });
    }
    obj.settings = {
      vnext: [
        {
          address: item.address || '',
          port: item.port || 443,
          users: [
            isXray
              ? {
                  id: item.uuid || '',
                  encryption: item.encryption || 'none',
                  flow: item.flow || ''
                }
              : { id: item.uuid || '', encryption: 'none' }
          ]
        }
      ]
    };
  } else if (proto === 'vmess') {
    obj.settings = {
      vnext: [
        {
          address: item.address || '',
          port: item.port || 443,
          users: [
            isXray
              ? { id: item.uuid || '', security: item.security_cipher || 'auto' }
              : {
                  id: item.uuid || '',
                  alterId: item.alter_id || 0,
                  security: item.security_cipher || 'auto'
                }
          ]
        }
      ]
    };
  } else if (proto === 'trojan') {
    obj.settings = {
      servers: [
        { address: item.address || '', port: item.port || 443, password: item.password || '' }
      ]
    };
  } else if (proto === 'shadowsocks') {
    const srv: Record<string, unknown> = {
      address: item.address || '',
      port: item.port || 8388,
      method: item.method || 'aes-256-gcm',
      password: item.password || ''
    };
    if (isXray && item.ss_uot) srv.uot = true;
    if (!isXray && item.ss_iv_check) srv.ivCheck = true;
    obj.settings = { servers: [srv] };
  } else if (proto === 'hysteria') {
    obj.settings = { version: 2, address: item.address || '', port: item.port || 443 };
  } else if (proto === 'hysteria2') {
    obj.settings = { servers: [{ address: item.address || '', port: item.port || 443 }] };
  } else if (proto === 'socks' || proto === 'http') {
    const srv: Record<string, unknown> = { address: item.address || '', port: item.port || 1080 };
    if (item.username) srv.users = [{ user: item.username, pass: item.password || '' }];
    obj.settings = { servers: [srv] };
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
      noKernelTun: item.wg_no_kernel_tun !== false
    };
    if (item.wg_reserved && item.wg_reserved.length > 0) {
      wg.reserved = item.wg_reserved.map((n) => Number(n)).filter((n) => Number.isFinite(n));
    }
    obj.settings = wg;
  }

  if (!isXray && item.dialer_proxy) {
    obj.proxySettings = { tag: item.dialer_proxy, transportLayer: true };
  }

  const mark = proto === 'dns' ? null : defaultMark;
  obj.streamSettings = buildStreamSettings(item, core, false, mark, diagnostics, `outbounds.${item.tag}`);

  if (item.mux_enabled) {
    const mux: Record<string, unknown> = {
      enabled: true,
      concurrency: item.mux_concurrency ?? 8
    };
    if (isXray) {
      if (item.mux_xudp_concurrency) mux.xudpConcurrency = item.mux_xudp_concurrency;
      if (item.mux_xudp_proxy_udp443) mux.xudpProxyUDP443 = item.mux_xudp_proxy_udp443;
    }
    obj.mux = mux;
  }

  const custom = parseJsonSafe(item.custom_config);
  return custom ? deepMerge(obj, custom) : obj;
}

export function compileConfig(cfg: AiosConfig, detectedCore?: CoreType): CompileResult {
  const core = resolveEffectiveCore(cfg.general.core_type, detectedCore, cfg.general.core_bin);
  if (core === 'v2ray' && cfg.general.v2ray_format === 'jsonv5') {
    return compileV2RayV5(cfg);
  }
  const isXray = core === 'xray';
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
      doc.api = {
        tag: 'api',
        services: ['HandlerService', 'LoggerService', 'StatsService', 'ObservatoryService']
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
    const compiled = compileInbound(ib, core, diagnostics);
    if (compiled) (doc.inbounds as Record<string, unknown>[]).push(compiled);
  }

  for (const ob of cfg.outbounds) {
    if (!ob.enabled) continue;
    const compiled = compileOutbound(ob, core, outMark, diagnostics);
    if (compiled) (doc.outbounds as Record<string, unknown>[]).push(compiled);
  }

  // DNS
  if (cfg.dns.enabled) {
    const servers = cfg.dns_servers
      .filter((s) => s.enabled)
      .map((s) => {
        const srv: Record<string, unknown> = { address: s.address };
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
      dnsObj.serveStale = cfg.dns.serve_stale;
      dnsObj.enableParallelQuery = cfg.dns.enable_parallel_query;
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
      if (rr.attrs && rr.attrs.trim()) {
        if (isXray) {
          const parsedAttrs = parseJsonSafe(rr.attrs);
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
            message: 'V2Ray 不支持 leastLoad，已自动降级为 leastPing。'
          });
        }
      }
      const out: Record<string, unknown> = {
        tag: b.tag,
        selector: b.selector,
        strategy: { type: strat }
      };
      if (isXray && b.fallback_tag) out.fallbackTag = b.fallback_tag;
      return out;
    });

    doc.routing = {
      domainStrategy: cfg.routing.domain_strategy,
      domainMatcher: !isXray && cfg.routing.domain_matcher === 'hybrid' ? 'linear' : cfg.routing.domain_matcher,
      rules,
      balancers
    };
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

  // Policy
  if (cfg.policy.enabled) {
    doc.policy = {
      levels: {
        '0': {
          handshake: cfg.policy.handshake,
          connIdle: cfg.policy.conn_idle,
          uplinkOnly: cfg.policy.uplink_only,
          downlinkOnly: cfg.policy.downlink_only,
          bufferSize: cfg.policy.buffer_size
        }
      },
      system: {
        statsInboundUplink: cfg.policy.stats_inbound_uplink,
        statsInboundDownlink: cfg.policy.stats_inbound_downlink,
        statsOutboundUplink: cfg.policy.stats_outbound_uplink,
        statsOutboundDownlink: cfg.policy.stats_outbound_downlink
      }
    };
  }

  // Reverse
  if (cfg.reverse.enabled) {
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

  return { core, json: doc, diagnostics };
}
