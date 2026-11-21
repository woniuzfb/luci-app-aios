import type { AiosConfig, InboundConfig, OutboundConfig, StreamFields } from '@/schema/types';
import type { CompileDiagnostic, CompileResult } from './index';

function buildV5Stream(
  item: StreamFields & { password?: string },
  isInbound: boolean,
  defaultMark: number | null,
  diagnostics: CompileDiagnostic[],
  pathPrefix: string
): Record<string, unknown> {
  let transport = item.transport || 'tcp';
  if (transport === 'raw') transport = 'tcp';
  if (transport === 'websocket') transport = 'ws';
  if (transport === 'h2') transport = 'http';
  if (transport === 'hysteria') transport = 'hysteria2';
  if (transport === 'xhttp' || transport === 'splithttp' || transport === 'masque') {
    diagnostics.push({
      level: 'error',
      path: `${pathPrefix}.transport`,
      message: `V2Ray jsonv5 不支持传输层 "${transport}"，已降级为 tcp。`
    });
    transport = 'tcp';
  }

  let transportSettings: Record<string, unknown> = {};
  if (transport === 'ws') {
    transportSettings = {
      path: item.ws_path || '/',
      maxEarlyData: item.ws_max_early_data || 0,
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
      header: headers.length > 0 ? headers : undefined
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

  let security = item.security || 'none';
  if (security === 'reality') {
    diagnostics.push({
      level: 'error',
      path: `${pathPrefix}.security`,
      message: 'V2Ray jsonv5 不支持 REALITY，已自动降级为 utls。'
    });
    security = 'utls';
  }

  let securitySettings: Record<string, unknown> | undefined;
  if (security === 'tls') {
    const tls: Record<string, unknown> = {};
    if (item.tls_server_name) tls.serverName = item.tls_server_name;
    if (item.tls_allow_insecure) tls.allowInsecure = true;
    if (item.tls_alpn && item.tls_alpn.length > 0) tls.nextProtocol = item.tls_alpn;
    if (item.tls_ech_config) tls.echConfig = item.tls_ech_config;
    if (isInbound && item.tls_certificates && item.tls_certificates.length > 0) {
      tls.certificate = item.tls_certificates;
    }
    securitySettings = tls;
  } else if (security === 'utls') {
    securitySettings = {
      tlsConfig: {
        serverName: item.tls_server_name || '',
        allowInsecure: !!item.tls_allow_insecure,
        nextProtocol: item.tls_alpn && item.tls_alpn.length > 0 ? item.tls_alpn : undefined
      },
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
  diagnostics: CompileDiagnostic[]
): Record<string, unknown> | null {
  if (item.protocol === 'tun' || item.protocol === 'wireguard' || item.protocol === 'masque') {
    diagnostics.push({
      level: 'warning',
      path: `inbounds.${item.tag}`,
      message: `V2Ray jsonv5 入站协议不支持 "${item.protocol}"（TUN 请改用 services.tun），已跳过。`
    });
    return null;
  }
  const proto = item.protocol === 'tunnel' ? 'dokodemo-door' : item.protocol === 'hysteria' ? 'hysteria2' : item.protocol;
  const settings: Record<string, unknown> = {};
  if (proto === 'socks') {
    settings.auth = item.socks_auth || 'noauth';
    settings.udpEnabled = !!item.socks_udp;
  } else if (proto === 'dokodemo-door') {
    settings.networks = (item.dokodemo_network || 'tcp,udp').split(',').map((s) => s.trim().toUpperCase());
    settings.followRedirect = !!item.dokodemo_follow_redirect;
    if (item.dokodemo_address) settings.address = item.dokodemo_address;
    if (item.dokodemo_port) settings.port = item.dokodemo_port;
  } else if (proto === 'vmess' || proto === 'vless') {
    settings.users = (item.users && item.users.length > 0 ? item.users : [{ id: item.uuid || '' }]).map((u) => ({
      uuid: u.id || ''
    }));
  } else if (proto === 'trojan') {
    settings.users = (item.users && item.users.length > 0 ? item.users : [{ password: item.password || '' }]).map((u) => ({
      password: u.password || ''
    }));
  }

  return {
    tag: item.tag || item.id,
    listen: item.listen || '0.0.0.0',
    port: item.port,
    protocol: proto,
    settings,
    streamSettings: buildV5Stream(item, true, null, diagnostics, `inbounds.${item.tag}`),
    sniffingSettings: item.sniffing_enabled
      ? {
          enabled: true,
          destinationOverride: item.sniffing_dest_override || ['http', 'tls'],
          metadataOnly: !!item.sniffing_metadata_only
        }
      : undefined
  };
}

function compileV5Outbound(
  item: OutboundConfig,
  defaultMark: number | null,
  diagnostics: CompileDiagnostic[]
): Record<string, unknown> | null {
  if (item.protocol === 'wireguard' || item.protocol === 'masque') {
    diagnostics.push({
      level: 'warning',
      path: `outbounds.${item.tag}`,
      message: `V2Ray jsonv5 不支持出站协议 "${item.protocol}"，已跳过。`
    });
    return null;
  }

  const proto = item.protocol === 'hysteria' ? 'hysteria2' : item.protocol;
  let settings: Record<string, unknown> = {};

  if (proto === 'shadowsocks2022') {
    settings = {
      address: item.address || '',
      port: item.port || 8388,
      method: item.method || '2022-blake3-aes-128-gcm',
      psk: item.password || ''
    };
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
    settings = {
      address: item.address || '',
      port: item.port || 8388,
      method: item.method || 'aes-256-gcm',
      password: item.password || ''
    };
  } else if (proto === 'hysteria2') {
    settings = {
      server: [{ address: item.address || '', port: item.port || 443 }]
    };
  } else if (proto === 'freedom') {
    settings = { domainStrategy: item.domain_strategy || 'AsIs' };
  } else if (proto === 'blackhole') {
    settings = { response: { type: item.blackhole_response || 'none' } };
  } else if (proto === 'dns') {
    settings = { nonIPQuery: 'skip' };
  }

  const obj: Record<string, unknown> = {
    tag: item.tag || item.id,
    protocol: proto,
    settings,
    streamSettings: buildV5Stream(item, false, proto === 'dns' ? null : defaultMark, diagnostics, `outbounds.${item.tag}`)
  };
  if (item.dialer_proxy) {
    obj.proxySettings = { tag: item.dialer_proxy, transportLayer: true };
  }
  return obj;
}

export function compileV2RayV5(cfg: AiosConfig): CompileResult {
  const diagnostics: CompileDiagnostic[] = [];
  const outMark = cfg.transparent_proxy.enabled
    ? Number.parseInt(cfg.transparent_proxy.outbound_mark, 16) || null
    : null;

  const services: Record<string, unknown> = {};
  if (cfg.general.stats_enabled) services.stats = {};
  if (cfg.observatory.enabled) {
    services.backgroundObservatory = {
      subjectSelector: cfg.observatory.subject_selector,
      probeURL: cfg.observatory.probe_url,
      probeInterval: cfg.observatory.probe_interval || '1m'
    };
  }
  if (cfg.policy.enabled) {
    services.policy = {
      level: {
        '0': {
          handshake: cfg.policy.handshake,
          connIdle: cfg.policy.conn_idle,
          uplinkOnly: cfg.policy.uplink_only,
          downlinkOnly: cfg.policy.downlink_only,
          bufferSize: cfg.policy.buffer_size
        }
      }
    };
  }
  // Convert any TUN inbound into V2Ray v5 services.tun
  const tunInbound = cfg.inbounds.find((i) => i.enabled && i.protocol === 'tun');
  if (tunInbound) {
    services.tun = {
      name: tunInbound.tun_name || 'aios0',
      mtu: tunInbound.tun_mtu || 1500,
      tag: tunInbound.tag || 'tun-in',
      ips: [{ ip: [10, 0, 0, 1], prefix: 24 }],
      routes: [{ ip: [0, 0, 0, 0], prefix: 0 }]
    };
  }

  const inbounds = cfg.inbounds
    .filter((i) => i.enabled)
    .map((i) => compileV5Inbound(i, diagnostics))
    .filter((x): x is Record<string, unknown> => x !== null);

  const outbounds = cfg.outbounds
    .filter((o) => o.enabled)
    .map((o) => compileV5Outbound(o, outMark, diagnostics))
    .filter((x): x is Record<string, unknown> => x !== null);

  const doc: Record<string, unknown> = {
    log: {
      access: {
        type: cfg.general.access_log === 'none' ? 'None' : 'File',
        path: cfg.general.access_log === 'none' ? undefined : cfg.general.access_log
      },
      error: {
        type: cfg.general.error_log ? 'File' : 'Console',
        path: cfg.general.error_log || undefined,
        level: (cfg.general.log_level || 'warning').toUpperCase()
      }
    },
    inbounds,
    outbounds,
    router: cfg.routing.enabled
      ? {
          domainStrategy: cfg.routing.domain_strategy,
          rule: cfg.routing_rules
            .filter((r) => r.enabled)
            .map((r) => ({
              domain: r.domain && r.domain.length > 0 ? r.domain : undefined,
              ip: r.ip && r.ip.length > 0 ? r.ip : undefined,
              port: r.port || undefined,
              inboundTag: r.inbound_tag && r.inbound_tag.length > 0 ? r.inbound_tag : undefined,
              tag: r.outbound_tag || undefined,
              balancingTag: r.balancer_tag || undefined
            })),
          balancingRule: cfg.balancers.map((b) => ({
            tag: b.tag,
            outboundSelector: b.selector,
            strategy: b.strategy === 'leastPing' ? 'leastPing' : 'random'
          }))
        }
      : undefined,
    services: Object.keys(services).length > 0 ? services : undefined
  };

  return { core: 'v2ray', json: doc, diagnostics };
}
