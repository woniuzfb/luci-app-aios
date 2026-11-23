import type { CoreType } from './types';

export type V2RayFormat = 'jsonv4' | 'jsonv5';
export type CoreProfileKey = 'xray' | 'v2ray_v4' | 'v2ray_v5';

export interface CoreCapability {
  label: string;
  inboundProtocols: string[];
  outboundProtocols: string[];
  transports: string[];
  securities: Array<'none' | 'tls' | 'reality' | 'utls'>;
  balancerStrategies: Array<'random' | 'roundRobin' | 'leastPing' | 'leastLoad'>;
  sniffingDestOverrides: string[];
  maxMuxConcurrency: number;
  supportsMetrics: boolean;
  supportsFinalmask: boolean;
  supportsReality: boolean;
  supportsVlessFlow: boolean;
  supportsVlessEncryption: boolean;
  supportsXhttp: boolean;
  supportsWireguard: boolean;
  supportsMasque: boolean;
  supportsTunInbound: boolean;
  supportsTunService: boolean;
  supportsServeStale: boolean;
  supportsUnexpectedIps: boolean;
  supportsDnsLog: boolean;
  supportsAttrsJson: boolean;
}

export const CORE_PROFILE_CAPABILITIES: Record<CoreProfileKey, CoreCapability> = {
  xray: {
    label: 'Xray-core',
    inboundProtocols: [
      'dokodemo-door',
      'tunnel',
      'socks',
      'http',
      'vless',
      'vmess',
      'trojan',
      'shadowsocks',
      'hysteria',
      'wireguard',
      'masque',
      'tun'
    ],
    outboundProtocols: [
      'vless',
      'vmess',
      'trojan',
      'shadowsocks',
      'hysteria',
      'wireguard',
      'masque',
      'freedom',
      'blackhole',
      'dns',
      'socks',
      'http',
      'loopback'
    ],
    transports: [
      'raw',
      'websocket',
      'grpc',
      'httpupgrade',
      'xhttp',
      'mkcp',
      'hysteria',
      'masque'
    ],
    securities: ['none', 'tls', 'reality'],
    balancerStrategies: ['random', 'roundRobin', 'leastPing', 'leastLoad'],
    sniffingDestOverrides: ['http', 'tls', 'quic', 'fakedns'],
    maxMuxConcurrency: 128,
    supportsMetrics: true,
    supportsFinalmask: true,
    supportsReality: true,
    supportsVlessFlow: true,
    supportsVlessEncryption: true,
    supportsXhttp: true,
    supportsWireguard: true,
    supportsMasque: true,
    supportsTunInbound: true,
    supportsTunService: false,
    supportsServeStale: true,
    supportsUnexpectedIps: true,
    supportsDnsLog: true,
    supportsAttrsJson: true
  },
  v2ray_v4: {
    label: 'V2Ray (jsonv4)',
    inboundProtocols: [
      'dokodemo-door',
      'socks',
      'http',
      'vless',
      'vmess',
      'trojan',
      'shadowsocks',
      'hysteria2',
      'tun'
    ],
    outboundProtocols: [
      'vmess',
      'vless',
      'trojan',
      'shadowsocks',
      'hysteria2',
      'freedom',
      'blackhole',
      'dns',
      'socks',
      'http',
      'loopback'
    ],
    transports: [
      'tcp',
      'ws',
      'grpc',
      'http',
      'kcp',
      'quic',
      'domainsocket',
      'hysteria2'
    ],
    securities: ['none', 'tls'],
    balancerStrategies: ['random', 'leastPing', 'leastLoad'],
    sniffingDestOverrides: ['http', 'tls', 'quic', 'fakedns', 'fakedns+others'],
    maxMuxConcurrency: 1024,
    supportsMetrics: false,
    supportsFinalmask: false,
    supportsReality: false,
    supportsVlessFlow: false,
    supportsVlessEncryption: false,
    supportsXhttp: false,
    supportsWireguard: false,
    supportsMasque: false,
    supportsTunInbound: false,
    supportsTunService: true,
    supportsServeStale: false,
    supportsUnexpectedIps: false,
    supportsDnsLog: false,
    supportsAttrsJson: false
  },
  v2ray_v5: {
    label: 'V2Ray (jsonv5)',
    inboundProtocols: [
      'dokodemo-door',
      'socks',
      'http',
      'vless',
      'vmess',
      'trojan',
      'shadowsocks',
      'hysteria2',
      'tun'
    ],
    outboundProtocols: [
      'vmess',
      'vless',
      'trojan',
      'shadowsocks',
      'shadowsocks2022',
      'hysteria2',
      'freedom',
      'blackhole',
      'dns',
      'socks',
      'http',
      'loopback'
    ],
    transports: [
      'tcp',
      'ws',
      'grpc',
      'httpupgrade',
      'kcp',
      'quic',
      'hysteria2'
    ],
    securities: ['none', 'tls', 'utls'],
    balancerStrategies: ['random', 'leastPing', 'leastLoad'],
    sniffingDestOverrides: ['http', 'tls', 'quic', 'fakedns', 'fakedns+others'],
    maxMuxConcurrency: 1024,
    supportsMetrics: false,
    supportsFinalmask: false,
    supportsReality: false,
    supportsVlessFlow: false,
    supportsVlessEncryption: false,
    supportsXhttp: false,
    supportsWireguard: false,
    supportsMasque: false,
    supportsTunInbound: false,
    supportsTunService: true,
    supportsServeStale: false,
    supportsUnexpectedIps: false,
    supportsDnsLog: false,
    supportsAttrsJson: false
  }
};

export const CORE_CAPABILITIES: Record<CoreType, CoreCapability> = {
  xray: CORE_PROFILE_CAPABILITIES.xray,
  v2ray: CORE_PROFILE_CAPABILITIES.v2ray_v4
};

export function getCoreCapabilities(core: CoreType, v2rayFormat: V2RayFormat = 'jsonv4'): CoreCapability {
  if (core === 'xray') return CORE_PROFILE_CAPABILITIES.xray;
  return v2rayFormat === 'jsonv5' ? CORE_PROFILE_CAPABILITIES.v2ray_v5 : CORE_PROFILE_CAPABILITIES.v2ray_v4;
}

export interface StreamComboIssue {
  level: 'warning' | 'error';
  message: string;
}

export function validateStreamCombination(
  core: CoreType,
  v2rayFormat: V2RayFormat,
  protocol: string,
  transport: string,
  security: string,
  direction: 'inbound' | 'outbound' = 'outbound'
): StreamComboIssue[] {
  const issues: StreamComboIssue[] = [];
  if (core === 'xray') {
    if (protocol === 'hysteria' && transport !== 'hysteria') {
      issues.push({ level: 'error', message: 'Xray hysteria 协议只能搭配 hysteria 传输方式。' });
    }
    if (protocol === 'masque' && transport !== 'masque') {
      issues.push({ level: 'error', message: 'Xray masque 协议只能搭配 masque 传输方式。' });
    }
    if (transport === 'masque' && protocol !== 'masque') {
      issues.push({ level: 'error', message: 'Xray masque 传输方式仅适用于 masque 协议。' });
    }
    if ((transport === 'hysteria' || transport === 'masque') && security !== 'tls') {
      issues.push({ level: 'error', message: `Xray ${transport} 传输方式必须使用 tls 安全层（不支持 ${security}）。` });
    }
    if (security === 'reality' && !['raw', 'xhttp', 'grpc'].includes(transport)) {
      issues.push({ level: 'error', message: `Xray REALITY 仅支持与 raw / xhttp / grpc 传输方式组合，当前为 ${transport}。` });
    }
  } else {
    if (security === 'reality') {
      issues.push({ level: 'error', message: `V2Ray ${v2rayFormat} 不支持 REALITY 安全层。` });
    }
    if (security === 'utls' && direction === 'inbound') {
      issues.push({ level: 'error', message: 'V2Ray uTLS 仅支持客户端出站（Outbound），不能用于入站（Inbound）。' });
    }
    if (v2rayFormat === 'jsonv4' && security === 'utls') {
      issues.push({ level: 'error', message: 'V2Ray jsonv4 不支持独立 utls 安全层，请切换 jsonv5 或改用 tls。' });
    }
    if (v2rayFormat === 'jsonv5' && security === 'utls' && !['tcp', 'ws'].includes(transport)) {
      issues.push({ level: 'error', message: `V2Ray jsonv5 uTLS 仅支持 tcp / ws 传输方式，当前为 "${transport}"。` });
    }
    if (v2rayFormat === 'jsonv5' && (transport === 'http' || transport === 'domainsocket')) {
      issues.push({ level: 'error', message: `V2Ray jsonv5 不支持传输方式 "${transport}"。` });
    }
    if (['xhttp', 'splithttp', 'masque'].includes(transport)) {
      issues.push({ level: 'error', message: `V2Ray ${v2rayFormat} 不支持传输方式 "${transport}"。` });
    }
    if (v2rayFormat !== 'jsonv5' && transport === 'httpupgrade') {
      issues.push({ level: 'error', message: 'V2Ray jsonv4 不支持传输方式 "httpupgrade"（请切换 jsonv5）。' });
    }
  }
  return issues;
}

export function resolveEffectiveCore(
  configured: 'auto' | CoreType,
  detected?: CoreType,
  coreBin?: string
): CoreType {
  if (configured === 'xray' || configured === 'v2ray') return configured;
  if (detected === 'xray' || detected === 'v2ray') return detected;
  if (coreBin && coreBin.toLowerCase().includes('v2ray')) return 'v2ray';
  return 'xray';
}
