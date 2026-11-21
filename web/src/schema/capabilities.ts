import type { CoreType } from './types';

export interface CoreCapability {
  label: string;
  inboundProtocols: string[];
  outboundProtocols: string[];
  transports: string[];
  securities: Array<'none' | 'tls' | 'reality' | 'utls'>;
  balancerStrategies: Array<'random' | 'roundRobin' | 'leastPing' | 'leastLoad'>;
  supportsMetrics: boolean;
  supportsFinalmask: boolean;
  supportsReality: boolean;
  supportsVlessFlow: boolean;
  supportsVlessEncryption: boolean;
  supportsXhttp: boolean;
  supportsWireguard: boolean;
  supportsMasque: boolean;
  supportsTunInbound: boolean;
  supportsServeStale: boolean;
  supportsUnexpectedIps: boolean;
  supportsDnsLog: boolean;
}

export const CORE_CAPABILITIES: Record<CoreType, CoreCapability> = {
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
      'splithttp',
      'mkcp',
      'hysteria',
      'masque'
    ],
    securities: ['none', 'tls', 'reality'],
    balancerStrategies: ['random', 'roundRobin', 'leastPing', 'leastLoad'],
    supportsMetrics: true,
    supportsFinalmask: true,
    supportsReality: true,
    supportsVlessFlow: true,
    supportsVlessEncryption: true,
    supportsXhttp: true,
    supportsWireguard: true,
    supportsMasque: true,
    supportsTunInbound: true,
    supportsServeStale: true,
    supportsUnexpectedIps: true,
    supportsDnsLog: true
  },
  v2ray: {
    label: 'V2Ray (v2fly)',
    inboundProtocols: [
      'dokodemo-door',
      'socks',
      'http',
      'vless',
      'vmess',
      'trojan',
      'shadowsocks',
      'hysteria2'
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
      'http',
      'kcp',
      'quic',
      'domainsocket',
      'hysteria2'
    ],
    securities: ['none', 'tls', 'utls'],
    balancerStrategies: ['random', 'leastPing'],
    supportsMetrics: false,
    supportsFinalmask: false,
    supportsReality: false,
    supportsVlessFlow: false,
    supportsVlessEncryption: false,
    supportsXhttp: false,
    supportsWireguard: false,
    supportsMasque: false,
    supportsTunInbound: false,
    supportsServeStale: false,
    supportsUnexpectedIps: false,
    supportsDnsLog: false
  }
};

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
