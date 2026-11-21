import type { OutboundConfig } from '@/schema/types';

function makeId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 8)}`;
}

function decodeBase64(input: string): string {
  const norm = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm.length % 4 === 0 ? norm : norm + '='.repeat(4 - (norm.length % 4));
  return atob(pad);
}

export function parseShareUri(raw: string): OutboundConfig | null {
  const line = raw.trim();
  if (!line) return null;

  try {
    if (line.startsWith('vmess://')) {
      const json = JSON.parse(decodeBase64(line.slice(8))) as Record<string, string>;
      return {
        id: makeId('vmess'),
        enabled: true,
        alias: json.ps || `${json.add}:${json.port}`,
        tag: `vmess-${makeId('n')}`,
        protocol: 'vmess',
        address: json.add || '',
        port: Number(json.port || 443),
        uuid: json.id || '',
        alter_id: Number(json.aid || 0),
        security_cipher: json.scy || 'auto',
        transport: json.net || 'tcp',
        security: json.tls === 'tls' ? 'tls' : 'none',
        tls_server_name: json.sni || json.host || '',
        ws_path: json.path || '/',
        ws_host: json.host || ''
      };
    }

    if (line.startsWith('vless://')) {
      const u = new URL(line);
      const q = u.searchParams;
      const alias = decodeURIComponent(u.hash.replace(/^#/, '')) || `${u.hostname}:${u.port}`;
      const sec = (q.get('security') || 'none') as 'none' | 'tls' | 'reality';
      return {
        id: makeId('vless'),
        enabled: true,
        alias,
        tag: `vless-${makeId('n')}`,
        protocol: 'vless',
        address: u.hostname,
        port: Number(u.port || 443),
        uuid: decodeURIComponent(u.username),
        encryption: q.get('encryption') || 'none',
        flow: q.get('flow') || '',
        transport: q.get('type') || 'raw',
        security: sec,
        tls_server_name: q.get('sni') || '',
        tls_fingerprint: q.get('fp') || 'chrome',
        reality_server_name: q.get('sni') || '',
        reality_public_key: q.get('pbk') || '',
        reality_short_id: q.get('sid') || '',
        reality_spider_x: q.get('spx') || '/',
        reality_fingerprint: q.get('fp') || 'chrome',
        ws_path: q.get('path') || '/',
        ws_host: q.get('host') || '',
        grpc_service_name: q.get('serviceName') || '',
        xhttp_path: q.get('path') || '/',
        xhttp_host: q.get('host') || ''
      };
    }

    if (line.startsWith('trojan://')) {
      const u = new URL(line);
      const q = u.searchParams;
      const alias = decodeURIComponent(u.hash.replace(/^#/, '')) || `${u.hostname}:${u.port}`;
      return {
        id: makeId('trojan'),
        enabled: true,
        alias,
        tag: `trojan-${makeId('n')}`,
        protocol: 'trojan',
        address: u.hostname,
        port: Number(u.port || 443),
        password: decodeURIComponent(u.username),
        transport: q.get('type') || 'raw',
        security: (q.get('security') as 'none' | 'tls' | 'reality') || 'tls',
        tls_server_name: q.get('sni') || u.hostname,
        tls_fingerprint: q.get('fp') || 'chrome',
        ws_path: q.get('path') || '/',
        ws_host: q.get('host') || '',
        grpc_service_name: q.get('serviceName') || ''
      };
    }

    if (line.startsWith('hy2://') || line.startsWith('hysteria2://')) {
      const normalized = line.replace(/^hy2:\/\//, 'https://').replace(/^hysteria2:\/\//, 'https://');
      const u = new URL(normalized);
      const q = u.searchParams;
      const alias = decodeURIComponent(u.hash.replace(/^#/, '')) || `${u.hostname}:${u.port}`;
      return {
        id: makeId('hy2'),
        enabled: true,
        alias,
        tag: `hy2-${makeId('n')}`,
        protocol: 'hysteria',
        address: u.hostname,
        port: Number(u.port || 443),
        password: decodeURIComponent(u.username),
        hysteria_auth: decodeURIComponent(u.username),
        hysteria_obfs_password: q.get('obfs-password') || '',
        transport: 'hysteria',
        security: 'tls',
        tls_server_name: q.get('sni') || u.hostname,
        tls_allow_insecure: q.get('insecure') === '1'
      };
    }

    if (line.startsWith('ss://')) {
      const hashIdx = line.indexOf('#');
      const alias = hashIdx >= 0 ? decodeURIComponent(line.slice(hashIdx + 1)) : 'Shadowsocks';
      const body = hashIdx >= 0 ? line.slice(5, hashIdx) : line.slice(5);
      let method = 'aes-256-gcm';
      let password = '';
      let host = '';
      let port = 8388;

      if (body.includes('@')) {
        const [userPart, hostPart] = body.split('@');
        const decoded = userPart.includes(':') ? userPart : decodeBase64(userPart);
        const sep = decoded.indexOf(':');
        method = decoded.slice(0, sep);
        password = decoded.slice(sep + 1);
        const [h, p] = hostPart.split('?')[0].split(':');
        host = h;
        port = Number(p || 8388);
      } else {
        const decoded = decodeBase64(body);
        const [cred, hostPart] = decoded.split('@');
        const sep = cred.indexOf(':');
        method = cred.slice(0, sep);
        password = cred.slice(sep + 1);
        const [h, p] = hostPart.split(':');
        host = h;
        port = Number(p || 8388);
      }

      return {
        id: makeId('ss'),
        enabled: true,
        alias,
        tag: `ss-${makeId('n')}`,
        protocol: 'shadowsocks',
        address: host,
        port,
        method,
        password,
        transport: 'raw',
        security: 'none'
      };
    }
  } catch {
    return null;
  }

  return null;
}

export function parseShareUriList(text: string): OutboundConfig[] {
  return text
    .split(/\r?\n/)
    .map((l) => parseShareUri(l))
    .filter((item): item is OutboundConfig => item !== null);
}
