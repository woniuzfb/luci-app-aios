import type { OutboundConfig } from '@/schema/types';

function makeId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 8)}`;
}

function decodeBase64Utf8(input: string): string {
  const norm = input.trim().replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm.length % 4 === 0 ? norm : norm + '='.repeat(4 - (norm.length % 4));
  const bin = atob(pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return new TextDecoder('utf-8').decode(bytes);
}

function stripIpv6Brackets(host: string): string {
  return host.replace(/^\[|\]$/g, '');
}

function splitHostPort(hostPort: string, defaultPort: number): { host: string; port: number } {
  const clean = hostPort.split('?')[0].split('/')[0].trim();
  if (clean.startsWith('[')) {
    const closeIdx = clean.indexOf(']');
    if (closeIdx > 0) {
      const host = clean.slice(1, closeIdx);
      const rest = clean.slice(closeIdx + 1);
      const port = rest.startsWith(':') ? Number(rest.slice(1)) || defaultPort : defaultPort;
      return { host, port };
    }
  }
  const lastColon = clean.lastIndexOf(':');
  if (lastColon > 0 && clean.indexOf(':') === lastColon) {
    return {
      host: clean.slice(0, lastColon),
      port: Number(clean.slice(lastColon + 1)) || defaultPort
    };
  }
  return { host: stripIpv6Brackets(clean), port: defaultPort };
}

export function parseShareUri(raw: string): OutboundConfig | null {
  const line = raw.trim();
  if (!line) return null;

  try {
    if (line.startsWith('vmess://')) {
      const json = JSON.parse(decodeBase64Utf8(line.slice(8))) as Record<string, string>;
      return {
        id: makeId('vmess'),
        enabled: true,
        alias: json.ps || `${json.add}:${json.port}`,
        tag: `vmess-${makeId('n')}`,
        protocol: 'vmess',
        address: stripIpv6Brackets(json.add || ''),
        port: Number(json.port || 443),
        uuid: json.id || '',
        alter_id: Number(json.aid || 0),
        security_cipher: json.scy || 'auto',
        transport: json.net || 'tcp',
        security: json.tls === 'tls' ? 'tls' : 'none',
        tls_server_name: json.sni || json.host || '',
        tls_alpn: json.alpn ? json.alpn.split(',').filter(Boolean) : undefined,
        tls_fingerprint: json.fp || undefined,
        ws_path: json.path || '/',
        ws_host: json.host || ''
      };
    }

    if (line.startsWith('vless://')) {
      const u = new URL(line);
      const q = u.searchParams;
      const host = stripIpv6Brackets(u.hostname);
      const alias = decodeURIComponent(u.hash.replace(/^#/, '')) || `${host}:${u.port}`;
      const sec = (q.get('security') || 'none') as 'none' | 'tls' | 'reality';
      const alpn = q.get('alpn') ? q.get('alpn')!.split(',').filter(Boolean) : undefined;
      return {
        id: makeId('vless'),
        enabled: true,
        alias,
        tag: `vless-${makeId('n')}`,
        protocol: 'vless',
        address: host,
        port: Number(u.port || 443),
        uuid: decodeURIComponent(u.username),
        encryption: q.get('encryption') || 'none',
        flow: q.get('flow') || '',
        transport: q.get('type') || 'raw',
        security: sec,
        tls_server_name: q.get('sni') || '',
        tls_alpn: alpn,
        tls_allow_insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1',
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
        xhttp_host: q.get('host') || '',
        xhttp_mode: (q.get('mode') as OutboundConfig['xhttp_mode']) || undefined
      };
    }

    if (line.startsWith('trojan://')) {
      const u = new URL(line);
      const q = u.searchParams;
      const host = stripIpv6Brackets(u.hostname);
      const alias = decodeURIComponent(u.hash.replace(/^#/, '')) || `${host}:${u.port}`;
      const alpn = q.get('alpn') ? q.get('alpn')!.split(',').filter(Boolean) : undefined;
      return {
        id: makeId('trojan'),
        enabled: true,
        alias,
        tag: `trojan-${makeId('n')}`,
        protocol: 'trojan',
        address: host,
        port: Number(u.port || 443),
        password: decodeURIComponent(u.password ? `${u.username}:${u.password}` : u.username),
        transport: q.get('type') || 'raw',
        security: (q.get('security') as 'none' | 'tls' | 'reality') || 'tls',
        tls_server_name: q.get('sni') || host,
        tls_alpn: alpn,
        tls_allow_insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1',
        tls_fingerprint: q.get('fp') || 'chrome',
        ws_path: q.get('path') || '/',
        ws_host: q.get('host') || '',
        grpc_service_name: q.get('serviceName') || ''
      };
    }

    if (line.startsWith('hy2://') || line.startsWith('hysteria2://') || line.startsWith('hysteria://')) {
      const normalized = line.replace(/^(hy2|hysteria2|hysteria):\/\//, 'https://');
      const u = new URL(normalized);
      const q = u.searchParams;
      const host = stripIpv6Brackets(u.hostname);
      const alias = decodeURIComponent(u.hash.replace(/^#/, '')) || `${host}:${u.port}`;
      const rawAuth = u.password ? `${u.username}:${u.password}` : u.username;
      const auth = decodeURIComponent(rawAuth || q.get('auth') || '');
      return {
        id: makeId('hy2'),
        enabled: true,
        alias,
        tag: `hy2-${makeId('n')}`,
        protocol: 'hysteria',
        address: host,
        port: Number(u.port || 443),
        password: auth,
        hysteria_auth: auth,
        hysteria_obfs_password: q.get('obfs-password') || '',
        transport: 'hysteria',
        security: 'tls',
        tls_server_name: q.get('sni') || q.get('peer') || host,
        tls_allow_insecure: q.get('insecure') === '1'
      };
    }

    if (line.startsWith('wireguard://') || line.startsWith('wg://')) {
      const rawWithoutScheme = line.replace(/^(wireguard|wg):\/\//, '');
      const authorityPart = rawWithoutScheme.split(/[/?#]/)[0];
      const hostPortPart = authorityPart.includes('@') ? authorityPart.slice(authorityPart.lastIndexOf('@') + 1) : authorityPart;
      const explicitPortMatch = hostPortPart.match(/:(\d+)$/);
      const normalized = `https://${rawWithoutScheme}`;
      const u = new URL(normalized);
      const q = u.searchParams;
      const host = stripIpv6Brackets(u.hostname);
      const port = Number(explicitPortMatch ? explicitPortMatch[1] : u.port || 51820);
      const alias = decodeURIComponent(u.hash.replace(/^#/, '')) || `${host}:${port}`;
      const addrList = (q.get('address') || '10.0.0.2/32')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const endpoint = host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
      const pubKey = q.get('publickey') || q.get('publicKey') || '';
      return {
        id: makeId('wg'),
        enabled: true,
        alias,
        tag: `wg-${makeId('n')}`,
        protocol: 'wireguard',
        address: host,
        port,
        wg_secret_key: decodeURIComponent(u.username || q.get('privateKey') || ''),
        wg_address: addrList,
        wg_mtu: Number(q.get('mtu') || 1420),
        wg_peer_public_key: pubKey,
        wg_endpoint: endpoint,
        wg_peers: pubKey ? [{ publicKey: pubKey, endpoint }] : [],
        transport: 'raw',
        security: 'none'
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

      const atIdx = body.lastIndexOf('@');
      if (atIdx >= 0) {
        const userPart = body.slice(0, atIdx);
        const hostPart = body.slice(atIdx + 1);
        const decoded = userPart.includes(':') ? decodeURIComponent(userPart) : decodeBase64Utf8(userPart);
        const sep = decoded.indexOf(':');
        method = sep >= 0 ? decoded.slice(0, sep) : method;
        password = sep >= 0 ? decoded.slice(sep + 1) : decoded;
        const hp = splitHostPort(hostPart, 8388);
        host = hp.host;
        port = hp.port;
      } else {
        const decoded = decodeBase64Utf8(body);
        const decAt = decoded.lastIndexOf('@');
        if (decAt < 0) return null;
        const cred = decoded.slice(0, decAt);
        const hostPart = decoded.slice(decAt + 1);
        const sep = cred.indexOf(':');
        method = sep >= 0 ? cred.slice(0, sep) : method;
        password = sep >= 0 ? cred.slice(sep + 1) : cred;
        const hp = splitHostPort(hostPart, 8388);
        host = hp.host;
        port = hp.port;
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
    .map((line) => parseShareUri(line))
    .filter((x): x is OutboundConfig => x !== null);
}
