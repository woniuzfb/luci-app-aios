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

function safeDecodeURIComponent(s: string): string {
  try {
    return decodeURIComponent(s.replace(/%(?![0-9a-fA-F]{2})/g, '%25'));
  } catch {
    return s;
  }
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
      const net = json.net || 'tcp';
      const out: OutboundConfig = {
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
        transport: net,
        security: json.tls === 'tls' ? 'tls' : 'none',
        tls_server_name: json.sni || json.host || '',
        tls_alpn: json.alpn ? json.alpn.split(',').filter(Boolean) : undefined,
        tls_fingerprint: json.fp || undefined
      };
      if (net === 'ws') {
        out.ws_path = json.path || '/';
        out.ws_host = json.host || '';
      } else if (net === 'grpc') {
        out.grpc_service_name = json.path || '';
        if (json.host) out.grpc_authority = json.host;
        if (json.type === 'multi') out.grpc_multi_mode = true;
      } else if (net === 'h2' || net === 'http') {
        out.h2_path = json.path || '/';
        out.h2_host = json.host
          ? json.host
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
          : undefined;
      } else if (net === 'httpupgrade') {
        out.httpupgrade_path = json.path || '/';
        out.httpupgrade_host = json.host || '';
      } else if (net === 'tcp' && json.type === 'http') {
        out.tcp_header_type = 'http';
      }
      return out;
    }

    if (line.startsWith('vless://')) {
      const u = new URL(line);
      const q = u.searchParams;
      const host = stripIpv6Brackets(u.hostname);
      const port = Number(u.port || 443);
      const alias = safeDecodeURIComponent(u.hash.replace(/^#/, '')) || `${host}:${port}`;
      const sec = (q.get('security') || 'none') as 'none' | 'tls' | 'reality';
      const alpn = q.get('alpn') ? q.get('alpn')!.split(',').filter(Boolean) : undefined;
      const mode = q.get('mode') || '';
      const transport = q.get('type') || 'raw';
      const isXhttp = transport === 'xhttp' || transport === 'splithttp';
      return {
        id: makeId('vless'),
        enabled: true,
        alias,
        tag: `vless-${makeId('n')}`,
        protocol: 'vless',
        address: host,
        port,
        uuid: safeDecodeURIComponent(u.username),
        encryption: q.get('encryption') || 'none',
        flow: q.get('flow') || '',
        transport,
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
        reality_mldsa65_verify: q.get('pqv') || '',
        ws_path: q.get('path') || '/',
        ws_host: q.get('host') || '',
        httpupgrade_path: q.get('path') || '/',
        httpupgrade_host: q.get('host') || '',
        grpc_service_name: q.get('serviceName') || '',
        grpc_authority: q.get('authority') || '',
        grpc_multi_mode: mode === 'multi',
        xhttp_path: q.get('path') || '/',
        xhttp_host: q.get('host') || '',
        xhttp_mode: isXhttp && mode && mode !== 'multi' ? (mode as OutboundConfig['xhttp_mode']) : undefined
      };
    }

    if (line.startsWith('trojan://')) {
      const u = new URL(line);
      const q = u.searchParams;
      const host = stripIpv6Brackets(u.hostname);
      const port = Number(u.port || 443);
      const alias = safeDecodeURIComponent(u.hash.replace(/^#/, '')) || `${host}:${port}`;
      const alpn = q.get('alpn') ? q.get('alpn')!.split(',').filter(Boolean) : undefined;
      const sec = (q.get('security') as 'none' | 'tls' | 'reality') || 'tls';
      const mode = q.get('mode') || '';
      const transport = q.get('type') || 'raw';
      const isXhttp = transport === 'xhttp' || transport === 'splithttp';
      const out: OutboundConfig = {
        id: makeId('trojan'),
        enabled: true,
        alias,
        tag: `trojan-${makeId('n')}`,
        protocol: 'trojan',
        address: host,
        port,
        password: safeDecodeURIComponent(u.password ? `${u.username}:${u.password}` : u.username),
        transport,
        security: sec,
        tls_server_name: q.get('sni') || host,
        tls_alpn: alpn,
        tls_allow_insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1',
        tls_fingerprint: q.get('fp') || 'chrome',
        ws_path: q.get('path') || '/',
        ws_host: q.get('host') || '',
        httpupgrade_path: q.get('path') || '/',
        httpupgrade_host: q.get('host') || '',
        grpc_service_name: q.get('serviceName') || '',
        grpc_authority: q.get('authority') || '',
        grpc_multi_mode: mode === 'multi',
        xhttp_path: q.get('path') || '/',
        xhttp_host: q.get('host') || '',
        xhttp_mode: isXhttp && mode && mode !== 'multi' ? (mode as OutboundConfig['xhttp_mode']) : undefined
      };
      if (sec === 'reality') {
        out.reality_server_name = q.get('sni') || '';
        out.reality_public_key = q.get('pbk') || '';
        out.reality_short_id = q.get('sid') || '';
        out.reality_spider_x = q.get('spx') || '/';
        out.reality_fingerprint = q.get('fp') || 'chrome';
        out.reality_mldsa65_verify = q.get('pqv') || '';
      }
      return out;
    }

    if (line.startsWith('hy2://') || line.startsWith('hysteria2://') || line.startsWith('hysteria://')) {
      const normalized = line.replace(/^(hy2|hysteria2|hysteria):\/\//, 'https://');
      const u = new URL(normalized);
      const q = u.searchParams;
      const host = stripIpv6Brackets(u.hostname);
      const port = Number(u.port || 443);
      const alias = safeDecodeURIComponent(u.hash.replace(/^#/, '')) || `${host}:${port}`;
      const rawAuth = u.password ? `${u.username}:${u.password}` : u.username;
      const auth = safeDecodeURIComponent(rawAuth || q.get('auth') || '');
      return {
        id: makeId('hy2'),
        enabled: true,
        alias,
        tag: `hy2-${makeId('n')}`,
        protocol: 'hysteria',
        address: host,
        port,
        password: auth,
        hysteria_auth: auth,
        hysteria_obfs_password: q.get('obfs-password') || '',
        hysteria_udphop_port: q.get('mport') || undefined,
        transport: 'hysteria',
        security: 'tls',
        tls_server_name: q.get('sni') || q.get('peer') || host,
        tls_allow_insecure: q.get('insecure') === '1' || q.get('allowInsecure') === '1'
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
      const alias = safeDecodeURIComponent(u.hash.replace(/^#/, '')) || `${host}:${port}`;
      const addrList = (q.get('address') || '10.0.0.2/32')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const endpoint = host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
      const pubKey = q.get('publickey') || q.get('publicKey') || '';
      const reservedRaw = q.get('reserved') || '';
      const wgReserved = reservedRaw
        ? reservedRaw
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean)
        : undefined;
      const psk = q.get('presharedkey') || q.get('preSharedKey') || '';
      return {
        id: makeId('wg'),
        enabled: true,
        alias,
        tag: `wg-${makeId('n')}`,
        protocol: 'wireguard',
        address: host,
        port,
        wg_secret_key: safeDecodeURIComponent(u.username || q.get('privateKey') || ''),
        wg_address: addrList,
        wg_mtu: Number(q.get('mtu') || 1420),
        wg_reserved: wgReserved,
        wg_peer_public_key: pubKey,
        wg_endpoint: endpoint,
        wg_peers: pubKey ? [{ publicKey: pubKey, endpoint, ...(psk ? { preSharedKey: psk } : {}) }] : [],
        transport: 'raw',
        security: 'none'
      };
    }

    if (line.startsWith('ss://')) {
      const hashIdx = line.indexOf('#');
      const alias = hashIdx >= 0 ? safeDecodeURIComponent(line.slice(hashIdx + 1)) : 'Shadowsocks';
      const body = hashIdx >= 0 ? line.slice(5, hashIdx) : line.slice(5);
      let method = 'aes-256-gcm';
      let password = '';
      let host = '';
      let port = 8388;

      const authority = body.split('?')[0];
      const atIdx = authority.lastIndexOf('@');
      if (atIdx >= 0) {
        const userPart = authority.slice(0, atIdx);
        const hostPart = authority.slice(atIdx + 1);
        const decoded =
          userPart.includes(':') || /%3a/i.test(userPart)
            ? safeDecodeURIComponent(userPart)
            : decodeBase64Utf8(userPart);
        const sep = decoded.indexOf(':');
        method = sep >= 0 ? decoded.slice(0, sep) : method;
        password = sep >= 0 ? decoded.slice(sep + 1) : decoded;
        const hp = splitHostPort(hostPart, 8388);
        host = hp.host;
        port = hp.port;
      } else {
        const decoded = decodeBase64Utf8(authority);
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
