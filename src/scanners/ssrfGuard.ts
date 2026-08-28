import dns from 'node:dns';
import net from 'node:net';

/**
 * Private/internal IPv4 ranges — includes RFC1918, loopback, link-local
 * (which covers cloud metadata endpoints like 169.254.169.254), CGNAT,
 * benchmarking, and multicast/reserved space.
 */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true; // loopback / unspecified
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true; // fe80::/10 link-local
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true; // fc00::/7 unique local
  if (lower.startsWith('::ffff:')) {
    const v4 = lower.split(':').pop();
    if (v4 && net.isIPv4(v4)) return isPrivateIPv4(v4);
  }
  return false;
}

export function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) return isPrivateIPv6(ip);
  return true; // unrecognizable — treat as unsafe
}

const BLOCKED_HOSTNAMES = new Set(['localhost', 'localhost.localdomain', 'metadata.google.internal']);

/**
 * Rejects a hostname that is (or resolves to) a private, loopback, link-local,
 * or otherwise internal address — prevents SSRF via a "domain" that actually
 * points at internal infrastructure or a cloud metadata endpoint. Resolution
 * failures are left to the caller's own connection attempt to surface.
 *
 * Pass `allowPrivate: true` (the CLI's `--allow-private` flag) to skip this
 * check entirely for legitimate local/private-network testing.
 */
export async function assertPublicHostname(rawHostname: string, allowPrivate = false): Promise<void> {
  if (allowPrivate) return;

  const hostname = String(rawHostname || '').trim().toLowerCase();
  if (!hostname) throw new Error('Hostname is required');
  if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('This hostname is not allowed (use --allow-private to override for local testing)');
  }

  if (net.isIP(hostname)) {
    if (isPrivateIP(hostname)) throw new Error('This hostname is not allowed (use --allow-private to override for local testing)');
    return;
  }

  const addresses: string[] = [];
  try {
    const [v4, v6] = await Promise.allSettled([
      dns.promises.resolve4(hostname),
      dns.promises.resolve6(hostname),
    ]);
    if (v4.status === 'fulfilled') addresses.push(...v4.value);
    if (v6.status === 'fulfilled') addresses.push(...v6.value);
  } catch {
    return;
  }

  if (addresses.length > 0 && addresses.some(isPrivateIP)) {
    throw new Error('This hostname resolves to a private or internal address and cannot be checked (use --allow-private to override for local testing)');
  }
}
