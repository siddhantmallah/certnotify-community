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
  if (a === 192 && b === 0) return true; // 192.0.0.0/24 IETF protocol assignments
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a >= 224) return true; // multicast + reserved
  return false;
}

/**
 * An IPv6 address as its sixteen bytes, or null if it will not parse.
 *
 * Deciding from the bytes rather than from the text is what makes this hard
 * to slip past: every alternative spelling of one address — compressed,
 * expanded, dotted-quad tail, mixed case — collapses to the same sixteen
 * bytes, so there is no "other way to write it" left.
 *
 * The bug this replaces: the previous check tested `startsWith('::ffff:')`
 * and then read the last colon-separated group as an IPv4 address. That works
 * for `::ffff:127.0.0.1` and fails for `::ffff:7f00:1`, which is the same
 * address and is exactly what `new URL('http://[::ffff:127.0.0.1]/').hostname`
 * normalises to. Loopback was reported as public.
 */
export function ipv6Bytes(input: string): number[] | null {
  const address = String(input).split('%')[0];
  if (!net.isIPv6(address)) return null;

  const compressed = address.includes('::');
  const [headText, tailText = ''] = address.split('::');
  const split = (text: string): string[] => (text ? text.split(':').filter(Boolean) : []);

  const expand = (groups: string[]): string[] | null => {
    const last = groups[groups.length - 1];
    if (last && last.includes('.')) {
      const quad = last.split('.').map(Number);
      if (quad.length !== 4 || quad.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
      groups.pop();
      groups.push((((quad[0] << 8) | quad[1]) >>> 0).toString(16));
      groups.push((((quad[2] << 8) | quad[3]) >>> 0).toString(16));
    }
    return groups;
  };

  const head = expand(split(headText));
  const tail = expand(compressed ? split(tailText) : []);
  if (!head || !tail) return null;

  const missing = 8 - (head.length + tail.length);
  if (compressed ? missing < 0 : missing !== 0) return null;

  const groups = compressed ? [...head, ...Array(missing).fill('0'), ...tail] : head;
  if (groups.length !== 8) return null;

  const bytes: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    const value = parseInt(group, 16);
    bytes.push((value >> 8) & 0xff, value & 0xff);
  }
  return bytes;
}

function isPrivateIPv6(ip: string): boolean {
  const b = ipv6Bytes(ip);
  if (!b) return true; // unparseable - unsafe

  const quad = (offset: number): string =>
    `${b[offset]}.${b[offset + 1]}.${b[offset + 2]}.${b[offset + 3]}`;

  // :: (unspecified) and ::1 (loopback).
  if (b.slice(0, 15).every((x) => x === 0)) return true;

  const first10Zero = b.slice(0, 10).every((x) => x === 0);
  // ::ffff:0:0/96 IPv4-mapped and the deprecated ::/96 IPv4-compatible.
  if (first10Zero && ((b[10] === 0xff && b[11] === 0xff) || (b[10] === 0 && b[11] === 0))) {
    return isPrivateIPv4(quad(12));
  }
  // 64:ff9b::/96 NAT64 carries an IPv4 destination in the low bytes.
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b
      && b.slice(4, 12).every((x) => x === 0)) {
    return isPrivateIPv4(quad(12));
  }
  // 2002::/16 6to4 embeds the IPv4 address it tunnels to.
  if (b[0] === 0x20 && b[1] === 0x02) return isPrivateIPv4(quad(2));

  if ((b[0] & 0xfe) === 0xfc) return true;                  // fc00::/7 unique local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true; // fe80::/10 link local
  if (b[0] === 0xff) return true;                           // ff00::/8 multicast

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
/**
 * Bare hostname, lowercased, with an IPv6 literal's brackets removed.
 *
 * Brackets are URL syntax, not part of the address. `new URL()` keeps them on
 * `hostname` for an IPv6 literal, and leaving them on made `net.isIP` return 0
 * for every IPv6 address - so the literal-IP branch was skipped, the string
 * went to DNS, resolution failed, and the failure was treated as permission to
 * proceed. `http://[::1]/` reached loopback.
 */
export function normaliseHostname(rawHostname: string): string {
  let hostname = String(rawHostname || '').trim().toLowerCase();
  if (hostname.startsWith('[') && hostname.endsWith(']')) hostname = hostname.slice(1, -1);
  if (hostname.endsWith('.')) hostname = hostname.slice(0, -1);
  return hostname;
}

/** Names refused regardless of what they resolve to. */
function assertNameAllowed(hostname: string): void {
  if (!hostname) throw new Error('Hostname is required');
  if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('This hostname is not allowed (use --allow-private to override for local testing)');
  }
}

export async function assertPublicHostname(rawHostname: string, allowPrivate = false): Promise<void> {
  if (allowPrivate) return;

  const hostname = normaliseHostname(rawHostname);
  assertNameAllowed(hostname);

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

/**
 * Resolve once, validate, and pin — so the socket goes where the check went.
 *
 * `assertPublicHostname` resolves a name and validates the addresses; the
 * caller then connects *by hostname*, which resolves a second time. Those are
 * two independent lookups, and whoever runs the authoritative server for a
 * domain can answer them differently: public for the check, private for the
 * connection. The name stays a legitimate public domain throughout — only the
 * answer changes. That is DNS rebinding, and no amount of care in the
 * validator prevents it, because the validator is not the thing that connects.
 *
 * Pass the returned `lookup` to `tls.connect` or `net.connect` and the socket
 * goes to the address that was actually checked. The hostname is still used
 * for SNI and the Host header, so virtual hosting and certificate validation
 * are unaffected — which is why this works where connecting to a bare IP
 * would not.
 */
export interface PinnedHost {
  hostname: string;
  addresses: dns.LookupAddress[];
  /** Performs no DNS. Pass as the `lookup` option. */
  lookup: net.LookupFunction;
}

export async function pinPublicHost(rawHostname: string, allowPrivate = false): Promise<PinnedHost> {
  const hostname = normaliseHostname(rawHostname);
  if (!allowPrivate) assertNameAllowed(hostname);
  if (!hostname) throw new Error('Hostname is required');

  let addresses: dns.LookupAddress[];

  if (net.isIP(hostname)) {
    addresses = [{ address: hostname, family: net.isIP(hostname) }];
  } else {
    try {
      // `lookup`, not `resolve4`/`resolve6`: this is the resolver the socket
      // would have used, so the answer being pinned is the one that matters.
      addresses = await dns.promises.lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw new Error(`${hostname} could not be resolved`);
    }
  }

  if (addresses.length === 0) throw new Error(`${hostname} resolved to no addresses`);

  // Every address, not just the first: a name resolving to one public and one
  // private address would otherwise be reachable whenever the stack picked the
  // second.
  if (!allowPrivate && addresses.some((entry) => isPrivateIP(entry.address))) {
    throw new Error('This hostname resolves to a private or internal address and cannot be checked (use --allow-private to override for local testing)');
  }

  const pinned = [...addresses];

  const lookup: net.LookupFunction = (_hostname, options, callback) => {
    // The hostname argument is ignored on purpose. Consulting it would
    // reintroduce the second resolution this exists to remove.
    const requested = options?.family;
    const family =
      requested === 'IPv4' ? 4
      : requested === 'IPv6' ? 6
      : typeof requested === 'number' && requested !== 0 ? requested
      : undefined;

    const matching = family ? pinned.filter((entry) => entry.family === family) : pinned;
    if (matching.length === 0) {
      const err = new Error(`No pinned address for family ${String(family)}`) as NodeJS.ErrnoException;
      err.code = 'ENOTFOUND';
      callback(err, '');
      return;
    }

    if (options?.all) callback(null, matching);
    else callback(null, matching[0].address, matching[0].family);
  };

  return { hostname, addresses: pinned, lookup };
}
