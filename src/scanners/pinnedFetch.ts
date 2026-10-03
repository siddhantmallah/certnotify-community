import http from 'node:http';
import https from 'node:https';
import { pinPublicHost } from './ssrfGuard.js';

/**
 * A GET/HEAD to a host somebody else chose, without the DNS-rebinding window.
 *
 * The scanners used to do this:
 *
 *   await assertPublicHostname(host);   // resolve #1: public — passes
 *   await fetch(`https://${host}`);     // resolve #2: whatever DNS says now
 *
 * Two independent lookups, and whoever controls the domain's DNS can answer
 * them differently. Here there is one: `pinPublicHost` resolves and validates,
 * and the request's socket gets *those addresses* through the `lookup`
 * option, so it can only land where the check looked. The name still goes in
 * SNI and the Host header, so TLS and virtual hosting are unaffected.
 *
 * Redirects are followed by hand and every hop is re-pinned — a public host
 * redirecting to an internal one is the same attack with one more step.
 *
 * Built on node:http/https rather than a fetch client so the package keeps
 * its two dependencies and its Node 18 floor; `lookup` is the one hook the
 * built-ins offer, and it is exactly the one needed.
 */

export interface PinnedResponse {
  status: number;
  ok: boolean;
  /** The URL the final response came from, after redirects. */
  url: string;
  redirected: boolean;
  headers: Headers;
  text(): Promise<string>;
}

export interface PinnedFetchOptions {
  method?: 'GET' | 'HEAD';
  headers?: Record<string, string>;
  /** Across every hop. */
  timeoutMs?: number;
  maxRedirects?: number;
  /** Body bytes kept; the rest is discarded, not an error. */
  maxBytes?: number;
  /** For local CLI testing only — the same switch the guard has. */
  allowPrivate?: boolean;
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export async function pinnedFetch(input: string, opts: PinnedFetchOptions = {}): Promise<PinnedResponse> {
  const method = opts.method ?? 'GET';
  const maxRedirects = opts.maxRedirects ?? 5;
  const maxBytes = opts.maxBytes ?? 2 * 1024 * 1024;
  const deadline = Date.now() + (opts.timeoutMs ?? 10_000);

  let url = new URL(input);
  for (let hop = 0; ; hop++) {
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      throw new Error(`Refusing to fetch a ${url.protocol} URL`);
    }
    const pinned = await pinPublicHost(url.hostname, opts.allowPrivate);
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error('The request timed out');

    const res = await requestOnce(url, method, opts.headers ?? {}, pinned.lookup, remaining, maxBytes);
    const location = res.headers.get('location');
    if (REDIRECTS.has(res.status) && location && hop < maxRedirects) {
      url = new URL(location, url);
      continue;
    }
    const body = res.body;
    return {
      status: res.status,
      ok: res.status >= 200 && res.status < 300,
      url: url.toString(),
      redirected: hop > 0,
      headers: res.headers,
      text: async () => body.toString('utf8'),
    };
  }
}

function requestOnce(
  url: URL,
  method: string,
  headers: Record<string, string>,
  lookup: NonNullable<http.RequestOptions['lookup']>,
  timeoutMs: number,
  maxBytes: number,
): Promise<{ status: number; headers: Headers; body: Buffer }> {
  const lib = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(
      url,
      {
        method,
        headers,
        // The pin. Without it the socket resolves the name a second time.
        lookup,
        // `URL` keeps IPv6 literals bracketed; SNI wants the bare name.
        servername: url.hostname.replace(/^\[|\]$/g, ''),
        // One socket per request: a pooled socket could outlive its pin.
        agent: false,
        timeout: timeoutMs,
      },
      (res) => {
        const out = new Headers();
        for (const [k, v] of Object.entries(res.headers)) {
          if (v === undefined) continue;
          for (const value of Array.isArray(v) ? v : [v]) out.append(k, value);
        }
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          if (total >= maxBytes) return;
          const room = maxBytes - total;
          chunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
          total += Math.min(chunk.length, room);
          if (total >= maxBytes) res.destroy();
        });
        const done = () => resolve({ status: res.statusCode ?? 0, headers: out, body: Buffer.concat(chunks) });
        res.on('end', done);
        res.on('close', done);
        res.on('error', (e) => (total >= maxBytes ? done() : reject(e)));
      },
    );
    req.on('timeout', () => req.destroy(new Error('The request timed out')));
    req.on('error', reject);
    req.end();
  });
}
