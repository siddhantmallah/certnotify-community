import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * src/scanners/pinnedFetch.ts — GET/HEAD without the DNS-rebinding window.
 *
 * DNS is replaced so the attack can be staged exactly: the first answer is
 * the address of a real local server, every later answer an address nothing
 * listens on. Pinned, the request reaches the server; resolving a second
 * time, it would not. `allowPrivate` is on only so a loopback server can
 * stand in for the "public" host; the refusal tests run with it off.
 */

const dnsState = vi.hoisted(() => ({
  answers: new Map<string, Array<Array<{ address: string; family: number }>>>(),
  calls: [] as string[],
}));
vi.mock('node:dns', async (orig) => {
  const actual = (await orig()) as typeof import('node:dns');
  const lookup = async (host: string) => {
    dnsState.calls.push(host);
    const queue = dnsState.answers.get(host);
    if (!queue || !queue.length) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    return queue.length > 1 ? queue.shift()! : queue[0];
  };
  const promises = { ...actual.promises, lookup };
  return { ...actual, promises, default: { ...actual, promises } };
});

import { pinnedFetch } from '../src/scanners/pinnedFetch.js';
import { sitemapPages } from '../src/scanners/mixedContent.js';

let server: http.Server;
let port = 0;
const hits: string[] = [];

beforeAll(async () => {
  server = http.createServer((req, res) => {
    hits.push(`${req.headers.host}${req.url}`);
    if (req.url === '/hop') { res.writeHead(302, { location: `http://second.test:${port}/end` }); res.end(); return; }
    if (req.url === '/to-metadata') { res.writeHead(302, { location: 'http://metadata.test/latest' }); res.end(); return; }
    if (req.url === '/big') { res.writeHead(200); res.end('x'.repeat(10_000)); return; }
    res.writeHead(200, { 'x-from': 'local' });
    res.end('hello');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => {
  dnsState.answers.clear();
  dnsState.calls.length = 0;
  hits.length = 0;
});

const LOCAL = [{ address: '127.0.0.1', family: 4 }];
const NOWHERE = [{ address: '10.255.255.1', family: 4 }];

describe('pinnedFetch', () => {
  it('connects to the address it validated, even when DNS changes its answer', async () => {
    dnsState.answers.set('rebind.test', [LOCAL, NOWHERE]);
    const res = await pinnedFetch(`http://rebind.test:${port}/`, { allowPrivate: true, timeoutMs: 3000 });
    expect(await res.text()).toBe('hello');
    expect(res.headers.get('x-from')).toBe('local');
    expect(dnsState.calls).toEqual(['rebind.test']);
    // SNI/Host keep the name; only the address was pinned.
    expect(hits).toEqual([`rebind.test:${port}/`]);
  });

  it('refuses a name that resolves to a private address', async () => {
    dnsState.answers.set('internal.test', [[{ address: '169.254.169.254', family: 4 }]]);
    await expect(pinnedFetch('http://internal.test/')).rejects.toThrow();
    expect(hits).toEqual([]);
  });

  it('refuses a literal private address', async () => {
    await expect(pinnedFetch(`http://127.0.0.1:${port}/`)).rejects.toThrow();
    expect(hits).toEqual([]);
  });

  it('re-pins every redirect hop and reports the final URL', async () => {
    dnsState.answers.set('first.test', [LOCAL]);
    dnsState.answers.set('second.test', [LOCAL]);
    const res = await pinnedFetch(`http://first.test:${port}/hop`, { allowPrivate: true, timeoutMs: 3000 });
    expect(res.status).toBe(200);
    expect(res.redirected).toBe(true);
    expect(res.url).toBe(`http://second.test:${port}/end`);
    expect(dnsState.calls).toEqual(['first.test', 'second.test']);
  });

  it('resolves and checks a redirect target itself, rather than following blind', async () => {
    // The loopback stand-in needs allowPrivate, so this cannot show the
    // refusal (the guard's own tests do); it shows the redirect target is
    // put through the guard at all — its own lookup, its own pin.
    dnsState.answers.set('public.test', [LOCAL]);
    dnsState.answers.set('metadata.test', [[{ address: '169.254.169.254', family: 4 }]]);
    await pinnedFetch(`http://public.test:${port}/to-metadata`, { allowPrivate: true, timeoutMs: 2000 }).catch(() => undefined);
    expect(dnsState.calls).toEqual(['public.test', 'metadata.test']);
  });

  it('caps the body', async () => {
    dnsState.answers.set('big.test', [LOCAL]);
    const res = await pinnedFetch(`http://big.test:${port}/big`, { allowPrivate: true, maxBytes: 100, timeoutMs: 3000 });
    expect((await res.text()).length).toBe(100);
  });

  it('refuses non-HTTP schemes', async () => {
    await expect(pinnedFetch('file:///etc/passwd')).rejects.toThrow(/file:/);
  });
});

describe('sitemapPages', () => {
  it("keeps only https URLs on the scanned site's own host", () => {
    const xml = `
      <urlset>
        <url><loc>https://example.com/a</loc></url>
        <url><loc> https://example.com/b </loc></url>
        <url><loc>http://example.com/plain</loc></url>
        <url><loc>https://10.0.0.5/admin</loc></url>
        <url><loc>https://169.254.169.254/latest/meta-data</loc></url>
        <url><loc>https://evil.example.net/</loc></url>
        <url><loc>https://sub.example.com/</loc></url>
        <url><loc>not a url</loc></url>
      </urlset>`;
    expect(sitemapPages(xml, 'example.com')).toEqual(['https://example.com/a', 'https://example.com/b']);
  });
});
