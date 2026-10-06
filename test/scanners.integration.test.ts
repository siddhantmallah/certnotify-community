/**
 * Integration tests against real, well-known, stable domains — no mocks.
 * This matches the project's own philosophy (every check is a real network
 * call against a real target), so these tests hit the actual internet and
 * require network access. They can be flaky if a third-party service
 * (RDAP, crt.sh-style endpoints, DNSBL zones) has a transient outage;
 * assertions are written to check result *shape* and known-stable facts
 * rather than volatile details (exact cert issuer, exact SPF string) that
 * are expected to change over time.
 */
import { describe, it, expect } from 'vitest';
import { checkSSL } from '../src/scanners/ssl.js';
import { checkWhois } from '../src/scanners/whois.js';
import { checkDns } from '../src/scanners/dns.js';
import { checkDnssec } from '../src/scanners/dnssec.js';
import { checkEmail } from '../src/scanners/email.js';
import { checkHeaders } from '../src/scanners/headers.js';
import { checkPorts } from '../src/scanners/ports.js';
import { checkBlacklist } from '../src/scanners/blacklist.js';
import { checkUptime } from '../src/scanners/uptime.js';

const TARGET = 'github.com';
const DNSSEC_TARGET = 'cloudflare.com'; // Cloudflare has run DNSSEC on its own domain for years — a stable fixture

describe('checkSSL (live)', () => {
  it('returns a valid certificate for a well-known HTTPS domain', async () => {
    const result = await checkSSL(TARGET);
    expect(result.valid).toBe(true);
    expect(result.authorized).toBe(true);
    expect(result.authorizationError).toBeNull();
    expect(result.hostnameMatch).toBe(true);
    expect(result.daysRemaining).toBeGreaterThan(0);
    expect(result.tlsVersion).toMatch(/^TLSv1\.[23]$/);
    expect(result.hostname).toBe(TARGET);
    // GitHub turned off TLS 1.0/1.1 in 2018.
    expect(result.legacyProtocols).toEqual([]);
  });

  it('checks www.<domain> as itself, not as the apex', async () => {
    const result = await checkSSL(`www.${TARGET}`);
    expect(result.hostname).toBe(`www.${TARGET}`);
  });

  // badssl.com publishes these hosts so that clients can be tested against them.
  it('reports a certificate for another name as untrusted and mismatched', async () => {
    const result = await checkSSL('wrong.host.badssl.com');
    expect(result.authorized).toBe(false);
    expect(result.hostnameMatch).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('reports a TLS 1.0-only server as legacy, not as a failed check', async () => {
    const result = await checkSSL('tls-v1-0.badssl.com', { port: 1010 });
    expect(result.tlsVersion).toBe('TLSv1');
    expect(result.legacyProtocols).toEqual(['TLSv1']);
    expect(result.securityGrade).toBe('D');
  });
});

describe('checkWhois (live)', () => {
  it('returns a well-shaped result whether or not the RDAP lookup itself succeeds', async () => {
    const result = await checkWhois(TARGET);
    expect(result.domain).toBe(TARGET);
    expect(typeof result.valid).toBe('boolean');
    expect(Array.isArray(result.nameServers)).toBe(true);
    expect(Array.isArray(result.status)).toBe(true);
    // Public RDAP endpoints occasionally rate-limit automated requests —
    // only assert on success shape when it actually succeeded.
    if (!result.error) {
      expect(result.nameServers.length).toBeGreaterThan(0);
    }
  });
});

describe('checkDns (live)', () => {
  it('resolves real A and MX records', async () => {
    const result = await checkDns(TARGET, ['A', 'MX']);
    const a = result.results.find((r) => r.type === 'A');
    const mx = result.results.find((r) => r.type === 'MX');
    expect(a?.records.length).toBeGreaterThan(0);
    expect(mx?.records.length).toBeGreaterThan(0);
  });

  it('reverse-resolves a well-known public IP via PTR', async () => {
    const result = await checkDns('1.1.1.1', ['PTR']);
    const ptr = result.results.find((r) => r.type === 'PTR');
    expect(ptr?.error).toBeUndefined();
    expect(ptr?.records.length).toBeGreaterThan(0);
  });
});

describe('checkDnssec (live)', () => {
  it('reports signed-valid for a domain known to run DNSSEC', async () => {
    const result = await checkDnssec(DNSSEC_TARGET);
    expect(result.status).toBe('signed-valid');
    expect(result.dnssecValid).toBe(true);
    expect(typeof result.rcode.dnskey).not.toBe('undefined');
    expect(typeof result.rcode.ds).not.toBe('undefined');
  });

  it('reports unsigned for a domain known not to run DNSSEC', async () => {
    const result = await checkDnssec(TARGET);
    expect(result.status).toBe('unsigned');
    expect(result.dnssecEnabled).toBe(false);
  });
});

describe('checkEmail (live)', () => {
  it('returns a well-graded SPF/DKIM/DMARC result', async () => {
    const result = await checkEmail(TARGET);
    expect(typeof result.spf.valid).toBe('boolean');
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(['A+', 'A', 'B', 'C', 'D', 'F']).toContain(result.grade);
  });
});

describe('checkHeaders (live)', () => {
  it('checks all 10 headers and returns a valid score/grade', async () => {
    const result = await checkHeaders(TARGET);
    expect(result.error).toBeUndefined();
    expect(result.headers).toHaveLength(10);
    expect(result.headers.find((h) => h.name === 'X-XSS-Protection')?.scored).toBe(false);
    expect(result.headers.filter((h) => h.scored)).toHaveLength(9);
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(Object.keys(result.rawHeaders).length).toBeGreaterThan(0);
  });
});

describe('checkPorts (live)', () => {
  it('finds port 443 open on a live HTTPS site and scans all 15 ports', async () => {
    const result = await checkPorts(TARGET);
    expect(result.scanned).toBe(15);
    expect(result.results.find((r) => r.port === 443)?.open).toBe(true);
  });

  it('blocks scanning a private IP by default', async () => {
    await expect(checkPorts('127.0.0.1')).rejects.toThrow();
  });

  it('allows scanning a private IP with allowPrivate', async () => {
    const result = await checkPorts('127.0.0.1', { allowPrivate: true });
    expect(result.scanned).toBe(15);
  });
});

describe('checkBlacklist (live)', () => {
  it('resolves an IP and returns a reputation verdict', async () => {
    const result = await checkBlacklist(TARGET);
    expect(result.ip).not.toBeNull();
    // `unknown` is a legitimate answer when every list times out from this network.
    expect(['clean', 'suspicious', 'blacklisted', 'unknown']).toContain(result.reputation);
    expect(result.results).toHaveLength(4);
    expect(result.checkedCount + result.errorCount).toBe(4);
    for (const r of result.results) expect(['listed', 'not_listed', 'error']).toContain(r.status);
  });
});

describe('checkUptime (live)', () => {
  it('reports a live site as up', async () => {
    const result = await checkUptime(TARGET);
    expect(result.status).toBe('up');
    expect(result.online).toBe(true);
    expect(result.responseTimeMs).toBeGreaterThan(0);
  });
});
