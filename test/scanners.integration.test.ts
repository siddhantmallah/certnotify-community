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
    expect(result.daysRemaining).toBeGreaterThan(0);
    expect(result.tlsVersion).toMatch(/^TLSv1\.[23]$/);
    expect(result.hostname).toBe(TARGET);
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
    expect(['clean', 'suspicious', 'blacklisted']).toContain(result.reputation);
    expect(result.results).toHaveLength(7);
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
