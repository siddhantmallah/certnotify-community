import { describe, it, expect } from 'vitest';
import { compositeScore } from '../src/score.js';
import type { ScanReport } from '../src/types.js';

function baseReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return { target: 'example.com', scannedAt: new Date(0).toISOString(), ...overrides };
}

describe('compositeScore', () => {
  it('returns null when no scored checks are present', () => {
    expect(compositeScore(baseReport())).toBeNull();
  });

  it('returns 100 when every present check is fully healthy', () => {
    const report = baseReport({
      ssl: { valid: true } as any,
      dnssec: { status: 'signed-valid' } as any,
      email: { score: 100 } as any,
      headers: { score: 100 } as any,
      ports: { riskLevel: 'low' } as any,
      blacklist: { reputation: 'clean' } as any,
      uptime: { status: 'up' } as any,
    });
    expect(compositeScore(report)).toBe(100);
  });

  it('returns 0 when every present check is maximally unhealthy', () => {
    const report = baseReport({
      ssl: { valid: false } as any,
      dnssec: { status: 'unsigned' } as any,
      email: { score: 0 } as any,
      headers: { score: 0 } as any,
      ports: { riskLevel: 'critical' } as any,
      blacklist: { reputation: 'blacklisted' } as any,
      uptime: { status: 'down' } as any,
    });
    expect(compositeScore(report)).toBe(0);
  });

  it('a single failing check pulls the score down but does not zero it out', () => {
    const allGoodExceptSsl = baseReport({
      ssl: { valid: false } as any,
      email: { score: 100 } as any,
      headers: { score: 100 } as any,
    });
    const score = compositeScore(allGoodExceptSsl)!;
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThan(100);
  });

  it('ignores checks that errored out instead of crashing', () => {
    const report = baseReport({
      ssl: { error: 'timeout' } as any,
      email: { score: 80 } as any,
    });
    expect(compositeScore(report)).toBe(80);
  });

  it('leaves an unknown blacklist reputation out of the score instead of scoring it clean', () => {
    // Every list timing out used to score 100, the same as a clean result.
    expect(compositeScore(baseReport({ blacklist: { reputation: 'unknown' } as any }))).toBeNull();
    expect(compositeScore(baseReport({ blacklist: { reputation: 'unknown' } as any, email: { score: 40 } as any }))).toBe(40);
  });

  it('leaves an unknown DNSSEC status out of the score instead of scoring it unsigned', () => {
    const report = baseReport({ dnssec: { status: 'unknown' } as any, email: { score: 80 } as any });
    expect(compositeScore(report)).toBe(80);
  });

  it('scores an in-date but untrusted certificate as a failure', () => {
    // The shape checkSSL now returns for a self-signed certificate.
    const report = baseReport({ ssl: { valid: false, dateValid: true, authorized: false, legacyProtocols: [] } as any });
    expect(compositeScore(report)).toBe(0);
  });

  it('gives half marks to a trusted certificate on a server that still accepts legacy TLS', () => {
    expect(compositeScore(baseReport({ ssl: { valid: true, legacyProtocols: ['TLSv1'] } as any }))).toBe(50);
    expect(compositeScore(baseReport({ ssl: { valid: true, legacyProtocols: [] } as any }))).toBe(100);
    // Unknown legacy support is not penalised.
    expect(compositeScore(baseReport({ ssl: { valid: true, legacyProtocols: null } as any }))).toBe(100);
  });
});
