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

  it('treats an unknown blacklist reputation as neutral (100), not a penalty', () => {
    const report = baseReport({ blacklist: { reputation: 'unknown' } as any });
    expect(compositeScore(report)).toBe(100);
  });
});
