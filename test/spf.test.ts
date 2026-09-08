import { describe, it, expect } from 'vitest';
import { evaluateSpf } from '../src/scanners/email.js';

/**
 * Pure parsing tests — `evaluateSpf` takes the raw apex TXT records, so every
 * interesting case can be expressed as a plain array with no DNS involved.
 *
 * The multiple-record case is the reason this function exists separately: a
 * checker that takes the first `v=spf1` hit calls a hard-failing domain
 * healthy, and that is the failure mode these tests exist to prevent
 * regressing.
 */
describe('evaluateSpf', () => {
  const OTHER_TXT = [
    'google-site-verification=3yLmva3heBrtZRCqg-FP3uYmXl2EE1SoysRYU-o3RVo',
    'MS=ms12345678',
  ];

  it('accepts a single well-formed record', () => {
    const spf = evaluateSpf([...OTHER_TXT, 'v=spf1 include:_spf.google.com ~all']);
    expect(spf.valid).toBe(true);
    expect(spf.multipleRecords).toBe(false);
    expect(spf.error).toBeNull();
    expect(spf.mechanism).toBe('~all');
    expect(spf.records).toHaveLength(1);
  });

  it('reports no record when the domain publishes none', () => {
    const spf = evaluateSpf(OTHER_TXT);
    expect(spf.valid).toBe(false);
    expect(spf.record).toBeNull();
    expect(spf.records).toEqual([]);
    expect(spf.multipleRecords).toBe(false);
    // No record is a gap, not a permerror — only >1 record is an error.
    expect(spf.error).toBeNull();
  });

  it('fails a domain publishing two SPF records (RFC 7208 permerror)', () => {
    // This is certnotify.com's own real DNS as of 2026-09-09 — the case that
    // motivated the check. Both records are individually valid, which is
    // exactly why a first-match checker waves it through.
    const spf = evaluateSpf([
      ...OTHER_TXT,
      'v=spf1 include:_spf.mail.hostinger.com ~all',
      'v=spf1 include:_spf.mail.hostinger.com include:_spf.reach.hostinger.com ~all',
    ]);
    expect(spf.multipleRecords).toBe(true);
    expect(spf.valid).toBe(false);
    expect(spf.records).toHaveLength(2);
    expect(spf.error).toMatch(/permerror/i);
    // No mechanism is reported: there is no single record to read it from,
    // and surfacing one would imply the policy is in force. It is not.
    expect(spf.mechanism).toBeNull();
  });

  it('scores nothing for SPF when duplicates make it unevaluable', () => {
    const broken = evaluateSpf(['v=spf1 -all', 'v=spf1 include:example.com -all']);
    const healthy = evaluateSpf(['v=spf1 -all']);
    expect(broken.valid).toBe(false);
    expect(healthy.valid).toBe(true);
    expect(healthy.mechanism).toBe('-all');
  });

  it('matches the version tag case-insensitively (RFC 7208 §3.2)', () => {
    const spf = evaluateSpf(['V=SPF1 include:example.com -all']);
    expect(spf.valid).toBe(true);
    expect(spf.mechanism).toBe('-all');
  });

  it('does not mistake a TXT record that merely mentions spf1 for a record', () => {
    const spf = evaluateSpf(['note: our v=spf1 record lives on the mail subdomain']);
    expect(spf.valid).toBe(false);
    expect(spf.records).toEqual([]);
  });

  it('tolerates surrounding whitespace on the record', () => {
    const spf = evaluateSpf(['  v=spf1 include:example.com ~all']);
    expect(spf.valid).toBe(true);
  });

  it('reads every published record into records[], not just the first', () => {
    const spf = evaluateSpf(['v=spf1 a ~all', 'v=spf1 mx ~all', 'v=spf1 -all']);
    expect(spf.records).toHaveLength(3);
    expect(spf.error).toContain('3 SPF records');
  });
});
