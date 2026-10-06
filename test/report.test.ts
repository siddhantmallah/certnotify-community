import { describe, it, expect } from 'vitest';
import { formatText } from '../src/report.js';
import type { ScanReport, SSLResult } from '../src/types.js';

// picocolors may or may not colour depending on the terminal; assert on text.
const plain = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, '');

const ssl = (overrides: Partial<SSLResult>): SSLResult => ({
  hostname: 'example.com',
  valid: true,
  dateValid: true,
  authorized: true,
  authorizationError: null,
  hostnameMatch: true,
  legacyProtocols: [],
  validFrom: new Date(0).toISOString(),
  validTo: new Date(0).toISOString(),
  daysRemaining: 60,
  issuer: { organization: 'CA', commonName: 'CA', country: 'US' },
  subject: { commonName: 'example.com', altNames: ['example.com'] },
  tlsVersion: 'TLSv1.3',
  securityGrade: 'A+',
  serialNumber: '01',
  fingerprint: 'AA',
  keySize: 2048,
  algorithm: 'sha256WithRSAEncryption',
  ...overrides,
});

const report = (fields: Partial<ScanReport>): ScanReport => ({ target: 'example.com', scannedAt: new Date(0).toISOString(), ...fields });

describe('formatText', () => {
  it('shows an untrusted certificate as failing, with the reason', () => {
    const out = plain(formatText(report({
      ssl: ssl({ valid: false, authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }),
    })));
    expect(out).toContain('✗ SSL Certificate');
    expect(out).toContain('Certificate not trusted (DEPTH_ZERO_SELF_SIGNED_CERT)');
  });

  it('does not claim browsers reject a certificate whose chain is merely incomplete', () => {
    // Browsers that fetch the missing intermediate load these sites fine.
    const out = plain(formatText(report({
      ssl: ssl({ valid: false, authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }),
    })));
    expect(out).toContain('Certificate not trusted (UNABLE_TO_VERIFY_LEAF_SIGNATURE)');
    expect(out).not.toMatch(/browser/i);
  });

  it('shows a certificate issued for another name', () => {
    const out = plain(formatText(report({ ssl: ssl({ valid: false, authorized: false, hostnameMatch: false }) })));
    expect(out).toContain('Certificate is not issued for example.com');
  });

  it('shows accepted legacy protocols, and says so when support is unknown', () => {
    expect(plain(formatText(report({ ssl: ssl({ legacyProtocols: ['TLSv1', 'TLSv1.1'] }) }))))
      .toContain('Accepts legacy TLSv1 and TLSv1.1');
    expect(plain(formatText(report({ ssl: ssl({ legacyProtocols: null }) }))))
      .toContain('Legacy TLS 1.0/1.1 support could not be determined');
  });

  it('does not count blacklists that never answered as clean', () => {
    const out = plain(formatText(report({
      blacklist: { domain: 'example.com', ip: '192.0.2.1', reputation: 'clean', listedCount: 0, checkedCount: 2, errorCount: 2, results: [] },
    })));
    expect(out).toContain('listed on 0 of 2 lists checked, 2 could not be checked');
  });
});
