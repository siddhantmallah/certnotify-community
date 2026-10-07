import { describe, it, expect } from 'vitest';
import { cleanDomain, evaluateDnssec, type DohResponse } from '../src/scanners/dnssec.js';

/**
 * Real Cloudflare DNS-over-HTTPS answers, trimmed to the fields read, so each
 * rule is checked against what the resolver actually sends.
 */

// github.com: no DNSKEY, no DS, and (opt-out .com) no AD.
const unsignedNodata: DohResponse = { Status: 0, AD: false };

// The DS answer for google.se: .se proves there is no DS, and the resolver
// sets AD on that proof. The DNSKEY answer comes from google.se's own,
// unsigned servers, without AD.
const parentProvesNoDs: DohResponse = { Status: 0, AD: true };

// mail.ietf.org, both answers: a name inside the signed ietf.org zone. It has
// no keys of its own, and the resolver validated ietf.org's proof of that.
const authenticatedNodata: DohResponse = { Status: 0, AD: true };

// example.se: does not exist, and .se proves it.
const authenticatedNxdomain: DohResponse = { Status: 3, AD: true };

// this-name-does-not-exist-8f3a2c.com: does not exist, under opt-out .com.
const unauthenticatedNxdomain: DohResponse = { Status: 3, AD: false };

// cloudflare.com
const signedDnskey: DohResponse = {
  Status: 0,
  AD: true,
  Answer: [
    { name: 'cloudflare.com', type: 48, data: '256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==' },
    { name: 'cloudflare.com', type: 48, data: '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==' },
  ],
};
const signedDs: DohResponse = {
  Status: 0,
  AD: true,
  Answer: [{ name: 'cloudflare.com', type: 43, data: '2371 13 2 32996839a6d808afe3eb4a795a0e6a7a39a76fc52ff228b22b76f6d63826f2b9' }],
};

const ns: DohResponse = { Status: 0, Answer: [{ type: 2, data: 'ns1.example.' }] };

describe('evaluateDnssec', () => {
  it('reports an unsigned domain as unsigned', () => {
    const r = evaluateDnssec('github.com', { dnskey: unsignedNodata, ds: unsignedNodata, ns });
    expect(r.status).toBe('unsigned');
    expect(r.dnssecEnabled).toBe(false);
  });

  it('does not read the parent\'s authenticated "no DS" as the domain being signed', () => {
    // The 0.4.1 bug: AD on this DS answer made google.se signed-valid.
    const r = evaluateDnssec('google.se', { dnskey: unsignedNodata, ds: parentProvesNoDs, ns });
    expect(r.status).toBe('unsigned');
    expect(r.dnssecEnabled).toBe(false);
    expect(r.dnssecValid).toBe(false);
    expect(r.adBit).toBe(false);
  });

  it('reads a name inside a signed zone as signed-valid, though it has no keys of its own', () => {
    const r = evaluateDnssec('mail.ietf.org', { dnskey: authenticatedNodata, ds: authenticatedNodata, ns });
    expect(r.status).toBe('signed-valid');
    expect(r.dnssecEnabled).toBe(true);
    expect(r.adBit).toBe(true);
    expect(r.hasDNSKEY).toBe(false);
  });

  it('does not read an authenticated NXDOMAIN as signed', () => {
    const r = evaluateDnssec('example.se', { dnskey: authenticatedNxdomain, ds: authenticatedNxdomain, ns });
    expect(r.status).not.toBe('signed-valid');
    expect(r.dnssecEnabled).toBe(false);
    expect(r.adBit).toBe(false);
  });

  it('reports a name that does not exist as nonexistent, not unsigned', () => {
    // Was unsigned: a typo came back telling the owner to enable DNSSEC.
    for (const nx of [authenticatedNxdomain, unauthenticatedNxdomain]) {
      const r = evaluateDnssec('typo.example', { dnskey: nx, ds: nx, ns: nx });
      expect(r.status).toBe('nonexistent');
      expect(r.error).toBe('typo.example does not exist (NXDOMAIN)');
      expect(r.explanation).toContain('does not exist');
      expect(r.dnssecValid).toBe(false);
    }
  });

  it('still reports SERVFAIL as error when the DNSKEY answer is NXDOMAIN', () => {
    const r = evaluateDnssec('broken.test', { dnskey: authenticatedNxdomain, ds: { Status: 2 }, ns });
    expect(r.status).toBe('error');
  });

  it('reports a signed, authenticated domain as signed-valid', () => {
    const r = evaluateDnssec('cloudflare.com', { dnskey: signedDnskey, ds: signedDs, ns });
    expect(r.status).toBe('signed-valid');
    expect(r.dnssecValid).toBe(true);
    expect(r.adBit).toBe(true);
    expect(r.dnskeyCount).toBe(2);
    expect(r.dsCount).toBe(1);
    expect(r.nsRecords).toEqual(['ns1.example.']);
  });

  it('requires AD on the DNSKEY answer itself — AD on the DS answer is not enough', () => {
    const r = evaluateDnssec('example.test', { dnskey: { ...signedDnskey, AD: false }, ds: signedDs, ns });
    expect(r.status).toBe('signed-unvalidated');
    expect(r.dnssecEnabled).toBe(true);
    expect(r.dnssecValid).toBe(false);
  });

  it('reports SERVFAIL as error', () => {
    const r = evaluateDnssec('broken.test', { dnskey: { Status: 2 }, ds: signedDs, ns });
    expect(r.status).toBe('error');
  });

  it('reports unknown, not unsigned, when every lookup failed', () => {
    const down = new Error('fetch failed');
    const r = evaluateDnssec('example.com', { dnskey: down, ds: down, ns: down });
    expect(r.status).toBe('unknown');
    expect(r.dnssecEnabled).toBe(false);
    expect(r.error).toContain('fetch failed');
  });

  it('reports unknown when the DNSKEY lookup failed, whatever DS said', () => {
    const r = evaluateDnssec('example.com', { dnskey: new Error('timeout'), ds: signedDs, ns });
    expect(r.status).toBe('unknown');
    expect(r.dnssecValid).toBe(false);
  });

  it('reports unknown for a DNSKEY answer with a non-answer rcode (REFUSED)', () => {
    const r = evaluateDnssec('example.com', { dnskey: { Status: 5 }, ds: unsignedNodata, ns });
    expect(r.status).toBe('unknown');
    expect(r.error).toContain('rcode 5');
  });
});

describe('cleanDomain', () => {
  it('keeps www., like the SSL check: www.example.com is its own DNS name', () => {
    expect(cleanDomain('https://www.example.com/path')).toBe('www.example.com');
  });

  it('strips the scheme whatever its case, and behind whitespace', () => {
    expect(cleanDomain('HTTPS://Example.com/')).toBe('example.com');
    expect(cleanDomain('  http://example.com ')).toBe('example.com');
  });
});
