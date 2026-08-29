import { describe, it, expect } from 'vitest';
import { parsePrivacyStatus, extractContactInfo } from '../src/scanners/whoisPrivacy.js';

describe('parsePrivacyStatus', () => {
  it('detects a WhoisGuard-protected domain', () => {
    const text = 'roles: registrant\norg: WhoisGuard, Inc.\nfn: WhoisGuard Protected';
    const { isPrivate, provider } = parsePrivacyStatus(text);
    expect(isPrivate).toBe(true);
    expect(provider).toBe('WhoisGuard');
  });

  it('detects Domains By Proxy', () => {
    const { isPrivate, provider } = parsePrivacyStatus('org: Domains By Proxy, LLC');
    expect(isPrivate).toBe(true);
    expect(provider).toBe('Domains By Proxy');
  });

  it('falls back to "Unknown Privacy Service" for an unrecognized privacy keyword', () => {
    const { isPrivate, provider } = parsePrivacyStatus('fn: REDACTED FOR PRIVACY\norg: Data Redacted');
    expect(isPrivate).toBe(true);
    expect(provider).toBe('Unknown Privacy Service');
  });

  it('reports no privacy protection for a fully public registration', () => {
    const text = 'roles: registrant\nfn: Jane Doe\norg: Example Corp\nemail: jane@example.com';
    const { isPrivate, provider } = parsePrivacyStatus(text);
    expect(isPrivate).toBe(false);
    expect(provider).toBeNull();
  });
});

describe('extractContactInfo', () => {
  it('extracts a public registrant name, email, and org', () => {
    const text = 'registrant name: Jane Doe\nregistrant email: jane@example.com\norganization: Example Corp';
    const info = extractContactInfo(text);
    expect(info.name).toBe('Jane Doe');
    expect(info.email).toBe('jane@example.com');
    expect(info.organization).toBe('Example Corp');
  });

  it('does not extract a name/org marked as redacted', () => {
    const text = 'registrant name: REDACTED FOR PRIVACY\norganization: Redacted';
    const info = extractContactInfo(text);
    expect(info.name).toBeNull();
    expect(info.organization).toBeNull();
  });

  it('does not extract a privacy-service email address', () => {
    const text = 'registrant email: abc123@privacy.whoisguard.com';
    const info = extractContactInfo(text);
    expect(info.email).toBeNull();
  });

  it('extracts a phone number when present and not redacted', () => {
    // The extraction regex's character class is digits/space/dash/parens
    // (no dot) — matches the original app's behavior verbatim.
    const info = extractContactInfo('registrant phone: +1 415-555-1234');
    expect(info.phone).toBe('+1 415-555-1234');
  });
});
