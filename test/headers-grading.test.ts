import { describe, it, expect } from 'vitest';
import { gradeHeader } from '../src/scanners/headers.js';

describe('gradeHeader', () => {
  it('grades a missing header as bad', () => {
    expect(gradeHeader('Strict-Transport-Security', null)).toBe('bad');
  });

  it('grades a full HSTS policy (preload + includeSubDomains + long max-age) as good', () => {
    expect(gradeHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')).toBe('good');
  });

  it('grades a bare HSTS max-age (no preload/subdomains) as warn', () => {
    expect(gradeHeader('Strict-Transport-Security', 'max-age=3600')).toBe('warn');
  });

  it('grades a CSP with unsafe-inline as warn, otherwise good', () => {
    expect(gradeHeader('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'")).toBe('warn');
    expect(gradeHeader('Content-Security-Policy', "default-src 'self'")).toBe('good');
  });

  it('grades X-Frame-Options DENY/SAMEORIGIN as good, anything else as warn', () => {
    expect(gradeHeader('X-Frame-Options', 'DENY')).toBe('good');
    expect(gradeHeader('X-Frame-Options', 'SAMEORIGIN')).toBe('good');
    expect(gradeHeader('X-Frame-Options', 'ALLOW-FROM https://example.com')).toBe('warn');
  });

  it('grades X-Content-Type-Options nosniff as good, anything else as warn', () => {
    expect(gradeHeader('X-Content-Type-Options', 'nosniff')).toBe('good');
    expect(gradeHeader('X-Content-Type-Options', 'garbage')).toBe('warn');
  });

  it('grades Cross-Origin-Opener-Policy same-origin as good', () => {
    expect(gradeHeader('Cross-Origin-Opener-Policy', 'same-origin')).toBe('good');
    expect(gradeHeader('Cross-Origin-Opener-Policy', 'unsafe-none')).toBe('warn');
  });

  it('treats an unrecognized header name as warn rather than crashing', () => {
    expect(gradeHeader('X-Some-Unknown-Header', 'anything')).toBe('warn');
  });
});
