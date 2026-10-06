import { describe, it, expect } from 'vitest';
import { gradeHeader, scoreHeaders } from '../src/scanners/headers.js';
import type { HeaderCheckResult, HeaderGrade } from '../src/types.js';

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

describe('gradeHeader — HSTS max-age is parsed, not substring-matched', () => {
  const full = (maxAge: string) => `max-age=${maxAge}; includeSubDomains; preload`;

  it('grades a max-age of a year or more as long enough, whatever its first digit', () => {
    expect(gradeHeader('Strict-Transport-Security', full('63072000'))).toBe('good');
    expect(gradeHeader('Strict-Transport-Security', full('31536000'))).toBe('good');
  });

  it('grades a short max-age that happens to start with 3 as warn', () => {
    expect(gradeHeader('Strict-Transport-Security', full('300'))).toBe('warn');
  });

  it('grades max-age=0 as bad — it tells browsers to forget HSTS', () => {
    expect(gradeHeader('Strict-Transport-Security', full('0'))).toBe('bad');
    expect(gradeHeader('Strict-Transport-Security', 'max-age=0')).toBe('bad');
  });

  it('parses directives case-insensitively, in any order, with a quoted max-age', () => {
    expect(gradeHeader('Strict-Transport-Security', 'PRELOAD ; IncludeSubDomains;MAX-AGE="31536000"')).toBe('good');
  });

  it('grades a header browsers would ignore as bad', () => {
    expect(gradeHeader('Strict-Transport-Security', 'includeSubDomains; preload')).toBe('bad');
    expect(gradeHeader('Strict-Transport-Security', 'max-age=abc')).toBe('bad');
    expect(gradeHeader('Strict-Transport-Security', 'max-age=31536000; max-age=60; includeSubDomains; preload')).toBe('bad');
  });

  it('reads only the first header when HSTS is sent twice', () => {
    expect(gradeHeader('Strict-Transport-Security', `${full('31536000')}, ${full('31536000')}`)).toBe('good');
    expect(gradeHeader('Strict-Transport-Security', `max-age=0, ${full('31536000')}`)).toBe('bad');
  });
});

describe('gradeHeader — Referrer-Policy matches whole tokens', () => {
  it('grades no-referrer-when-downgrade as warn, not as no-referrer', () => {
    expect(gradeHeader('Referrer-Policy', 'no-referrer-when-downgrade')).toBe('warn');
  });

  it('grades the strict policies as good', () => {
    expect(gradeHeader('Referrer-Policy', 'no-referrer')).toBe('good');
    expect(gradeHeader('Referrer-Policy', 'strict-origin')).toBe('good');
    expect(gradeHeader('Referrer-Policy', 'Strict-Origin-When-Cross-Origin')).toBe('good');
  });

  it('grades a fallback list by the last token a browser recognises', () => {
    expect(gradeHeader('Referrer-Policy', 'no-referrer, strict-origin-when-cross-origin')).toBe('good');
    expect(gradeHeader('Referrer-Policy', 'strict-origin-when-cross-origin, unsafe-url')).toBe('warn');
    expect(gradeHeader('Referrer-Policy', 'no-referrer, not-a-policy')).toBe('good');
  });
});

describe('gradeHeader — repeated and permissive frame/sniffing values', () => {
  it('grades X-Frame-Options ALLOWALL as bad — it permits framing by anyone', () => {
    expect(gradeHeader('X-Frame-Options', 'ALLOWALL')).toBe('bad');
  });

  it('grades a value repeated by a header sent twice like the single value', () => {
    expect(gradeHeader('X-Frame-Options', 'DENY, DENY')).toBe('good');
    expect(gradeHeader('X-Frame-Options', 'sameorigin,SAMEORIGIN')).toBe('good');
    expect(gradeHeader('X-Content-Type-Options', 'nosniff, nosniff')).toBe('good');
  });

  it('grades conflicting X-Frame-Options values as warn', () => {
    expect(gradeHeader('X-Frame-Options', 'DENY, SAMEORIGIN')).toBe('warn');
  });
});

describe('scoreHeaders', () => {
  const result = (name: string, grade: HeaderGrade): HeaderCheckResult => ({
    name,
    present: true,
    value: 'x',
    grade,
    scored: name !== 'X-XSS-Protection',
    description: '',
    recommendation: null,
  });

  it('leaves X-XSS-Protection out, so a site with every other header right scores 100', () => {
    const names = [
      'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
      'Referrer-Policy', 'Permissions-Policy', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Embedder-Policy',
      'Cross-Origin-Resource-Policy',
    ];
    const results = [...names.map((n) => result(n, 'good')), result('X-XSS-Protection', 'warn')];
    expect(scoreHeaders(results)).toEqual({ score: 100, grade: 'A+' });
  });
});
