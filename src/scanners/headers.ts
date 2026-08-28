import { assertPublicHostname } from './ssrfGuard.js';
import type { HeaderCheckResult, HeaderGrade, HeadersResult } from '../types.js';

/**
 * Canonical security-headers rubric. The original app had three divergent,
 * inconsistent implementations of this check (a `services/` module and two
 * separate API routes with different header lists and scoring); this is the
 * single consolidated version — the quality-aware grading (good/warn/bad,
 * not just presence/absence) from the more sophisticated of the three,
 * extended with the modern cross-origin isolation headers from the other.
 */
const SECURITY_HEADERS: { name: string; description: string; recommendation: string }[] = [
  {
    name: 'Strict-Transport-Security',
    description: 'Forces browsers to use HTTPS for all future requests to the domain.',
    recommendation: 'Set to: max-age=31536000; includeSubDomains; preload',
  },
  {
    name: 'Content-Security-Policy',
    description: 'Restricts sources of content (scripts, styles, images) to prevent XSS attacks.',
    recommendation: 'Implement a strict CSP policy appropriate for your site.',
  },
  {
    name: 'X-Frame-Options',
    description: 'Prevents the page from being embedded in iframes (clickjacking protection).',
    recommendation: 'Set to: DENY or SAMEORIGIN',
  },
  {
    name: 'X-Content-Type-Options',
    description: 'Prevents browsers from MIME-sniffing the content type.',
    recommendation: 'Set to: nosniff',
  },
  {
    name: 'Referrer-Policy',
    description: 'Controls how much referrer information is sent with requests.',
    recommendation: 'Set to: strict-origin-when-cross-origin or no-referrer',
  },
  {
    name: 'Permissions-Policy',
    description: 'Controls which browser features and APIs can be used on the page.',
    recommendation: 'Restrict camera, microphone, geolocation as appropriate.',
  },
  {
    name: 'X-XSS-Protection',
    description: 'Legacy XSS filter for older browsers (modern browsers use CSP instead).',
    recommendation: 'Set to: 1; mode=block (though CSP is preferred)',
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    description: 'Isolates the browsing context from cross-origin windows to mitigate side-channel attacks.',
    recommendation: 'Set to: same-origin',
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    description: 'Requires cross-origin resources to explicitly opt in to being loaded.',
    recommendation: 'Set to: require-corp',
  },
  {
    name: 'Cross-Origin-Resource-Policy',
    description: 'Controls which origins can embed this resource.',
    recommendation: 'Set to: same-origin or same-site',
  },
];

function gradeHeader(name: string, value: string | null): HeaderGrade {
  if (!value) return 'bad';
  const v = value.toLowerCase();
  switch (name.toLowerCase()) {
    case 'strict-transport-security':
      if (v.includes('preload') && v.includes('includesubdomains') && v.includes('max-age=3')) return 'good';
      if (v.includes('max-age=')) return 'warn';
      return 'bad';
    case 'content-security-policy':
      if (v.includes("'unsafe-inline'") || v.includes("'unsafe-eval'")) return 'warn';
      return 'good';
    case 'x-frame-options':
      return v === 'deny' || v === 'sameorigin' ? 'good' : 'warn';
    case 'x-content-type-options':
      return v === 'nosniff' ? 'good' : 'warn';
    case 'referrer-policy':
      return v.includes('no-referrer') || v.includes('strict-origin') ? 'good' : 'warn';
    case 'permissions-policy':
      return 'good';
    case 'x-xss-protection':
      return v.includes('1') ? 'warn' : 'bad';
    case 'cross-origin-opener-policy':
      return v.includes('same-origin') ? 'good' : 'warn';
    case 'cross-origin-embedder-policy':
      return v.includes('require-corp') || v.includes('credentialless') ? 'good' : 'warn';
    case 'cross-origin-resource-policy':
      return v.includes('same-origin') || v.includes('same-site') ? 'good' : 'warn';
    default:
      return 'warn';
  }
}

export async function checkHeaders(rawDomain: string, opts: { allowPrivate?: boolean } = {}): Promise<HeadersResult> {
  const domain = rawDomain.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase().trim();

  try {
    await assertPublicHostname(domain, opts.allowPrivate);
  } catch (err: any) {
    return {
      domain,
      url: `https://${domain}`,
      finalUrl: `https://${domain}`,
      statusCode: null,
      score: 0,
      grade: 'F',
      headers: [],
      error: err.message ?? 'This hostname is not allowed',
    };
  }

  const url = `https://${domain}`;

  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
      headers: { 'User-Agent': 'certnotify-cli/0.1 (+https://www.certnotify.com)' },
    });

    const results: HeaderCheckResult[] = SECURITY_HEADERS.map((h) => {
      const value = res.headers.get(h.name);
      return {
        name: h.name,
        present: value !== null,
        value,
        grade: gradeHeader(h.name, value),
        description: h.description,
        recommendation: value ? null : h.recommendation,
      };
    });

    const good = results.filter((r) => r.grade === 'good').length;
    const score = Math.round((good / results.length) * 100);

    let grade = 'F';
    if (score >= 90) grade = 'A+';
    else if (score >= 75) grade = 'A';
    else if (score >= 60) grade = 'B';
    else if (score >= 45) grade = 'C';
    else if (score >= 30) grade = 'D';

    return { domain, url, finalUrl: res.url, statusCode: res.status, score, grade, headers: results };
  } catch (err: any) {
    return {
      domain,
      url,
      finalUrl: url,
      statusCode: null,
      score: 0,
      grade: 'F',
      headers: [],
      error: err.message ?? 'Failed to check security headers',
    };
  }
}
