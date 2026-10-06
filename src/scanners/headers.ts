import { assertPublicHostname } from './ssrfGuard.js';
import type { HeaderCheckResult, HeaderGrade, HeadersResult } from '../types.js';
import { pinnedFetch } from './pinnedFetch.js';
import { USER_AGENT } from '../version.js';

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

// Reported but not scored: its best possible grade is warn (browsers removed
// the filter it controls, which introduced XSS of its own), so counting it
// capped every site at 90.
const UNSCORED_HEADERS = new Set(['x-xss-protection']);

/** One year: the preload list's floor, and the value the recommendation names. */
const HSTS_MIN_MAX_AGE = 31536000;

const REFERRER_POLICIES = new Set([
  'no-referrer',
  'no-referrer-when-downgrade',
  'same-origin',
  'origin',
  'strict-origin',
  'origin-when-cross-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
]);

const GOOD_REFERRER_POLICIES = new Set(['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']);

/** A header sent more than once arrives as one value joined with ", ". */
function headerValues(value: string): string[] {
  return value.split(',').map((v) => v.trim().toLowerCase()).filter(Boolean);
}

function gradeHsts(value: string): HeaderGrade {
  // A browser honours only the first HSTS header in a response (RFC 6797 §8.1).
  const first = value.split(',')[0];
  const directives = new Set<string>();
  let maxAge: number | null = null;

  for (const part of first.split(';')) {
    const directive = part.trim();
    if (!directive) continue;
    const eq = directive.indexOf('=');
    const name = (eq === -1 ? directive : directive.slice(0, eq)).trim().toLowerCase();
    // A repeated directive invalidates the whole header (§6.1); browsers drop it.
    if (directives.has(name)) return 'bad';
    directives.add(name);
    if (name === 'max-age') {
      const raw = eq === -1 ? '' : directive.slice(eq + 1).trim().replace(/^"(.*)"$/, '$1');
      if (!/^\d+$/.test(raw)) return 'bad';
      maxAge = Number(raw);
    }
  }

  // Without max-age the header is ignored, and max-age=0 tells the browser to
  // forget HSTS for this host. A substring test for "max-age=3" passed
  // max-age=300 as good and failed max-age=63072000 (two years).
  if (maxAge === null || maxAge === 0) return 'bad';
  if (maxAge >= HSTS_MIN_MAX_AGE && directives.has('includesubdomains') && directives.has('preload')) return 'good';
  return 'warn';
}

export function gradeHeader(name: string, value: string | null): HeaderGrade {
  if (!value) return 'bad';
  const v = value.toLowerCase();
  switch (name.toLowerCase()) {
    case 'strict-transport-security':
      return gradeHsts(value);
    case 'content-security-policy':
      if (v.includes("'unsafe-inline'") || v.includes("'unsafe-eval'")) return 'warn';
      return 'good';
    case 'x-frame-options': {
      // Repeated values ("DENY, DENY") collapse to one. Conflicting values
      // block framing in browsers but are still a misconfiguration. ALLOWALL
      // is no typo: it permits framing by anyone, which is the attack.
      const values = new Set(headerValues(value));
      if (values.size !== 1) return 'warn';
      const [only] = values;
      if (only === 'allowall') return 'bad';
      return only === 'deny' || only === 'sameorigin' ? 'good' : 'warn';
    }
    case 'x-content-type-options':
      // Fetch reads only the first value, so a header sent twice still applies.
      return headerValues(value)[0] === 'nosniff' ? 'good' : 'warn';
    case 'referrer-policy': {
      // Browsers keep the last token they recognise (the list is a fallback
      // chain), so that token is the policy in force. A substring match on
      // "no-referrer" graded no-referrer-when-downgrade — the full URL to every
      // HTTPS site — as good.
      const policy = headerValues(value).filter((token) => REFERRER_POLICIES.has(token)).pop();
      return policy && GOOD_REFERRER_POLICIES.has(policy) ? 'good' : 'warn';
    }
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

export function scoreHeaders(results: HeaderCheckResult[]): { score: number; grade: string } {
  const scored = results.filter((r) => r.scored);
  const good = scored.filter((r) => r.grade === 'good').length;
  const score = scored.length === 0 ? 0 : Math.round((good / scored.length) * 100);

  let grade = 'F';
  if (score >= 90) grade = 'A+';
  else if (score >= 75) grade = 'A';
  else if (score >= 60) grade = 'B';
  else if (score >= 45) grade = 'C';
  else if (score >= 30) grade = 'D';

  return { score, grade };
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
      rawHeaders: {},
      error: err.message ?? 'This hostname is not allowed',
    };
  }

  const url = `https://${domain}`;

  try {
    // Pinned: the socket goes to the address just validated, on every
    // redirect hop, not to a second resolution of the name.
    const res = await pinnedFetch(url, {
      method: 'GET',
      timeoutMs: 10000,
      headers: { 'User-Agent': USER_AGENT },
      allowPrivate: opts.allowPrivate,
    });

    const results: HeaderCheckResult[] = SECURITY_HEADERS.map((h) => {
      const value = res.headers.get(h.name);
      return {
        name: h.name,
        present: value !== null,
        value,
        grade: gradeHeader(h.name, value),
        scored: !UNSCORED_HEADERS.has(h.name.toLowerCase()),
        description: h.description,
        recommendation: value ? null : h.recommendation,
      };
    });

    const { score, grade } = scoreHeaders(results);

    // Every header the server actually sent, beyond just the ones checked
    // above — lets a consumer inspect anything else (e.g. Cache-Control)
    // without a second network round-trip.
    const rawHeaders: Record<string, string> = {};
    res.headers.forEach((value, key) => { rawHeaders[key] = value; });

    return { domain, url, finalUrl: res.url, statusCode: res.status, score, grade, headers: results, rawHeaders };
  } catch (err: any) {
    return {
      domain,
      url,
      finalUrl: url,
      statusCode: null,
      score: 0,
      grade: 'F',
      headers: [],
      rawHeaders: {},
      error: err.message ?? 'Failed to check security headers',
    };
  }
}
