import { describeError } from '../errors.js';
import type { DnssecResult, DnssecStatus } from '../types.js';

const EXPLANATIONS: Record<DnssecStatus, string> = {
  'signed-valid':
    'DNSSEC is enabled and validated. DNS responses for this domain are cryptographically signed and verified.',
  'signed-unvalidated':
    'DNSSEC records exist (DNSKEY/DS) but the resolver could not fully authenticate the chain. This may indicate a partial deployment.',
  unsigned:
    'DNSSEC is not enabled. DNS responses for this domain cannot be cryptographically verified, leaving it vulnerable to DNS spoofing.',
  error:
    'DNSSEC validation failed (SERVFAIL). This may indicate misconfigured DNSSEC records — browsers and resolvers may reject DNS responses.',
  unknown:
    'The DNSSEC status could not be determined because the DNS lookups failed. This is a failure of the check, not a finding about the domain.',
  nonexistent:
    'This name does not exist in DNS (NXDOMAIN), so it has no DNSSEC status. Check the spelling, and that the domain is registered and its nameservers are set.',
};

const DNSKEY = 48;
const DS = 43;
const NS = 2;
const SERVFAIL = 2;
const NXDOMAIN = 3;

interface DohRecord {
  name?: string;
  type: number;
  data: string;
}

/** Cloudflare's JSON DNS answer format; only the fields read here. */
export interface DohResponse {
  Status: number;
  AD?: boolean;
  Answer?: DohRecord[];
}

async function doHQuery(domain: string, type: string): Promise<DohResponse> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
  const res = await fetch(url, {
    headers: { Accept: 'application/dns-json' },
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`DoH query failed: ${res.status}`);
  return res.json() as Promise<DohResponse>;
}

/**
 * Scheme and path off, but `www.` kept, as in ssl.ts. www.example.com is its
 * own DNS name: often a CNAME into a CDN's zone, sometimes a delegation, and
 * the answer a resolver validates for it is that chain, not the apex's keys.
 * Nor is stripping needed for a plain name inside the apex's zone: it has no
 * DNSKEY of its own, and evaluateDnssec reads it from the AD bit (www.ietf.org
 * and www.nic.cz are signed-valid, like their apexes). Stripping only `www.`
 * also checked every other subdomain as itself.
 */
export function cleanDomain(input: string): string {
  return String(input || '')
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .toLowerCase();
}

function recordsOfType(response: DohResponse | null, type: number): DohRecord[] {
  return (response?.Answer ?? []).filter((r) => r.type === type);
}

/**
 * Decides the status from the three DoH answers (an Error where a lookup
 * failed). Pure, so the rules can be tested against real resolver answers.
 *
 * Before 0.5.0 an AD bit on either answer made a domain signed-valid. But the
 * DS answer comes from the parent: an unsigned domain under a TLD that signs
 * its denials (google.se, google.nl) gets an authenticated "no DS", and was
 * reported as validated DNSSEC. Only the DNSKEY answer speaks for the name.
 *
 * An authenticated NOERROR there with no keys is not that case. The name sits
 * inside a signed zone (mail.ietf.org, www.nic.cz) — no delegation, so no keys
 * of its own — and the resolver could only set AD by validating that zone's
 * signed proof. Its records are signed; calling it unsigned is a false finding.
 *
 * NXDOMAIN on the DNSKEY answer is `nonexistent`: a name that does not exist
 * is neither signed nor unsigned, and reporting it `unsigned` told someone
 * with a typo to go and enable DNSSEC. Zones that answer a missing name with
 * NODATA instead (Cloudflare's signed zones do) are indistinguishable from a
 * name inside a signed zone here, and read as signed-valid — true of the zone.
 */
export function evaluateDnssec(
  domain: string,
  answers: { dnskey: DohResponse | Error; ds: DohResponse | Error; ns: DohResponse | Error }
): DnssecResult {
  const dnskey = answers.dnskey instanceof Error ? null : answers.dnskey;
  const ds = answers.ds instanceof Error ? null : answers.ds;
  const ns = answers.ns instanceof Error ? null : answers.ns;

  const dnskeyRecords = recordsOfType(dnskey, DNSKEY);
  const dsRecords = recordsOfType(ds, DS);
  const hasDNSKEY = dnskeyRecords.length > 0;
  const hasDS = dsRecords.length > 0;

  const servfail = dnskey?.Status === SERVFAIL || ds?.Status === SERVFAIL;
  // NOERROR or NXDOMAIN is an answer; a failed request or REFUSED-style rcode
  // is not. Without the DNSKEY answer, "unsigned" would be a guess.
  const dnskeyAnswered = dnskey !== null && (dnskey.Status === 0 || dnskey.Status === NXDOMAIN);

  const adBit = dnskey?.Status === 0 && dnskey.AD === true;
  const dnssecEnabled = hasDNSKEY || hasDS || adBit;
  const dnssecValid = adBit && !servfail;

  let status: DnssecStatus;
  if (servfail) status = 'error';
  else if (!dnskeyAnswered) status = 'unknown';
  else if (dnskey.Status === NXDOMAIN) status = 'nonexistent';
  else if (dnssecValid) status = 'signed-valid';
  else if (dnssecEnabled) status = 'signed-unvalidated';
  else status = 'unsigned';

  const result: DnssecResult = {
    domain,
    dnssecEnabled,
    dnssecValid,
    status,
    adBit,
    hasDNSKEY,
    hasDS,
    nsRecords: recordsOfType(ns, NS).map((r) => r.data),
    dnskeyCount: dnskeyRecords.length,
    dsCount: dsRecords.length,
    rcode: {
      dnskey: dnskey?.Status ?? null,
      ds: ds?.Status ?? null,
    },
    explanation: EXPLANATIONS[status],
  };

  if (status === 'unknown') {
    result.error = answers.dnskey instanceof Error
      ? `DNSKEY lookup failed: ${describeError(answers.dnskey)}`
      : `DNSKEY lookup returned rcode ${dnskey?.Status}`;
  } else if (status === 'nonexistent') {
    result.error = `${domain} does not exist (NXDOMAIN)`;
  }

  return result;
}

/**
 * DNSSEC validation via Cloudflare's public DNS-over-HTTPS resolver — checks
 * the resolver's AD (Authenticated Data) bit rather than performing full
 * chain-of-trust validation locally.
 */
export async function checkDnssec(rawDomain: string): Promise<DnssecResult> {
  const domain = cleanDomain(rawDomain);

  const settled = await Promise.allSettled([
    doHQuery(domain, 'DNSKEY'),
    doHQuery(domain, 'DS'),
    doHQuery(domain, 'NS'),
  ]);
  const [dnskey, ds, ns] = settled.map((s) =>
    s.status === 'fulfilled' ? s.value : s.reason instanceof Error ? s.reason : new Error(String(s.reason))
  );

  return evaluateDnssec(domain, { dnskey, ds, ns });
}
