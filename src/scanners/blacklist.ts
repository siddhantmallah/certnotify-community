import dns from 'node:dns';
import type { BlacklistEntryResult, BlacklistResult, DnsblStatus, ReputationStatus } from '../types.js';

/**
 * Note: some of these DNSBL zones (notably Spamhaus) have commercial-use
 * query-volume policies. Fine for occasional CLI use against your own
 * domains; don't hammer them in a tight loop or from a shared/high-volume
 * service without checking each provider's terms.
 *
 * Removed in 0.5.0: SORBS (shut down in 2024), MSRBL (defunct), and Abusix
 * Mail Intelligence (answers only with an account key). None could ever
 * report a listing here, and each still counted toward "0/7 lists".
 */
const DNSBLS = [
  { name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org' },
  { name: 'Barracuda', zone: 'b.barracudacentral.org' },
  { name: 'SpamCop', zone: 'bl.spamcop.net' },
  { name: 'UCEPROTECT L1', zone: 'dnsbl-1.uceprotect.net' },
];

const LOOKUP_TIMEOUT_MS = 5000;

function reversedIP(ip: string): string {
  return ip.split('.').reverse().join('.');
}

export interface DnsblVerdict {
  status: DnsblStatus;
  answers: string[];
  error?: string;
}

/**
 * What one DNSBL lookup means. Before 0.5.0 any error or timeout read as "not
 * listed", so a list that never answered reported every address clean.
 */
export function classifyDnsblAnswer(err: { code?: string } | null, addresses: string[] = []): DnsblVerdict {
  if (err) {
    // NXDOMAIN is how a list says "not listed". Anything else is a list that did not answer.
    if (err.code === 'ENOTFOUND') return { status: 'not_listed', answers: [] };
    return { status: 'error', answers: [], error: `Lookup failed (${err.code ?? 'unknown error'})` };
  }
  // 127.255.255.x is a refusal, not a listing: Spamhaus answers 127.255.255.254
  // to queries sent through public resolvers and .255 when rate-limiting.
  const refusal = addresses.find((a) => a.startsWith('127.255.255.'));
  if (refusal) return { status: 'error', answers: addresses, error: `The list refused the query (${refusal})` };
  if (addresses.some((a) => /^127\.0\.0\.\d{1,3}$/.test(a))) return { status: 'listed', answers: addresses };
  // Anything else — typically a resolver rewriting NXDOMAIN to its own
  // search page — is not a DNSBL answer, and is not a listing.
  return { status: 'error', answers: addresses, error: `Unexpected answer (${addresses.join(', ') || 'no records'})` };
}

function queryDnsbl(name: string): Promise<DnsblVerdict> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ status: 'error', answers: [], error: 'Lookup timed out' }), LOOKUP_TIMEOUT_MS);
    dns.resolve4(name, (err, addresses) => {
      clearTimeout(timer);
      resolve(classifyDnsblAnswer(err, addresses));
    });
  });
}

/** Errored lists are counted as unchecked, never as clean. */
export function summariseDnsblResults(results: BlacklistEntryResult[]): {
  reputation: ReputationStatus | 'unknown';
  listedCount: number;
  checkedCount: number;
  errorCount: number;
} {
  const listedCount = results.filter((r) => r.status === 'listed').length;
  const errorCount = results.filter((r) => r.status === 'error').length;
  const checkedCount = results.length - errorCount;

  let reputation: ReputationStatus | 'unknown';
  if (checkedCount === 0) reputation = 'unknown';
  else if (listedCount === 0) reputation = 'clean';
  else if (listedCount <= 2) reputation = 'suspicious';
  else reputation = 'blacklisted';

  return { reputation, listedCount, checkedCount, errorCount };
}

export async function checkBlacklist(rawDomain: string): Promise<BlacklistResult> {
  const hostname = rawDomain.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();

  let ip: string | null = null;
  try {
    const addresses = await dns.promises.resolve4(hostname);
    ip = addresses[0] ?? null;
  } catch {
    // ip stays null
  }

  if (!ip) {
    return {
      domain: hostname,
      ip: null,
      reputation: 'unknown',
      listedCount: 0,
      checkedCount: 0,
      errorCount: 0,
      results: [],
      error: 'Could not resolve domain to IP',
    };
  }

  const rev = reversedIP(ip);
  const results: BlacklistEntryResult[] = await Promise.all(
    DNSBLS.map(async (bl) => {
      const verdict = await queryDnsbl(`${rev}.${bl.zone}`);
      return {
        name: bl.name,
        zone: bl.zone,
        listed: verdict.status === 'listed',
        status: verdict.status,
        answers: verdict.answers,
        ...(verdict.error ? { error: verdict.error } : {}),
      };
    })
  );

  const summary = summariseDnsblResults(results);
  const result: BlacklistResult = { domain: hostname, ip, ...summary, results };
  if (summary.checkedCount === 0) {
    result.error = `None of the ${results.length} blacklists answered, so the reputation could not be checked`;
  }
  return result;
}
