import dns from 'node:dns';
import type { BlacklistEntryResult, BlacklistResult, ReputationStatus } from '../types.js';

/**
 * Note: some of these DNSBL zones (notably Spamhaus) have commercial-use
 * query-volume policies. Fine for occasional CLI use against your own
 * domains; don't hammer them in a tight loop or from a shared/high-volume
 * service without checking each provider's terms.
 */
const DNSBLS = [
  { name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org' },
  { name: 'Barracuda', zone: 'b.barracudacentral.org' },
  { name: 'SpamCop', zone: 'bl.spamcop.net' },
  { name: 'SORBS', zone: 'dnsbl.sorbs.net' },
  { name: 'UCEPROTECT L1', zone: 'dnsbl-1.uceprotect.net' },
  { name: 'Abusix Mail Intel', zone: 'combined.mail.abusix.zone' },
  { name: 'MSRBL', zone: 'combined.rbl.msrbl.net' },
];

function reversedIP(ip: string): string {
  return ip.split('.').reverse().join('.');
}

async function checkDNSBL(reversedIp: string, zone: string): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    dns.resolve4(`${reversedIp}.${zone}`, (err) => {
      if (!settled) {
        settled = true;
        resolve(!err);
      }
    });
    setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve(false);
      }
    }, 5000);
  });
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
    return { domain: hostname, ip: null, reputation: 'unknown', listedCount: 0, results: [], error: 'Could not resolve domain to IP' };
  }

  const rev = reversedIP(ip);
  const results: BlacklistEntryResult[] = await Promise.all(
    DNSBLS.map(async (bl) => ({ name: bl.name, zone: bl.zone, listed: await checkDNSBL(rev, bl.zone) }))
  );

  const listedCount = results.filter((r) => r.listed).length;
  const reputation: ReputationStatus = listedCount === 0 ? 'clean' : listedCount <= 2 ? 'suspicious' : 'blacklisted';

  return { domain: hostname, ip, reputation, listedCount, results };
}
