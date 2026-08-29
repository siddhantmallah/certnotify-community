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
};

async function doHQuery(domain: string, type: string): Promise<any> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
  const res = await fetch(url, {
    headers: { Accept: 'application/dns-json' },
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`DoH query failed: ${res.status}`);
  return res.json();
}

function cleanDomain(input: string): string {
  return input
    .replace(/^https?:\/\//i, '')
    .replace(/^www\./i, '')
    .replace(/\/.*$/, '')
    .toLowerCase()
    .trim();
}

/**
 * DNSSEC validation via Cloudflare's public DNS-over-HTTPS resolver — checks
 * the resolver's AD (Authenticated Data) bit rather than performing full
 * chain-of-trust validation locally.
 */
export async function checkDnssec(rawDomain: string): Promise<DnssecResult> {
  const domain = cleanDomain(rawDomain);

  const [dnskeyResult, dsResult, nsResult] = await Promise.allSettled([
    doHQuery(domain, 'DNSKEY'),
    doHQuery(domain, 'DS'),
    doHQuery(domain, 'NS'),
  ]);

  const dnskey = dnskeyResult.status === 'fulfilled' ? dnskeyResult.value : null;
  const ds = dsResult.status === 'fulfilled' ? dsResult.value : null;
  const ns = nsResult.status === 'fulfilled' ? nsResult.value : null;

  const hasDNSKEY = (dnskey?.Answer?.length ?? 0) > 0;
  const hasDS = (ds?.Answer?.length ?? 0) > 0;
  const nsRecords = (ns?.Answer ?? []).filter((r: any) => r.type === 2).map((r: any) => r.data);

  const adBit = dnskey?.AD === true || ds?.AD === true;
  const dnssecServFail = dnskey?.Status === 2 || ds?.Status === 2;
  const dnssecEnabled = hasDNSKEY || hasDS || adBit;
  const dnssecValid = adBit && !dnssecServFail;

  let status: DnssecStatus;
  if (dnssecServFail) status = 'error';
  else if (dnssecValid) status = 'signed-valid';
  else if (dnssecEnabled) status = 'signed-unvalidated';
  else status = 'unsigned';

  const dnskeyRecords = (dnskey?.Answer ?? []).filter((r: any) => r.type === 48);
  const dsRecords = (ds?.Answer ?? []).filter((r: any) => r.type === 43);

  return {
    domain,
    dnssecEnabled,
    dnssecValid,
    status,
    adBit,
    hasDNSKEY,
    hasDS,
    nsRecords,
    dnskeyCount: dnskeyRecords.length,
    dsCount: dsRecords.length,
    rcode: {
      dnskey: dnskey?.Status ?? null,
      ds: ds?.Status ?? null,
    },
    explanation: EXPLANATIONS[status],
  };
}
