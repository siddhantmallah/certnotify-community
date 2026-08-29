import dns from 'node:dns';
import { readState, writeState, type StateOptions } from '../state.js';
import type { SubdomainCandidate, SubdomainDiscoveryResult } from '../types.js';

const COMMON_SUBDOMAINS = [
  'www', 'api', 'admin', 'app', 'staging', 'dev', 'mail', 'portal', 'cdn', 'status',
  'm', 'beta', 'test', 'uat', 'auth', 'login', 'docs', 'help', 'support', 'blog',
  'shop', 'store', 'checkout', 'pay', 'assets', 'img', 'media', 'files', 'static', 'edge',
  'dashboard', 'panel', 'client', 'partners', 'sso', 'vpn', 'gw', 'gateway', 'db', 'cache',
  'smtp', 'imap', 'pop', 'mx', 'ns1', 'ns2', 'monitor', 'metrics', 'alerts', 'events',
  'jobs', 'queue', 'worker', 'internal', 'intranet', 'crm', 'erp', 'billing', 'finance', 'hr',
  'kibana', 'grafana', 'jenkins', 'git', 'gitlab', 'jira', 'confluence', 'wiki', 'backup', 'cdn2',
];

interface CTCert {
  name_value: string;
}

/**
 * Passive discovery via Certificate Transparency logs — every certificate
 * ever issued for the domain (including SANs and wildcards) is public,
 * so this surfaces real subdomains an operator actually uses, not just
 * guesses. Same crt.sh endpoint/pattern the CertNotify dashboard's own CT
 * monitoring feature uses.
 */
async function queryCtLogs(domain: string): Promise<{ hosts: Set<string>; ok: boolean }> {
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      headers: { Accept: 'application/json', 'User-Agent': 'certnotify-cli/0.2 (+https://www.certnotify.com)' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return { hosts: new Set(), ok: false };
    const text = await res.text();
    if (!text.trim()) return { hosts: new Set(), ok: false };
    const raw: CTCert[] = JSON.parse(text);

    const hosts = new Set<string>();
    for (const cert of raw) {
      for (const line of String(cert.name_value ?? '').split('\n')) {
        const host = line.trim().toLowerCase();
        if (host && !host.startsWith('*.') && host.endsWith(`.${domain}`)) hosts.add(host);
      }
    }
    return { hosts, ok: true };
  } catch {
    return { hosts: new Set(), ok: false };
  }
}

function resolveAny(hostname: string): Promise<boolean> {
  return dns.promises
    .resolveAny(hostname)
    .then((records) => Array.isArray(records) && records.length > 0)
    .catch(() => false);
}

/**
 * Subdomain discovery: combines real passive discovery from Certificate
 * Transparency logs with the common-prefix brute-force probe as a
 * supplement (useful for domains with sparse CT history, e.g. wildcard-
 * only certs that never reveal individual hostnames). Every candidate is
 * verified to actually resolve before being reported as discovered.
 */
export async function discoverSubdomains(rawDomain: string, opts: StateOptions & { limit?: number } = {}): Promise<SubdomainDiscoveryResult> {
  const domain = rawDomain.replace(/^https?:\/\//i, '').replace(/^www\./i, '').replace(/\/.*$/, '').toLowerCase().trim();
  const limit = Math.max(5, Math.min(200, opts.limit ?? COMMON_SUBDOMAINS.length));
  const checkedAt = new Date().toISOString();

  const { hosts: ctHosts, ok: ctLogQueried } = await queryCtLogs(domain);

  const bruteForceHosts = COMMON_SUBDOMAINS.slice(0, limit).map((prefix) => `${prefix}.${domain}`);
  const candidateSources = new Map<string, 'ct-log' | 'dns-probe'>();
  for (const h of ctHosts) candidateSources.set(h, 'ct-log');
  for (const h of bruteForceHosts) if (!candidateSources.has(h)) candidateSources.set(h, 'dns-probe');

  const state = await readState(domain, opts);
  const previouslySeen = new Set<string>(state.subdomains?.seen ?? []);

  const results = await Promise.all(
    [...candidateSources.entries()].map(async ([host, source]) => {
      const discovered = await resolveAny(host);
      return { host, source, discovered } as const;
    })
  );

  const discovered: SubdomainCandidate[] = results
    .filter((r) => r.discovered)
    .map((r) => ({ host: r.host, discovered: true, source: r.source, isNew: !previouslySeen.has(r.host) }));

  const allSeen = new Set([...previouslySeen, ...discovered.map((d) => d.host)]);
  state.subdomains = { seen: [...allSeen], updatedAt: checkedAt };
  await writeState(domain, state, opts);

  return {
    domain,
    scannedCandidates: candidateSources.size,
    discoveredCount: discovered.length,
    newCount: discovered.filter((d) => d.isNew).length,
    discovered,
    ctLogQueried,
    checkedAt,
  };
}
