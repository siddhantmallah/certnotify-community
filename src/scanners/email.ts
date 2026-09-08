import dns from 'node:dns';
import type { EmailSecurityResult } from '../types.js';

async function getTxt(host: string): Promise<string[]> {
  try {
    const records = await dns.promises.resolveTxt(host);
    return records.flat();
  } catch {
    return [];
  }
}

const DKIM_SELECTORS = ['google', 'default', 'mail', 'dkim', 'k1', 'selector1', 'selector2', 'mandrill', 'sendgrid'];

/**
 * Evaluate a domain's SPF posture from its raw apex TXT records.
 *
 * Split out from the network call so the rules can be unit-tested against
 * plain arrays — the interesting cases here are all parsing, not DNS.
 *
 * RFC 7208 §3.2: the `v=spf1` version tag is case-insensitive.
 * RFC 7208 §4.5: a domain publishing MORE THAN ONE SPF record is a permanent
 * error. A receiver must not pick one of them — it fails SPF for the domain
 * entirely. Taking the first match (what this checker used to do) reports a
 * comprehensively broken domain as healthy, which is the most consequential
 * way an SPF check can be wrong: worse than no record at all, and invisible
 * to the owner precisely because most checkers only look at the first hit.
 */
export function evaluateSpf(txtRecords: string[]): EmailSecurityResult['spf'] {
  const records = txtRecords.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  const record = records[0] ?? null;
  const multipleRecords = records.length > 1;

  if (multipleRecords) {
    return {
      record,
      records,
      valid: false,
      mechanism: null,
      multipleRecords: true,
      error: `permerror: ${records.length} SPF records published — RFC 7208 requires exactly one, so receivers fail SPF outright`,
    };
  }

  if (!record) {
    return { record: null, records, valid: false, mechanism: null, multipleRecords: false, error: null };
  }

  return {
    record,
    records,
    valid: true,
    mechanism: record.match(/\s([+\-~?]all)/)?.[1] ?? null,
    multipleRecords: false,
    error: null,
  };
}

/**
 * Email authentication posture: SPF, DMARC, and a best-effort DKIM probe
 * across common selectors (DKIM has no discovery mechanism — the selector
 * is chosen by the sending mail provider, so this can miss custom selectors).
 */
export async function checkEmail(rawDomain: string): Promise<EmailSecurityResult> {
  const domain = rawDomain.replace(/^https?:\/\//i, '').replace(/\/$/, '').split('/')[0].toLowerCase();

  const [dmarcRecords, domainTxtRecords] = await Promise.all([
    getTxt(`_dmarc.${domain}`),
    getTxt(domain),
  ]);

  const dmarcRaw = dmarcRecords.find((r) => r.startsWith('v=DMARC1')) ?? null;
  let dmarcPolicy: 'none' | 'quarantine' | 'reject' | null = null;
  let dmarcPct = 100;
  let dmarcRua: string | null = null;
  if (dmarcRaw) {
    const pMatch = dmarcRaw.match(/\bp=(\w+)/);
    const pctMatch = dmarcRaw.match(/\bpct=(\d+)/);
    const ruaMatch = dmarcRaw.match(/\brua=([^;]+)/);
    const p = pMatch?.[1];
    dmarcPolicy = p === 'quarantine' || p === 'reject' || p === 'none' ? p : 'none';
    dmarcPct = pctMatch ? parseInt(pctMatch[1], 10) : 100;
    dmarcRua = ruaMatch?.[1]?.trim() ?? null;
  }

  const spf = evaluateSpf(domainTxtRecords);

  let dkimSelector: string | null = null;
  let dkimRecord: string | null = null;
  await Promise.all(
    DKIM_SELECTORS.map(async (sel) => {
      if (dkimSelector) return;
      const records = await getTxt(`${sel}._domainkey.${domain}`);
      const hit = records.find((r) => r.includes('v=DKIM1') || r.includes('p='));
      if (hit && !dkimSelector) {
        dkimSelector = sel;
        dkimRecord = hit;
      }
    })
  );

  let score = 0;
  if (spf.valid) score += 25;
  if (spf.mechanism === '-all') score += 10;
  else if (spf.mechanism === '~all') score += 5;
  if (dmarcRaw) score += 25;
  if (dmarcPolicy === 'quarantine') score += 15;
  else if (dmarcPolicy === 'reject') score += 20;
  if (dkimSelector) score += 20;

  const grade =
    score >= 90 ? 'A+' : score >= 75 ? 'A' : score >= 55 ? 'B' : score >= 35 ? 'C' : score >= 15 ? 'D' : 'F';

  const recommendations: string[] = [];
  if (spf.multipleRecords)
    recommendations.push(
      `Remove ${spf.records.length - 1} of your ${spf.records.length} SPF records — a domain may publish only one. ` +
        'Merge every `include:` into a single record; until you do, SPF fails for all of your mail.'
    );
  if (!spf.valid && !spf.multipleRecords)
    recommendations.push('Add an SPF TXT record to authorize which servers can send email for your domain.');
  if (spf.valid && spf.mechanism !== '-all' && spf.mechanism !== '~all')
    recommendations.push('End your SPF record with -all (fail) or ~all (softfail) to reject unauthorized senders.');
  if (!dmarcRaw) recommendations.push(`Add a DMARC record at _dmarc.${domain} to protect against email spoofing.`);
  if (dmarcPolicy === 'none')
    recommendations.push('Upgrade DMARC policy from p=none to p=quarantine then p=reject once monitoring confirms alignment.');
  if (!dkimSelector) recommendations.push('Configure DKIM signing in your email provider and publish the public key as a TXT record.');
  if (dmarcRaw && !dmarcRua) recommendations.push('Add a rua= address to your DMARC record to receive aggregate reports.');

  return {
    domain,
    spf,
    dmarc: { record: dmarcRaw, policy: dmarcPolicy, pct: dmarcPct, rua: dmarcRua },
    dkim: { selector: dkimSelector, record: dkimRecord },
    score,
    grade,
    recommendations,
  };
}
