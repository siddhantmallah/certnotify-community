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

  const spfRaw = domainTxtRecords.find((r) => r.startsWith('v=spf1')) ?? null;
  let spfPass = false;
  let spfMechanism: string | null = null;
  if (spfRaw) {
    spfPass = true;
    const allMatch = spfRaw.match(/\s([+\-~?]all)/);
    spfMechanism = allMatch?.[1] ?? null;
  }

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
  if (spfPass) score += 25;
  if (spfMechanism === '-all') score += 10;
  else if (spfMechanism === '~all') score += 5;
  if (dmarcRaw) score += 25;
  if (dmarcPolicy === 'quarantine') score += 15;
  else if (dmarcPolicy === 'reject') score += 20;
  if (dkimSelector) score += 20;

  const grade =
    score >= 90 ? 'A+' : score >= 75 ? 'A' : score >= 55 ? 'B' : score >= 35 ? 'C' : score >= 15 ? 'D' : 'F';

  const recommendations: string[] = [];
  if (!spfPass) recommendations.push('Add an SPF TXT record to authorize which servers can send email for your domain.');
  if (spfPass && spfMechanism !== '-all' && spfMechanism !== '~all')
    recommendations.push('End your SPF record with -all (fail) or ~all (softfail) to reject unauthorized senders.');
  if (!dmarcRaw) recommendations.push(`Add a DMARC record at _dmarc.${domain} to protect against email spoofing.`);
  if (dmarcPolicy === 'none')
    recommendations.push('Upgrade DMARC policy from p=none to p=quarantine then p=reject once monitoring confirms alignment.');
  if (!dkimSelector) recommendations.push('Configure DKIM signing in your email provider and publish the public key as a TXT record.');
  if (dmarcRaw && !dmarcRua) recommendations.push('Add a rua= address to your DMARC record to receive aggregate reports.');

  return {
    domain,
    spf: { record: spfRaw, valid: spfPass, mechanism: spfMechanism },
    dmarc: { record: dmarcRaw, policy: dmarcPolicy, pct: dmarcPct, rua: dmarcRua },
    dkim: { selector: dkimSelector, record: dkimRecord },
    score,
    grade,
    recommendations,
  };
}
