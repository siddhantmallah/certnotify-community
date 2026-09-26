import { fetchRdapData, cleanDomain } from './whois.js';
import { describeError } from '../errors.js';
import { readState, writeState, type StateOptions } from '../state.js';
import type { WhoisPrivacyContact, WhoisPrivacyResult } from '../types.js';

const PRIVACY_KEYWORDS = [
  'privacy', 'protection', 'proxy', 'redacted', 'data redacted',
  'not disclosed', 'whoisguard', 'private registration', 'domains by proxy',
];

function rdapToLines(data: any): string {
  const lines: string[] = [];
  if (Array.isArray(data?.status)) lines.push(`status: ${data.status.join(', ')}`);

  if (Array.isArray(data?.events)) {
    for (const ev of data.events) {
      if (ev?.eventAction || ev?.eventDate) lines.push(`event ${ev.eventAction || 'unknown'}: ${ev.eventDate || ''}`.trim());
    }
  }

  if (Array.isArray(data?.entities)) {
    for (const entity of data.entities) {
      const roles = Array.isArray(entity?.roles) ? entity.roles.join(', ') : '';
      if (roles) lines.push(`roles: ${roles}`);

      const vcard = entity?.vcardArray;
      if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
        for (const item of vcard[1]) {
          if (!Array.isArray(item) || item.length < 4) continue;
          const key = String(item[0] || '').toLowerCase();
          const value = item[3];
          if (value != null) lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : String(value)}`);
        }
      }
    }
  }

  if (Array.isArray(data?.nameservers)) {
    const names = data.nameservers.map((ns: any) => ns?.ldhName || ns?.unicodeName || ns?.handle).filter(Boolean);
    if (names.length) lines.push(`nameservers: ${names.join(', ')}`);
  }

  return lines.join('\n');
}

export function parsePrivacyStatus(whoisText: string): { isPrivate: boolean; provider: string | null } {
  const dataLower = whoisText.toLowerCase();
  const hasPrivacyKeyword = PRIVACY_KEYWORDS.some((keyword) => dataLower.includes(keyword));

  let provider: string | null = null;
  if (dataLower.includes('whoisguard')) provider = 'WhoisGuard';
  else if (dataLower.includes('domains by proxy')) provider = 'Domains By Proxy';
  else if (dataLower.includes('privacy protect')) provider = 'Privacy Protect';
  else if (dataLower.includes('privatewhois')) provider = 'PrivateWhois';
  else if (dataLower.includes('contactprivacy')) provider = 'Contact Privacy';
  else if (hasPrivacyKeyword) provider = 'Unknown Privacy Service';

  return { isPrivate: hasPrivacyKeyword, provider };
}

export function extractContactInfo(whoisText: string): WhoisPrivacyContact {
  const info: WhoisPrivacyContact = { name: null, email: null, phone: null, organization: null };

  for (const line of whoisText.split('\n')) {
    const lower = line.toLowerCase();

    if ((lower.includes('registrant name') || lower.includes('registrant:')) && !lower.includes('redacted') && !lower.includes('privacy')) {
      const match = line.match(/:\s*(.+)$/);
      if (match && match[1].trim().length > 2) info.name = match[1].trim();
    }

    if (lower.includes('registrant email') || lower.includes('email:')) {
      const emailMatch = line.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (emailMatch && !emailMatch[1].includes('privacy') && !emailMatch[1].includes('whois')) info.email = emailMatch[1];
    }

    if (lower.includes('registrant phone') || lower.includes('phone:')) {
      const phoneMatch = line.match(/([+]?[\d\s\-()]{10,})/);
      if (phoneMatch && !lower.includes('redacted')) info.phone = phoneMatch[1].trim();
    }

    if ((lower.includes('registrant org') || lower.includes('organization:')) && !lower.includes('redacted') && !lower.includes('privacy')) {
      const match = line.match(/:\s*(.+)$/);
      if (match && match[1].trim().length > 2) info.organization = match[1].trim();
    }
  }

  return info;
}

/**
 * WHOIS privacy-change monitoring: detects when a domain's registration
 * privacy protection gets disabled, exposing the registrant's real contact
 * details — the kind of change that's easy to miss and valuable to catch
 * quickly (a lapsed privacy add-on, a registrar migration, etc).
 */
export async function checkWhoisPrivacy(rawDomain: string, opts: StateOptions = {}): Promise<WhoisPrivacyResult> {
  const domain = cleanDomain(rawDomain);
  const checkedAtOnError = new Date().toISOString();

  let data: any;
  try {
    data = await fetchRdapData(domain);
  } catch (error: any) {
    return {
      domain,
      baseline: true,
      privacyEnabled: false,
      privacyProvider: null,
      privacyChanged: false,
      previouslyPrivate: null,
      exposedData: null,
      checkedAt: checkedAtOnError,
      error: `Unable to retrieve WHOIS data for ${domain}. ${describeError(error)}`,
    };
  }

  const whoisText = rdapToLines(data);
  const { isPrivate, provider } = parsePrivacyStatus(whoisText);
  const contact = extractContactInfo(whoisText);
  const checkedAt = new Date().toISOString();

  const state = await readState(domain, opts);
  const previous = state.whoisPrivacy as { isPrivate: boolean } | undefined;
  const privacyChanged = previous ? previous.isPrivate !== isPrivate : false;

  state.whoisPrivacy = { isPrivate, provider, checkedAt };
  await writeState(domain, state, opts);

  return {
    domain,
    baseline: !previous,
    privacyEnabled: isPrivate,
    privacyProvider: provider,
    privacyChanged,
    previouslyPrivate: previous?.isPrivate ?? null,
    exposedData: isPrivate ? null : contact,
    checkedAt,
  };
}
