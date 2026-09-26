import type { WhoisResult } from '../types.js';
import { describeError } from '../errors.js';

export function cleanDomain(input: string): string {
  return String(input || '')
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/.*$/, '')
    .toLowerCase()
    .trim();
}

async function fetchJsonWithTimeout(url: string, timeoutMs = 12000): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { accept: 'application/rdap+json, application/json' },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`RDAP request failed: ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Raw RDAP lookup, shared with checkWhoisPrivacy() so both features use the
 * same fetch/timeout/header code without each maintaining a separate RDAP
 * client. Each still makes its own network request when called
 * independently — this only dedupes the code, not the request itself.
 */
export async function fetchRdapData(domain: string): Promise<any> {
  const cleaned = cleanDomain(domain);
  return fetchJsonWithTimeout(`https://rdap.org/domain/${encodeURIComponent(cleaned)}`);
}

function pickExpiryFromEvents(events: any): string | null {
  if (!Array.isArray(events)) return null;
  const preferredActions = new Set(['expiration', 'expiry', 'registration expiration', 'expires']);
  for (const event of events) {
    const action = String(event?.eventAction ?? '').toLowerCase();
    if (preferredActions.has(action) && event?.eventDate) return event.eventDate;
  }
  for (const event of events) {
    if (event?.eventDate && String(event?.eventAction ?? '').toLowerCase().includes('expir')) return event.eventDate;
  }
  return null;
}

function pickEventDateByAction(events: any, actionSnippets: string[]): string | null {
  if (!Array.isArray(events)) return null;
  for (const event of events) {
    const action = String(event?.eventAction ?? '').toLowerCase();
    if (actionSnippets.some((snippet) => action.includes(snippet)) && event?.eventDate) return event.eventDate;
  }
  return null;
}

function pickRegistrar(entities: any): string {
  if (!Array.isArray(entities)) return 'Unknown';
  for (const entity of entities) {
    const roles = Array.isArray(entity?.roles) ? entity.roles.map((r: string) => String(r).toLowerCase()) : [];
    if (!roles.includes('registrar')) continue;
    const vcard = entity?.vcardArray;
    if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
      const fn = vcard[1].find((item: any) => Array.isArray(item) && item[0] === 'fn');
      if (Array.isArray(fn) && fn[3]) return String(fn[3]);
      const org = vcard[1].find((item: any) => Array.isArray(item) && item[0] === 'org');
      if (Array.isArray(org) && org[3]) return String(org[3]);
    }
    if (entity?.handle) return String(entity.handle);
  }
  return 'Unknown';
}

function pickNameServers(nameservers: any): string[] {
  if (!Array.isArray(nameservers)) return [];
  return nameservers
    .map((ns) => ns?.ldhName ?? ns?.unicodeName ?? ns?.handle)
    .filter(Boolean)
    .map((v) => String(v).trim());
}

/**
 * Domain registration lookup via public RDAP (the modern replacement for
 * the legacy WHOIS TCP/43 protocol) — free, keyless, no traditional WHOIS
 * client needed.
 */
export async function checkWhois(domain: string): Promise<WhoisResult> {
  const cleaned = cleanDomain(domain);

  try {
    const data = await fetchJsonWithTimeout(`https://rdap.org/domain/${encodeURIComponent(cleaned)}`);
    const expiryDate = pickExpiryFromEvents(data?.events);

    if (!expiryDate) {
      return {
        domain: cleaned,
        valid: false,
        error: 'RDAP_PARSE_ERROR',
        message: `Domain registration found for ${cleaned}, but expiry date is not available. This domain may have privacy protection enabled.`,
        registrar: pickRegistrar(data?.entities),
        nameServers: pickNameServers(data?.nameservers),
        status: Array.isArray(data?.status) ? data.status : [],
        expiryDate: null,
        daysRemaining: null,
      };
    }

    const parsedExpiry = new Date(expiryDate);
    if (Number.isNaN(parsedExpiry.getTime())) {
      return {
        domain: cleaned,
        valid: false,
        error: 'RDAP_PARSE_ERROR',
        message: `Could not parse expiry date for ${cleaned}. Raw value: ${expiryDate}`,
        registrar: pickRegistrar(data?.entities),
        nameServers: pickNameServers(data?.nameservers),
        status: Array.isArray(data?.status) ? data.status : [],
        expiryDate: null,
        daysRemaining: null,
      };
    }

    const now = new Date();
    const daysRemaining = Math.floor((parsedExpiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

    return {
      domain: cleaned,
      valid: parsedExpiry > now,
      expiryDate: parsedExpiry.toISOString(),
      daysRemaining,
      registrar: pickRegistrar(data?.entities),
      nameServers: pickNameServers(data?.nameservers),
      createdDate: pickEventDateByAction(data?.events ?? [], ['registration', 'registered']),
      updatedDate: pickEventDateByAction(data?.events ?? [], ['last changed', 'updated']),
      status: Array.isArray(data?.status) ? data.status : [],
    };
  } catch (error: any) {
    return {
      domain: cleaned,
      valid: false,
      error: 'RDAP_LOOKUP_ERROR',
      message: `Unable to retrieve domain information for ${cleaned}. ${describeError(error)}`,
      registrar: 'Unknown',
      nameServers: [],
      status: [],
      expiryDate: null,
      daysRemaining: null,
    };
  }
}
