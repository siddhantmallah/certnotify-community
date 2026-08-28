import dns from 'node:dns';
import net from 'node:net';
import type { DnsRecordResult, DnsRecordType, DnsResult } from '../types.js';

const RECORD_TYPES: DnsRecordType[] = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR'];

function cleanDomain(input: string): string {
  return input.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase().trim();
}

async function resolveRecord(domain: string, type: DnsRecordType): Promise<DnsRecordResult> {
  try {
    let records: string[] = [];
    switch (type) {
      case 'A':
        records = await dns.promises.resolve4(domain);
        break;
      case 'AAAA':
        records = await dns.promises.resolve6(domain);
        break;
      case 'MX': {
        const mx = await dns.promises.resolveMx(domain);
        records = mx.map((r) => `${r.priority} ${r.exchange}`);
        break;
      }
      case 'TXT': {
        const txt = await dns.promises.resolveTxt(domain);
        records = txt.map((r) => r.join(''));
        break;
      }
      case 'NS':
        records = await dns.promises.resolveNs(domain);
        break;
      case 'CNAME':
        records = await dns.promises.resolveCname(domain);
        break;
      case 'SOA': {
        const soa = await dns.promises.resolveSoa(domain);
        records = [`${soa.nsname} ${soa.hostmaster} ${soa.serial} ${soa.refresh} ${soa.retry} ${soa.expire} ${soa.minttl}`];
        break;
      }
      case 'PTR': {
        // Reverse DNS: only meaningful for an IP literal, not a hostname.
        // Resolve the hostname to an IP first (if it isn't one already),
        // then look up the PTR record for that IP — genuinely implemented
        // here; the original app never actually did this server-side.
        const target = net.isIP(domain) ? domain : (await dns.promises.resolve4(domain).catch(() => []))[0];
        if (!target) throw Object.assign(new Error('No A record to reverse'), { code: 'ENODATA' });
        records = await dns.promises.reverse(target);
        break;
      }
    }
    return { type, records };
  } catch (e: any) {
    return {
      type,
      records: [],
      error: e.code === 'ENODATA' ? 'No records' : e.code === 'ENOTFOUND' ? 'Domain not found' : 'Query failed',
    };
  }
}

export async function checkDns(domain: string, types: DnsRecordType[] = RECORD_TYPES): Promise<DnsResult> {
  const clean = cleanDomain(domain);
  const results = await Promise.all(types.map((t) => resolveRecord(clean, t)));
  return { domain: clean, queriedAt: new Date().toISOString(), results };
}

export { RECORD_TYPES };
