import { afterAll, beforeAll, describe, it, expect } from 'vitest';
import dgram from 'node:dgram';
import dns from 'node:dns';
import { checkBlacklist, classifyDnsblAnswer, summariseDnsblResults } from '../src/scanners/blacklist.js';
import type { BlacklistEntryResult, DnsblStatus } from '../src/types.js';

describe('classifyDnsblAnswer', () => {
  it('reads NXDOMAIN as not listed', () => {
    expect(classifyDnsblAnswer({ code: 'ENOTFOUND' }).status).toBe('not_listed');
  });

  it('reads timeouts and resolver failures as errors, not as not listed', () => {
    for (const code of ['ETIMEOUT', 'ESERVFAIL', 'ECONNREFUSED', 'ENODATA', 'EREFUSED']) {
      const verdict = classifyDnsblAnswer({ code });
      expect(verdict.status).toBe('error');
      expect(verdict.error).toContain(code);
    }
  });

  it('reads a 127.0.0.x answer as listed', () => {
    expect(classifyDnsblAnswer(null, ['127.0.0.2'])).toEqual({ status: 'listed', answers: ['127.0.0.2'] });
    expect(classifyDnsblAnswer(null, ['127.0.0.11']).status).toBe('listed');
  });

  it('reads the Spamhaus refusal codes (127.255.255.x) as errors, not listings', () => {
    for (const code of ['127.255.255.252', '127.255.255.254', '127.255.255.255']) {
      const verdict = classifyDnsblAnswer(null, [code]);
      expect(verdict.status).toBe('error');
      expect(verdict.error).toContain(code);
    }
  });

  it('reads any other answer (an NXDOMAIN-rewriting resolver) as an error, not a listing', () => {
    expect(classifyDnsblAnswer(null, ['92.242.132.24']).status).toBe('error');
    expect(classifyDnsblAnswer(null, []).status).toBe('error');
  });
});

describe('summariseDnsblResults', () => {
  const entry = (status: DnsblStatus): BlacklistEntryResult => ({
    name: 'list',
    zone: 'list.example',
    listed: status === 'listed',
    status,
    answers: [],
  });

  it('reports unknown, not clean, when no list answered', () => {
    expect(summariseDnsblResults([entry('error'), entry('error')])).toEqual({
      reputation: 'unknown',
      listedCount: 0,
      checkedCount: 0,
      errorCount: 2,
    });
  });

  it('counts errored lists as unchecked rather than clean', () => {
    expect(summariseDnsblResults([entry('not_listed'), entry('error'), entry('not_listed'), entry('error')])).toEqual({
      reputation: 'clean',
      listedCount: 0,
      checkedCount: 2,
      errorCount: 2,
    });
  });

  it('keeps the listing thresholds', () => {
    expect(summariseDnsblResults([entry('listed'), entry('not_listed')]).reputation).toBe('suspicious');
    expect(summariseDnsblResults([entry('listed'), entry('listed'), entry('listed'), entry('error')]).reputation).toBe('blacklisted');
  });
});

/**
 * checkBlacklist end to end against a DNS server on loopback, so a refusal, a
 * real NXDOMAIN and a list that never answers can be staged on demand.
 * For 192.0.2.1 each list behaves differently; for 192.0.2.2 every list fails.
 */
describe('checkBlacklist against a local DNS server', () => {
  const originalServers = dns.getServers();
  let server: dgram.Socket;

  function questionEnd(query: Buffer): number {
    let offset = 12;
    while (query[offset] !== 0) offset += query[offset] + 1;
    return offset + 5; // root label, QTYPE, QCLASS
  }

  function questionName(query: Buffer): string {
    const labels: string[] = [];
    for (let offset = 12; query[offset] !== 0; offset += query[offset] + 1) {
      labels.push(query.subarray(offset + 1, offset + 1 + query[offset]).toString());
    }
    return labels.join('.').toLowerCase();
  }

  function reply(query: Buffer, rcode: number, addresses: string[] = []): Buffer {
    const header = Buffer.alloc(12);
    query.copy(header, 0, 0, 2);
    header.writeUInt16BE(0x8180 | rcode, 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(addresses.length, 6);
    const records = addresses.map((ip) =>
      Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...ip.split('.').map(Number)])
    );
    return Buffer.concat([header, query.subarray(12, questionEnd(query)), ...records]);
  }

  function respond(query: Buffer): Buffer | null {
    const name = questionName(query);
    if (name === '192.0.2.1' || name === '192.0.2.2') return reply(query, 0, [name]);
    if (name.startsWith('2.2.0.192.')) return reply(query, 2);
    if (name.endsWith('.zen.spamhaus.org')) return reply(query, 0, ['127.255.255.254']);
    if (name.endsWith('.b.barracudacentral.org')) return reply(query, 0, ['127.0.0.2']);
    if (name.endsWith('.bl.spamcop.net')) return reply(query, 3);
    return null; // dnsbl-1.uceprotect.net never answers
  }

  beforeAll(async () => {
    server = dgram.createSocket('udp4');
    server.on('message', (query, from) => {
      const answer = respond(query);
      if (answer) server.send(answer, from.port, from.address);
    });
    await new Promise<void>((resolve) => server.bind(0, '127.0.0.1', resolve));
    dns.setServers([`127.0.0.1:${server.address().port}`]);
  });

  afterAll(() => {
    dns.setServers(originalServers);
    server.close();
  });

  it('counts a refused query and a timed-out list as errors, not as clean', async () => {
    const r = await checkBlacklist('192.0.2.1');
    const byName = Object.fromEntries(r.results.map((entry) => [entry.name, entry]));
    expect(byName['Spamhaus ZEN']).toMatchObject({ status: 'error', listed: false, answers: ['127.255.255.254'] });
    expect(byName['Barracuda']).toMatchObject({ status: 'listed', listed: true, answers: ['127.0.0.2'] });
    expect(byName['SpamCop']).toMatchObject({ status: 'not_listed', listed: false });
    expect(byName['UCEPROTECT L1']).toMatchObject({ status: 'error', listed: false, error: 'Lookup timed out' });
    expect(r).toMatchObject({ reputation: 'suspicious', listedCount: 1, checkedCount: 2, errorCount: 2 });
  }, 15000);

  it('reports unknown with an error when no list answers', async () => {
    const r = await checkBlacklist('192.0.2.2');
    expect(r.reputation).toBe('unknown');
    expect(r.checkedCount).toBe(0);
    expect(r.errorCount).toBe(4);
    expect(r.error).toContain('None of the 4 blacklists answered');
  }, 15000);
});
