import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

// Each test scripts what the resolver answers, run by run.
const answers: Array<Record<string, string[] | string>> = [];
vi.mock('../src/scanners/dns.js', () => ({
  checkDns: async (target: string) => {
    const run = answers.shift() ?? {};
    return {
      domain: target,
      results: Object.entries(run).map(([type, v]) =>
        typeof v === 'string' ? { type, records: [], error: v } : { type, records: v }),
    };
  },
}));

const { checkDnsChanges } = await import('../src/scanners/dnsChanges.js');

let stateDir: string;
beforeEach(async () => { stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'dns-changes-')); answers.length = 0; });
afterEach(async () => { await fs.rm(stateDir, { recursive: true, force: true }); });

const MX = ['10 mx1.example.com', '20 mx2.example.com'];

describe('checkDnsChanges', () => {
  it('does not report a change when the baseline lookup failed and the next one succeeded', async () => {
    // The live test caught this: MX timed out on the first run and came back
    // on the second, which was reported as a critical change "from nothing".
    answers.push({ A: ['1.2.3.4'], MX: 'Query failed' }, { A: ['1.2.3.4'], MX });
    await checkDnsChanges('example.com', { stateDir });
    const second = await checkDnsChanges('example.com', { stateDir });
    expect(second.changes).toEqual([]);
  });

  it('keeps the last good records through a failed lookup, then compares against them', async () => {
    answers.push({ MX }, { MX: 'Query failed' }, { MX: ['10 evil.example.net'] });
    await checkDnsChanges('example.com', { stateDir });
    expect((await checkDnsChanges('example.com', { stateDir })).changes).toEqual([]);
    const third = await checkDnsChanges('example.com', { stateDir });
    expect(third.changes).toEqual([{ recordType: 'MX', from: MX, to: ['10 evil.example.net'], critical: true }]);
    expect(third.suspicious).toBe(true);
  });

  it('still reports records that really disappeared', async () => {
    answers.push({ MX }, { MX: 'No records' });
    await checkDnsChanges('example.com', { stateDir });
    const second = await checkDnsChanges('example.com', { stateDir });
    expect(second.changes).toEqual([{ recordType: 'MX', from: MX, to: [], critical: true }]);
  });

  it('reports a changed A record as critical', async () => {
    answers.push({ A: ['1.2.3.4'] }, { A: ['6.6.6.6'] });
    await checkDnsChanges('example.com', { stateDir });
    const second = await checkDnsChanges('example.com', { stateDir });
    expect(second.suspicious).toBe(true);
    expect(second.changes[0]).toMatchObject({ recordType: 'A', from: ['1.2.3.4'], to: ['6.6.6.6'] });
  });
});
