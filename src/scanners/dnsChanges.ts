import { checkDns } from './dns.js';
import { readState, writeState, type StateOptions } from '../state.js';
import type { DnsChangesResult, DnsRecordChange } from '../types.js';

const MONITORED_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'] as const;
const CRITICAL_TYPES = new Set(['A', 'AAAA', 'NS', 'MX']);

/**
 * DNS-hijack monitoring: resolves the monitored record types and compares
 * against the last-seen baseline for this target. First run establishes the
 * baseline; every run after that reports what changed, if anything.
 */
export async function checkDnsChanges(target: string, opts: StateOptions = {}): Promise<DnsChangesResult> {
  const scan = await checkDns(target, [...MONITORED_TYPES]);

  const current: Record<string, string[]> = {};
  for (const r of scan.results) {
    if (!r.error) current[r.type] = [...r.records].sort();
  }

  const state = await readState(scan.domain, opts);
  const previous = state.dns?.records as Record<string, string[]> | undefined;
  const checkedAt = new Date().toISOString();

  if (!previous) {
    state.dns = { records: current, updatedAt: checkedAt };
    await writeState(scan.domain, state, opts);
    return { target: scan.domain, baseline: true, changed: false, suspicious: false, changes: [], checkedAt };
  }

  const changes: DnsRecordChange[] = [];
  const allTypes = new Set([...Object.keys(previous), ...Object.keys(current)]);
  for (const type of allTypes) {
    const from = previous[type] ?? [];
    const to = current[type] ?? [];
    if (from.join(',') !== to.join(',')) {
      changes.push({ recordType: type, from, to, critical: CRITICAL_TYPES.has(type) });
    }
  }

  state.dns = { records: current, updatedAt: checkedAt };
  await writeState(scan.domain, state, opts);

  return {
    target: scan.domain,
    baseline: false,
    changed: changes.length > 0,
    suspicious: changes.some((c) => c.critical),
    changes,
    checkedAt,
  };
}
