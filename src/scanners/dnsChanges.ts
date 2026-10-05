import { checkDns } from './dns.js';
import { readState, writeState, type StateOptions } from '../state.js';
import type { DnsChangesResult, DnsRecordChange } from '../types.js';

const MONITORED_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'] as const;
const CRITICAL_TYPES = new Set(['A', 'AAAA', 'NS', 'MX']);
/** checkDns errors that are an authoritative "nothing here", not a failed lookup. */
const ANSWERED_EMPTY = new Set(['No records', 'Domain not found']);

/**
 * DNS-hijack monitoring: resolves the monitored record types and compares
 * against the last-seen baseline for this target. First run establishes the
 * baseline; every run after that reports what changed, if anything.
 */
export async function checkDnsChanges(target: string, opts: StateOptions = {}): Promise<DnsChangesResult> {
  const scan = await checkDns(target, [...MONITORED_TYPES]);

  // Only answers count. "No records" and "Domain not found" are answers — the
  // records really are gone, which is exactly what hijack monitoring exists to
  // notice. "Query failed" is a timeout or a resolver error: it says nothing
  // about the zone, so that type is left out of `current` and is neither
  // compared nor allowed to overwrite the last good baseline. Treating a failed
  // lookup as an empty set reported a critical MX change "from nothing" the
  // moment the next lookup succeeded.
  const current: Record<string, string[]> = {};
  for (const r of scan.results) {
    if (!r.error) current[r.type] = [...r.records].sort();
    else if (ANSWERED_EMPTY.has(r.error)) current[r.type] = [];
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
  for (const type of Object.keys(current)) {
    // A type with no baseline yet (its earlier lookup failed) starts one here
    // rather than reporting everything it holds as new.
    if (!(type in previous)) continue;
    const from = previous[type];
    const to = current[type];
    if (from.join(',') !== to.join(',')) {
      changes.push({ recordType: type, from, to, critical: CRITICAL_TYPES.has(type) });
    }
  }

  // Types that failed this time keep their last known value.
  state.dns = { records: { ...previous, ...current }, updatedAt: checkedAt };
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
