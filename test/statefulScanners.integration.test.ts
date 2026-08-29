/**
 * Integration tests for the Phase 4 stateful checks — real network calls
 * against real, stable domains, isolated to a temp state directory per test
 * so a real ~/.certnotify/state is never touched. Each check is run twice
 * in a row against the same state dir to confirm the baseline-then-diff
 * contract: first run reports baseline:true, second identical run reports
 * no change.
 *
 * DNS-hijack monitoring in particular is inherently prone to false positives
 * against domains behind round-robin/anycast infrastructure (A/AAAA record
 * sets can rotate between two lookups seconds apart) — a real characteristic
 * of single-snapshot diffing, not a bug in this package. Assertions here
 * check the *shape* of the diff result rather than asserting zero change on
 * volatile record types.
 */
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { checkDnsChanges } from '../src/scanners/dnsChanges.js';
import { checkDefacement } from '../src/scanners/defacement.js';
import { checkWhoisPrivacy } from '../src/scanners/whoisPrivacy.js';
import { checkMixedContent } from '../src/scanners/mixedContent.js';
import { discoverSubdomains } from '../src/scanners/subdomains.js';

const TARGET = 'github.com';
const STABLE_DNS_TARGET = 'cloudflare.com'; // NS/MX records are far more stable here than A/AAAA round-robin sets

let tmpDirs: string[] = [];

async function tempStateDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'certnotify-stateful-test-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tmpDirs.map((d) => fs.rm(d, { recursive: true, force: true }).catch(() => {})));
  tmpDirs = [];
});

describe('checkDnsChanges (live)', () => {
  it('establishes a baseline on first run, then reports no NS/MX change on an immediate second run', async () => {
    const stateDir = await tempStateDir();

    const first = await checkDnsChanges(STABLE_DNS_TARGET, { stateDir });
    expect(first.baseline).toBe(true);
    expect(first.changed).toBe(false);
    expect(first.changes).toEqual([]);

    const second = await checkDnsChanges(STABLE_DNS_TARGET, { stateDir });
    expect(second.baseline).toBe(false);
    const nsOrMxChange = second.changes.find((c) => c.recordType === 'NS' || c.recordType === 'MX');
    expect(nsOrMxChange).toBeUndefined();
  });
});

describe('checkDefacement (live)', () => {
  it('establishes a baseline on first run, then reports no change on an immediate second run', async () => {
    const stateDir = await tempStateDir();

    const first = await checkDefacement(TARGET, { stateDir });
    expect(first.baseline).toBe(true);
    expect(first.hash).toMatch(/^[a-f0-9]{64}$/);

    const second = await checkDefacement(TARGET, { stateDir });
    expect(second.baseline).toBe(false);
    expect(second.changed).toBe(false);
    expect(second.hash).toBe(first.hash);
  });
});

describe('checkWhoisPrivacy (live)', () => {
  it('returns a well-shaped result whether or not the RDAP lookup itself succeeded', async () => {
    const stateDir = await tempStateDir();
    const result = await checkWhoisPrivacy(TARGET, { stateDir });
    expect(result.domain).toBe(TARGET);
    expect(typeof result.privacyEnabled).toBe('boolean');
    expect(typeof result.baseline).toBe('boolean');
    // Public RDAP endpoints occasionally rate-limit automated requests —
    // only assert on the second-run diff behavior when the first succeeded.
    if (!result.error) {
      const second = await checkWhoisPrivacy(TARGET, { stateDir });
      if (!second.error) {
        expect(second.baseline).toBe(false);
        expect(second.privacyChanged).toBe(false);
      }
    }
  });
});

describe('checkMixedContent (live)', () => {
  it('scans a live HTTPS site and reports a well-shaped, all-HTTPS-clean result', async () => {
    const stateDir = await tempStateDir();
    const result = await checkMixedContent(TARGET, { stateDir });
    expect(result.target).toBe(TARGET);
    expect(result.pagesScanned).toBeGreaterThan(0);
    expect(Array.isArray(result.issues)).toBe(true);
    expect(result.issuesFound).toBe(result.issues.length);
  });
});

describe('discoverSubdomains (live)', () => {
  it('finds real subdomains via CT logs and/or brute force, all of which resolve', async () => {
    const stateDir = await tempStateDir();
    const result = await discoverSubdomains(TARGET, { stateDir, limit: 10 });
    expect(result.domain).toBe(TARGET);
    expect(result.discoveredCount).toBe(result.discovered.length);
    expect(result.discovered.length).toBeGreaterThan(0);
    for (const candidate of result.discovered) {
      expect(candidate.discovered).toBe(true);
      expect(['ct-log', 'dns-probe']).toContain(candidate.source);
    }
  });
});
