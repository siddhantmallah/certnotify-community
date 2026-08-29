import crypto from 'node:crypto';
import { assertPublicHostname } from './ssrfGuard.js';
import { readState, writeState, type StateOptions } from '../state.js';
import type { DefacementResult } from '../types.js';

/**
 * Extract a stable content fingerprint from raw HTML — title, meta
 * description, headings, and visible body text: the elements an attacker
 * would change during a defacement, while ignoring markup/whitespace noise
 * that changes on every deploy for unrelated reasons.
 */
function extractFingerprint(html: string): string {
  const title = html.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim() ?? '';
  const metaDesc = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']{0,500})/i)?.[1]?.trim() ?? '';

  const headings = [...html.matchAll(/<h[1-3][^>]*>([\s\S]{0,300}?)<\/h[1-3]>/gi)]
    .map((m) => m[1].replace(/<[^>]+>/g, '').trim())
    .join(' | ');

  const visible = html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 5000);

  return crypto.createHash('sha256').update(`${title}|||${metaDesc}|||${headings}|||${visible}`).digest('hex');
}

/**
 * Website defacement detection: fingerprints the homepage and compares
 * against the last-seen baseline for this target. First run establishes
 * the baseline; every run after that reports whether the fingerprint
 * changed since.
 */
export async function checkDefacement(rawTarget: string, opts: StateOptions & { allowPrivate?: boolean } = {}): Promise<DefacementResult> {
  const hostname = rawTarget.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase().trim();
  await assertPublicHostname(hostname, opts.allowPrivate);

  const res = await fetch(`https://${hostname}`, {
    signal: AbortSignal.timeout(12000),
    headers: { 'User-Agent': 'certnotify-cli/0.2 (+https://www.certnotify.com)' },
    redirect: 'follow',
  });
  if (!res.ok) throw new Error(`Could not fetch page (HTTP ${res.status}) — site may be down or blocking requests`);
  const html = await res.text();
  const hash = extractFingerprint(html);
  const checkedAt = new Date().toISOString();

  const state = await readState(hostname, opts);
  const previous = state.defacement as { hash: string } | undefined;

  state.defacement = { hash, checkedAt };
  await writeState(hostname, state, opts);

  if (!previous) {
    return { target: hostname, baseline: true, changed: false, hash, checkedAt };
  }

  return { target: hostname, baseline: false, changed: previous.hash !== hash, previousHash: previous.hash, hash, checkedAt };
}
