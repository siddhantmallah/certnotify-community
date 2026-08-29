import { assertPublicHostname } from './ssrfGuard.js';
import { readState, writeState, type StateOptions } from '../state.js';
import type { MixedContentIssue, MixedContentResourceType, MixedContentResult } from '../types.js';

const MAX_PAGES = 10;
const COMMON_PATHS = ['/about', '/contact', '/blog', '/products', '/services', '/pricing'];
const INLINE_HTTP_PATTERN = /http:\/\/[^"')\s]+/gi;

function getAttr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i'));
  return m ? m[1] : null;
}

function findTags(html: string, tagName: string): string[] {
  return html.match(new RegExp(`<${tagName}\\b[^>]*>`, 'gi')) ?? [];
}

interface RawIssue {
  type: MixedContentResourceType;
  url: string;
}

/**
 * Finds HTTP resources embedded in an HTTPS page — the exact set of checks
 * a browser's own mixed-content blocker flags. Uses plain regex/attribute
 * matching rather than a full HTML parser: the original app's own broadest
 * check (the inline catch-all) already worked this way, and the structured
 * per-tag checks below are simple enough attribute patterns not to need a
 * DOM — keeps this package free of a heavy parsing dependency.
 */
export function scanHtml(html: string): RawIssue[] {
  const issues: RawIssue[] = [];
  const seen = new Set<string>();

  const add = (type: MixedContentResourceType, url: string) => {
    if (seen.has(url)) return;
    seen.add(url);
    issues.push({ type, url });
  };

  for (const tag of findTags(html, 'img')) {
    const src = getAttr(tag, 'src');
    if (src?.startsWith('http://')) add('image', src);
  }
  for (const tag of findTags(html, 'script')) {
    const src = getAttr(tag, 'src');
    if (src?.startsWith('http://')) add('script', src);
  }
  for (const tag of findTags(html, 'link')) {
    const rel = getAttr(tag, 'rel');
    const href = getAttr(tag, 'href');
    if (rel?.toLowerCase() === 'stylesheet' && href?.startsWith('http://')) add('stylesheet', href);
  }
  for (const tag of findTags(html, 'iframe')) {
    const src = getAttr(tag, 'src');
    if (src?.startsWith('http://')) add('iframe', src);
  }
  for (const tag of findTags(html, 'source')) {
    const src = getAttr(tag, 'src');
    if (src?.startsWith('http://')) add('media', src);
  }

  const inlineMatches = html.match(INLINE_HTTP_PATTERN) ?? [];
  for (const match of inlineMatches) add('inline', match);

  return issues;
}

async function fetchText(url: string, timeoutMs: number): Promise<string | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { 'User-Agent': 'certnotify-cli/0.2 (+https://www.certnotify.com)' },
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

async function discoverPages(baseUrl: string): Promise<string[]> {
  const domain = baseUrl.replace(/\/$/, '');
  const pages = COMMON_PATHS.map((p) => `${domain}${p}`);

  const sitemapXml = await fetchText(`${domain}/sitemap.xml`, 5000);
  if (sitemapXml) {
    const locs = [...sitemapXml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]);
    for (const url of locs) {
      if (url.startsWith('https://') && pages.length < MAX_PAGES) pages.push(url);
    }
  }

  return [...new Set(pages)];
}

/**
 * Mixed-content scanning: scans the homepage plus a handful of common/
 * sitemap-discovered pages for HTTP resources embedded in HTTPS pages.
 * Tracks first-seen time and occurrence count per issue in local state, so
 * repeat scans can tell "still here" apart from "new since last run".
 */
export async function checkMixedContent(rawTarget: string, opts: StateOptions & { allowPrivate?: boolean } = {}): Promise<MixedContentResult> {
  const hostname = rawTarget.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase().trim();
  const checkedAt = new Date().toISOString();

  try {
    await assertPublicHostname(hostname, opts.allowPrivate);
  } catch (err: any) {
    return { target: hostname, pagesScanned: 0, issuesFound: 0, newIssues: 0, issues: [], error: err.message, checkedAt };
  }

  const homeUrl = `https://${hostname}`;
  const pagesToScan = [homeUrl, ...(await discoverPages(homeUrl)).filter((p) => p !== homeUrl)].slice(0, MAX_PAGES);

  const foundByUrl = new Map<string, RawIssue>();
  let pagesScanned = 0;

  for (const pageUrl of pagesToScan) {
    const html = await fetchText(pageUrl, 10000);
    if (html === null) continue;
    pagesScanned++;
    for (const issue of scanHtml(html)) {
      if (!foundByUrl.has(issue.url)) foundByUrl.set(issue.url, issue);
    }
  }

  const state = await readState(hostname, opts);
  const previousIssues = (state.mixedContent?.issues ?? {}) as Record<string, { type: string; firstSeenAt: string; occurrences: number }>;

  const issues: MixedContentIssue[] = [];
  let newIssues = 0;
  const nextIssues: Record<string, { type: string; firstSeenAt: string; occurrences: number }> = {};

  for (const [url, issue] of foundByUrl) {
    const prev = previousIssues[url];
    const firstSeenAt = prev?.firstSeenAt ?? checkedAt;
    const occurrences = (prev?.occurrences ?? 0) + 1;
    if (!prev) newIssues++;
    nextIssues[url] = { type: issue.type, firstSeenAt, occurrences };
    issues.push({ type: issue.type, url, fix: url.replace('http://', 'https://'), firstSeenAt, occurrences });
  }

  state.mixedContent = { issues: nextIssues, lastScannedAt: checkedAt };
  await writeState(hostname, state, opts);

  return { target: hostname, pagesScanned, issuesFound: issues.length, newIssues, issues, checkedAt };
}
