import { assertPublicHostname } from './ssrfGuard.js';
import { readState, writeState, type StateOptions } from '../state.js';
import type { MixedContentIssue, MixedContentResourceType, MixedContentResult } from '../types.js';
import { pinnedFetch } from './pinnedFetch.js';
import { USER_AGENT } from '../version.js';

const MAX_PAGES = 10;
const COMMON_PATHS = ['/about', '/contact', '/blog', '/products', '/services', '/pricing'];
/**
 * `url(http://…)` and `@import "http://…"` inside CSS — the inline loads a
 * browser actually makes. Reported as type `inline`.
 *
 * This replaced a whole-page `http://` text search, which flagged anything
 * that merely *mentioned* a URL: the `xmlns="http://www.w3.org/2000/svg"` on
 * every inline SVG, JSON-LD `@context`, plain `<a href>` links, font licence
 * URLs, comments. None of those is fetched, so none is mixed content, and in
 * production every single `inline` finding it produced was one of them.
 */
const CSS_HTTP_URL = /url\(\s*["']?(http:\/\/[^"')\s]+)["']?\s*\)|@import\s+["'](http:\/\/[^"']+)["']/gi;

function cssLoads(css: string): string[] {
  const out: string[] = [];
  for (const m of css.matchAll(CSS_HTTP_URL)) out.push(m[1] ?? m[2]);
  return out;
}

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
 * Finds HTTP resources an HTTPS page makes the browser *load* — the set a
 * browser's own mixed-content blocker acts on. A URL that is only mentioned
 * (a link, a namespace, structured data) is not mixed content and is not
 * reported. Uses plain regex/attribute matching rather than a full HTML
 * parser: the per-tag checks are simple attribute patterns, and it keeps this
 * package free of a heavy parsing dependency.
 */
export function scanHtml(html: string): RawIssue[] {
  const issues: RawIssue[] = [];
  const seen = new Set<string>();

  const add = (type: MixedContentResourceType, url: string) => {
    if (seen.has(url)) return;
    seen.add(url);
    issues.push({ type, url });
  };

  const httpCandidates = (srcset: string | null) =>
    (srcset ?? '').split(',').map((part) => part.trim().split(/\s+/)[0]).filter((u) => u?.startsWith('http://'));

  for (const tag of findTags(html, 'img')) {
    const src = getAttr(tag, 'src');
    if (src?.startsWith('http://')) add('image', src);
    for (const u of httpCandidates(getAttr(tag, 'srcset'))) add('image', u);
  }
  for (const tag of findTags(html, 'script')) {
    const src = getAttr(tag, 'src');
    if (src?.startsWith('http://')) add('script', src);
  }
  for (const tag of findTags(html, 'link')) {
    const rel = getAttr(tag, 'rel');
    const href = getAttr(tag, 'href');
    if (!href?.startsWith('http://')) continue;
    // Only the rel values that make the browser fetch the href. A canonical,
    // alternate or author link is a reference, not a load.
    const rels = (rel ?? '').toLowerCase().split(/\s+/);
    const as = getAttr(tag, 'as')?.toLowerCase();
    if (rels.includes('stylesheet')) add('stylesheet', href);
    else if (rels.includes('icon') || rels.includes('apple-touch-icon')) add('image', href);
    else if (rels.includes('modulepreload')) add('script', href);
    else if (rels.includes('preload')) {
      add(as === 'script' ? 'script' : as === 'style' ? 'stylesheet' : as === 'image' ? 'image' : 'media', href);
    }
  }
  for (const tag of findTags(html, 'iframe')) {
    const src = getAttr(tag, 'src');
    if (src?.startsWith('http://')) add('iframe', src);
  }
  for (const tagName of ['source', 'video', 'audio', 'track', 'embed']) {
    for (const tag of findTags(html, tagName)) {
      const src = getAttr(tag, 'src');
      if (src?.startsWith('http://')) add('media', src);
      if (tagName === 'source') for (const u of httpCandidates(getAttr(tag, 'srcset'))) add('image', u);
    }
  }
  for (const tag of findTags(html, 'video')) {
    const poster = getAttr(tag, 'poster');
    if (poster?.startsWith('http://')) add('image', poster);
  }
  for (const tag of findTags(html, 'object')) {
    const data = getAttr(tag, 'data');
    if (data?.startsWith('http://')) add('media', data);
  }

  // CSS: <style> blocks and style="" attributes.
  for (const m of html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) {
    for (const u of cssLoads(m[1])) add('inline', u);
  }
  for (const m of html.matchAll(/\bstyle\s*=\s*(["'])([\s\S]*?)\1/gi)) {
    for (const u of cssLoads(m[2])) add('inline', u);
  }

  return issues;
}

async function fetchText(url: string, timeoutMs: number, allowPrivate = false): Promise<string | null> {
  try {
    // Pinned per hop, and checked for every URL — including the ones read
    // out of the site's sitemap, which used to be fetched with no host check
    // at all: a sitemap listing https://10.0.0.5/ was an SSRF.
    const res = await pinnedFetch(url, {
      timeoutMs,
      headers: { 'User-Agent': USER_AGENT },
      allowPrivate,
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

/**
 * The https URLs a sitemap lists on `host` itself.
 *
 * Same host only. A sitemap is written by whoever runs the site being
 * scanned, and before this filter any `<loc>` was fetched — a sitemap listing
 * an internal address made the scanner request it.
 */
export function sitemapPages(xml: string, host: string): string[] {
  const out: string[] = [];
  for (const m of xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
    let u: URL;
    try { u = new URL(m[1]); } catch { continue; }
    if (u.protocol === 'https:' && u.hostname === host) out.push(u.toString());
  }
  return out;
}

async function discoverPages(baseUrl: string, allowPrivate = false): Promise<string[]> {
  const domain = baseUrl.replace(/\/$/, '');
  const pages = COMMON_PATHS.map((p) => `${domain}${p}`);
  const host = new URL(domain).hostname;

  const sitemapXml = await fetchText(`${domain}/sitemap.xml`, 5000, allowPrivate);
  if (sitemapXml) {
    for (const url of sitemapPages(sitemapXml, host)) {
      if (pages.length < MAX_PAGES) pages.push(url);
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
  const pagesToScan = [homeUrl, ...(await discoverPages(homeUrl, opts.allowPrivate)).filter((p) => p !== homeUrl)].slice(0, MAX_PAGES);

  const foundByUrl = new Map<string, RawIssue>();
  let pagesScanned = 0;

  for (const pageUrl of pagesToScan) {
    const html = await fetchText(pageUrl, 10000, opts.allowPrivate);
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
