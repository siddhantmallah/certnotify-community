import { describe, it, expect } from 'vitest';
import { scanHtml } from '../src/scanners/mixedContent.js';

describe('scanHtml', () => {
  it('finds an HTTP image on an otherwise clean page', () => {
    const html = `<html><body><img src="http://example.com/logo.png"></body></html>`;
    const issues = scanHtml(html);
    expect(issues).toContainEqual({ type: 'image', url: 'http://example.com/logo.png' });
  });

  it('does not flag HTTPS resources', () => {
    const html = `<img src="https://example.com/logo.png"><script src="https://example.com/app.js"></script>`;
    expect(scanHtml(html)).toHaveLength(0);
  });

  it('flags a non-stylesheet link as "stylesheet" only when rel=stylesheet is present', () => {
    const html = `<link rel="stylesheet" href="http://example.com/style.css">`;
    const issues = scanHtml(html);
    expect(issues).toContainEqual({ type: 'stylesheet', url: 'http://example.com/style.css' });
  });

  it('still catches a non-stylesheet link\'s HTTP href via the inline catch-all, just not as type "stylesheet"', () => {
    // Matches the original app's own intentionally-broad inline scan — it's
    // a whole-page text search, so it isn't scoped to only "real" resource
    // attributes. A known, accepted over-inclusiveness of the simple regex
    // approach, not something this port introduces.
    const html = `<link rel="canonical" href="http://example.com/page">`;
    const issues = scanHtml(html);
    expect(issues.find((i) => i.url === 'http://example.com/page')?.type).toBe('inline');
  });

  it('finds a stylesheet link regardless of attribute order', () => {
    const html = `<link href="http://example.com/style.css" rel="stylesheet">`;
    const issues = scanHtml(html);
    expect(issues).toContainEqual({ type: 'stylesheet', url: 'http://example.com/style.css' });
  });

  it('finds iframes and media sources', () => {
    const html = `
      <iframe src="http://example.com/widget"></iframe>
      <video><source src="http://example.com/video.mp4"></video>
    `;
    const issues = scanHtml(html);
    expect(issues).toContainEqual({ type: 'iframe', url: 'http://example.com/widget' });
    expect(issues).toContainEqual({ type: 'media', url: 'http://example.com/video.mp4' });
  });

  it('catches inline HTTP URLs not inside a recognized tag/attribute', () => {
    const html = `<style>body { background: url(http://example.com/bg.png); }</style>`;
    const issues = scanHtml(html);
    expect(issues.some((i) => i.type === 'inline' && i.url.includes('bg.png'))).toBe(true);
  });

  it('deduplicates the same URL found by multiple checks', () => {
    const html = `<img src="http://example.com/logo.png">`;
    const issues = scanHtml(html);
    expect(issues.filter((i) => i.url === 'http://example.com/logo.png')).toHaveLength(1);
  });
});
