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

  it('does not flag a link the browser does not load', () => {
    // A canonical link is a reference. The old whole-page text search
    // reported it as "inline", and this test used to require that.
    expect(scanHtml(`<link rel="canonical" href="http://example.com/page">`)).toEqual([]);
  });

  // Every one of these was a real production finding from the old whole-page
  // text search, and none of them is fetched by a browser.
  it.each([
    ['an inline SVG namespace', `<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>`],
    ['an ordinary hyperlink', `<a href="http://example.com/">a site</a>`],
    ['JSON-LD structured data', `<script type="application/ld+json">{"@context":"http://schema.org","@type":"Organization"}</script>`],
    ['a font licence URL in a comment', `<!-- SIL Open Font License, http://scripts.sil.org/OFL -->`],
    ['XMP metadata in inline SVG', `<svg><metadata><x:xmpmeta xmlns:x="adobe:ns:meta/" xmlns:xmp="http://ns.adobe.com/xap/1.0/"/></metadata></svg>`],
    ['a URL in visible text', `<p>See http://www.microsoft.com/ for details.</p>`],
  ])('does not flag %s', (_label, html) => {
    expect(scanHtml(html)).toEqual([]);
  });

  it('finds the loads the old tag checks missed', () => {
    const issues = scanHtml(`
      <img src="https://example.com/a.png" srcset="http://example.com/a2x.png 2x, https://example.com/a3x.png 3x">
      <link rel="icon" href="http://example.com/favicon.ico">
      <link rel="preload" as="script" href="http://example.com/early.js">
      <video src="http://example.com/clip.mp4" poster="http://example.com/poster.jpg"></video>
      <object data="http://example.com/doc.pdf"></object>
      <div style="background-image: url('http://example.com/hero.jpg')"></div>
      <style>@import "http://example.com/theme.css";</style>
    `);
    expect(issues).toEqual(expect.arrayContaining([
      { type: 'image', url: 'http://example.com/a2x.png' },
      { type: 'image', url: 'http://example.com/favicon.ico' },
      { type: 'script', url: 'http://example.com/early.js' },
      { type: 'media', url: 'http://example.com/clip.mp4' },
      { type: 'image', url: 'http://example.com/poster.jpg' },
      { type: 'media', url: 'http://example.com/doc.pdf' },
      { type: 'inline', url: 'http://example.com/hero.jpg' },
      { type: 'inline', url: 'http://example.com/theme.css' },
    ]));
    expect(issues.some((i) => i.url.startsWith('https://'))).toBe(false);
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

  it('catches an HTTP url() inside a <style> block', () => {
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
