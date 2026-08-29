import { describe, it, expect } from 'vitest';
import { isPrivateIP, assertPublicHostname } from '../src/scanners/ssrfGuard.js';

describe('isPrivateIP', () => {
  it('flags RFC1918 private IPv4 ranges', () => {
    expect(isPrivateIP('10.0.0.1')).toBe(true);
    expect(isPrivateIP('172.16.0.1')).toBe(true);
    expect(isPrivateIP('172.31.255.255')).toBe(true);
    expect(isPrivateIP('192.168.1.1')).toBe(true);
  });

  it('does not flag 172.15.x.x or 172.32.x.x (just outside the 172.16/12 block)', () => {
    expect(isPrivateIP('172.15.0.1')).toBe(false);
    expect(isPrivateIP('172.32.0.1')).toBe(false);
  });

  it('flags loopback and link-local (including cloud metadata) IPv4', () => {
    expect(isPrivateIP('127.0.0.1')).toBe(true);
    expect(isPrivateIP('169.254.169.254')).toBe(true); // AWS/GCP/Azure metadata endpoint
  });

  it('flags CGNAT and benchmarking ranges', () => {
    expect(isPrivateIP('100.64.0.1')).toBe(true);
    expect(isPrivateIP('198.18.0.1')).toBe(true);
  });

  it('does not flag well-known public IPv4 addresses', () => {
    expect(isPrivateIP('8.8.8.8')).toBe(false);
    expect(isPrivateIP('1.1.1.1')).toBe(false);
  });

  it('flags IPv6 loopback and link-local/unique-local', () => {
    expect(isPrivateIP('::1')).toBe(true);
    expect(isPrivateIP('fe80::1')).toBe(true);
    expect(isPrivateIP('fd00::1')).toBe(true);
  });

  it('does not flag a well-known public IPv6 address', () => {
    expect(isPrivateIP('2606:4700:4700::1111')).toBe(false); // Cloudflare DNS
  });

  it('treats malformed input as unsafe', () => {
    expect(isPrivateIP('not-an-ip')).toBe(true);
    expect(isPrivateIP('999.999.999.999')).toBe(true);
  });
});

describe('assertPublicHostname', () => {
  it('rejects localhost and .local/.internal suffixes', async () => {
    await expect(assertPublicHostname('localhost')).rejects.toThrow();
    await expect(assertPublicHostname('printer.local')).rejects.toThrow();
    await expect(assertPublicHostname('app.internal')).rejects.toThrow();
  });

  it('rejects a private IP literal', async () => {
    await expect(assertPublicHostname('127.0.0.1')).rejects.toThrow();
    await expect(assertPublicHostname('192.168.1.1')).rejects.toThrow();
  });

  it('rejects the AWS/GCP/Azure metadata IP', async () => {
    await expect(assertPublicHostname('169.254.169.254')).rejects.toThrow();
  });

  it('allows a public IP literal', async () => {
    await expect(assertPublicHostname('1.1.1.1')).resolves.toBeUndefined();
  });

  it('allowPrivate=true bypasses every check, including malformed input', async () => {
    await expect(assertPublicHostname('localhost', true)).resolves.toBeUndefined();
    await expect(assertPublicHostname('127.0.0.1', true)).resolves.toBeUndefined();
    await expect(assertPublicHostname('169.254.169.254', true)).resolves.toBeUndefined();
  });
});
