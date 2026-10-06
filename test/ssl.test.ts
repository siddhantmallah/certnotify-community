import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import {
  checkSSL,
  classifyLegacyProbeError,
  cleanHostname,
  gradeTlsProtocols,
  summariseLegacyProbes,
} from '../src/scanners/ssl.js';

/**
 * checkSSL against real TLS servers on loopback. The certificates in
 * fixtures/tls are self-signed test-only keys valid until 2126: `loopback`
 * names 127.0.0.1, `other-name` names something else. `allowPrivate` is on
 * only so 127.0.0.1 can stand in for a public host.
 */

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'tls');
const pem = (name: string) => fs.readFileSync(path.join(fixtures, name));

function listen(cert: 'loopback' | 'other-name', options: tls.TlsOptions = {}): Promise<tls.Server> {
  return new Promise((resolve) => {
    const server = tls.createServer({ key: pem(`${cert}.key`), cert: pem(`${cert}.crt`), ...options }, (socket) => socket.end());
    // Refused probes are the point of several tests; unheard, they would crash the run.
    server.on('tlsClientError', () => {});
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

const portOf = (server: tls.Server) => (server.address() as AddressInfo).port;
const LEGACY_SERVER: tls.TlsOptions = { ciphers: 'DEFAULT@SECLEVEL=0' };

describe('cleanHostname', () => {
  it('keeps www. — www.example.com is a different TLS name from example.com', () => {
    expect(cleanHostname('https://www.example.com/path')).toBe('www.example.com');
  });
});

describe('classifyLegacyProbeError', () => {
  it('reads a server alert, a version mismatch or a hang-up as the server refusing', () => {
    expect(classifyLegacyProbeError({ code: 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION' })).toBe('refused');
    expect(classifyLegacyProbeError({ code: 'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE' })).toBe('refused');
    expect(classifyLegacyProbeError({ code: 'ERR_SSL_UNSUPPORTED_PROTOCOL' })).toBe('refused');
    expect(classifyLegacyProbeError({ code: 'ECONNRESET' })).toBe('refused');
  });

  it('counts a handshake abandoned after the server picked the legacy version as accepted', () => {
    // What a runtime that ignores SECLEVEL=0 sees from a TLS 1.0 server.
    expect(classifyLegacyProbeError({ code: 'ERR_SSL_LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED' })).toBe('accepted');
  });

  it('reads the runtime being unable to offer the version as unsupported, not refused', () => {
    expect(classifyLegacyProbeError({ code: 'ERR_SSL_NO_PROTOCOLS_AVAILABLE' })).toBe('unsupported');
    expect(classifyLegacyProbeError({ code: 'ERR_SSL_NO_CIPHER_MATCH' })).toBe('unsupported');
    expect(classifyLegacyProbeError({ code: 'ERR_TLS_INVALID_PROTOCOL_VERSION' })).toBe('unsupported');
  });

  it('gives no verdict for a timeout, an unreachable host or an unknown error', () => {
    expect(classifyLegacyProbeError({ code: 'ETIMEDOUT' })).toBe('inconclusive');
    expect(classifyLegacyProbeError({ code: 'ECONNREFUSED' })).toBe('inconclusive');
    expect(classifyLegacyProbeError(new Error('something new'))).toBe('inconclusive');
  });
});

describe('summariseLegacyProbes', () => {
  it('lists the accepted versions, oldest first', () => {
    expect(summariseLegacyProbes({ TLSv1: 'accepted', 'TLSv1.1': 'accepted' })).toEqual(['TLSv1', 'TLSv1.1']);
    expect(summariseLegacyProbes({ TLSv1: 'refused', 'TLSv1.1': 'accepted' })).toEqual(['TLSv1.1']);
  });

  it('reports [] only when the server refused every probe', () => {
    expect(summariseLegacyProbes({ TLSv1: 'refused', 'TLSv1.1': 'refused' })).toEqual([]);
  });

  it('reports null, never [], when this runtime could not make the probes', () => {
    expect(summariseLegacyProbes({ TLSv1: 'unsupported', 'TLSv1.1': 'unsupported' })).toBeNull();
    expect(summariseLegacyProbes({ TLSv1: 'refused', 'TLSv1.1': 'inconclusive' })).toBeNull();
  });
});

describe('gradeTlsProtocols', () => {
  it('grades from the worst accepted protocol, not the negotiated one', () => {
    expect(gradeTlsProtocols('TLSv1.3', [])).toBe('A+');
    expect(gradeTlsProtocols('TLSv1.3', ['TLSv1.1'])).toBe('C');
    expect(gradeTlsProtocols('TLSv1.3', ['TLSv1', 'TLSv1.1'])).toBe('D');
  });

  it('matches Node\'s exact protocol names (TLS 1.0 is "TLSv1")', () => {
    expect(gradeTlsProtocols('TLSv1', null)).toBe('D');
    expect(gradeTlsProtocols('TLSv1.2', null)).toBe('A');
  });
});

describe('checkSSL against loopback TLS servers', () => {
  const servers: tls.Server[] = [];
  let modern = 0;
  let wrongName = 0;
  let tls10Only = 0;
  let everything = 0;

  beforeAll(async () => {
    const started = await Promise.all([
      listen('loopback'),
      listen('other-name'),
      listen('loopback', { ...LEGACY_SERVER, minVersion: 'TLSv1', maxVersion: 'TLSv1' }),
      listen('loopback', { ...LEGACY_SERVER, minVersion: 'TLSv1' }),
    ]);
    servers.push(...started);
    [modern, wrongName, tls10Only, everything] = started.map(portOf);
  });

  afterAll(() => {
    for (const server of servers) server.close();
  });

  it('reports a self-signed certificate as untrusted and not valid, though in date', async () => {
    const r = await checkSSL('127.0.0.1', { port: modern, allowPrivate: true });
    expect(r.dateValid).toBe(true);
    expect(r.authorized).toBe(false);
    expect(r.authorizationError).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
    expect(r.valid).toBe(false);
  });

  it('checks the name separately, since Node skips it when the chain fails', async () => {
    const matching = await checkSSL('127.0.0.1', { port: modern, allowPrivate: true });
    const mismatched = await checkSSL('127.0.0.1', { port: wrongName, allowPrivate: true });
    expect(matching.hostnameMatch).toBe(true);
    expect(mismatched.hostnameMatch).toBe(false);
    // Both fail the chain first, so authorized cannot tell them apart.
    expect(mismatched.authorizationError).toBe(matching.authorizationError);
  });

  it('reports a server that refuses TLS 1.0/1.1 as legacyProtocols []', async () => {
    const r = await checkSSL('127.0.0.1', { port: modern, allowPrivate: true });
    expect(r.tlsVersion).toBe('TLSv1.3');
    expect(r.legacyProtocols).toEqual([]);
    expect(r.securityGrade).toBe('A+');
  });

  it('grades a modern server that still accepts TLS 1.0 by the TLS 1.0 it accepts', async () => {
    const r = await checkSSL('127.0.0.1', { port: everything, allowPrivate: true });
    expect(r.tlsVersion).toBe('TLSv1.3');
    expect(r.legacyProtocols).toEqual(['TLSv1', 'TLSv1.1']);
    expect(r.securityGrade).toBe('D');
  });

  it('reports a TLS 1.0-only server as legacy rather than failing the check', async () => {
    const r = await checkSSL('127.0.0.1', { port: tls10Only, allowPrivate: true });
    expect(r.tlsVersion).toBe('TLSv1');
    expect(r.legacyProtocols).toEqual(['TLSv1']);
    expect(r.securityGrade).toBe('D');
  });
});
