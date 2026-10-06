import crypto from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import { describeError } from '../errors.js';
import { pinPublicHost } from './ssrfGuard.js';
import type { LegacyTlsVersion, SSLResult } from '../types.js';

const HANDSHAKE_TIMEOUT_MS = 10000;

/** Oldest first. */
export const LEGACY_TLS_VERSIONS: readonly LegacyTlsVersion[] = ['TLSv1', 'TLSv1.1'];

function asString(value: string | string[] | undefined, fallback: string): string {
  if (Array.isArray(value)) return value[0] ?? fallback;
  return value ?? fallback;
}

/**
 * Scheme and path off, nothing else. This used to strip `www.` too, so a check
 * of www.example.com connected to example.com and reported the apex
 * certificate — a different TLS name, often served by a different certificate
 * or by none at all. Reducing a name to its registered domain is a WHOIS
 * concern, and whois.ts does that for itself.
 */
export function cleanHostname(input: string): string {
  return String(input || '')
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .toLowerCase()
    .trim();
}

interface Handshake {
  certificate: tls.DetailedPeerCertificate;
  protocol: string;
  authorized: boolean;
  authorizationError: string | null;
}

function handshake(
  hostname: string,
  port: number,
  lookup: net.LookupFunction,
  extra: tls.ConnectionOptions = {}
): Promise<Handshake> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        // SNI stays the hostname, so the certificate presented is the one for
        // the name the caller asked about — pinning the address does not
        // change which virtual host answers. RFC 6066 forbids an IP literal as
        // SNI, so an IP target sends none.
        servername: net.isIP(hostname) ? undefined : hostname,
        lookup,
        // Not rejecting is what lets an untrusted certificate be reported at
        // all; trust is read back from `authorized` below instead.
        rejectUnauthorized: false,
        ...extra,
      },
      () => {
        // Typed as an Error, but Node stores the verify code string here.
        const authorizationError = socket.authorizationError ? String(socket.authorizationError) : null;
        resolve({
          certificate: socket.getPeerCertificate(true),
          protocol: socket.getProtocol() || 'Unknown',
          authorized: socket.authorized,
          authorizationError,
        });
        socket.destroy();
      }
    );

    socket.on('error', (error) => {
      socket.destroy();
      reject(error);
    });

    socket.setTimeout(HANDSHAKE_TIMEOUT_MS);
    socket.on('timeout', () => {
      socket.destroy();
      reject(Object.assign(new Error('Connection timeout'), { code: 'ETIMEDOUT' }));
    });
  });
}

function legacyHandshakeOptions(version: LegacyTlsVersion): tls.ConnectionOptions {
  return {
    minVersion: version,
    maxVersion: version,
    // Node's default floor is TLS 1.2, and OpenSSL 3 will not complete TLS
    // 1.0/1.1 above security level 0 (both sign the handshake with SHA-1).
    // Without both overrides the probe could never succeed, which is why the
    // C and D grades never fired before 0.5.0.
    ciphers: 'DEFAULT@SECLEVEL=0',
    // Servers old enough to stop at TLS 1.0 often predate RFC 5746, and
    // OpenSSL 3 drops their ServerHello ("unsafe legacy renegotiation").
    secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
  };
}

export type LegacyProbeOutcome = 'accepted' | 'refused' | 'unsupported' | 'inconclusive';

// Raised only after the ServerHello has fixed the version: the server agreed
// to speak it, and it was this client that would not finish. A runtime that
// ignores SECLEVEL=0 ends every legacy probe here, so this is not a refusal.
const ACCEPTED_THEN_ABANDONED = new Set([
  'ERR_SSL_LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED',
  'ERR_SSL_UNSAFE_LEGACY_RENEGOTIATION_DISABLED',
]);

// This runtime could not offer the version at all — an OpenSSL built without
// it, a FIPS policy, a TLS library that rejects the cipher string. Nothing was
// learned about the server.
const RUNTIME_CANNOT_OFFER = new Set([
  'ERR_SSL_NO_PROTOCOLS_AVAILABLE',
  'ERR_SSL_NO_CIPHERS_AVAILABLE',
  'ERR_SSL_NO_CIPHER_MATCH',
  'ERR_TLS_INVALID_PROTOCOL_VERSION',
  'ERR_TLS_PROTOCOL_VERSION_CONFLICT',
]);

// The server's own answer to a legacy hello: a different version, or hanging up.
const SERVER_REFUSED = new Set([
  'ERR_SSL_UNSUPPORTED_PROTOCOL',
  'ERR_SSL_WRONG_VERSION_NUMBER',
  'ERR_SSL_VERSION_TOO_LOW',
  'ERR_SSL_UNEXPECTED_EOF_WHILE_READING',
  'ECONNRESET',
  'EPIPE',
]);

/** What a failed legacy handshake says about the server. Pure, so each rule is testable. */
export function classifyLegacyProbeError(err: unknown): LegacyProbeOutcome {
  const code = String((err as { code?: unknown } | null)?.code ?? '');
  if (ACCEPTED_THEN_ABANDONED.has(code)) return 'accepted';
  if (RUNTIME_CANNOT_OFFER.has(code)) return 'unsupported';
  // A TLS alert is the server talking, e.g. "protocol version" or "handshake failure".
  if (SERVER_REFUSED.has(code) || (code.startsWith('ERR_SSL_') && code.includes('_ALERT_'))) return 'refused';
  // Timeouts, unreachable networks, anything unrecognised: no verdict.
  return 'inconclusive';
}

/**
 * `[]` is a clean bill, so it is given only when the server itself turned
 * away every legacy probe. A probe this runtime could not make, or one that
 * timed out, learned nothing — and reporting nothing learned as "no legacy
 * TLS" is exactly the false all-clear this field exists to stop.
 */
export function summariseLegacyProbes(
  outcomes: Record<LegacyTlsVersion, LegacyProbeOutcome>
): LegacyTlsVersion[] | null {
  const accepted = LEGACY_TLS_VERSIONS.filter((version) => outcomes[version] === 'accepted');
  if (accepted.length > 0) return accepted;
  return LEGACY_TLS_VERSIONS.every((version) => outcomes[version] === 'refused') ? [] : null;
}

const GRADE_ORDER = ['F', 'D', 'C', 'A', 'A+'];

const PROTOCOL_GRADES: Record<string, string> = {
  SSLv2: 'F',
  SSLv3: 'F',
  TLSv1: 'D',
  'TLSv1.1': 'C',
  'TLSv1.2': 'A',
  'TLSv1.3': 'A+',
};

/**
 * The worst protocol the server accepts sets the grade, not the best one it
 * negotiates: an attacker in the middle gets to pick the version.
 * Exact names, not substrings — Node reports TLS 1.0 as `TLSv1`.
 */
export function gradeTlsProtocols(negotiated: string, legacyProtocols: readonly string[] | null): string {
  const grades = [negotiated, ...(legacyProtocols ?? [])].map((protocol) => PROTOCOL_GRADES[protocol] ?? 'A');
  return grades.reduce((worst, grade) => (GRADE_ORDER.indexOf(grade) < GRADE_ORDER.indexOf(worst) ? grade : worst));
}

function buildResult(hostname: string, h: Handshake, legacyProtocols: LegacyTlsVersion[] | null): SSLResult {
  const certificate = h.certificate;
  if (!certificate || Object.keys(certificate).length === 0) throw new Error('No certificate found');

  const validTo = new Date(certificate.valid_to);
  const validFrom = new Date(certificate.valid_from);
  const now = new Date();
  const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
  const dateValid = now < validTo && now > validFrom;

  return {
    hostname,
    valid: dateValid && h.authorized,
    dateValid,
    authorized: h.authorized,
    authorizationError: h.authorizationError,
    // Asked separately: Node checks the name only after the chain verifies, so
    // for a self-signed or unknown-CA certificate `authorized` is silent on it.
    hostnameMatch: tls.checkServerIdentity(hostname, certificate) === undefined,
    legacyProtocols,
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    daysRemaining: daysUntilExpiry,
    issuer: {
      organization: asString(certificate.issuer?.O, 'Unknown'),
      commonName: asString(certificate.issuer?.CN, 'Unknown'),
      country: asString(certificate.issuer?.C, 'Unknown'),
    },
    subject: {
      commonName: asString(certificate.subject?.CN, hostname),
      altNames: certificate.subjectaltname
        ? certificate.subjectaltname.split(', ').map((s) => s.replace('DNS:', ''))
        : [],
    },
    tlsVersion: h.protocol,
    securityGrade: gradeTlsProtocols(h.protocol, legacyProtocols),
    serialNumber: certificate.serialNumber,
    fingerprint: certificate.fingerprint,
    keySize: certificate.bits ?? 'Unknown',
    algorithm: (certificate as unknown as { signatureAlgorithm?: string }).signatureAlgorithm ?? 'Unknown',
  };
}

export async function checkSSL(rawHostname: string, opts: { port?: number; allowPrivate?: boolean } = {}): Promise<SSLResult> {
  const port = opts.port ?? 443;

  // Pinned, not merely validated. Connecting by hostname would resolve a
  // second time, and a hostile authoritative server can answer that lookup
  // differently from the one the check saw. Every handshake below, probes
  // included, goes to these addresses.
  const pinned = await pinPublicHost(cleanHostname(rawHostname), opts.allowPrivate);
  const hostname = pinned.hostname;

  // Probes run alongside the main handshake rather than after it: a server
  // that speaks nothing newer than TLS 1.1 fails the main handshake, and the
  // probe is then the only thing that can say why.
  const [main, ...probes] = await Promise.allSettled([
    handshake(hostname, port, pinned.lookup),
    ...LEGACY_TLS_VERSIONS.map((version) => handshake(hostname, port, pinned.lookup, legacyHandshakeOptions(version))),
  ]);

  const outcomes = Object.fromEntries(
    LEGACY_TLS_VERSIONS.map((version, i) => {
      const probe = probes[i];
      return [version, probe.status === 'fulfilled' ? 'accepted' : classifyLegacyProbeError(probe.reason)];
    })
  ) as Record<LegacyTlsVersion, LegacyProbeOutcome>;
  const legacyProtocols = summariseLegacyProbes(outcomes);

  if (main.status === 'fulfilled') return buildResult(hostname, main.value, legacyProtocols);

  // Legacy-only server: report it from the newest legacy handshake that
  // completed, so the result says "TLS 1.0, grade D" instead of a bare failure.
  const legacyOnly = [...probes].reverse().find((p): p is PromiseFulfilledResult<Handshake> => p.status === 'fulfilled');
  if (legacyOnly) return buildResult(hostname, legacyOnly.value, legacyProtocols);
  if (legacyProtocols && legacyProtocols.length > 0) {
    throw new Error(`SSL check failed: the server only offers ${legacyProtocols.join(' and ')}, which this runtime will not complete a handshake over`);
  }

  const reason = main.reason as NodeJS.ErrnoException;
  if (reason?.code === 'ETIMEDOUT' && reason.message === 'Connection timeout') throw new Error('Connection timeout');
  // describeError, not error.message: a host refusing on both its A and AAAA
  // records raises an AggregateError whose message is empty, and this line
  // then recorded "SSL check failed: " and nothing else.
  throw new Error(`SSL check failed: ${describeError(reason)}`);
}
