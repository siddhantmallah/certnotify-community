import tls from 'node:tls';
import { pinPublicHost } from './ssrfGuard.js';
import type { SSLResult } from '../types.js';

function asString(value: string | string[] | undefined, fallback: string): string {
  if (Array.isArray(value)) return value[0] ?? fallback;
  return value ?? fallback;
}

export function cleanHostname(input: string): string {
  return String(input || '')
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/^www\./, '')
    .toLowerCase()
    .trim();
}

export async function checkSSL(rawHostname: string, opts: { port?: number; allowPrivate?: boolean } = {}): Promise<SSLResult> {
  const hostname = cleanHostname(rawHostname);
  const port = opts.port ?? 443;

  // Pinned, not merely validated. Connecting by hostname would resolve a
  // second time, and a hostile authoritative server can answer that lookup
  // differently from the one the check saw.
  const pinned = await pinPublicHost(hostname, opts.allowPrivate);

  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        // SNI stays the hostname, so the certificate presented is the one for
        // the name the caller asked about — pinning the address does not
        // change which virtual host answers.
        servername: hostname,
        lookup: pinned.lookup,
        rejectUnauthorized: false,
      },
      () => {
        const certificate = socket.getPeerCertificate(true);

        if (!certificate || Object.keys(certificate).length === 0) {
          socket.destroy();
          reject(new Error('No certificate found'));
          return;
        }

        const validTo = new Date(certificate.valid_to);
        const validFrom = new Date(certificate.valid_from);
        const now = new Date();
        const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        const tlsVersion = socket.getProtocol() || 'Unknown';

        let securityGrade = 'A';
        if (tlsVersion.includes('TLSv1.3')) securityGrade = 'A+';
        else if (tlsVersion.includes('TLSv1.2')) securityGrade = 'A';
        else if (tlsVersion.includes('TLSv1.1')) securityGrade = 'C';
        else if (tlsVersion.includes('TLSv1')) securityGrade = 'D';
        else if (tlsVersion.includes('SSLv')) securityGrade = 'F';

        const result: SSLResult = {
          hostname,
          valid: now < validTo && now > validFrom,
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
          tlsVersion,
          securityGrade,
          serialNumber: certificate.serialNumber,
          fingerprint: certificate.fingerprint,
          keySize: certificate.bits ?? 'Unknown',
          algorithm: (certificate as unknown as { signatureAlgorithm?: string }).signatureAlgorithm ?? 'Unknown',
        };

        socket.destroy();
        resolve(result);
      }
    );

    socket.on('error', (error) => {
      socket.destroy();
      reject(new Error(`SSL check failed: ${error.message}`));
    });

    socket.setTimeout(10000);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('Connection timeout'));
    });
  });
}
