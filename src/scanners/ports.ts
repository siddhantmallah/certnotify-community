import net from 'node:net';
import { pinPublicHost } from './ssrfGuard.js';
import type { PortCheckResult, PortRisk, PortsResult } from '../types.js';

const PORTS: { port: number; service: string; risk: PortRisk }[] = [
  { port: 21, service: 'FTP', risk: 'high' },
  { port: 22, service: 'SSH', risk: 'medium' },
  { port: 23, service: 'Telnet', risk: 'critical' },
  { port: 25, service: 'SMTP', risk: 'medium' },
  { port: 80, service: 'HTTP', risk: 'low' },
  { port: 443, service: 'HTTPS', risk: 'low' },
  { port: 3000, service: 'Dev Server', risk: 'high' },
  { port: 3306, service: 'MySQL', risk: 'critical' },
  { port: 5432, service: 'PostgreSQL', risk: 'critical' },
  { port: 5601, service: 'Kibana', risk: 'high' },
  { port: 6379, service: 'Redis', risk: 'critical' },
  { port: 8080, service: 'HTTP-Alt', risk: 'medium' },
  { port: 8443, service: 'HTTPS-Alt', risk: 'low' },
  { port: 9200, service: 'Elasticsearch', risk: 'critical' },
  { port: 27017, service: 'MongoDB', risk: 'critical' },
];

function tcpProbe(host: string, port: number, timeoutMs = 3000): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const s = new net.Socket();
    s.setTimeout(timeoutMs);
    s.connect(port, host, () => {
      if (!done) {
        done = true;
        resolve(true);
        s.destroy();
      }
    });
    s.on('error', () => {
      if (!done) {
        done = true;
        resolve(false);
      }
    });
    s.on('timeout', () => {
      if (!done) {
        done = true;
        resolve(false);
        s.destroy();
      }
    });
  });
}

/**
 * TCP-connect probe against 15 well-known ports. This is the REAL scanner —
 * the equivalent public tool page in the original app was a `Math.random()`
 * simulation that never made a network connection at all.
 */
export async function checkPorts(rawHostname: string, opts: { allowPrivate?: boolean } = {}): Promise<PortsResult> {
  const hostname = rawHostname.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();

  // This scanner was already safe from rebinding — it resolves once and then
  // connects to the resolved *address*, so there is no second lookup to
  // poison. What it did not do is check every address: it took `addresses[0]`
  // and validated only that, so a name resolving to one public and one private
  // address passed whenever the public one happened to sort first.
  //
  // `pinPublicHost` validates all of them and rejects if any is private, which
  // is the stricter and simpler rule. The probe still connects by address.
  const pinned = await pinPublicHost(hostname, opts.allowPrivate);
  const hostIp = pinned.addresses[0].address;

  const results: PortCheckResult[] = await Promise.all(
    PORTS.map(async ({ port, service, risk }) => ({ port, service, risk, open: await tcpProbe(hostIp, port) }))
  );

  const openPorts = results.filter((r) => r.open);
  const riskLevel: PortRisk = openPorts.some((p) => p.risk === 'critical')
    ? 'critical'
    : openPorts.some((p) => p.risk === 'high')
      ? 'high'
      : openPorts.some((p) => p.risk === 'medium')
        ? 'medium'
        : 'low';

  return { domain: hostname, ip: hostIp, scanned: results.length, openPorts, riskLevel, results };
}
