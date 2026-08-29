export * from './scanners/index.js';
export * from './types.js';
export { defaultStateDir, readState, writeState, type StateOptions } from './state.js';

import { checkSSL } from './scanners/ssl.js';
import { checkWhois } from './scanners/whois.js';
import { checkDns } from './scanners/dns.js';
import { checkDnssec } from './scanners/dnssec.js';
import { checkEmail } from './scanners/email.js';
import { checkHeaders } from './scanners/headers.js';
import { checkPorts } from './scanners/ports.js';
import { checkBlacklist } from './scanners/blacklist.js';
import { checkUptime } from './scanners/uptime.js';
import type { CheckName, ScanReport } from './types.js';
import { ALL_CHECKS } from './types.js';

export interface ScanOptions {
  checks?: CheckName[];
  allowPrivate?: boolean;
}

/**
 * Runs the requested checks (default: all) against a single target and
 * returns a combined report. Each check fails independently — one failing
 * check (e.g. a domain with no open ports reachable, or blocked ICMP) never
 * aborts the others.
 */
export async function scan(target: string, options: ScanOptions = {}): Promise<ScanReport> {
  const checks = options.checks ?? ALL_CHECKS;
  const allowPrivate = options.allowPrivate ?? false;
  const report: ScanReport = { target, scannedAt: new Date().toISOString() };

  const tasks: Promise<void>[] = [];

  if (checks.includes('ssl')) {
    tasks.push(
      checkSSL(target, { allowPrivate }).then(
        (r) => { report.ssl = r; },
        (e) => { report.ssl = { error: e.message }; }
      )
    );
  }
  if (checks.includes('whois')) {
    tasks.push(checkWhois(target).then((r) => { report.whois = r; }));
  }
  if (checks.includes('dns')) {
    tasks.push(checkDns(target).then((r) => { report.dns = r; }));
  }
  if (checks.includes('dnssec')) {
    tasks.push(checkDnssec(target).then((r) => { report.dnssec = r; }));
  }
  if (checks.includes('email')) {
    tasks.push(checkEmail(target).then((r) => { report.email = r; }));
  }
  if (checks.includes('headers')) {
    tasks.push(checkHeaders(target, { allowPrivate }).then((r) => { report.headers = r; }));
  }
  if (checks.includes('ports')) {
    tasks.push(
      checkPorts(target, { allowPrivate }).then(
        (r) => { report.ports = r; },
        (e) => { report.ports = { error: e.message }; }
      )
    );
  }
  if (checks.includes('blacklist')) {
    tasks.push(checkBlacklist(target).then((r) => { report.blacklist = r; }));
  }
  if (checks.includes('uptime')) {
    tasks.push(
      checkUptime(target, { allowPrivate }).then(
        (r) => { report.uptime = r; },
        (e) => { report.uptime = { error: e.message }; }
      )
    );
  }

  await Promise.all(tasks);
  return report;
}
