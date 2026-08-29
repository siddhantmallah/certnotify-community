import type { ScanReport } from './types.js';

/**
 * A simple, transparent weighted composite of the individual check scores —
 * NOT a replacement for real cross-check risk correlation (which needs
 * production-exposure/exploitability context this CLI doesn't have). This
 * exists so a single-run scan has one headline number, the way the product
 * vision describes; the real correlation engine is a CertNotify Cloud
 * feature, deliberately out of scope here.
 */
export function compositeScore(report: ScanReport): number | null {
  const weights: { value: number; weight: number }[] = [];

  if (report.ssl && !('error' in report.ssl)) {
    weights.push({ value: report.ssl.valid ? 100 : 0, weight: 15 });
  }
  if (report.dnssec) {
    const value = report.dnssec.status === 'signed-valid' ? 100 : report.dnssec.status === 'signed-unvalidated' ? 50 : 0;
    weights.push({ value, weight: 10 });
  }
  if (report.email) {
    weights.push({ value: report.email.score, weight: 20 });
  }
  if (report.headers) {
    weights.push({ value: report.headers.score, weight: 25 });
  }
  if (report.ports && !('error' in report.ports)) {
    const value = report.ports.riskLevel === 'critical' ? 0 : report.ports.riskLevel === 'high' ? 50 : 100;
    weights.push({ value, weight: 15 });
  }
  if (report.blacklist) {
    const value = report.blacklist.reputation === 'clean' ? 100 : report.blacklist.reputation === 'suspicious' ? 50 : report.blacklist.reputation === 'blacklisted' ? 0 : 100;
    weights.push({ value, weight: 15 });
  }
  if (report.uptime && !('error' in report.uptime)) {
    const value = report.uptime.status === 'up' ? 100 : report.uptime.status === 'degraded' ? 50 : 0;
    weights.push({ value, weight: 10 });
  }

  if (weights.length === 0) return null;

  const totalWeight = weights.reduce((s, w) => s + w.weight, 0);
  const weighted = weights.reduce((s, w) => s + w.value * w.weight, 0);
  return Math.round(weighted / totalWeight);
}
