import type { ScanReport } from './types.js';

/**
 * The SSL component for a trusted certificate, by `securityGrade`. B is a
 * modern server that still accepts TLS 1.0/1.1: half marks, since the
 * certificate is fine but old clients can still be served a protocol with
 * known attacks. C and D speak nothing newer, which current browsers refuse
 * to connect over at all, so they score like an untrusted certificate.
 */
const PROTOCOL_SCORES: Record<string, number> = { 'A+': 100, A: 100, B: 50, C: 0, D: 0, F: 0 };

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
    // `valid` includes trust since 0.5.0, so an untrusted certificate scores 0.
    const value = !report.ssl.valid ? 0 : (PROTOCOL_SCORES[report.ssl.securityGrade] ?? 100);
    weights.push({ value, weight: 15 });
  }
  // `unknown` means the lookups failed, and `nonexistent` that there is no
  // such name. Both are left out rather than scored: neither says anything
  // about how the domain's DNS is signed.
  if (report.dnssec && report.dnssec.status !== 'unknown' && report.dnssec.status !== 'nonexistent') {
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
  // An unknown reputation used to score 100, the same as clean — a run where
  // every list timed out read as a perfect result.
  if (report.blacklist && report.blacklist.reputation !== 'unknown') {
    const value = report.blacklist.reputation === 'clean' ? 100 : report.blacklist.reputation === 'suspicious' ? 50 : 0;
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
