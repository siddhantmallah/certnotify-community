import pc from 'picocolors';
import type { ScanReport } from './types.js';
import { compositeScore } from './score.js';

function statusIcon(ok: boolean | null): string {
  if (ok === null) return pc.gray('•');
  return ok ? pc.green('✓') : pc.red('✗');
}

function warnIcon(): string {
  return pc.yellow('⚠');
}

/**
 * The composite score is included alongside the report here, but deliberately
 * not on `ScanReport` itself: `scan()` returns raw findings, and callers that
 * want a number call `compositeScore()`. A CI consumer reading `--json` off
 * stdout has no such option, and threshold-gating a build is the main reason
 * to use `--json` at all — so the CLI's JSON carries it.
 */
export function formatJson(report: ScanReport): string {
  return JSON.stringify({ ...report, score: compositeScore(report) }, null, 2);
}

export function formatText(report: ScanReport): string {
  const lines: string[] = [];
  const score = compositeScore(report);

  lines.push(pc.bold('CERTNOTIFY SECURITY SCAN'));
  lines.push('');
  lines.push(`Target: ${pc.bold(report.target)}`);
  lines.push(`Scanned: ${report.scannedAt}`);
  if (score !== null) {
    const color = score >= 75 ? pc.green : score >= 40 ? pc.yellow : pc.red;
    lines.push('');
    lines.push(`Security Score: ${color(pc.bold(String(score)))}/100`);
  }
  lines.push('');

  if (report.ssl) {
    if ('error' in report.ssl) {
      lines.push(`${statusIcon(false)} SSL Certificate — ${report.ssl.error}`);
    } else {
      const s = report.ssl;
      lines.push(`${statusIcon(s.valid)} SSL Certificate — ${s.tlsVersion} (grade ${s.securityGrade}), expires in ${s.daysRemaining}d`);
      lines.push(`  Issuer: ${s.issuer.commonName} · Subject: ${s.subject.commonName}`);
    }
  }

  if (report.whois) {
    const w = report.whois;
    if (w.error) {
      lines.push(`${warnIcon()} Domain registration — ${w.message ?? w.error}`);
    } else {
      lines.push(`${statusIcon(w.valid)} Domain registration — registrar ${w.registrar}, expires in ${w.daysRemaining}d`);
    }
  }

  if (report.dnssec) {
    const d = report.dnssec;
    const ok = d.status === 'signed-valid' ? true : d.status === 'unsigned' ? false : null;
    lines.push(`${statusIcon(ok)} DNSSEC — ${d.status}`);
  }

  if (report.email) {
    const e = report.email;
    lines.push(`${statusIcon(e.score >= 55)} Email security (SPF/DKIM/DMARC) — grade ${e.grade} (${e.score}/100)`);
    // A grade drop alone buries this: multiple SPF records means every
    // receiver hard-fails SPF, which is worse than having no record at all.
    if (e.spf.multipleRecords) {
      lines.push(`  ${pc.red('✗')} ${e.spf.records.length} SPF records published — receivers fail SPF outright (RFC 7208 permerror)`);
    }
    for (const rec of e.recommendations) lines.push(`  ${warnIcon()} ${rec}`);
  }

  if (report.headers) {
    const h = report.headers;
    if (h.error) {
      lines.push(`${statusIcon(false)} Security headers — ${h.error}`);
    } else {
      lines.push(`${statusIcon(h.score >= 60)} Security headers — grade ${h.grade} (${h.score}/100)`);
      const missing = h.headers.filter((x) => !x.present);
      for (const m of missing) lines.push(`  ${warnIcon()} Missing ${m.name} — ${m.recommendation}`);
    }
  }

  if (report.ports) {
    if ('error' in report.ports) {
      lines.push(`${statusIcon(false)} Port scan — ${report.ports.error}`);
    } else {
      const p = report.ports;
      if (p.openPorts.length === 0) {
        lines.push(`${statusIcon(true)} Port scan — no unexpected open ports (checked ${p.scanned})`);
      } else {
        lines.push(`${statusIcon(p.riskLevel !== 'critical')} Port scan — ${p.openPorts.length} open, risk: ${p.riskLevel}`);
        for (const op of p.openPorts) lines.push(`  ${op.risk === 'critical' ? pc.red('🔴') : warnIcon()} ${op.port} (${op.service}) — ${op.risk} risk`);
      }
    }
  }

  if (report.blacklist) {
    const b = report.blacklist;
    if (b.error) {
      lines.push(`${warnIcon()} Blacklist check — ${b.error}`);
    } else {
      lines.push(`${statusIcon(b.reputation === 'clean')} Blacklist check — ${b.reputation} (${b.listedCount}/${b.results.length} lists)`);
    }
  }

  if (report.uptime) {
    if ('error' in report.uptime) {
      lines.push(`${statusIcon(false)} Uptime — ${report.uptime.error}`);
    } else {
      const u = report.uptime;
      lines.push(`${statusIcon(u.status === 'up')} Uptime — ${u.statusLabel} (${u.status}), ${u.responseTimeMs}ms (${u.performance})`);
    }
  }

  if (report.dns) {
    lines.push('');
    lines.push(pc.dim('DNS records:'));
    for (const r of report.dns.results) {
      if (r.error) continue;
      if (r.records.length === 0) continue;
      lines.push(pc.dim(`  ${r.type}: ${r.records.join(', ')}`));
    }
  }

  return lines.join('\n');
}
