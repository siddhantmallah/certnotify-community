import { createRequire } from 'node:module';
import { Command } from 'commander';
import pc from 'picocolors';
import { scan } from './index.js';
import { formatJson, formatText } from './report.js';
import { ALL_CHECKS, type CheckName } from './types.js';
import { checkSSL } from './scanners/ssl.js';
import { checkWhois } from './scanners/whois.js';
import { checkDns } from './scanners/dns.js';
import { checkDnssec } from './scanners/dnssec.js';
import { checkEmail } from './scanners/email.js';
import { checkHeaders } from './scanners/headers.js';
import { checkPorts } from './scanners/ports.js';
import { checkBlacklist } from './scanners/blacklist.js';
import { checkUptime } from './scanners/uptime.js';
import { checkDnsChanges } from './scanners/dnsChanges.js';
import { checkDefacement } from './scanners/defacement.js';
import { checkWhoisPrivacy } from './scanners/whoisPrivacy.js';
import { checkMixedContent } from './scanners/mixedContent.js';
import { discoverSubdomains } from './scanners/subdomains.js';
import { defaultStateDir } from './state.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

const program = new Command();

program
  .name('certnotify')
  .description('Open-source internet exposure scanner — SSL/TLS, DNS, DNSSEC, email security, HTTP headers, open ports, DNSBL reputation, uptime, DNS-hijack monitoring, defacement detection, WHOIS-privacy monitoring, mixed-content scanning, and subdomain discovery.')
  .version(pkg.version);

program
  .command('scan')
  .argument('<target>', 'domain or IP to scan')
  .description('Run all checks (or a chosen subset) against a target')
  .option('--only <checks>', `comma-separated list of checks to run (${ALL_CHECKS.join(', ')})`)
  .option('--json', 'output machine-readable JSON instead of a formatted report')
  .option('--allow-private', 'allow scanning private/internal/loopback targets (off by default for safety)')
  .action(async (target: string, opts: { only?: string; json?: boolean; allowPrivate?: boolean }) => {
    const checks = opts.only
      ? (opts.only.split(',').map((c) => c.trim()).filter((c): c is CheckName => (ALL_CHECKS as string[]).includes(c)))
      : ALL_CHECKS;

    if (opts.only && checks.length === 0) {
      console.error(pc.red(`No valid checks in --only. Valid checks: ${ALL_CHECKS.join(', ')}`));
      process.exitCode = 1;
      return;
    }

    try {
      const report = await scan(target, { checks, allowPrivate: opts.allowPrivate });
      console.log(opts.json ? formatJson(report) : formatText(report));
    } catch (err: any) {
      console.error(pc.red(`Scan failed: ${err.message}`));
      process.exitCode = 1;
    }
  });

function registerSingleCheck(name: CheckName, fn: (target: string, opts: any) => Promise<unknown>, needsAllowPrivate: boolean) {
  const cmd = program
    .command(name)
    .argument('<target>', 'domain or IP to check')
    .description(`Run only the ${name} check and print its raw JSON result`);

  if (needsAllowPrivate) {
    cmd.option('--allow-private', 'allow scanning private/internal/loopback targets (off by default for safety)');
  }

  cmd.action(async (target: string, opts: { allowPrivate?: boolean }) => {
    try {
      const result = needsAllowPrivate ? await fn(target, { allowPrivate: opts.allowPrivate }) : await fn(target, undefined);
      console.log(JSON.stringify(result, null, 2));
    } catch (err: any) {
      console.error(pc.red(`${name} check failed: ${err.message}`));
      process.exitCode = 1;
    }
  });
}

registerSingleCheck('ssl', (t, o) => checkSSL(t, o), true);
registerSingleCheck('whois', (t) => checkWhois(t), false);
registerSingleCheck('dns', (t) => checkDns(t), false);
registerSingleCheck('dnssec', (t) => checkDnssec(t), false);
registerSingleCheck('email', (t) => checkEmail(t), false);
registerSingleCheck('headers', (t, o) => checkHeaders(t, o), true);
registerSingleCheck('ports', (t, o) => checkPorts(t, o), true);
registerSingleCheck('blacklist', (t) => checkBlacklist(t), false);
registerSingleCheck('uptime', (t, o) => checkUptime(t, o), true);

// ── Stateful checks (compare against a local baseline from the previous
// run — see `certnotify --help` for the default baseline location) ────────

function statefulCommand(name: string, description: string) {
  return program
    .command(name)
    .argument('<target>', 'domain to check')
    .description(description)
    .option('--state-dir <path>', `override where baseline state is stored (default: ${defaultStateDir()})`)
    .option('--json', 'output the full JSON result instead of a short summary');
}

statefulCommand('dns-monitor', 'Detect DNS record changes since the last run (possible hijacking)')
  .option('--allow-private', 'allow scanning private/internal/loopback targets')
  .action(async (target: string, opts: { stateDir?: string; json?: boolean; allowPrivate?: boolean }) => {
    try {
      const r = await checkDnsChanges(target, { stateDir: opts.stateDir });
      if (opts.json) { console.log(JSON.stringify(r, null, 2)); return; }
      if (r.baseline) console.log(pc.green(`✓ Baseline established for ${target}.`));
      else if (!r.changed) console.log(pc.green(`✓ No DNS changes detected for ${target}.`));
      else {
        console.log(r.suspicious ? pc.red(`⚠ DNS changes detected for ${target} (includes critical record types):`) : pc.yellow(`⚠ DNS changes detected for ${target}:`));
        for (const c of r.changes) console.log(`  ${c.critical ? pc.red(c.recordType) : c.recordType}: ${c.from.join(', ') || '(none)'} → ${c.to.join(', ') || '(none)'}`);
      }
    } catch (err: any) {
      console.error(pc.red(`dns-monitor failed: ${err.message}`));
      process.exitCode = 1;
    }
  });

statefulCommand('defacement', 'Detect website content changes since the last run')
  .option('--allow-private', 'allow scanning private/internal/loopback targets')
  .action(async (target: string, opts: { stateDir?: string; json?: boolean; allowPrivate?: boolean }) => {
    try {
      const r = await checkDefacement(target, { stateDir: opts.stateDir, allowPrivate: opts.allowPrivate });
      if (opts.json) { console.log(JSON.stringify(r, null, 2)); return; }
      if (r.baseline) console.log(pc.green(`✓ Baseline captured for ${target}.`));
      else if (!r.changed) console.log(pc.green(`✓ No content changes detected for ${target}.`));
      else console.log(pc.red(`⚠ Content changed for ${target} since the last check — verify this wasn't unauthorized.`));
    } catch (err: any) {
      console.error(pc.red(`defacement check failed: ${err.message}`));
      process.exitCode = 1;
    }
  });

statefulCommand('whois-privacy', 'Detect WHOIS privacy protection being disabled since the last run')
  .action(async (target: string, opts: { stateDir?: string; json?: boolean }) => {
    try {
      const r = await checkWhoisPrivacy(target, { stateDir: opts.stateDir });
      if (opts.json) { console.log(JSON.stringify(r, null, 2)); return; }
      if (r.baseline) console.log(pc.green(`✓ Baseline captured for ${target} — privacy protection: ${r.privacyEnabled ? 'enabled' : 'disabled'}.`));
      else if (r.privacyChanged && !r.privacyEnabled) {
        console.log(pc.red(`⚠ WHOIS privacy protection was just disabled for ${target} — registrant contact details may now be public.`));
      } else if (!r.privacyEnabled) {
        console.log(pc.yellow(`⚠ ${target} has no WHOIS privacy protection.`));
      } else {
        console.log(pc.green(`✓ No change — privacy protection still enabled for ${target}.`));
      }
    } catch (err: any) {
      console.error(pc.red(`whois-privacy check failed: ${err.message}`));
      process.exitCode = 1;
    }
  });

statefulCommand('mixed-content', 'Scan for HTTP resources embedded in HTTPS pages')
  .option('--allow-private', 'allow scanning private/internal/loopback targets')
  .action(async (target: string, opts: { stateDir?: string; json?: boolean; allowPrivate?: boolean }) => {
    try {
      const r = await checkMixedContent(target, { stateDir: opts.stateDir, allowPrivate: opts.allowPrivate });
      if (opts.json) { console.log(JSON.stringify(r, null, 2)); return; }
      if (r.error) console.log(pc.red(`✗ ${r.error}`));
      else if (r.issuesFound === 0) console.log(pc.green(`✓ No mixed content found across ${r.pagesScanned} page(s) for ${target}.`));
      else {
        console.log(pc.yellow(`⚠ ${r.issuesFound} mixed-content issue(s) found across ${r.pagesScanned} page(s) for ${target} (${r.newIssues} new):`));
        for (const i of r.issues.slice(0, 20)) console.log(`  [${i.type}] ${i.url}`);
        if (r.issues.length > 20) console.log(`  … and ${r.issues.length - 20} more`);
      }
    } catch (err: any) {
      console.error(pc.red(`mixed-content check failed: ${err.message}`));
      process.exitCode = 1;
    }
  });

statefulCommand('subdomains', 'Discover subdomains via Certificate Transparency logs + common-prefix probing')
  .option('--limit <n>', 'max brute-force prefixes to try (default: all ~70)', (v) => parseInt(v, 10))
  .action(async (target: string, opts: { stateDir?: string; json?: boolean; limit?: number }) => {
    try {
      const r = await discoverSubdomains(target, { stateDir: opts.stateDir, limit: opts.limit });
      if (opts.json) { console.log(JSON.stringify(r, null, 2)); return; }
      console.log(`${pc.green(String(r.discoveredCount))} discovered (${r.newCount} new) from ${r.scannedCandidates} candidates ${r.ctLogQueried ? '(CT logs queried)' : pc.yellow('(CT logs unavailable — brute force only)')}:`);
      for (const d of r.discovered.slice(0, 30)) console.log(`  ${d.isNew ? pc.cyan('[new] ') : ''}${d.host} ${pc.dim(`(${d.source})`)}`);
      if (r.discovered.length > 30) console.log(`  … and ${r.discovered.length - 30} more`);
    } catch (err: any) {
      console.error(pc.red(`subdomains discovery failed: ${err.message}`));
      process.exitCode = 1;
    }
  });

program.parseAsync(process.argv);
