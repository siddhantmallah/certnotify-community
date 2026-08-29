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

const program = new Command();

program
  .name('certnotify')
  .description('Open-source internet exposure scanner — SSL/TLS, DNS, DNSSEC, email security, HTTP headers, open ports, DNSBL reputation, and uptime.')
  .version('0.1.0');

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

program.parseAsync(process.argv);
