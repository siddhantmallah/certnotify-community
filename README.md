# certnotify

Open-source internet exposure scanner, from the command line. No account, no API key, no phoning home.

```bash
npx certnotify scan example.com
```

```
CERTNOTIFY SECURITY SCAN

Target: example.com
Scanned: 2026-08-29T12:00:00.000Z

Security Score: 84/100

✓ SSL Certificate — TLSv1.3 (grade A+), expires in 62d
✓ Domain registration — registrar Example Registrar, expires in 210d
✓ DNSSEC — signed-valid
✓ Email security (SPF/DKIM/DMARC) — grade B (72/100)
✓ Security headers — grade B (70/100)
✓ Port scan — no unexpected open ports (checked 15)
✓ Blacklist check — clean (0/7 lists)
✓ Uptime — Online (up), 210ms (Good)
```

## What it checks

| Check | What it does |
|---|---|
| `ssl` | TLS handshake, certificate validity/expiry, issuer, TLS version and grade |
| `whois` | Domain registration status and expiry, via public RDAP (not the legacy WHOIS protocol) |
| `dns` | A / AAAA / MX / TXT / NS / CNAME / SOA / PTR (reverse) records |
| `dnssec` | DNSSEC signing and validation status, via DNS-over-HTTPS |
| `email` | SPF, DKIM (common selectors), and DMARC posture and grade |
| `headers` | HTTP security headers (HSTS, CSP, X-Frame-Options, and 7 more), graded not just presence-checked |
| `ports` | TCP-connect probe against 15 well-known ports (databases, admin panels, dev servers) |
| `blacklist` | Cross-references your domain's IP against 7 public DNSBL feeds |
| `uptime` | HTTPS check with HTTP fallback — status, response time, performance rating, redirects |

Every check uses only Node's built-in `tls`/`dns`/`net` modules or free, keyless public services (RDAP registries, Cloudflare DNS-over-HTTPS, public DNSBL zones) — no paid API keys, no telemetry, no phone-home.

## Install

```bash
npm install -g certnotify
certnotify scan example.com
```

Or run it once without installing:

```bash
npx certnotify scan example.com
```

## Usage

```bash
certnotify scan <target>                 # run every check
certnotify scan <target> --only ssl,dns,email
certnotify scan <target> --json          # machine-readable output, e.g. for CI
certnotify ssl <target>                  # run a single check directly, prints raw JSON
```

Every check that connects to a user-supplied host refuses to scan private, loopback, link-local, or cloud-metadata addresses by default (SSRF protection). Pass `--allow-private` to override this for legitimate local-network testing.

## As a library

```ts
import { scan } from 'certnotify';

const report = await scan('example.com', { checks: ['ssl', 'headers'] });
```

Each individual scanner (`checkSSL`, `checkWhois`, `checkDns`, `checkDnssec`, `checkEmail`, `checkHeaders`, `checkPorts`, `checkBlacklist`, `checkUptime`) is also exported directly.

## Relationship to CertNotify Cloud

This CLI is the open-source core of [CertNotify](https://www.certnotify.com) — continuous monitoring, historical trends, team alerting, and a hosted dashboard live at certnotify.com. This package will always contain a genuine, complete security engine on its own; the hosted product is about *continuous* monitoring and *correlation* across many assets over time, not gatekeeping the scanners themselves.

## License

[GNU AGPL v3.0](./LICENSE) or later. If you run a modified version of this project as a network service, you must make your modified source available to users of that service — this is what keeps the project from being quietly forked into a closed competing product.

## Changelog

- **0.1.1** — `checkDnssec` now returns `rcode: { dnskey, ds }` (the raw DoH response codes); `checkHeaders` now returns `rawHeaders` (every header the server sent, not just the 10 checked) so a consumer can inspect anything else — e.g. `Cache-Control` — without a second request. Both are additive, no breaking changes.
- **0.1.0** — Initial release: 9 checks (ssl, whois, dns, dnssec, email, headers, ports, blacklist, uptime), CLI + library.

## Status

`v0.1.1` — public. Live on [npm](https://www.npmjs.com/package/certnotify) and [GitHub](https://github.com/siddhantmallah/certnotify-community). 9 real checks, a `vitest` suite (unit tests for security-critical logic like the SSRF guard, plus live integration tests against real domains — no mocks anywhere). A GitHub Actions CI workflow exists but can't run yet — the repo owner's GitHub account is billing-locked, unrelated to this project; the workflow itself is unaffected and will start running the moment that's resolved. See [ROADMAP-OPENSOURCE.md](./ROADMAP-OPENSOURCE.md) for what's planned next (stateful checks like DNS-hijack and defacement monitoring, subdomain discovery, and new domains — secrets scanning, IaC/container scanning, SAST, DAST — built by orchestrating established open-source tools rather than reinventing them).

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit across src/ and test/
npm run build       # tsup — emits CJS + ESM + .d.ts to dist/
npm test            # vitest — unit tests + live integration tests against real domains
```
