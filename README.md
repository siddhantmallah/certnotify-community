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
✓ Blacklist check — clean (listed on 0 of 4 lists checked)
✓ Uptime — Online (up), 210ms (Good)
```

## What it checks

| Check | What it does |
|---|---|
| `ssl` | TLS handshake; certificate trust (chain and hostname), expiry and issuer; TLS version, legacy TLS 1.0/1.1 support, and grade |
| `whois` | Domain registration status and expiry, via public RDAP (not the legacy WHOIS protocol) |
| `dns` | A / AAAA / MX / TXT / NS / CNAME / SOA / PTR (reverse) records |
| `dnssec` | DNSSEC signing and validation status, via DNS-over-HTTPS |
| `email` | SPF, DKIM (common selectors), and DMARC posture and grade |
| `headers` | HTTP security headers (HSTS, CSP, X-Frame-Options, and 7 more), graded not just presence-checked |
| `ports` | TCP-connect probe against 15 well-known ports (databases, admin panels, dev servers) |
| `blacklist` | Cross-references your domain's IP against 4 public DNSBL feeds, reporting per list whether it is listed, not listed, or could not be checked |
| `uptime` | HTTPS check with HTTP fallback — status, response time, performance rating, redirects |

Every check uses only Node's built-in `tls`/`dns`/`net` modules or free, keyless public services (RDAP registries, Cloudflare DNS-over-HTTPS, public DNSBL zones) — no paid API keys, no telemetry, no phone-home.

### What the legacy TLS probe can and cannot see

`ssl` makes its normal handshake with Node's defaults (TLS 1.2 or newer, so trust is
judged the way a modern client judges it), plus one probe each pinned to exactly TLS 1.0
and TLS 1.1 with `DEFAULT@SECLEVEL=0`. `legacyProtocols` lists the versions the server
accepted, and the grade comes from the worst of them: TLS 1.1 is C, TLS 1.0 is D.

- **Detected** on Node 18+ (OpenSSL 3). Verified on Node 22.19 / OpenSSL 3.0.17 against
  `tls-v1-0.badssl.com:1010` (`["TLSv1"]`, D), `tls-v1-1.badssl.com:1011` (`["TLSv1.1"]`, C),
  `tls-v1-2.badssl.com:1012` and `github.com` (`[]`). A server that speaks *only* legacy TLS
  is reported as that version with its grade rather than as a failed handshake.
- **Unknown, not clean:** when this runtime cannot offer TLS 1.0/1.1 at all (an OpenSSL
  built without them, FIPS mode, a TLS library that rejects the cipher string), or a probe
  times out, `legacyProtocols` is `null`. `[]` is only reported when the server itself
  refused both versions.
- **Partly seen:** on a runtime that will not drop to security level 0, a server that agrees
  to TLS 1.0 is still caught (the handshake fails only after the server has chosen the
  version), but a legacy-only server then cannot be inspected and the check fails with a
  message saying so.
- **Not detected:** SSLv3 and SSLv2 (OpenSSL 3 has no client for them, and Node refuses the
  version), and servers whose only legacy cipher suites are outside OpenSSL's default list
  (RC4, 3DES-only), which read as refusing legacy TLS.

Each `ssl` check therefore opens three connections, and a server that silently drops
legacy handshakes can hold it for the full 10-second timeout.

### Blacklist lookups that cannot be answered

A DNSBL says "not listed" with NXDOMAIN. Timeouts, resolver failures, and refusal answers
(`127.255.255.x` — Spamhaus returns these to queries sent through large public resolvers)
are reported per list as `status: "error"`, counted in `errorCount`, and never as clean.
If no list answers, `reputation` is `unknown`.

## Stateful checks

The 9 checks above are stateless — run them anywhere, anytime, no history required. The 5 checks below compare against a local baseline from your *previous* run, so they need somewhere to remember what "normal" looked like. That baseline is a plain JSON file per target under `~/.certnotify/state` by default (override with `--state-dir <path>`) — no database, no account, nothing leaves your machine.

| Command | What it does |
|---|---|
| `dns-monitor` | Diffs A/AAAA/MX/NS/TXT/CNAME records against the last run — flags possible DNS hijacking. Changes to A/AAAA/NS/MX are marked critical. |
| `defacement` | Fingerprints the homepage (title, meta description, headings, visible text) and flags any change since the last run. |
| `whois-privacy` | Detects when WHOIS privacy protection gets disabled, exposing the registrant's real contact details. |
| `mixed-content` | Scans the homepage and a handful of linked/sitemap pages for HTTP resources embedded in HTTPS pages, tracking first-seen time and occurrence count. |
| `subdomains` | Combines real Certificate Transparency log data (every certificate ever issued for the domain) with a common-prefix DNS probe, and tracks which subdomains are new since the last run. |

```bash
certnotify dns-monitor example.com     # baseline on first run, diff on every run after
certnotify defacement example.com
certnotify whois-privacy example.com
certnotify mixed-content example.com
certnotify subdomains example.com --limit 30
```

All five accept `--state-dir <path>` and `--json`.

## Install

```bash
npm install -g certnotify
certnotify scan example.com
```

Or run it once without installing:

```bash
npx certnotify scan example.com
```

### Docker

```bash
docker build -t certnotify .
docker run --rm certnotify scan example.com
```

The stateful checks keep their baseline in `~/.certnotify/state`, which does not
survive a container exiting. Mount a volume to make them useful across runs:

```bash
docker run --rm -v certnotify-state:/home/certnotify/.certnotify \
  certnotify dns-monitor example.com
```

### GitHub Actions

```yaml
- uses: siddhantmallah/certnotify-community@main
  with:
    target: example.com
    fail-on: 70          # fail the job below 70/100; omit to only record
```

| Input | Default | |
|---|---|---|
| `target` | — | Domain or host to scan (required) |
| `checks` | all | Comma-separated subset, e.g. `ssl,headers,email` |
| `fail-on` | never | Fail the job when the composite score is below this |
| `version` | `latest` | Which `certnotify` release to run |
| `json-path` | `certnotify-report.json` | Where the JSON report is written |
| `summary` | `true` | Write the readable report to the job summary |

Outputs `score` and `json-path`. The scan runs once and the job summary is
rendered from that same result rather than scanning the target twice.

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

Each individual scanner (`checkSSL`, `checkWhois`, `checkDns`, `checkDnssec`, `checkEmail`, `checkHeaders`, `checkPorts`, `checkBlacklist`, `checkUptime`) is also exported directly, as are the 5 stateful checks (`checkDnsChanges`, `checkDefacement`, `checkWhoisPrivacy`, `checkMixedContent`, `discoverSubdomains`) and the `readState`/`writeState` helpers they're built on:

```ts
import { checkDnsChanges, readState } from 'certnotify';

const result = await checkDnsChanges('example.com', { stateDir: './baselines' });
if (result.suspicious) {
  // a critical record type (A/AAAA/NS/MX) changed since the last run
}
```

## Relationship to CertNotify Cloud

This CLI is the open-source core of [CertNotify](https://www.certnotify.com) — continuous monitoring, historical trends, team alerting, and a hosted dashboard live at certnotify.com. This package will always contain a genuine, complete security engine on its own; the hosted product is about *continuous* monitoring and *correlation* across many assets over time, not gatekeeping the scanners themselves.

## License

[GNU AGPL v3.0](./LICENSE) or later. If you run a modified version of this project as a network service, you must make your modified source available to users of that service — this is what keeps the project from being quietly forked into a closed competing product.

## Contributing

[CONTRIBUTING.md](./CONTRIBUTING.md) covers the setup, how to add a check, and
why there are no mocks in the test suite. Security issues go to
<security@certnotify.com> — see [SECURITY.md](./SECURITY.md).

A false positive or false negative is the most useful bug report this project
can get; there is an issue template for exactly that.

## Changelog

- **0.5.0** — **Results now say when a check could not tell, instead of reporting it
  clean.** Behaviour changes for consumers:
  - **`ssl.valid` now includes trust** (`dateValid && authorized`). It was the dates alone,
    read off a handshake that does not reject, so self-signed, unknown-CA and wrong-host
    certificates reported `valid: true`. New fields: `dateValid` (the old meaning),
    `authorized`, `authorizationError` (Node's code, e.g. `DEPTH_ZERO_SELF_SIGNED_CERT`),
    and `hostnameMatch`, which is checked on its own because Node skips the name check when
    the chain fails.
  - **`ssl` no longer strips `www.`**: `www.example.com` is checked as itself, and `hostname`
    in the result is the name checked. It was silently checking the apex certificate.
  - **`ssl.legacyProtocols`** lists accepted TLS 1.0/1.1 (`[]` none, `null` unknown), and
    `securityGrade` comes from the worst accepted protocol, so a TLS 1.3 server that still
    accepts TLS 1.0 grades D. A TLS 1.0-only server now returns a result instead of throwing.
    Before this, Node's TLS 1.2 floor meant the C and D grades could never fire.
  - **`blacklist` reports per-list `status`** (`listed` / `not_listed` / `error`), `answers`
    and `error`, plus `checkedCount` and `errorCount` on the result. Errors and timeouts
    counted as "not listed" before. Only a `127.0.0.x` answer is a listing; `127.255.255.x`
    and anything else is an error. `listed` is kept and is true only for `listed`. SORBS
    (shut down), MSRBL (defunct) and Abusix (needs a key) are removed, so there are 4 lists,
    not 7. When no list answers, `reputation` is `unknown` and `error` is set.
  - **`dnssec` has an `unknown` status** for when the DNSKEY lookup fails; it reported
    `unsigned`. AD on the DS answer no longer counts: the parent zone sets it on its signed
    proof that an unsigned domain has no DS (google.se, google.nl), and those domains read
    as `signed-valid`. Validity now needs AD on the DNSKEY answer, and `adBit` means exactly
    that. A name inside a signed zone (mail.ietf.org) has no keys of its own but an
    authenticated DNSKEY answer, and stays `signed-valid`; a name that does not exist
    (NXDOMAIN) no longer reads as signed.
  - **`headers` grading**: HSTS directives are parsed (max-age of a year or more is long
    enough, `max-age=0` is bad; `max-age=300` passed as good before); Referrer-Policy
    matches whole tokens (`no-referrer-when-downgrade` was graded good); X-Frame-Options
    `ALLOWALL` is bad; values repeated by a header sent twice are de-duplicated. Each header
    has a `scored` flag, and X-XSS-Protection is reported but no longer scored — it could
    never grade good, so it capped every site at 90.
  - **Composite score**: an untrusted certificate scores 0, accepting legacy TLS is half
    marks, and an `unknown` blacklist or DNSSEC result is left out instead of scoring 100
    and 0 respectively.
  - The User-Agent is now `certnotify-cli/0.5.0` (it said 0.1/0.2), and `VERSION` is exported.
- **0.4.1** — `mixed-content` reports only resources the browser loads, not every
  `http://` in the page; `dns-monitor` no longer reports a failed lookup as records changing.
- **0.4.0** — The fetch-based scanners (headers, uptime, defacement, mixed content) are
  pinned against DNS rebinding like the TLS and port scans, and mixed-content scans no
  longer follow sitemap entries on other hosts.
- **0.3.0** — **`email` now detects multiple SPF records.** A domain publishing
  more than one `v=spf1` record is a permanent error under RFC 7208 §4.5:
  receivers do not pick one, they fail SPF for the domain outright. This checker
  previously took the first match and reported such a domain as healthy — the
  worst way an SPF check can be wrong, since the owner's mail is failing
  authentication and every first-match tool tells them it is fine. `spf` now
  carries `records`, `multipleRecords` and `error`, the version tag is matched
  case-insensitively per §3.2, and `spf.valid` is false when duplicates make the
  policy unevaluable. Also: `--json` output now includes the composite `score`
  (it was only ever printed in the human-readable report, which made
  threshold-gating a CI build unnecessarily awkward), plus a `Dockerfile` and a
  GitHub Action.
- **0.2.0** — 5 new stateful checks that compare against a local baseline: `dns-monitor` (DNS-hijack detection), `defacement` (homepage content-fingerprint monitoring), `whois-privacy` (registrant privacy-protection monitoring), `mixed-content` (HTTP-in-HTTPS resource scanning), and `subdomains` (Certificate Transparency log + brute-force discovery). Baselines live in `~/.certnotify/state` by default, overridable with `--state-dir`. All additive, no breaking changes.
- **0.1.1** — `checkDnssec` now returns `rcode: { dnskey, ds }` (the raw DoH response codes); `checkHeaders` now returns `rawHeaders` (every header the server sent, not just the 10 checked) so a consumer can inspect anything else — e.g. `Cache-Control` — without a second request. Both are additive, no breaking changes.
- **0.1.0** — Initial release: 9 checks (ssl, whois, dns, dnssec, email, headers, ports, blacklist, uptime), CLI + library.

## Status

`v0.5.0` — public. Live on [npm](https://www.npmjs.com/package/certnotify) and [GitHub](https://github.com/siddhantmallah/certnotify-community). 14 real checks (9 stateless + 5 stateful), a `vitest` suite (unit tests for security-critical/pure logic like the SSRF guard, SPF parsing and the stateful checks' parsing logic, plus live integration tests against real domains — no mocks anywhere), distributed as a CLI, a library, a Docker image and a GitHub Action.

The CI workflow is set to manual dispatch rather than running on push: the repo owner's GitHub account is billing-locked (unrelated to this project and not being resolved), so every triggered run fails in two seconds without a runner ever starting. Rather than paint the history red with failures that say nothing about the code, the workflow is parked and `npm run verify` — the same typecheck, build and test steps — is the gate. Flipping the trigger back is a two-line change, documented in the workflow file.

See [ROADMAP-OPENSOURCE.md](./ROADMAP-OPENSOURCE.md) for what's planned next (new domains — secrets scanning, IaC/container scanning, SAST, DAST — built by orchestrating established open-source tools rather than reinventing them).

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit across src/ and test/
npm run build       # tsup — emits CJS + ESM + .d.ts to dist/
npm test            # vitest — unit tests + live integration tests against real domains
```
