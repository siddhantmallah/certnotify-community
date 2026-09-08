# CertNotify open-core roadmap

This package (`certnotify`, the CLI/library) is Phase 1 of a larger plan to grow CertNotify from a single-purpose SSL/domain monitor into an open-core internet-exposure / DevSecOps platform. Recorded here so the reasoning survives outside chat history.

1. **Phase 1 (done)** — Extract the real, stateless scanners (SSL, WHOIS/RDAP, DNS, DNSSEC, email security, HTTP security headers, port scanning, DNSBL reputation) out of the CertNotify SaaS app into this standalone, AGPL-3.0-or-later licensed package. Buildable and runnable locally.
2. **Phase 2 (done)** — Added the 9th check (`uptime`, consolidated from 3 divergent implementations the same way `headers` was in Phase 1), a `vitest` suite (unit tests for security-critical logic like the SSRF guard and the composite scorer, plus live integration tests against real domains — no mocks), and GitHub Actions CI across Node 18/20/22. Also fixed a real bug found during hardening: `package.json`'s `exports`/`module` fields pointed at `dist/index.mjs`, a file tsup never actually produces (it emits `index.js` for ESM and `index.cjs` for CJS) — anyone `require()`-ing the package before this fix would have gotten a module-not-found error.

**Public since 2026-08-29**: repo is live at [github.com/siddhantmallah/certnotify-community](https://github.com/siddhantmallah/certnotify-community), package is published as [`certnotify@0.1.0`](https://www.npmjs.com/package/certnotify) on npm, verified working via `npx certnotify@0.1.0 scan <target>` against the real public registry. The CI workflow itself can't run yet — the account it lives under is billing-locked on GitHub, unrelated to this project and not being resolved by choice — but the workflow is otherwise correct and will start working the moment that's cleared.
3. **Phase 3 (done)** — Wired the CertNotify Cloud dashboard to depend on this package for its stateless checks (all 9) instead of its own duplicated inline logic. Internals-only refactor — no behavior changes, app-facing shapes preserved byte-for-byte. Along the way, fixed 5 pre-existing bugs uncovered during the swap (a cron severity-scoring crash, an SPF/DKIM/reverse-DNS field-name mismatch in 3 public tool pages, a missing DMARC record type in DNS monitoring, and WHOIS-privacy checks never actually being run).
4. **Phase 4 (done)** — Added the 5 stateful checks (DNS-hijack monitoring, website defacement detection, WHOIS-privacy-change detection, mixed-content scanning) with a local persistence design (`~/.certnotify/state/<target>.json`, one file per target, overridable via `--state-dir`) — these only worked before via the SaaS app's database. Also added real subdomain discovery via passive Certificate Transparency log enumeration (crt.sh), combined with the existing common-prefix brute force as a supplement. `certnotify` is now at `0.2.0` with 14 real checks (9 stateless + 5 stateful) and a `vitest` suite covering both. Package-only — the SaaS app keeps its own live, Prisma-backed implementations of these same 4 checks for now; whether/how it later adopts this package's versions is a separate future decision.
5. **Phase 5** — New security domains, each by wrapping a mature existing open-source tool rather than building from scratch: secrets scanning (Gitleaks) and IaC/container scanning (Trivy) first — both ship as single static binaries, cheapest to integrate. SAST (Semgrep) and DAST (OWASP ZAP) follow once that orchestration pattern is proven.
6. **Phase 6** — CertNotify Cloud only, proprietary: a correlation engine (turns "you have 40 findings" into "this one is actually exploitable and internet-facing"), an AI security analyst, and compliance-framework mapping (ISO 27001, SOC 2, PCI DSS, GDPR).
7. **Phase 7** — Positioning/marketing layer (new tagline, homepage restructure, GitHub as a growth channel) — deliberately last. Don't market capability that doesn't exist yet.

## Distribution surfaces (shipped in 0.3.0)

The engine reaches people through four surfaces now, not one: **npm** (CLI +
library), **Docker** (`Dockerfile`, non-root, with a volume for the stateful
checks' baselines), and a **GitHub Action** (`action.yml` — a composite action
with a `fail-on` score threshold so a scan can gate a build). A self-hosted HTTP
API and dashboard remain unbuilt and are the obvious next distribution step.

## What stays open vs. what's commercial

Open (this package, forever): the scanners themselves — SSL/TLS, DNS, DNSSEC, email, headers, ports, blacklist, uptime, the stateful local checks (DNS-hijack, defacement, WHOIS-privacy, mixed-content), subdomain discovery, and (later) secrets/IaC/container/SAST/DAST orchestration.

Commercial (CertNotify Cloud / Enterprise): continuous managed monitoring, historical trends, team/RBAC, the correlation engine, the AI analyst, compliance reporting, SSO/SAML, and private/on-prem deployment.

## Known pre-existing issues in the CertNotify SaaS app, discovered while extracting this package

Flagged here because they're relevant context for anyone reading this scanning engine's code, but they're a separate fix, not part of this package:
- The public `/tools/port-scanner` page on certnotify.com is simulated (`Math.random()`), not a real scan. The real scanner is this package's `ports` check.
- The public `/tools/asn-lookup` and `/tools/ip-reputation` pages silently return the visitor's own IP regardless of what they typed in — there's no real arbitrary-IP lookup in the SaaS app today.
- The public "reverse DNS" tool fabricates a fake result for anything not in a small hardcoded table. This package's `dns` check with `PTR` does a real reverse lookup.
