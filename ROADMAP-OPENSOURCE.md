# CertNotify open-core roadmap

This package (`certnotify`, the CLI/library) is Phase 1 of a larger plan to grow CertNotify from a single-purpose SSL/domain monitor into an open-core internet-exposure / DevSecOps platform. Recorded here so the reasoning survives outside chat history.

1. **Phase 1 (done)** — Extract the real, stateless scanners (SSL, WHOIS/RDAP, DNS, DNSSEC, email security, HTTP security headers, port scanning, DNSBL reputation) out of the CertNotify SaaS app into this standalone, AGPL-3.0-or-later licensed package. Buildable and runnable locally.
2. **Phase 2 (done)** — Added the 9th check (`uptime`, consolidated from 3 divergent implementations the same way `headers` was in Phase 1), a `vitest` suite (unit tests for security-critical logic like the SSRF guard and the composite scorer, plus live integration tests against real domains — no mocks), and GitHub Actions CI across Node 18/20/22. Also fixed a real bug found during hardening: `package.json`'s `exports`/`module` fields pointed at `dist/index.mjs`, a file tsup never actually produces (it emits `index.js` for ESM and `index.cjs` for CJS) — anyone `require()`-ing the package before this fix would have gotten a module-not-found error.

**Public since 2026-08-29**: repo is live at [github.com/siddhantmallah/certnotify-community](https://github.com/siddhantmallah/certnotify-community), package is published as [`certnotify@0.1.0`](https://www.npmjs.com/package/certnotify) on npm, verified working via `npx certnotify@0.1.0 scan <target>` against the real public registry. The CI workflow itself can't run yet — the account it lives under is billing-locked on GitHub, unrelated to this project and not being resolved by choice — but the workflow is otherwise correct and will start working the moment that's cleared.
3. **Phase 3** — Wire the CertNotify Cloud dashboard to depend on this package for its stateless checks instead of its own duplicated inline logic.
4. **Phase 4** — Add stateful checks (DNS-hijack monitoring, website defacement detection, WHOIS-privacy-change detection, mixed-content scanning) with a local persistence design (a `.certnotify/` baseline file) — these only work today via the SaaS app's database. Also: real subdomain discovery via passive Certificate Transparency log enumeration (today's implementation is a shallow common-prefix brute force).
5. **Phase 5** — New security domains, each by wrapping a mature existing open-source tool rather than building from scratch: secrets scanning (Gitleaks) and IaC/container scanning (Trivy) first — both ship as single static binaries, cheapest to integrate. SAST (Semgrep) and DAST (OWASP ZAP) follow once that orchestration pattern is proven.
6. **Phase 6** — CertNotify Cloud only, proprietary: a correlation engine (turns "you have 40 findings" into "this one is actually exploitable and internet-facing"), an AI security analyst, and compliance-framework mapping (ISO 27001, SOC 2, PCI DSS, GDPR).
7. **Phase 7** — Positioning/marketing layer (new tagline, homepage restructure, GitHub as a growth channel) — deliberately last. Don't market capability that doesn't exist yet.

## What stays open vs. what's commercial

Open (this package, forever): the scanners themselves — SSL/TLS, DNS, DNSSEC, email, headers, ports, blacklist, and (later) secrets/IaC/container/SAST/DAST orchestration, subdomain discovery, and the stateful local checks.

Commercial (CertNotify Cloud / Enterprise): continuous managed monitoring, historical trends, team/RBAC, the correlation engine, the AI analyst, compliance reporting, SSO/SAML, and private/on-prem deployment.

## Known pre-existing issues in the CertNotify SaaS app, discovered while extracting this package

Flagged here because they're relevant context for anyone reading this scanning engine's code, but they're a separate fix, not part of this package:
- The public `/tools/port-scanner` page on certnotify.com is simulated (`Math.random()`), not a real scan. The real scanner is this package's `ports` check.
- The public `/tools/asn-lookup` and `/tools/ip-reputation` pages silently return the visitor's own IP regardless of what they typed in — there's no real arbitrary-IP lookup in the SaaS app today.
- The public "reverse DNS" tool fabricates a fake result for anything not in a small hardcoded table. This package's `dns` check with `PTR` does a real reverse lookup.
