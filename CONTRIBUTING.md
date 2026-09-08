# Contributing to certnotify

Thanks for looking. This is the open-source scanning engine behind
[CertNotify](https://www.certnotify.com) — the checks themselves are open and
stay open, and contributions to them are genuinely welcome.

## Quick start

```bash
git clone https://github.com/siddhantmallah/certnotify-community.git
cd certnotify-community
npm install
npm run verify        # typecheck + build + full test suite
node dist/cli.js scan github.com
```

Node 18 or newer. There is no database, no service to run, and no configuration
— clone and go.

## Before you open a pull request

Run `npm run verify` and make sure it passes.

**Please do this locally.** CI cannot currently run on this repository: the
GitHub account it lives under is billing-locked, which is unrelated to this
project and is not being resolved. The workflow in `.github/workflows/ci.yml` is
correct and set to manual dispatch so it does not litter the history with runs
that never start; it will go back to running on every push the moment that
clears. Until then, `npm run verify` is the gate, and a PR that has not passed
it locally cannot be merged.

## How the tests work

There are no mocks anywhere, deliberately. A scanner that only ever runs against
a fake DNS server is a scanner nobody has actually tested. The suite splits in
two:

- **Unit tests** — pure, deterministic logic with no network: the SSRF guard's
  IP classification, the security-header grading rubric, SPF parsing, the
  composite scorer, state serialisation. Run them alone with `npm run test:unit`.
- **Integration tests** — real scans against real domains (`github.com`,
  `cloudflare.com`), asserting on shape and on facts that are stable in the real
  world rather than on volatile details. `cloudflare.com` is used for DNSSEC
  because it has been reliably signed for years; assertions avoid things like
  exact issuer strings or A-record addresses, which legitimately change.

This means the integration tests need network access and can fail for reasons
that are not your fault — an RDAP mirror rate-limiting you is common. If a test
fails, check whether it fails on `main` too before assuming you broke it.

When you add logic worth testing, prefer making it a pure function that takes
data and returns a verdict, then unit-test that. `evaluateSpf` in
`src/scanners/email.ts` is the pattern: the network call fetches TXT records,
and a separate exported function decides what they mean.

## Adding a new check

1. Create `src/scanners/<name>.ts` exporting one `async function check<Name>()`.
2. Add its result type to `src/types.ts` and, if it belongs in a full scan, to
   `ScanReport`.
3. Export it from `src/scanners/index.ts`.
4. Wire it into `scan()` in `src/index.ts` and into `ALL_CHECKS`.
5. Register a CLI subcommand in `src/cli.ts`.
6. Render it in `src/report.ts` for the human-readable output.
7. Add tests — pure unit tests for the parsing, an integration test for the
   network path.
8. Document it in the README's check table.

House rules for a new check:

- **Free and keyless.** Every check must work with no account and no API key.
  Node built-ins or free public services only. A check that needs a paid API
  does not belong in this package.
- **Guard the network call.** Anything that connects to a user-supplied host
  goes through `assertPublicHostname` first, unless `allowPrivate` is set.
- **Dependency-light.** The runtime dependencies are `commander` and
  `picocolors`, and the bar for adding a third is high. Use `fetch` and regex
  over pulling in an HTTP client and an HTML parser — `checkMixedContent` does
  exactly this.
- **Report honestly.** A check that cannot determine something must say so.
  Never return a fabricated or simulated result, and never let a "no data"
  answer render as a pass. Wrong-but-confident output is the worst thing a
  security tool can produce.

## Reporting an incorrect finding

A false positive or false negative is a real bug and one of the most useful
things you can report. Use the "Incorrect finding" issue template and include
the domain, so the result can be reproduced against live data.

## Style

Match the surrounding code. TypeScript, ESM, no semicolon-free experiments, and
comments that explain *why* something is the way it is — particularly where a
standard, a real-world quirk, or a deliberate trade-off is involved. Comments
restating what the line already says are not wanted.

## Licence and provenance

This project is **AGPL-3.0-or-later**. Contributions are accepted under the same
licence.

The AGPL is a deliberate choice, not a default: it means anyone who runs a
modified version of this engine as a network service has to publish their
modifications. That is what stops the open engine from being quietly forked into
a closed competing product, and it is why the licence will not be relaxed to MIT
or Apache.

Only submit code you wrote or have the right to contribute. Do not paste code
from another project unless its licence is compatible and you say so in the PR.

## Relationship to CertNotify Cloud

Worth being direct about, since it affects what gets merged. The scanners are
open and stay open. The hosted product at certnotify.com is about running them
continuously, correlating findings across many assets over time, and alerting a
team — that layer is commercial. A contribution that improves a check will be
merged on its merits; there is no plan to move existing open checks behind the
paid product.
