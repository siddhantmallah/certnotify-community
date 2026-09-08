# Security Policy

`certnotify` is a security tool, so it is held to the standard it measures. This
document covers how to report a vulnerability *in this package*, and what the
package's own security boundaries are.

## Reporting a vulnerability

**Email <security@certnotify.com>.** Please do not open a public issue for
anything exploitable.

Include whatever you have — a description of the flaw, the version
(`certnotify --version`), and ideally a target or input that reproduces it. A
plain description is welcome; you do not need a polished write-up.

What to expect:

| | |
|---|---|
| First response | Within 5 working days |
| Assessment and a fix plan | Within 14 days of the first response |
| Fix released | As soon as it is ready — patched to npm, then disclosed |
| Credit | Named in the release notes and this repository, unless you prefer not to be |

This is a small project maintained by one person, and the timelines above are
honest targets rather than a contractual SLA. If you have not heard back in
five working days, please send a follow-up — it means the mail went astray.

## Supported versions

Only the latest minor release receives security fixes. The package is on `0.x`
and moves quickly; upgrade before reporting a bug against an older version.

| Version | Supported |
|---|---|
| 0.3.x | ✅ |
| 0.2.x and earlier | ❌ — upgrade to 0.3.x |

## Security boundaries of this package

Understanding what the package does and does not defend against will tell you
whether something is a vulnerability or intended behaviour.

**In scope — please report these:**

- **SSRF-guard bypass.** `assertPublicHostname` is a real security boundary. It
  refuses to scan private, loopback, link-local, CGNAT and cloud-metadata
  addresses by default. Any input that reaches a network call against one of
  those without `--allow-private` is a vulnerability. DNS-rebinding-style
  bypasses and unusual IPv6 or integer-notation encodings are all in scope.
- **Command or code injection** from a scan target, a DNS response, an HTTP
  header, or any other attacker-controlled input. Nothing this package reads
  from the network should ever reach a shell or an evaluator.
- **Path traversal via state files.** `--state-dir` and the target name are used
  to build a filename; a target that escapes the state directory is a
  vulnerability.
- **Denial of service against the user running the scan** — an unbounded read,
  a decompression bomb, or a hang with no timeout triggered by a hostile
  target's response.
- Anything that causes the tool to send data anywhere other than the target
  being scanned and the public services documented in the README.

**Out of scope — these are by design:**

- **`--allow-private` reaching private addresses.** That is the entire point of
  the flag. It is off by default and must be passed explicitly.
- **Scanning a host you do not own.** The tool does not and cannot verify
  authorisation. That responsibility is yours — see below.
- **A check being wrong** (missing a real problem, or flagging a healthy
  domain). That is a bug, and a valuable one, but it is not a vulnerability —
  open a public issue using the "Incorrect finding" template so it can be
  discussed in the open.
- **Vulnerabilities in the public services the package queries** (crt.sh, RDAP
  registries, Cloudflare DNS-over-HTTPS, public DNSBL zones). Report those to
  the operators.

## What this package sends, and where

No telemetry, no analytics, no phone-home, no account, no API key. There is no
code path that reports your usage or your scan results to CertNotify or to
anyone else. The only outbound traffic is the scan itself:

- **Directly to the target you named** — TLS handshakes, TCP connects to the 15
  probed ports, HTTP(S) requests for headers, uptime, defacement and
  mixed-content checks.
- **To public infrastructure required by a check** — your system's DNS
  resolvers, Cloudflare DNS-over-HTTPS (`cloudflare-dns.com`, for DNSSEC),
  public RDAP registries (for WHOIS), `crt.sh` (for Certificate Transparency
  subdomain discovery), and seven public DNSBL zones (for reputation).

Scan state stays on your machine, in `~/.certnotify/state` by default.

## Responsible use

Port scanning and active probing may be unlawful without the target owner's
permission, depending on where you and the target are. Scan systems you own or
have written authorisation to test. The SSRF guard protects you and your
network from a mistyped target — it is not a licence to scan third parties.
