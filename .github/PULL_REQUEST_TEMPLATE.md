<!--
Thanks for contributing. CI cannot run on this repository right now (the
account is billing-locked, unrelated to this project), so the local checklist
below is the actual gate rather than a formality.
-->

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- What was wrong, or what this makes possible. For a fix to a check, say how
     you know the new behaviour is correct — an RFC section, another tool's
     result, or a real domain that demonstrates it. -->

## Checklist

- [ ] `npm run verify` passes locally (typecheck + build + tests)
- [ ] New logic has tests — pure unit tests where the logic is deterministic
- [ ] No new runtime dependency, or the PR explains why one is needed
- [ ] Any network call against a user-supplied host goes through the SSRF guard
- [ ] No check returns a fabricated, simulated or guessed result
- [ ] README updated if a check, flag or command changed
- [ ] I have the right to contribute this code under AGPL-3.0-or-later

## Verification

<!-- Paste the real output showing this works. For a scanner change, a before
     and after against a real domain is the most convincing thing you can
     include. -->
