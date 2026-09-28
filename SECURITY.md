# Security policy

## Reporting a vulnerability

Report a vulnerability privately, by either:

- GitHub's private vulnerability reporting: **Report a vulnerability** on this
  repository's Security tab;
- email to vltbcnsec@gmail.com.

Do not open a public issue for it.

Include what you found, how to reproduce it, and the version or commit. A report of a way
past the proxy is in scope: a package installed without waharoa deciding on it, other
than the bypasses [docs/threat-model.md](docs/threat-model.md) already lists.

## What happens next

waharoa is pre-release, maintained without a fixed response time. A report is answered as
soon as it can be.

A vulnerability is disclosed when a fixed release is published, with credit to the
reporter unless they ask otherwise. There is no fixed disclosure deadline.

## Supported versions

Only the latest release and `main` receive security fixes.

## Scope

[docs/threat-model.md](docs/threat-model.md) says what waharoa defends against, what it
trusts, and what it does not cover.
