# Reporting: accounts, installed dependencies and notifications

- **Status:** Decided 2026-09-19. Not yet implemented. TODO Stage 8.
- **Related:** [account-identification](account-identification.md),
  [snapshot-identity](snapshot-identity.md), [ingestion-history](ingestion-history.md)

A user with an account sees every dependency they installed through the proxy, and is told
by email when one of those versions gets a new malware advisory, or a new vulnerability that
is critical or high.

## Decisions

| Question | Decided | Rejected |
|---|---|---|
| How a request names its account | A token per account, sent as each client sends a registry credential: [account-identification](account-identification.md) | a token in the path, which four lockfiles record; `user:pass@` in the URL, which npm, pnpm and yarn drop on artifact requests and bun never sends; the network address |
| Where accounts and installs live | New tables in the intel Postgres, the database `WAHAROA_DATABASE_URL` names: accounts, tokens stored hashed, installs. A refresh replaces advisory tables only | a second Postgres; the audit log file, which listing and matching would scan whole |
| How email is sent | waharoa writes each notification to an outbox table in the same database, and an external mailer sends it and marks it sent. No email code in waharoa | an SMTP client crate; one provider's HTTP API |
| What is new for an account | After each refresh, every account's installed versions are matched against the current advisories, and a notification is written for each (account, advisory, version) not written before. When an account is created, its existing matches are recorded as already sent | notifying on the difference a refresh made, which loses a notification whenever sending fails |

"Critical or high" is a CVSS score of 7.0 or more, or a band of `HIGH` or `CRITICAL` where no
score is given. Malware is any advisory with `malware` set.

## What follows

- An install is an artifact request the proxy served, recorded with the account, package,
  version and time. A metadata request alone is not an install.
- The proxy stops forwarding `Authorization` upstream. A private upstream is given its own
  credential in the proxy's configuration.
- Matching is the same lookup `explain` and the proxy use, `Intel::lookup`, for each
  installed version.
- The mailer contract is the outbox table's columns, and is documented with them.
