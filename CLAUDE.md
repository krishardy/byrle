# Byrle

Dependency Firewall - Detects and blocks malicious dependencies

## Documentation

* README.md - Top-level description of the project
* docs/project_plan.md - Deeper project plan
* docs/quickstart.md - From a checkout to enforcing installs, npm and PyPI
* docs/fronting-tls.md - nginx in front of the proxy, tested by make smoke-tls-front
* docs/request-flow.md - How the proxy answers a request, and each status code
* docs/break-glass.md - Installing when the proxy is down, and releasing a refused package
* docs/threat-model.md - What byrle defends against, what it trusts, and its bypasses
* docs/policy-reference.md - Every policy key, its default, and which way it loosens
* docs/admin-plan.md - Stage 4.9 plan: admin console, its APIs and web interface

## Standards

* Common maintenance tasks should be added to Makefile.
* Makefile recipes must be thin wrappers around scripts in `scripts/make/<target>.sh` (or `.py` if it leads to simpler script). Do NOT embed multi-line shell logic (loops, conditionals, error handling) directly in recipes — put it in a real script (`set -euo pipefail`, executable) and have the recipe one-line invoke it. The architecture doc's inline-shell examples are logic to extract, not a template to copy.
* Unit test coverage of the library must be 100%. The corpus and live tests are excluded from the test coverage requirement.
* DRY (Don't Repeat Yourself): Search for duplicate code or duplicate strings throughout the application, especially in your recent changes, and refactor the code to consolidation them.
* Don't use pkill. Only kill by pid after confirming the process is the one you intend to target.

## Documentation standards

* Where there is duplication between the project_plan.md and architecture.md, put the content in architecture.md and remove it from project_plan.md.
* Engineering decisions should be documented in docs/engineering_decisions/<decision_name>.md
* Write plainly, concretely and succinctly. Things like "Lowercasing therefore silently misses the one rule nobody is allowed to override" is unacceptable because it is a non-specific interprative statement of previous sentences. Let the data and information speak for themselves.
* Check each word means what you intend, not something near it. Use the literal verb: "uses", "asks", "reports", "contains", "until". "Ready, deciding against intel snapshot X" is wrong because "decide against" means reject; "ready, using intel snapshot X" is the fix. Watch words with a second meaning: "against", "consult", "names", "holds", "through", "pin", "dead". This applies to code identifiers, user-facing strings, doc comments, commit messages and reports.
* No em-dashes. For love of God and all that is holy, NO EM-DASHES!

## Reporting to the user

These apply to chat messages. The documentation rules above apply here too.

* Lead with the result: First line is what happened and the identifier: `b8221cc`
  landed, 393 tests, smoke 6/6 green. Not "I've completed the work on decision #4."
* No bold thesis sentence before the content: Writing `**Abstract claim.**` and then
  the real content makes the claim a compressed restatement of what follows. Start at the
  content. "The two reasons to drop a version share one pass" is the failure; "Origin-
  refused and policy-refused versions are removed in one pass" is the fix.
* Name the thing: `decide.rs:282`, `cooldown_days: 0`, 221,548 records,
  `PolicyError::DenialNeedsAVersion`. Not "the check", "a setting", "a large number of
  advisories", "a new error variant".
* Paste output rather than describing it: Four lines of real test output beat a
  sentence characterising them, and are usually shorter.
* Stop after the finding: "npm sends `time` only in the full packument, so `published`
  is `None` for every record the proxy holds" is complete. Add a consequence only when it
  does not follow from the fact.
* No counting preamble: "Three notes on the implementation:" adds nothing.
* Defects get what broke, evidence, fix, whether it was mutation-tested: In that
  order. The mutation result is what makes it credible, so it is part of the report.
* Questions and decisions go last and alone: one line, their own paragraph. Never
  appended to a summary.
* Short sentences: One clause carrying one fact. Two facts joined by "and", "so", "which"
  or a comma splice should be two sentences. "Filtering a refused version is a policy
  question and repointing artifact URLs is a transport one, and enforcement-tiers.md says
  rewriting is correctly turned off once the proxy terminates TLS, which silently stopped
  the filtering with it" is three sentences pretending to be one.
* Length: Routine work under 150 words. A session with real findings under 400. Longer
  than that means explaining rather than reporting.

### Tables

* Use a table whenever three or more rows share the same shape: per-stage counts, per-file coverage, licence per source, what each capability does. Prose is for single instances: one defect, one decision, one result.

| Instead of | Use |
|---|---|
| "Stage 2 has 74 open, Stage 3 has 11, Stage 5 has 29..." | a stage/count table |
| "OSSF is Apache-2.0 with no attribution, GHSA is CC-BY-4.0 requiring it..." | a source/licence/attribution table |
| "`Match` originates findings, `Enrich` only adds to them..." | a capability/meaning table |

## GitHub

* The repository is public: https://github.com/krishardy/byrle. The `origin` remote pushes over SSH through the host alias `krishardy-github`.
* `gh` is not installed. Read the repository and its Actions through the REST API with `curl`, which needs no token for a public repository but allows 60 requests an hour:
  * Recent runs: `curl -s "https://api.github.com/repos/krishardy/byrle/actions/runs?per_page=5"`, each with `id`, `name`, `event`, `status`, `conclusion` and `head_sha`
  * A run's jobs and steps: `curl -s "https://api.github.com/repos/krishardy/byrle/actions/runs/<run id>/jobs"`
  * A run's artifacts: `curl -s "https://api.github.com/repos/krishardy/byrle/actions/runs/<run id>/artifacts"`
  * A commit on GitHub: `curl -s "https://api.github.com/repos/krishardy/byrle/commits/<sha>"`
* A job's log needs a token, so ask the user for a failing job's output.
* The workflows are `.github/workflows/ci.yml` (lint, test, sqlx on each push) and `.github/workflows/release.yml` (a `v*` tag builds, attests and publishes; run by hand, it only builds). Check them with `GOFLAGS=-mod=mod go run github.com/rhysd/actionlint/cmd/actionlint@latest`.

## Finalization

* make lint (runs clippy)
* make verify (runs kani)
* make test
* make check-deps. If there are any issues, make a note. Do not updated them yourself unless you have been told to by the operator.
* Check docker image versions to ensure that they are the latest version. If they are not, make a note. Do not update them yourself unless you have been told to by the operator.
