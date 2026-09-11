# Waharoa

Dependency Firewall - Detects and blocks malicious dependencies

## Standards

* Common maintenance tasks should be added to Makefile.
* Makefile recipes must be thin wrappers around scripts in `scripts/make/<target>.sh` (or `.py` if it leads to simpler script). Do NOT embed multi-line shell logic (loops, conditionals, error handling) directly in recipes — put it in a real script (`set -euo pipefail`, executable) and have the recipe one-line invoke it. The architecture doc's inline-shell examples are logic to extract, not a template to copy.
* No em-dashes. For love of God and all that is holy, NO EM-DASHES!

### Documentation

* README.md - Top-level description of the project
* docs/project_plan.md - Deeper project plan
* Where there is duplication between the project_plan.md and architecture.md, put the content in architecture.md and remove it from project_plan.md.
* Engineering decisions should be documented in docs/engineering_decisions/<decision_name>.md
* Write plainly and concretely. Things like "Lowercasing therefore silently misses the one rule nobody is allowed to override" is unacceptable because it is a non-specific interprative statement of previous sentences. Let the data and information speak for themselves.

### Finalization

* make lint (runs clippy)
* make verify (runs kani)
