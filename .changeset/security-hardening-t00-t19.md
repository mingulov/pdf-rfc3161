---
"pdf-rfc3161": minor
"pdf-rfc3161-cli": minor
---

Security-hardening release: fail-closed verification verdicts (revocation, trust-target, and parser contracts), bounded transport/operation budgets with distinct error codes, preserved diagnostics across all API paths, and measured packaging hygiene (cycle-free entry, side-effect-free metadata). New `INVALID_ARGUMENT`/`NETWORK_ERROR`/timeout/budget error codes and `ltvErrors` diagnostics may surface where calls previously threw unstructured errors or retried terminal failures; see the review record for the per-finding migration notes.
