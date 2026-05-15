# Security Policy

This library handles cryptographic timestamps and processes potentially-untrusted PDFs. We take security reports seriously.

## Supported versions

We support the latest released minor version. Security fixes ship as patch releases against the latest minor.

| Version | Supported |
|---|---|
| 0.2.x   | ✓ (current) |
| 0.1.x   | — please upgrade |

The 0.2.0 line closed multiple high-severity findings from an internal audit (`REVIEW-2026-02-09.md`) and incorporated CRITICAL findings from post-redesign red-team audits. 0.1.x is **not** maintained.

## Reporting a vulnerability

**Please do not file public issues for security vulnerabilities.**

Preferred channel: **GitHub Security Advisories** at <https://github.com/mingulov/pdf-rfc3161/security/advisories/new>.

Alternative: email `denis@mingulov.com` with subject `[pdf-rfc3161 security]`.

You can expect:

- An initial acknowledgement within **5 business days**.
- A triage assessment within 10 business days.
- A coordinated-disclosure timeline that respects your needs and the project's ability to ship a fix.
- Credit in the resulting advisory (unless you ask to remain anonymous).

When reporting, please include:

- A description of the issue and its impact.
- Steps to reproduce — a minimal PDF, certificate chain, or TSA URL helps.
- The pdf-rfc3161 version and Node runtime version.
- Whether disclosure is time-sensitive (e.g. you intend to publish at a conference).

We coordinate disclosure roughly as: triage → fix → coordinated release → CVE if applicable → public advisory.

## Threat model and out-of-scope items

In scope:

- Any cryptographic-integrity weakness in the signing or verify path.
- Any SSRF / remote-code-execution / OOM path reachable from a crafted PDF, certificate, or TSA response.
- Any case where a relying party would mistakenly trust a token they shouldn't (e.g. forged nonce, replayed response, wrong message digest accepted).
- Resource-exhaustion vectors (ReDoS, decompression bombs in PDF objects, large response bodies — most of these are guarded but new ones may exist).

Out of scope:

- SSRF to private IPs when the caller has **explicitly** set `allowPrivateUrls: true` (this is an intentional opt-out for development environments).
- Trust-store gaps for callers who don't pass a `trustStore` or `getDefaultTrustStore()` to `verifyTimestamp` — chain validation is the caller's responsibility until the curated default trust-store bundle ships.
- Issues in upstream dependencies (`pkijs`, `asn1js`, `pdf-lib-incremental-save`) — please report those upstream. We will track them and bump as fixes ship.
- General TSA outages, rate-limiting, or TSA-side certificate revocation handling that doesn't intersect with library behaviour.

## Hardening defaults

For production deployments processing untrusted PDFs, see the README "Production checklist" section. Since 0.2.0, the previously-opt-in checks `enableLTV`, `requireTimestampingEKU`, and `requireCertValidAtGenTime` default to `true`. The remaining opt-in for stricter PAdES compliance is `strictESSValidation: true`.
