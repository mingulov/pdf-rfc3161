# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For breaking-change migration guidance, see [MIGRATION.md](./MIGRATION.md).

## [0.2.0] - 2026-05-14

Major release combining security hardening from `REVIEW-2026-02-09.md`,
an API redesign with stricter defaults, and audit follow-ups. See
[MIGRATION.md](./MIGRATION.md) for diff-level upgrade guidance from 0.1.x.
**The basic `timestampPdf({ pdf, tsa })` call signature is unchanged**; the
verify / extract path gain stricter defaults and several new opt-in checks.

### Added

- `verifyPdfTimestamps(pdfBytes, options)` -- extract + verify in one call.
- `archiveTimestamp` for PAdES-LTA archival (replaces `timestampPdfLTA`; old
  name kept as a `@deprecated` alias). `ArchiveTimestampOptions extends
  TimestampOptions`, so every applicable `TimestampOptions` field
  (`reason`, `location`, `contactInfo`, `omitModificationTime`, `maxSize`,
  `optimizePlaceholder`, `rejectOnRevocationWarning`) is forwarded to the
  inner `timestampPdf` call. New `strictExistingVerification: true` throws
  on the first failing in-PDF timestamp; default is to warn via
  `getLogger().warn`. New `existingTimestampVerifyOptions?:
  VerificationOptions` lets callers add a `trustStore` or opt out of G1/G2
  strictness when verifying legacy tokens.
- `getDefaultTrustStore()` scaffolding (curated root CA bundle to follow).
  Throws `TimestampError(STATE_ERROR, ...)` while the bundled root list is
  empty (current state); see `MIGRATION.md` for the three correct
  migrations.
- `VerificationOptions.requireTimestampingEKU` (default `true`) -- enforce
  `id-kp-timeStamping` (RFC 3161 §2.3) on the signing cert. Closes G1.
- `VerificationOptions.requireCertValidAtGenTime` (default `true`) --
  enforce signing cert validity at the timestamp's `genTime`. Closes G2.
- `VerificationOptions.trustStore` accepts `TrustStore | null` so the
  documented `{ trustStore: null }` opt-out typechecks.
- `TimestampOptions.rejectOnRevocationWarning` -- turn TSA status 4/5 into
  fatal errors. Closes M4.
- `TimestampResult.tsaRevocationWarning` -- surfaces TSA status 4/5 to
  callers.
- `TimestampOptions.ignoreEncryption`, `TimestampSessionOptions.ignoreEncryption`,
  `ExtractOptions` -- control PDF-encryption handling.
- `TimestampInfo.nonce` -- populated from the TSTInfo nonce when present.
- `TimestampRequestOptions` type; `createTimestampRequestFromHash` exported
  from main entry.
- `TimestampErrorCode.MALFORMED_RESPONSE` -- distinguishes "outer parse
  failed, raw-token fallback OK" from "parsed but inner structure broken,
  must not silently embed". Callers that switch on `code` should add a
  case for this.
- New error codes `STATE_ERROR` and `INVALID_ARGUMENT` (replace misplaced
  `PDF_ERROR` and `TSA_ERROR` use, respectively).
- `pdf-rfc3161/internals` subpath for low-level PDF/PKI helpers (main
  `.d.ts` shrunk by ~50%: 41 KB -> 21 KB).
- `MIGRATION.md` covering 0.1.x -> 0.2.0.
- Production checklist + Command-line interface sections in README; API
  tables list the full 0.2.0 fields.
- CLI verify flags `--strict-ess`, `--trust-store`, `--no-require-eku`,
  `--no-require-validity`; timestamp flags `--reject-on-revocation-warning`,
  `--ignore-encryption`, `--no-ltv`; archive `--no-update` (now wired
  correctly).
- `docs/maintain-trust-store.md` for curating the bundled root list.
- `pdf/internals.ts` (`restoreLargestObjectNumber`) and `utils/pdf-date.ts`
  (PDF date parser) -- both extracted from duplicated inline workarounds.
- Project hygiene: `SECURITY.md`, `.nvmrc`, `.editorconfig`, CODEOWNERS,
  PR/issue templates, Dependabot, CI matrix + Codecov, bundle-size guard,
  changesets-based automated release.
- `bugs` URL in package metadata for both `pdf-rfc3161` and
  `pdf-rfc3161-cli`.
- Audit roadmap and audit reports (`REVIEW-2026-02-09.md`).

### Changed

- `timestampPdf({ enableLTV })` defaults to `true` (matches
  `TimestampSession`). Pass `enableLTV: false` to opt out.
- `verifyTimestamp` enforces `requireTimestampingEKU` and
  `requireCertValidAtGenTime` by default. Opt out per-call to verify legacy
  tokens.
- `createTimestampRequest` / `createTimestampRequestFromHash` take a focused
  `TimestampRequestOptions` (`{ hashAlgorithm, policy, requestCertificate }`)
  instead of a URL-less `TSAConfig`. Network options belong on
  `sendTimestampRequest`.
- `timestampPdfMultiple` forwards every `TimestampOptions` field per-TSA.
- `ParsedTimestampResponse` is now a discriminated union; granted statuses
  carry non-optional `token` and `info`.
- **H1** TSA response nonce verified against the request nonce (replay
  defence per RFC 3161 §2.4.2).
- **H2** `verifyTimestamp` rejects SignedData whose `eContentType` is not
  `id-ct-TSTInfo`.
- **H4** AIA / OCSP / CRL / TSA URLs validated against a strict allowlist
  (no loopback, RFC 1918, link-local, CGN, IPv4-mapped IPv6 private, etc.).
- **H5** Per-client response-size caps prevent OOM on malicious responses.
- `TimestampSession.embedTimestampToken` pre-detects TSR vs raw-CMS-token
  shape via outer ASN.1 inspection; nonce/digest validation failures are
  no longer silently swallowed.
- `tryExtractStatusFromASN1` walks the asn1js `valueBlock.value` structure
  correctly and returns `null` for non-PKIStatusInfo shapes (no more
  sentinel "granted" for arbitrary ASN.1 input).
- **M1** OCSP and CRL circuit breakers now `recordFailure()` after retry
  exhaustion.
- **M2** `ValidationSession.exportLTVData()` returns the OCSP / CRL bytes
  actually fetched.
- **M5** `pdf/archive.ts` warnings flow through `getLogger()` instead of
  `console.warn`.
- **M6** `.changeset/config.json` access flipped to `public`.
- All `throw new Error(...)` in user-facing paths converted to
  `TimestampError` with the proper code.
- `TimestampSession.dispose()` uses an explicit `disposed` flag; mid-session
  dispose between `createTimestampRequest` and `embedTimestampToken`
  reliably throws `STATE_ERROR`.
- ESM build's `globalThis.crypto` polyfill is functional via lazy
  `await import("node:crypto")` (`ensureWebCrypto()`). The previous
  `require("node:crypto")` was transformed by tsup to `__require("crypto")`,
  which threw silently in ESM bundles.
- CJS consumers receive correct `.d.cts` types via the dual-condition
  `exports` map. Verified clean against `arethetypeswrong`.
- Network-touching unit tests use `vi.useFakeTimers()`; full unit suite
  wall-clock significantly improved.
- Coverage instrumentation fixed (absolute paths through alias boundary).
- **L1** Real CRL Number / Delta CRL Indicator parsing.
- **L3** New `toArrayBuffer` helper replaces 24 `.slice().buffer` defensive
  copies.
- **L4** Shared `fetchBytesWithRetry` helper unifies the cert / OCSP / CRL
  / TSA / DefaultFetcher retry-loop bodies.
- **L5** PDF strings (`reason`, `location`, `contactInfo`) length-capped to
  2048 chars; reject embedded NUL.
- Performance: precomputed lookup tables for `bytesToHex` / `hexToBytes`;
  O(N²)→O(N) issuer lookup in LTV chain building; LTA verify-once-and-reuse.

### Breaking

- `createTimestampRequest()` / `createTimestampRequestFromHash()` return
  `{ request: Uint8Array; nonce: Uint8Array }` instead of `Uint8Array`.
  Required for H1.
- `createTimestampRequest` / `createTimestampRequestFromHash` argument
  shape changed from URL-less `TSAConfig` to `TimestampRequestOptions`.
- `extractTimestamps()` (and adjacent extract APIs) default to
  `ignoreEncryption: false`. Pass `{ ignoreEncryption: true }` to keep the
  0.1.4 behaviour.
- `timestampPdfLTA` renamed to `archiveTimestamp` (old name kept as
  `@deprecated` alias).
- `timestampPdf({ enableLTV })` defaults to `true`; pass `false` to opt out.
- `verifyTimestamp` enforces EKU and gen-time validity by default; pass
  `false` per-call to verify legacy tokens.
- `getDefaultTrustStore()` throws `STATE_ERROR` while the bundled root list
  is empty. The previous empty-store-with-warn behaviour was hazardous.
  See `MIGRATION.md`.
- CLI: `verify --require-eku` / `--require-validity` flags (which were CLI
  defaults of `false` overriding library `true`) replaced with positive
  `--no-require-eku` / `--no-require-validity` opt-outs. `--strict-ess` is
  a positive opt-in (library default for `strictESSValidation` is `false`).
- CLI: `timestamp --ltv` (which was a CLI default of `false`) replaced
  with `--no-ltv` opt-out.
- CLI: `archive --no-update` now reads from commander's `update` field
  (previously a silent no-op).
- Deep-import-only: `pdf-rfc3161/internals` no longer re-exports
  `resetCertCircuits`, `resetCRLCircuits`, `resetOCSPCircuits` (these
  mutate process-shared singleton state).

### Removed

- `rfcs/rfc4998` module (`createEvidenceRecord`, `addTimestampToEvidence`,
  `validateEvidenceRecord`, `extractTimestampsFromEvidence`,
  `RFC4998_OIDS`). These were stubs -- `validateEvidenceRecord` returned
  `true` for any ASN.1 SEQUENCE, `extractTimestampsFromEvidence` returned
  `[]` -- and risked being mistaken for real implementations. RFC 4998
  (Evidence Record Syntax) is a standalone archival format unrelated to
  PAdES-LTA, which is what `pdf-rfc3161` covers. If you need real RFC
  4998, use a dedicated library.
- **BREAKING (deep import only)**: `pdf-rfc3161/rfcs/rfc6211`. The module's
  `validateAlgorithmProtectAttribute` always returned `true` because its
  underlying `getProtectedAlgorithms` was a stub returning `[]`. Real RFC
  8933 algorithm protection is exposed via
  `validateTimestampTokenRFC8933Compliance` from the main entry point.
- Dead exports trimmed: `parseOCSPNonce`, `OCSPNonceInfo`,
  `ValidationResult.ocspStatus`, `CertificateToValidate.purposes`,
  `"TRUSTED"` from `ValidationResult.sources`,
  `ValidationSessionOptions.{timeout, maxRetries, trustStore}`.
- Dropped unused `pvutils` direct dependency (still pulled transitively by
  `pkijs`).

### Fixed

- `rfc5544` parser correctly distinguishes the `metaData` Sequence from the
  `temporalEvidence` Sequence; envelopes carrying only a `dataUri` (no
  embedded data) no longer throw.

### Documentation

- **M3** OCSP-wins revocation priority model documented in
  `validation-session.ts`.
- `types.ts` JSDoc on `requireTimestampingEKU` /
  `requireCertValidAtGenTime` reflects the default-true polarity.
- `TimestampSession` `@example` shows the correct constructor.
- `embed.ts` `@throws` references `preparePdfForTimestamp` correctly.
- README "Flag reference" tables corrected; CLI examples use `npx
  pdf-rfc3161-cli`.
- README RFC table: dropped RFC 6211 row; RFC 5544 marked Implemented; RFC
  8933 row added.
- README PAdES-LTA example imports `archiveTimestamp`.
- `createTimestampRequestFromHash` JSDoc documents the sync-crypto
  constraint and the `ensureWebCrypto` workaround.
- README setup commands corrected to `pnpm install` + `pnpm --filter
  pdf-rfc3161-demo dev`.
- **L7** Documented serverless caveat on `CircuitBreakerMap`.
- `CLAUDE.md` known-issues block refreshed; only H3 (default trust store
  empty) remains open.

### Security

Closes 4 of 5 high-severity items, all 6 medium-severity items, and 6 of 7
low-severity items from `REVIEW-2026-02-09.md`. H3 (default chain
validation with bundled roots) ships infrastructure only; the curated root
bundle is deferred to a follow-up release.

## [0.1.4] - 2026-01-14

### Fixed

- Fixed OCSP "UNKNOWN" status issues by robust issuer matching (AKI/SKI) and improved compatibility with TSA warnings.

## [0.1.3] - 2026-01-12

### Added

- Demo website for easy testing and visualization
- Improved internal engine (TimestampSession, VRI support, OCSP/CRL handling)

### Changed

- Refactored library structure for better maintainability

## [0.1.2] - 2026-01-10

### Added

- PAdES-LTA support: `timestampPdfLTA` for archival workflows
- Structural validation tests for LTV

### Changed

- Cleaned up API by removing deprecated functions (`timestampPdfWithLTV`, `fetchOCSP`)

## [0.1.1] - 2026-01-09

### Fixed

- LTV PDF fixed implementation (fixed issues where some PDFs could not be opened by some viewers)
- Signature validation (fixed ByteRange calculation and dictionary structure for Adobe validation)

### Added

- Unified `timestampPdf` API with `enableLTV` support
- LTV support in `timestampPdfMultiple`

### Deprecated

- `timestampPdfWithLTV` (use `timestampPdf` with `enableLTV: true`)

## [0.1.0] - 2026-01-07

### Added

- Initial release
- `timestampPdf()` function for adding RFC 3161 timestamps to PDFs
- Support for SHA-256, SHA-384, and SHA-512 hash algorithms
- Document timestamp (DocTimeStamp with ETSI.RFC3161 SubFilter)
- Cloudflare Workers and edge runtime compatibility
- Browser support via Web Crypto API
- TypeScript type definitions
- Low-level API for advanced usage
- Known TSA server constants
