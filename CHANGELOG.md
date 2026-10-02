# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For breaking-change migration guidance, see [MIGRATION.md](./MIGRATION.md).

## [Unreleased]

### Changed

- **Behavior (HTTP transport bounds, C06):** the shared TSA / OCSP / CRL /
  AIA fetch path now sends `redirect: "manual"` and terminally rejects
  3xx and opaque/opaqueredirect responses instead of following them;
  every 4xx (including 408 and 429) fails fast in one attempt instead of
  being retried; the per-attempt deadline covers response bodies, so a
  stalled body rejects with `TIMEOUT` after the configured retries
  instead of hanging; invalid numeric retry/timeout/size options reject
  with `INVALID_ARGUMENT` before any fetch. Previously followed
  redirects, retried 4xx responses, and never-settling bodies now fail
  loudly; see MIGRATION.md.
- **Behavior (transport error taxonomy):** an open per-URL circuit breaker
  now short-circuits with `TimestampError(CIRCUIT_OPEN)` (zero fetches,
  no backoff) instead of `CircuitBreakerError`, and attempts exhausted
  on the built-in deadline now report `TIMEOUT` instead of
  `NETWORK_ERROR`. Terminal rejections (redirect, 4xx, empty or
  over-cap body, validator failure) make one attempt and no longer
  record a remote-outage circuit failure. Callers may pass an
  `AbortSignal` to cancel without retrying; cancellation stays distinct
  from retryable timeouts.
- **Behavior (transport diagnostics):** `NETWORK_ERROR`, `TIMEOUT`, and
  `CIRCUIT_OPEN` messages now carry the origin plus path only; embedded
  credentials, query strings, and fragments are redacted. `timeout` and
  `retryDelay` above the 2^31 - 1 ms platform timer ceiling now reject
  with `INVALID_ARGUMENT`, and exponential backoff is capped at that
  ceiling. A bare `AbortError` with a live attempt signal and unexpired
  deadline now reports `NETWORK_ERROR` instead of `TIMEOUT`; see
  MIGRATION.md.
- **Behavior (input resource bounds, C02/C06):** `signatureSize` must now
  be omitted, 0 (auto), or a positive safe integer of at most
  `MAX_SIGNATURE_SIZE` (65,536) bytes, and `maxSize` must be a positive
  safe integer of at most `MAX_PDF_SIZE` (250 MiB); anything else rejects
  with `INVALID_ARGUMENT` before any allocation, PDF parsing, or TSA
  request. The PDF ceiling is now enforced at every entry
  (`timestampPdf`, `TimestampSession`, `extractTimestamps`,
  `verifyPdfTimestamps`, archive discovery, archive renewal) instead of
  only the one-call path, and `TimestampSession`/`extractTimestamps`
  accept a `maxSize` override. Formerly accepted larger overrides and
  over-ceiling extract/archive inputs now fail loudly; see MIGRATION.md.
- **Behavior (placeholder retry, C06):** placeholder exhaustion now throws
  the typed `PlaceholderTooSmallError` (still `PDF_ERROR`-coded with the
  historical message plus `requiredSignatureSize`), and the `timestampPdf`
  retry loop matches on that type instead of the message text, so an
  unrelated error that merely mentions the placeholder no longer triggers
  another TSA request. Automatic growth is capped at 65,536 bytes: the
  loop never repeats an identical too-small reservation and never issues
  another TSA request once the cap is reached.
- **Behavior (revocation verdict containment, C01/C06):** advanced
  `ValidationSession` results now carry `revocationStatus: "good" |
"revoked" | "unknown"` (also exported as the `RevocationStatus` type),
  and `isValid` is a deprecated alias for `revocationStatus === "good"`.
  Missing endpoints/issuers, outages, malformed responses, and
  unauthenticated (including forged) OCSP/CRL evidence all yield
  "unknown" with `isValid` false; most of these cases previously
  returned `isValid` true. Both authenticated evaluators have landed
  since (OCSP, then CRL); there is no compatibility switch to restore
  the old `true`. The
  `preferOCSP: false` order now falls back to OCSP after CRL instead of
  never trying OCSP. The one-call signing path is unaffected: it never
  consumed these verdicts and still signs with partial LTV plus
  diagnostics when optional collection fails. See MIGRATION.md.
- **Behavior (verified issuers and byte identity, C01/C03/C05):** advanced
  `ValidationSession` OCSP requests are now built only with a verified
  issuer: an explicitly supplied issuer must have issued the target (name
  match plus target signature verification), and `queueChain` stores
  candidate issuers that are narrowed (names/AKI/SKI) and
  signature-verified at use instead of trusting the first name match.
  Unverifiable issuers yield "unknown" with an issuer diagnostic and no
  OCSP fetch; the target itself is never its own issuer.
  `getResultForCert` and `exportLTVData` now use exact certificate and
  artifact bytes instead of serial strings and length-plus-64-byte-prefix
  fingerprints, so serial twins under different issuers resolve to their
  own results and same-length same-prefix evidence with different tails
  is all retained. `InMemoryValidationCache` now keys OCSP entries by the
  full request bytes scoped by exact URL, copies bytes on insertion and
  retrieval, and honors retention (300,000 ms), entry (256), and byte
  (20 MiB) limits with oldest-first eviction, tunable via the new
  `InMemoryValidationCacheOptions`; oversized single entries are not
  cached. Cached bytes are revalidated on use and refetched once after
  rejection. See MIGRATION.md.
- **Behavior (AIA issuer gating, C01/C03):** `completeLTVData` chain
  building now only accepts a fetched certificate that actually issued
  its target -- fetched bytes with a non-matching subject name or a
  non-verifying key are skipped with a diagnostic error instead of
  joining the chain -- and tracks collected certificates by exact bytes
  rather than serials, so same-serial distinct issuers are now both
  retained and same-serial legitimate issuers are no longer skipped for
  OCSP collection. The embedded ContentInfo bytes remain exactly the
  accepted token bytes plus reservation zero padding; see MIGRATION.md.
- **Behavior (authenticated OCSP evidence, C01/C06):** advanced
  `ValidationSession` now authenticates OCSP responses instead of
  reporting "unknown" for every certificate. A response yields "good"
  or "revoked" only when it is signed by the verified issuer (no
  embedded responder certificate needed) or an authorized delegate
  (directly issued, `id-kp-OCSPSigning` EKU, `digitalSignature` key
  usage when present, live at the check date, and carrying
  `id-pkix-ocsp-nocheck`; delegates without nocheck are an unsupported
  policy and stay "unknown"), answers the exact request CertID and
  nonce, and is fresh at the check date. Wrong signers, CertID/nonce
  mismatches, conflicting matches, stale or future-dated times, and
  unauthorized responders yield "unknown" with a diagnostic; `isValid`
  stays true only for authenticated "good". Fetched bytes are still
  collected into `sources`, `ocspResponses`, and `exportLTVData` even
  when strict evaluation stays unknown, and the one-call signing path
  is unchanged (LTV collection stays structural). CRL evidence is
  authenticated too; see the next entry. See MIGRATION.md.
- **Behavior (OCSP request nonce, C06):** OCSP requests now serialize a
  fresh random 32-byte nonce inside `requestExtensions` (previously the
  nonce was assigned to a pkijs field that never reached the wire, so
  consecutive requests were byte-identical), and strict validation
  requires an exact echo. Responders that drop or rewrite the nonce
  yield "unknown"; pass the new `includeOCSPNonce: false` session
  option for nonce-free requests. Fresh-nonce requests normally miss
  the OCSP cache now. See MIGRATION.md.
- **Behavior (session OCSP policy options, C01):** `ValidationSession`
  accepts new optional `checkDate` (default: when `validateAll()`
  runs), `clockSkewMs` (default: 300,000, i.e. 5 minutes), and
  `maxAgeWithoutNextUpdateMs` (default: 604,800,000, i.e. 7 days)
  options governing OCSP freshness; invalid values reject with
  `INVALID_ARGUMENT`. A certificate with no OCSP responder URL and no
  CRL distribution points now records one "No revocation endpoints
  attempted" diagnostic in `errors` instead of succeeding silently.
- **Behavior (strict OCSP profile hardening):** advanced OCSP validation
  now rejects unsupported critical extensions (any critical extension
  besides the nonce echo in responseExtensions, and besides key usage
  / EKU / nocheck on the selected delegate; no SingleResponse
  extension is processed, so any critical single extension fails
  closed), requires
  complete TBS consumption on the request, response, and selected
  delegate certificate TBS (extra or duplicated TBS members yield
  "unknown"), plus explicit Name/RDN/AttributeTypeAndValue grammar for
  the delegate issuer/subject and responderID names that pkijs retains
  verbatim (a malformed responder name matches nothing; an empty RDN
  SET fails while an entirely empty Name passes), enforces v1-only
  request and response versions, requires exactly one NULL-valued nocheck and a
  clean id-kp-OCSPSigning EKU, requires canonical DER extension payloads
  (nonce, key usage with zeroed padding bits, EKU) with complete
  consumption, requires canonical DER OBJECT IDENTIFIER contents
  (nonempty, terminated, minimal base-128) in every EKU member and
  Name attribute type, rejects empty extension OIDs (extnID) in
  response, SingleResponse, and delegate-certificate extension lists,
  requires X.509 v3 for the selected
  delegate, requires the delegate inner/outer signature algorithms to
  agree and suit the issuer key family (RSA/ECDSA families only,
  RSA-PSS unsupported), requires primitive octet-aligned signature BIT
  STRINGs with canonical two-INTEGER ECDSA payloads on both the
  response and the delegate certificate, requires strict delegate
  public-key encodings (RSA parameters NULL-or-absent with a canonical
  two-INTEGER key payload, EC parameters exactly the named-curve OID),
  rejects inverted delegate validity intervals before skew is applied,
  falls through from a non-verifying
  issuer to matching embedded delegates, and checks the declared
  signature algorithm against the responder key (RSA/ECDSA families
  only, RSA-PSS unsupported, ECDSA parameters must be absent) before
  verifying. Responses outside this narrowed profile yield "unknown"
  with a diagnostic instead of a decisive verdict; see MIGRATION.md.
- **Behavior (authenticated CRL evidence, C01/C06):** advanced
  `ValidationSession` now authenticates CRLs instead of reporting
  "unknown" for every certificate. A CRL yields "good" or "revoked"
  only when it is a complete CRL issued directly by the verified
  issuer key, in scope for the certificate distribution point, and
  fresh at the check date (a CRL without nextUpdate fails closed as
  unbounded freshness). Wrong keys, forged signatures, stale/future
  dates, missing cRLSign key usage, unknown critical extensions,
  scope mismatches, and indirect/partitioned/delta CRLs yield
  "unknown" with a diagnostic; `isValid` stays true only for
  authenticated "good". Serials compare by exact numeric identity
  (no float extraction, no -128/128 conflation), entry scope follows
  the complete certificateIssuer grammar (same-issuer accepted,
  foreign/malformed fails the CRL -- no per-entry skip), entry
  processing is whole-CRL (critical faults on any entry fail closed,
  duplicate serials reject), cRLIssuer-bearing distribution points
  are out of scope per RFC 5280 6.3.3(b)(1), nested explicit
  wrappers must prove complete (single-Name directoryNames,
  single-choice distributionPoint fields with ordered unique
  members, otherName/x400Address/ediPartyName outside the profile),
  authority key identifiers need ordered unique [0]/[1]/[2] members
  with a complete authorityCertIssuer under the same name profile,
  removeFromCRL and undefined reason values fail the
  complete-CRL profile (hold stays revoked), invalidity dates need
  canonical UTC-seconds grammar, and the issuer SPKI is gated before
  use; delta CRLs are explicitly deferred (never complete; base/delta
  merging is future work with follow-up criteria in MIGRATION.md).
  Fetching needs only the leaf distribution point,
  so CRL bytes are still collected into `sources`, `crls`, and
  `exportLTVData` even when strict evaluation stays unknown -- and
  even when no issuer can validate them -- while issuer resolution
  failure stops the URL loop after the first fetch. The one-call
  signing path is unchanged (LTV collection stays structural). See
  MIGRATION.md.
- **Behavior (historical chain validation, C05):** `verifyTimestamp`
  and `verifyPdfTimestamps` accept
  `VerificationOptions.chainValidationTime` (`"current"` default,
  `"genTime"`, or a finite `Date`), and `TrustStore` gains the
  optional `verifyChainAtTime(chain, checkDate)` capability
  (implemented by `SimpleTrustStore`). Explicit historical requests
  validate `chain[0]` as of the carried date and fail with
  `INVALID_ARGUMENT` -- surfaced as `verified: false` with the new
  `verificationErrorCode` field -- against stores without the
  capability or with a non-finite date, instead of silently
  validating at the wrong date. Historical path validity alone
  establishes neither historical revocation nor archival
  qualification; see MIGRATION.md.
- **Behavior (revocation instants evaluated):** strict OCSP and CRL
  evaluation now check the revocation instant itself: a revoked
  verdict additionally requires a finite `revocationTime` /
  `revocationDate` no later than `thisUpdate` plus skew (inclusive
  boundary). Responses listing a later instant yield "unknown" with
  a diagnostic instead of "revoked". This closes the documented
  T06/T07 deferral; see MIGRATION.md.
- **Behavior (trust-anchor and chain DER consumption):**
  `SimpleTrustStore.addCertificate` and `verifyChain` /
  `verifyChainAtTime` now reject DER inputs with trailing garbage
  (or unparseable framing) with `INVALID_RESPONSE` instead of
  silently accepting the leading value (anchors) or surfacing a raw
  schema error (chain inputs). `pkijs.Certificate` objects are
  unaffected. See MIGRATION.md.

### Fixed

- **Reliability (transport cleanup and deadlines):** rejected-body
  cleanup is now fire-and-observe, so a never-settling or rejecting
  `cancel()` can neither hang the caller past abort/deadline nor
  corrupt the verdict, and declared-oversized bodies are released too.
  Caller cancellation now preempts terminal discards, validation (both
  return and throw paths), and the backoff-to-dispatch boundary, so no
  new fetch starts after abort and no cancelled call records success.
  An absolute per-attempt deadline is now checked around body progress
  and synchronous validation, so responses completing after the
  deadline report `TIMEOUT` through the normal retry/accounting policy
  even when timer callbacks cannot run in time.

- **Security (trust-target binding):** `TrustStore.verifyChain(chain)` now
  verifies `chain[0]` as the trust target; every other entry is an
  untrusted path-building candidate. Previously the underlying path engine
  selected its own leaf, so an untrusted signer accompanied by an unrelated
  trusted intermediate in the CMS certificate bag could verify as trusted.
  `verifyTimestamp`/`verifyPdfTimestamps` with a custom trust store now
  reject such tokens with "Certificate chain not trusted". Callers that
  relied on the old order-dependent behavior must place the selected signer
  first; see MIGRATION.md.

- **Security (DER/PDF resource bounds):** the canonical DER validator is
  now iterative with a 64-level nesting limit and a 1,000,000-node budget
  enforced before any recursive decoder runs, so hostile values fail with
  `INVALID_RESPONSE` instead of an uncategorized `RangeError`. The PDF
  embed primitive now validates `Contents` delimiters, even hex
  reservation length, ByteRange-hole consistency, and in-bounds offsets
  before writing, so a malformed `PreparedPDF` fails with `PDF_ERROR`
  instead of silently truncating the token.
- **Security (CRL evidence reads):** `parseCRLInfo` now reads
  `crlExtensions.extensions` (the pkijs v3 `Extensions` object) instead
  of iterating `crlExtensions` as an array, so delta CRLs are detected
  via the DeltaCRLIndicator extension instead of always reporting
  non-delta; it also reports a new additive `parsed` flag separating
  malformed input from a parsed complete non-delta CRL. The session CRL
  scan now reads `revokedCertificates` (previously the nonexistent
  `revokedCertificateEntries`, so listed serials were never found) with
  leading-zero-tolerant serial comparison. Neither repair produces a
  verdict on its own: unauthenticated evidence still yields "unknown".
- **Security (pre-embed signer validity at genTime, C05):**
  `timestampPdf` and `TimestampSession.embedTimestampToken` now reject
  tokens whose SID-selected signer certificate was expired, not yet
  valid, or carried unparseable validity dates at the token `genTime`,
  with `VERIFICATION_FAILED` ("... was not valid at genTime").
  Previously only the post-embed `verifyTimestamp` default (opt-outable
  via `requireCertValidAtGenTime: false`) enforced the window, so such
  tokens embedded successfully. The pre-embed gate compares against
  `genTime`, never the current wall-clock time: a token whose signer
  has lapsed since issuance still embeds, and the embedded ContentInfo
  bytes remain exactly the accepted token bytes plus reservation zero
  padding. There is no opt-out for the pre-embed check; see
  MIGRATION.md.

## [0.2.2] - 2026-09-07

Release tooling and dependency refresh. **Node.js >=22.12.0 is now required**
for both the library and CLI; Node.js 20 is no longer supported.

### Fixed

- Updated the build-tool esbuild dependency to 0.28.2, removing the affected
  version reported by GHSA-g7r4-m6w7-qqqr.
- Kept all CodeQL steps on 4.37.9 and grouped future Dependabot updates to
  prevent mixed-version initialization and analysis failures.
- Packed-consumer tests now use pnpm 12's workspace override so the CLI and
  consumer both load the supplied core tarball. Unpublished releases can be
  tested before publishing, and a resolution check rejects a registry core
  substituted for the candidate artifact.

### Changed

- Refreshed dependencies and development tools, including Commander 15,
  pnpm 12, TypeScript 7, and the pinned PDF validation tools.
- Updated CI coverage to Node.js 22, 24, and 26, pinned GitHub Actions to
  immutable commits, and made the dependency audit blocking.
- Added independent timestamp verification with verifiedby to the offline
  PAdES conformance checks.

## [0.2.1] - 2026-08-30

Patch release: macOS Preview/Quick Look compatibility fix for timestamped
output. No API changes.

### Fixed

- PDFs timestamped from inputs that use cross-reference streams (the modern
  default) failed to open in macOS Preview/Quick Look and strict Ghostscript,
  because incremental updates always appended classic xref tables. Incremental
  sections now use a cross-reference stream whenever the input contains one,
  and a classic xref table for pure classic-table inputs. The `/DocTimeStamp`
  signature dictionary is serialized and written as a pre-rendered object so
  neither incremental writer can compress it into an object stream (reported
  in #63; regression harness in #65). Note that files already produced by
  0.2.0 from cross-reference-stream inputs stay unopenable in macOS Preview
  and are not repaired by re-timestamping them; regenerate them by
  timestamping the original input again.

## [0.2.0] - 2026-08-28

This release combines security hardening, an API redesign with stricter defaults,
and PDF timestamp interoperability fixes. See
[MIGRATION.md](./MIGRATION.md) for diff-level upgrade guidance from 0.1.x.
**The basic `timestampPdf({ pdf, tsa })` call signature is unchanged**; the
verify / extract path gain stricter defaults and several new opt-in checks.

### Added

- `verifyPdfTimestamps(pdfBytes, options)` -- extract + verify in one call.
- `archiveTimestamp` for RFC 3161 document-timestamp renewal (replaces
  `timestampPdfLTA`; old name kept as a `@deprecated` alias). It verifies
  recognized document timestamps, merges global DSS candidate material, and
  adds a new document timestamp. It is not a general PAdES-LTA upgrader or an
  indefinite-validity guarantee, and it never creates VRI automatically.
  `ArchiveTimestampOptions extends TimestampOptions`, so every applicable
  `TimestampOptions` field
  (`signatureFieldName`, `signatureSize`, `ignoreEncryption`, `reason`,
  `location`, `contactInfo`, `omitModificationTime`, `maxSize`,
  `optimizePlaceholder`, `rejectOnRevocationWarning`) is forwarded to the
  inner `timestampPdf` call. `enableLTV` is accepted but forced to `false`
  because archive owns the DSS update (and warns when it was explicitly
  `true`); `revocationData` is merged as caller-responsible candidate material
  into that archive-owned DSS update. New `strictExistingVerification: true` throws
  on the first failing in-PDF timestamp; default is to warn via
  `getLogger().warn`. New `existingTimestampVerifyOptions?:
VerificationOptions` lets callers add a `trustStore` or opt out of the
  default timestamping-EKU and certificate-validity checks when required by
  caller policy.
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
- `TimestampOptions.rejectOnRevocationWarning` -- retained as a deprecated
  no-op for source compatibility; TSA statuses 4/5 are always fatal.
- `TimestampResult.tsaRevocationWarning` -- retained as a deprecated field
  that is never set because TSA statuses 4/5 are always fatal.
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
  `.d.ts` is about 40% smaller: ~41 KB -> ~24 KB).
- `addVRIForSignature(pdf, { fieldName }, { validationData })` for explicit,
  field-bound VRI updates. The legacy VRI wrappers remain available only as
  deprecated compatibility calls.
- `MIGRATION.md` covering 0.1.x -> 0.2.0.
- Production checklist + Command-line interface sections in README; API
  tables list the new fields.
- CLI verify flags `--strict-ess`, `--trust-store`, `--no-require-eku`,
  `--no-require-validity`; timestamp flags
  `--reject-on-revocation-warning` (deprecated no-op), `--ignore-encryption`,
  `--no-ltv`; archive `--no-update` (now wired correctly).
- `docs/maintain-trust-store.md` for curating the bundled root list.
- `pdf/internals.ts` (`restoreLargestObjectNumber`) and `utils/pdf-date.ts`
  (PDF date parser) -- both extracted from duplicated inline workarounds.
- Project hygiene: `SECURITY.md`, `.nvmrc`, `.editorconfig`, CODEOWNERS,
  PR/issue templates, Dependabot, CI matrix + Codecov, bundle-size guard,
  changesets-based automated release.
- `bugs` URL in package metadata for both `pdf-rfc3161` and
  `pdf-rfc3161-cli`.
- Security guidance, release checks, and regression coverage for the stricter API.

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
- A successful `ParsedTimestampResponse` has a granted status and non-optional
  `token` and `info`.
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
- New document timestamps use `/Type /DocTimeStamp` with `/SubFilter
/ETSI.RFC3161` while retaining `/FT /Sig` on the AcroForm field. The
  placeholder revision uses the classic incremental writer and preserves the
  original PDF bytes as an exact prefix.
- `/M`, `Reason`, `Location`, and `ContactInfo` are omitted by default;
  explicit metadata remains a compatibility opt-in. Requested signature field
  names receive deterministic suffixes rather than overwriting existing form
  fields or widgets.
- `addVRIForSignature` derives its uppercase SHA-1 key from the selected
  field's complete decoded, padded `/Contents` bytes. DSS updates preserve
  existing global arrays, VRI entries, and unknown DSS keys; VRI references
  share the global DSS validation streams.
- The request-bound validation gate is mandatory immediately before every
  embed, and the raw PDF embed primitive is no longer public.
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
  O(N^2) to O(N) issuer lookup in LTV chain building; archive renewal
  verification reuse.

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
  (Evidence Record Syntax) is a standalone archival format unrelated to the
  RFC 3161 document-timestamp renewal provided here. If you need real RFC
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
- README and migration guidance describe `archiveTimestamp` as RFC 3161
  document-timestamp renewal, not a general PAdES-LTA or indefinite-validity
  claim. They also document the explicit VRI migration, the offline and packed
  artifact gates, manual Acrobat observation protocol, and separate official
  PDF-loader limitations.
- `createTimestampRequestFromHash` JSDoc documents the sync-crypto
  constraint and the `ensureWebCrypto` workaround.
- README setup commands corrected to `pnpm install` + `pnpm --filter
pdf-rfc3161-demo dev`.
- Documented the serverless lifecycle caveat for `CircuitBreakerMap`.
- `CLAUDE.md` known-issues block records that the default trust store remains empty.

### Security

The stricter verification defaults, request/response binding, bounded network
and parser paths, and circuit-breaker protections are described above. The
default chain-validation root bundle remains empty; curating and publishing it
is deferred to a separate release decision.

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

- Historical `timestampPdfLTA` archive helper for archival workflows; it is
  now a deprecated alias and is not a general PAdES-LTA conformance guarantee
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
- Initial RFC 3161 PDF timestamp support (later DocTimeStamp dictionary
  metadata corrections are documented in the 0.2.0 section)
- Cloudflare Workers and edge runtime compatibility
- Browser support via Web Crypto API
- TypeScript type definitions
- Low-level API for advanced usage
- Known TSA server constants
