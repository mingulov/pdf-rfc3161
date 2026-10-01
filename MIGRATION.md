# Migration Guide

This document covers breaking changes between major releases of `pdf-rfc3161`.

## Unreleased

### HTTP transport rejects redirects, fails fast on 4xx, and bounds bodies

TSA, OCSP, CRL, and AIA fetches now use `redirect: "manual"`: a 3xx (or
opaque/opaqueredirect) response is a terminal `NETWORK_ERROR` and the
`Location` is never fetched. If your TSA or responder sits behind a
redirect, reconfigure the client with the final URL; there is no
automatic manual-hop support in this iteration. Likewise every 4xx,
including 408 and 429, now fails in one attempt without retrying, so
callers that relied on 429 retries must implement their own backoff
(this iteration does not honor `Retry-After`; adopting that policy is a
separate decision). A response body that stalls past the per-attempt
`timeout` now rejects with `TIMEOUT` after the configured retries
instead of hanging; raise `timeout` if you serve slow responders.

An open circuit breaker now surfaces as `TimestampError` with code
`"CIRCUIT_OPEN"` rather than `CircuitBreakerError`, and deadline
exhaustion reports `TIMEOUT` rather than `NETWORK_ERROR`. The
`CircuitBreakerError` class remains exported for direct
`CircuitBreaker.execute()` users. Invalid numeric `retry`, `retryDelay`,
`timeout`, or `maxResponseBytes` options now reject with
`INVALID_ARGUMENT` before any fetch. Optional AIA/OCSP/CRL failures
still yield a signed PDF with partial LTV material plus diagnostics;
only the mandatory TSA path fails signing.

Transport error messages now carry the origin plus path only: embedded
credentials, query strings, and fragments are redacted. `timeout` and
`retryDelay` above the 2^31 - 1 ms platform timer ceiling now reject
with `INVALID_ARGUMENT`, and exponential backoff is capped at that
ceiling instead of misfiring. A bare `AbortError` with a live attempt
signal and unexpired deadline now reports `NETWORK_ERROR`; `TIMEOUT`
requires owned-deadline state (timer fired or elapsed).

### Direct-TSA browser calls need TSA CORS; `no-cors` cannot help

A page calling a TSA directly issues a cross-origin TSQ `POST` whose
`Content-Type: application/timestamp-query` triggers a CORS preflight,
so the TSA must answer `Access-Control-Allow-Origin` for the page
origin (and allow the content type); otherwise the browser blocks the
response and signing fails with `NETWORK_ERROR`. Retrying that request
with `mode: "no-cors"` cannot recover the token: the response becomes
opaque, hiding its status and bytes from the page, so there is nothing
usable to embed. The library therefore never uses `no-cors` itself.

When the TSA does not serve CORS, use the existing manual
request/response workflow instead of the one-call path: build the
request with `TimestampSession.createTimestampRequest()`, carry the
TSQ bytes to the TSA over a channel of your choice (for example a
server-side fetch), and hand the TSR bytes back to
`TimestampSession.embedTimestampToken()`, which runs the same
request-bound pre-embed validation before writing the PDF. See the
"Session Pattern for Complex Workflows" section in
[README.md](./README.md). These requirements were exercised in
the controlled local-TSA browser gate only; live-TSA CORS behavior
varies by operator and still needs per-TSA confirmation.

### `verifyChain` verifies `chain[0]` (trust-target binding)

`TrustStore.verifyChain(chain)` now defines first-certificate target
semantics: only `chain[0]` is verified, and the remaining entries are
untrusted path-building candidates rather than additional trust sources.
Previously the verdict could follow an unrelated trusted intermediate
elsewhere in the array, so an untrusted signer with such a bag entry could
verify as trusted. That input now returns `false`, and
`verifyTimestamp`/`verifyPdfTimestamps` report "Certificate chain not
trusted".

No change is needed if you already pass the selected signer first (as
`verifyTimestamp` does). If you relied on the old order-dependent behavior,
place the intended target at index 0. A target that is itself a pinned
anchor is verified against that anchor without needing intermediates, but
engine validation still applies: CA-ness, validity-period, and name-chaining
checks must pass. In particular a pinned self-signed end-entity (non-CA)
target still returns `false`, while a pinned intermediate still chains to
its issuer anchor.

### Signature reservations and PDF ceilings are validated at every entry

`signatureSize` must now be omitted, 0 (auto), or a positive safe integer of
at most 65,536 bytes; fractional, negative, `NaN`, infinite, and over-cap
values reject with `INVALID_ARGUMENT` before any allocation, PDF parsing, or
TSA request. Previously `Infinity` threw an uncategorized `RangeError` while
negative, `NaN`, and over-cap values were silently accepted or remapped to
the default. If you passed a reservation above 65,536 bytes, lower it to the
cap: ordinary TSA tokens (including chained RSA fixtures at ~1.5 KB against
the 8/16 KB defaults) fit with wide headroom, and the retry loop now grows
automatically up to the cap instead of past it.

`maxSize` must now be a positive safe integer of at most 250 MiB
(`MAX_PDF_SIZE`); invalid overrides reject with `INVALID_ARGUMENT`, and
inputs above the effective ceiling reject with `PDF_ERROR` before parsing.
The ceiling is now enforced at every entry -- `timestampPdf`,
`TimestampSession` (new `maxSize` option), `extractTimestamps`,
`verifyPdfTimestamps`, archive discovery, and archive renewal -- instead of
only the one-call path. `extractTimestamps` previously attempted a full parse
(returning timestamps or `[]`) for over-ceiling inputs; it now throws `PDF_ERROR`.
If you relied on scanning inputs above 250 MiB, split the document first: the ceiling
itself cannot be raised.

Placeholder exhaustion now throws the internal typed `PlaceholderTooSmallError`
(still `PDF_ERROR`-coded with the historical "Increase signatureSize" message,
plus a `requiredSignatureSize` lower bound), and the one-call retry loop
matches on that type rather than the message text. An unrelated error that
merely mentions the placeholder no longer triggers another TSA request. The
class is internal to the signing path (not on a published subpath), so
external callers keep matching `code === "PDF_ERROR"` as before. The loop
also never repeats an identical too-small reservation and stops with a
cap-citing error instead of issuing another TSA request once the 65,536-byte
reservation cap is reached.

DER decoding keeps its contracted 1,000,000-node preflight budget, but the effective node ceiling is the binding asn1js 10,000-node default (the 1M preflight binds only above it).

## 0.2.1 -> 0.2.2

Both the library and CLI now require Node.js >=22.12.0. Upgrade Node.js before
installing 0.2.2 if you are using Node.js 20. The public timestamping API is
unchanged. Repository contributors should use the pnpm version declared in
the root `packageManager` field.

## 0.1.x -> 0.2.0 (breaking)

This guide describes the 0.2.0 release, which combines security hardening, an
API redesign with stricter defaults, and PDF timestamp interoperability fixes.
The basic `timestampPdf({ pdf, tsa })` call signature is unchanged, but the
verify / extract path and several helpers have defaults that are stricter than
0.1.x.

### 1. `createTimestampRequest` / `createTimestampRequestFromHash` return `{ request, nonce }`

The functions previously returned just `Uint8Array` (the DER-encoded request).
In 0.2.0, the API returns an object containing the request _and_ the 8-byte
nonce that was embedded inside it, so callers can verify the TSA echoed the
nonce back (RFC 3161 Sec. 2.4.2).

```diff
- const request = await createTimestampRequest(data, config);
- const responseBytes = await sendTimestampRequest(request, config);
+ const { request, nonce } = await createTimestampRequest(data, config);
+ const responseBytes = await sendTimestampRequest(request, config);
+ // Keep `nonce` with this exact request/response pair.
```

The main entry does not publish a standalone `validateTimestampResponse`
helper. Do not import an internal response helper to embed into a PDF. Use the
supported session flow, which performs request-bound validation immediately
before embedding the timestamp into the PDF:

```typescript
import { TimestampSession, sendTimestampRequest } from "pdf-rfc3161";

const session = new TimestampSession(pdfBytes, { hashAlgorithm: "SHA-256" });
const request = await session.createTimestampRequest();
const responseBytes = await sendTimestampRequest(request, { url: tsaUrl });
const timestampedPdf = await session.embedTimestampToken(responseBytes);
```

The session preserves its request nonce and checks it with the prepared
ByteRange, requested policy, CMS signer, ESS binding, and timestamping EKU.
Skipping that checked session embed defeats the protection the new request
shape is meant to enable.

### 2. `createTimestampRequest` / `createTimestampRequestFromHash` take `TimestampRequestOptions`

These helpers previously accepted a partial `TSAConfig` (URL-less). They now
accept a focused `TimestampRequestOptions` covering only what shapes the
request body (`hashAlgorithm`, `policy`, `requestCertificate`). Network
details remain on `TSAConfig` and are passed to `sendTimestampRequest`
instead.

```diff
- const { request, nonce } = await createTimestampRequest(data, {
-     url: "http://...",          // ignored, but accepted
-     hashAlgorithm: "SHA-256",
-     policy: "1.2.3.4",
- });
+ const { request, nonce } = await createTimestampRequest(data, {
+     hashAlgorithm: "SHA-256",
+     policy: "1.2.3.4",
+ });
+ // The TSA URL belongs on sendTimestampRequest:
+ const responseBytes = await sendTimestampRequest(request, { url: "http://..." });
```

`createTimestampRequestFromHash` is now also exported from the main entry
point.

### 3. `extractTimestamps`: `ignoreEncryption` defaults to `false`

In 0.1.x, the library silently treated encrypted PDFs as if they were plain
documents, which produced misleading "no timestamps found" results. In 0.2.0,
the default is `false`: calling `extractTimestamps` on an encrypted PDF now
throws `TimestampError` with code `PDF_ERROR`. If you need the old behaviour
(useful for diagnostic tooling on hostile inputs), set it explicitly:

```diff
- const timestamps = await extractTimestamps(pdfBytes);
+ const timestamps = await extractTimestamps(pdfBytes, { ignoreEncryption: true });
```

This flag is also exposed on the `verify` CLI command.

### 4. `timestampPdf({ enableLTV })` defaults to `true`

In 0.1.x, `timestampPdf` defaulted `enableLTV` to `false`. This was
inconsistent with `TimestampSession` (which defaulted to `true`) and meant a
typical call would produce a signature without candidate validation material,
requiring an opt-in to embed it. In 0.2.0, the default is `true`. If
you intentionally want a signature _without_ the embedded validation data,
set `enableLTV: false` explicitly.

```diff
- const result = await timestampPdf({ pdf, tsa });            // no LTV in 0.1.x
+ const result = await timestampPdf({ pdf, tsa });            // LTV in 0.2.0
+ // Or, to keep 0.1.x behaviour:
+ const result = await timestampPdf({ pdf, tsa, enableLTV: false });
```

The one-call `timestampPdf()` path initially reserves 8KB for the RFC 3161
token, including when LTV is enabled, because it adds the candidate validation
material after embedding that token. If the token does not fit, the one-call
retry loop grows the placeholder. A directly constructed `TimestampSession`
uses a 16KB default when `enableLTV: true` and 8KB otherwise. Set
`signatureSize` explicitly if the TSA token for your policy requires more
space.

### 5. `verifyTimestamp` enforces id-kp-timeStamping EKU and cert-validity-at-genTime by default

The timestamping-EKU and certificate-validity checks previously had to be
enabled via `requireTimestampingEKU: true` / `requireCertValidAtGenTime: true`.
In 0.2.0 both default to `true`. Verifying a legacy or
non-conforming token whose certificate lacks the required RFC 3161 EKU (or was
outside its validity window at `genTime`) now fails by default; pass
`{ requireTimestampingEKU: false }` or
`{ requireCertValidAtGenTime: false }` to restore the looser behaviour.

```typescript
// 0.2.0: same call, stricter result
const verified = await verifyTimestamp(ts, { trustStore });

// To match 0.1.x leniency exactly:
const verified = await verifyTimestamp(ts, {
    trustStore,
    requireTimestampingEKU: false,
    requireCertValidAtGenTime: false,
});
```

### 6. `getDefaultTrustStore()` throws on empty bundle

The function returned an empty `SimpleTrustStore` in 0.1.x. This was
hazardous: a custom `TrustStore` wrapper that returns `true` on empty trust
could silently accept any chain. In 0.2.0, the bundled root list is empty, so
the function throws `TimestampError(STATE_ERROR, ...)` until maintainers
populate it with curated roots.

Three correct migrations:

```typescript
// 1. Pin your own roots (recommended for production):
import { SimpleTrustStore } from "pdf-rfc3161";
const trustStore = new SimpleTrustStore();
trustStore.addCertificate(myRootDer);
const result = await verifyTimestamp(ts, { trustStore });

// 2. Skip chain validation explicitly (cryptographic-only verify):
const result = await verifyTimestamp(ts, { trustStore: null });

// 3. Omit trustStore only when cryptographic-only verification is intentional:
const result = await verifyTimestamp(ts);
```

Omitting `trustStore` does not select default roots now or automatically later.
It performs cryptographic and, when `pdf` is supplied, PDF-consistency checks
only; it does not trust the TSA chain. For a trust decision, explicitly provide
and maintain a trust store appropriate to the relying party's policy.

### 7. Low-level helpers moved to `pdf-rfc3161/internals`

The top-level entry retains the common signing/verification surface
(`timestampPdf`, `archiveTimestamp`, `timestampPdfMultiple`,
`extractTimestamps`, `verifyTimestamp`, `verifyPdfTimestamps`,
`TimestampSession`), request/response helpers, trust-store types, errors,
constants, and RFC helpers. Lower-level PDF and PKI helpers moved to the
`pdf-rfc3161/internals` subpath.

```diff
- import {
-     addDSS, addVRI, extractLTVData, completeLTVData, getDSSInfo,
-     embedTimestampToken, preparePdfForTimestamp, extractBytesToHash,
-     getOCSPURI, createOCSPRequest, parseOCSPResponse,
-     getCaIssuers, fetchCertificate, getCRLDistributionPoints,
- } from "pdf-rfc3161";
+ import {
+     addDSS, addVRI, extractLTVData, completeLTVData, getDSSInfo,
+     preparePdfForTimestamp, extractBytesToHash,
+     getOCSPURI, createOCSPRequest, parseOCSPResponse,
+     getCaIssuers, fetchCertificate, getCRLDistributionPoints,
+ } from "pdf-rfc3161/internals";
```

The raw PDF embed primitive is intentionally no longer published. Move manual
flows to `TimestampSession.createTimestampRequest()` followed by
`TimestampSession.embedTimestampToken()`. The session validates the response
against the prepared ByteRange, request nonce, requested policy, CMS signer,
ESS binding, and exclusive critical timestamping EKU immediately before it
embeds the timestamp into the PDF. This is mandatory request-bound pre-embed validation, not an
optional post-write check.

The main bundle's `.d.ts` is now about 40% smaller (~41 KB -> ~24 KB).

`/internals` does **not** re-export the circuit-breaker reset functions
(`resetCertCircuits`, `resetCRLCircuits`, `resetOCSPCircuits`). They mutate
process-shared singleton state; exposing them on a supported public surface
let any plugin in the same import graph defeat rate-limiting telemetry meant
to absorb outages against revocation responders. **There is no replacement
on the published API surface.** Module-level singletons reset on process
restart (serverless cold start, Workers isolate recycle, Deno deploy
restart). For long-running Node processes, restructure so each request
builds its own client.

### 8. `timestampPdfMultiple` forwards every `TimestampOptions` field; `timestampPdfLTA` renamed to `archiveTimestamp`

`timestampPdfMultiple` previously only forwarded `reason`, `location`,
`contactInfo`, and `enableLTV` to each underlying `timestampPdf` call.
In 0.2.0, every active `TimestampOptions` field is forwarded (for example,
`signatureFieldName` and `revocationData`), so you can configure the
whole pipeline once. `rejectOnRevocationWarning` remains accepted only for
source compatibility; it is a deprecated no-op because TSA statuses 4/5 are
always fatal.

```typescript
const result = await timestampPdfMultiple({
    pdf,
    tsaList: [tsa1, tsa2],
    signatureFieldName: "Timestamp", // forwarded to each timestamp request
    enableLTV: false,
});
```

`timestampPdfLTA` is now exposed as `archiveTimestamp`. The old name remains
as a `@deprecated` alias and continues to work; new code should use
`archiveTimestamp`. `ArchiveTimestampOptions` now `extends TimestampOptions`,
so every flag you can pass to `timestampPdf` is also accepted on the archive
path.

### 9. New `TimestampErrorCode.MALFORMED_RESPONSE`

Existing `catch` blocks that test for `TimestampError` generically are
unaffected; code that `switch`-es on the error code may want to add a case
for this. The new code is thrown when a TSR's outer ASN.1 parses but the
inner TSTInfo / token extraction fails -- previously this was conflated under
`INVALID_RESPONSE` and silently swallowed by the session, allowing an MITM
to substitute the wrong token.

### 10. CLI flag changes

Several CLI flag groups switched from positive to negative form. The default
behaviour for each is now to ENFORCE the security check (matching the new
library defaults). Pass the new `--no-*` form to opt out.

| Was (0.1.x)          | Now (0.2.0)             | New default                                          |
| -------------------- | ----------------------- | ---------------------------------------------------- |
| `--ltv`              | `--no-ltv`              | LTV enabled                                          |
| `--require-eku`      | `--no-require-eku`      | EKU enforced                                         |
| `--require-validity` | `--no-require-validity` | validity enforced                                    |
| (n/a)                | `--strict-ess`          | strict ESS still opt-in (library default is `false`) |

If you were invoking the CLI with an explicit positive flag (e.g.
`pdf-rfc3161-cli timestamp ... --ltv`), drop the flag -- the protections are
now on by default. To restore the 0.1.x CLI behaviour of producing a
non-LTV signature, pass `--no-ltv` explicitly.

`archive --no-update` previously was documented but ineffective. It now skips
embedded OCSP/CRL candidates from verified existing document timestamps. Their
certificates are still retained, and fresh OCSP/CRL candidates may still be
fetched. The archive path is RFC 3161 document-timestamp renewal: it verifies
recognized document timestamps, merges global DSS candidate material, and adds
a new document timestamp. It is not a general PAdES-LTA upgrader or an
indefinite-validity guarantee, and it never creates VRI entries automatically.

### 11. Removed: `rfcs/rfc4998` deep import

The `rfcs/rfc4998` module was a stub: `extractTimestampsFromEvidence` returned
`[]` unconditionally, masking real ERS evidence. It has been removed.
If you depended on the import path, please open an issue describing your use
case -- a real RFC 4998 implementation is on the roadmap.

```diff
- import { extractTimestampsFromEvidence } from "pdf-rfc3161/rfcs/rfc4998";
+ // No replacement yet. Track progress at:
+ // https://github.com/mingulov/pdf-rfc3161/issues
```

### 12. Removed: `rfcs/rfc6211` deep import

`pdf-rfc3161/rfcs/rfc6211` was a stub: `validateAlgorithmProtectAttribute`
always returned `true` because its underlying `getProtectedAlgorithms`
returned `[]`. The real RFC 8933 algorithm protection is exposed via
`validateTimestampTokenRFC8933Compliance` from the main entry point.

### 13. Document timestamp metadata is omitted by default

New document timestamps write a value dictionary with `/Type /DocTimeStamp`
and `/SubFilter /ETSI.RFC3161`. The AcroForm field remains `/FT /Sig`; a
DocTimeStamp is not an approval or certification signature merely because it
uses the signature field type.

`/M`, `Reason`, `Location`, and `ContactInfo` are omitted unless requested.
`omitModificationTime: false` restores the legacy `/M` behavior for a
compatibility case. Treat metadata as an explicit opt-in, not as a baseline
default.

`signatureFieldName` is a requested base name. When a fully qualified field
name already exists, the library adds a deterministic numeric suffix rather
than overwriting an existing form field. Existing field and widget structures
remain unchanged; the new timestamp field and widget are appended. Do not
assume the requested string is always the literal final field name in a
pre-existing AcroForm.

### 14. Replace legacy VRI calls with `addVRIForSignature`

VRI is field-specific and optional. The legacy wrappers are still callable but
deprecated. They now require a `signatureFieldName`, reject reusable PDF
references from another load context, and reject unsupported key choices.
Move code that supplied a certificate and loose references to raw validation
bytes bound to one named PDF signature field:

```diff
- import { addVRI } from "pdf-rfc3161/internals";
+ import { addVRIForSignature } from "pdf-rfc3161/internals";

- const updated = await addVRI(pdf, signingCert, { crls, ocspResponses });
+ const updated = await addVRIForSignature(
+     pdf,
+     { fieldName: "Timestamp" },
+     {
+         validationData: {
+             certificates: [certificateDer], // DER-encoded Uint8Array
+             crls,
+             ocspResponses,
+         },
+     }
+ );
```

The replacement resolves the field in the loaded PDF, derives an uppercase
SHA-1 VRI key from that signature's complete decoded, padded `/Contents`
value, and puts VRI below Catalog `/DSS`. It preserves existing global DSS
arrays, VRI entries, and unknown DSS keys, reusing byte-identical validation
streams where possible. The decoded-and-padded interpretation is this
project's implementation reading of the relevant PDF and ETSI material; the
current ETSI text calls the input the complete hexadecimal `/Contents`
string, so do not treat this sentence as a verbatim ETSI quote or an assertion
that every producer uses the same encoding.

VRI is optional, and ETSI EN 319 142-1 says it `SHOULD NOT` be used in the
baseline profile. `archiveTimestamp` merges global DSS candidate material but
does not create VRI automatically. Use the explicit API only for a
field-specific interoperability need.

### 15. Validate the published artifact and document loader limits

On a clean Ubuntu 24.04 AMD64 runner, install the locked validation tools using
[the clean-run recipe](./docs/pades-oracle-tools.md#run-from-a-clean-checkout),
then run the offline structural/interoperability and packed-consumer gates:

```bash
pnpm build
PYTHON=/tmp/pdf-rfc3161-pades-python/bin/python \
  pnpm --filter pdf-rfc3161-tests test:interoperability
pnpm --filter pdf-rfc3161-tests test:package
```

For the tool-role boundaries and a reproducible later Acrobat Reader
observation, see [docs/validation-tools.md](./docs/validation-tools.md) and
[docs/manual-acrobat-validation.md](./docs/manual-acrobat-validation.md).
These tests do not change the official `pdf-lib-incremental-save@1.17.4`
loader boundary. Its hostile-PDF parsing and resource limitations remain
separate and deferred; see
[docs/pdf-lib-incremental-save-limitations.md](./docs/pdf-lib-incremental-save-limitations.md).

---

For the full list of changes, see [CHANGELOG.md](./CHANGELOG.md).
