# Migration Guide

This document covers breaking changes between major releases of `pdf-rfc3161`.

## 0.1.x -> 0.2.0 (breaking)

0.2.0 is a major release combining security hardening, an API redesign with
stricter defaults, and follow-up audit fixes. The basic `timestampPdf({ pdf,
tsa })` call signature is unchanged, but the verify / extract path and several
helpers acquired new defaults that are stricter than 0.1.x.

### 1. `createTimestampRequest` / `createTimestampRequestFromHash` return `{ request, nonce }`

The functions previously returned just `Uint8Array` (the DER-encoded request).
0.2.0 returns an object containing the request *and* the 8-byte nonce that was
embedded inside it, so callers can verify the TSA echoed the nonce back (RFC
3161 Sec. 2.4.2).

```diff
- const request = await createTimestampRequest(data, config);
- const responseBytes = await sendTimestampRequest(request, config);
- const info = parseTimestampResponse(responseBytes);
+ const { request, nonce } = await createTimestampRequest(data, config);
+ const responseBytes = await sendTimestampRequest(request, config);
+ const info = parseTimestampResponse(responseBytes);
+ // Strongly recommended:
+ validateTimestampResponse(info, hash, "SHA-256", nonce);
```

`validateTimestampResponse(info, hash, alg, nonce)` rejects replays and
echo-mismatch attacks. Pass the `nonce` from `createTimestampRequest` and the
hash you originally fed in. Skipping the nonce check defeats the protection
the new shape exists to enable.

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
throws `TimestampError` with code `INVALID_PDF`. If you need the old behaviour
(useful for diagnostic tooling on hostile inputs), set it explicitly:

```diff
- const timestamps = await extractTimestamps(pdfBytes);
+ const timestamps = await extractTimestamps(pdfBytes, { ignoreEncryption: true });
```

This flag is also exposed on the `verify` CLI command.

### 4. `timestampPdf({ enableLTV })` defaults to `true`

In 0.1.x, `timestampPdf` defaulted `enableLTV` to `false`. This was
inconsistent with `TimestampSession` (which defaulted to `true`) and meant a
typical call would produce a signature without the LTV bundle, requiring
opt-in to get the production-ready behaviour. 0.2.0 flips the default. If
you intentionally want a signature *without* the embedded validation data,
set `enableLTV: false` explicitly.

```diff
- const result = await timestampPdf({ pdf, tsa });            // no LTV in 0.1.x
+ const result = await timestampPdf({ pdf, tsa });            // LTV in 0.2.0
+ // Or, to keep 0.1.x behaviour:
+ const result = await timestampPdf({ pdf, tsa, enableLTV: false });
```

### 5. `verifyTimestamp` enforces id-kp-timeStamping EKU and cert-validity-at-genTime by default

The two security checks (G1 and G2 in the audit) previously had to be opted
into via `requireTimestampingEKU: true` / `requireCertValidAtGenTime: true`.
In 0.2.0 both default to `true`. Verifying a legacy token that pre-dates the
RFC 3161 EKU requirement (or whose TSA cert had expired by signing time) now
fails by default; pass `{ requireTimestampingEKU: false }` or
`{ requireCertValidAtGenTime: false }` to restore the looser behaviour.

```typescript
// 0.2.0+: same call, stricter result
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
could silently accept any chain. The function now throws
`TimestampError(STATE_ERROR, ...)` until the bundled root list is populated.

Three correct migrations:

```typescript
// 1. Pin your own roots (recommended for production):
import { SimpleTrustStore } from "pdf-rfc3161";
const trustStore = new SimpleTrustStore();
trustStore.addCertificate(myRootDer);
const result = await verifyTimestamp(ts, { trustStore });

// 2. Skip chain validation explicitly (cryptographic-only verify):
const result = await verifyTimestamp(ts, { trustStore: null });

// 3. Don't call getDefaultTrustStore() at all -- omit the trustStore option
//    entirely, which is equivalent to #2 for now and will pick up the
//    curated bundle automatically once it ships:
const result = await verifyTimestamp(ts);
```

### 7. Low-level helpers moved to `pdf-rfc3161/internals`

The top-level entry now exports only the high-frequency signing/verification
surface (`timestampPdf`, `archiveTimestamp`, `timestampPdfMultiple`,
`extractTimestamps`, `verifyTimestamp`, `verifyPdfTimestamps`, `TimestampSession`,
trust-store types, error types). Lower-level helpers moved to a new
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
+     embedTimestampToken, preparePdfForTimestamp, extractBytesToHash,
+     getOCSPURI, createOCSPRequest, parseOCSPResponse,
+     getCaIssuers, fetchCertificate, getCRLDistributionPoints,
+ } from "pdf-rfc3161/internals";
```

The main bundle's `.d.ts` is now ~50% smaller (41 KB -> 21 KB).

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
0.2.0 forwards every `TimestampOptions` field (e.g. `requireTimestampingEKU`,
`rejectOnRevocationWarning`, `revocationData`), so you can configure the
whole pipeline once.

```typescript
const result = await timestampPdfMultiple({
    pdf,
    tsaList: [tsa1, tsa2],
    requireTimestampingEKU: true,    // 0.2.0: forwarded; 0.1.x: silently dropped
    rejectOnRevocationWarning: true, // 0.2.0: forwarded; 0.1.x: silently dropped
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

| Was (0.1.x)              | Now (0.2.0)               | New default     |
| ------------------------ | ------------------------- | --------------- |
| `--ltv`                  | `--no-ltv`                | LTV enabled     |
| `--require-eku`          | `--no-require-eku`        | EKU enforced    |
| `--require-validity`     | `--no-require-validity`   | validity enforced |
| (n/a)                    | `--strict-ess`            | strict ESS still opt-in (library default is `false`) |

If you were invoking the CLI with an explicit positive flag (e.g.
`pdf-rfc3161-cli timestamp ... --ltv`), drop the flag -- the protections are
now on by default. To restore the pre-0.2.0 CLI behaviour of producing a
non-LTV signature, pass `--no-ltv` explicitly.

`archive --no-update` previously was documented but ineffective. It now
works: without it, `archiveTimestamp` harvests revocation data from existing
in-PDF signatures; with it, the harvest is skipped and only freshly-fetched
OCSP/CRL go into the new DSS.

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

---

For the full list of changes, see [CHANGELOG.md](./CHANGELOG.md).
