# pdf-rfc3161

A pure JavaScript/TypeScript library for adding RFC 3161 document timestamps to PDFs. Works in Node.js, Cloudflare Workers, Deno, and modern browsers without native dependencies.

## About RFC 3161

RFC 3161 defines the Time-Stamp Protocol (TSP). A Time Stamping Authority (TSA) signs a
data hash and timestamp. Whether that TSA is trusted is a separate caller policy decision:
the caller must supply and apply an appropriate trust store.

When embedded in a PDF as a Document Timestamp (DocTimeStamp):

- It provides cryptographic evidence about a document hash and timestamp
- PDF readers such as Adobe Acrobat can inspect it; their validation result
  depends on the reader build and configured trust policy
- It does not require a signing certificate from the user
- Its long-term acceptance depends on the verifier's TSA, path, revocation, and freshness policy

The timestamp value dictionary is emitted as `/Type /DocTimeStamp` with
`/SubFilter /ETSI.RFC3161`; its AcroForm field remains `/FT /Sig`. This is a
structural interoperability behavior, not a claim of general PAdES conformance
or viewer-independent trust.

Existing AcroForm fields and widgets are preserved. A new timestamp field is
appended using the requested name or a deterministic collision-safe suffix.

## Features

- RFC 3161 compliant implementation of the Time-Stamp Protocol
- Document timestamps using the DocTimeStamp (ETSI.RFC3161) format
- Candidate certificate and revocation-material embedding for LTV workflows
- Support for multiple timestamps from different TSAs
- Extraction and verification of timestamps from existing PDFs
- RFC 8933 CMS Algorithm Identifier Protection validation
- Edge runtime compatible (Cloudflare Workers, Vercel Edge, Deno Deploy)
- Browser support via the Web Crypto API
- Full TypeScript type definitions
- No native dependencies

## Quick Start

```typescript
import { timestampPdf, KNOWN_TSA_URLS } from "pdf-rfc3161";
import { readFile, writeFile } from "fs/promises";

const pdfBytes = await readFile("document.pdf");

const result = await timestampPdf({
    pdf: new Uint8Array(pdfBytes),
    tsa: {
        url: KNOWN_TSA_URLS.FREETSA,
    },
});

await writeFile("document-timestamped.pdf", result.pdf);

console.log("Timestamp added at:", result.timestamp.genTime);
```

## Installation

```bash
npm install pdf-rfc3161
```

```bash
yarn add pdf-rfc3161
```

```bash
pnpm add pdf-rfc3161
```

## Production checklist

Defaults are tuned for compatibility; production workloads should enable the
stricter options below explicitly. SSRF protection (URL allowlist for AIA /
OCSP / CRL fetches) is **on by default** and has no opt-out at the public-call
level.

Minimal timestamp metadata is the default: `/M`, `Reason`, `Location`, and
`ContactInfo` are omitted unless explicitly requested. `omitModificationTime:
false` restores `/M` for a compatibility use case; metadata opt-ins can take a
file outside baseline recommendations.

### Signing path

```typescript
const result = await timestampPdf({
    pdf,
    tsa: { url: KNOWN_TSA_URLS.FREETSA },
    enableLTV: true,
});
```

`enableLTV` embeds collected certificate and revocation candidates. It does not establish TSA
trust, validate revocation freshness, or guarantee validity after certificate expiry.

Every public timestamp path validates the TSA response against the prepared
ByteRange, request nonce, requested policy, CMS signature, signer selection,
ESS binding, and timestamping EKU immediately before the PDF embed operation.
The raw PDF embed primitive is deliberately not published. For an external TSA
round trip, use `TimestampSession.createTimestampRequest()` followed by
`TimestampSession.embedTimestampToken()`; the session applies the same gate.

### Verify path

```typescript
const verified = await verifyTimestamp(ts, {
    trustStore, // your SimpleTrustStore
    pdf, // enables PDF-level checks
    requireTimestampingEKU: true, // RFC 3161 EKU 1.3.6.1.5.5.7.3.8
    requireCertValidAtGenTime: true, // cert valid at signing instant
    strictESSValidation: true, // ESS cert identifier must match
});
```

### Flag reference

The unreleased next-major work flips `enableLTV`, `requireTimestampingEKU`,
and `requireCertValidAtGenTime` to default `true`. See `MIGRATION.md` if you
need to verify legacy or non-conforming tokens whose certificates do not satisfy the
RFC 3161 EKU requirement.

| Flag                        | Default                        | Recommended for prod                              |
| --------------------------- | ------------------------------ | ------------------------------------------------- |
| `enableLTV`                 | `true` (unreleased next major) | `true`                                            |
| `rejectOnRevocationWarning` | deprecated no-op               | not applicable; TSA statuses 4/5 are always fatal |
| `requireTimestampingEKU`    | `true` (unreleased next major) | `true`                                            |
| `requireCertValidAtGenTime` | `true` (unreleased next major) | `true`                                            |
| `strictESSValidation`       | `false`                        | `true`                                            |
| `ignoreEncryption`          | `false`                        | leave as `false`                                  |

## Command-line interface

`pdf-rfc3161-cli` ships the same operations as a CLI.

```bash
npx pdf-rfc3161-cli --help
npx pdf-rfc3161-cli timestamp https://freetsa.org/tsr input.pdf output.pdf
npx pdf-rfc3161-cli verify input.pdf -v
npx pdf-rfc3161-cli archive https://freetsa.org/tsr input.pdf output.pdf
```

See `npx pdf-rfc3161-cli <command> --help` for the full flag set on each subcommand.

## Usage

### Basic Timestamping

```typescript
import { timestampPdf } from "pdf-rfc3161";

const result = await timestampPdf({
    pdf: pdfBytes,
    tsa: {
        url: "https://freetsa.org/tsr",
        hashAlgorithm: "SHA-256", // or SHA-384, SHA-512
        timeout: 30000,
    },
});
```

The default output omits `/M`, `Reason`, `Location`, and `ContactInfo`. If a
legacy workflow requires metadata, set `omitModificationTime: false` and the
metadata fields deliberately; do not treat that compatibility shape as the
default output profile.

### LTV (Long-Term Validation)

Enable LTV to embed candidate certificates and revocation material for a verifier to evaluate:

```typescript
import { timestampPdf } from "pdf-rfc3161";

const result = await timestampPdf({
    pdf: pdfBytes,
    tsa: { url: "https://freetsa.org/tsr" },
    enableLTV: true,
});
```

### Signature-specific VRI (explicit opt-in)

VRI is optional. If a caller has a field-specific interoperability reason, use
the internal subpath API after selecting the signed field. The VRI key is
derived inside the loaded PDF context from the complete decoded, padded
`/Contents` value; callers do not supply a certificate hash or PDF reference.
This is the project's implementation interpretation; see
[MIGRATION.md](./MIGRATION.md) for the standards and producer-compatibility
nuance.

```typescript
import { addVRIForSignature } from "pdf-rfc3161/internals";

const updatedPdf = await addVRIForSignature(
    timestampedPdf,
    { fieldName: "Timestamp" },
    {
        validationData: {
            certificates,
            crls,
            ocspResponses,
        },
    }
);
```

`addVRI` and `addVRIEnhanced` are deprecated transition wrappers. See
[MIGRATION.md](./MIGRATION.md) for the supported field-bound replacement. Archive renewal never
creates VRI entries automatically.

### Multiple Timestamps

Add timestamps from multiple Time Stamping Authorities for redundancy:

```typescript
import { timestampPdfMultiple, KNOWN_TSA_URLS } from "pdf-rfc3161";

const result = await timestampPdfMultiple({
    pdf: pdfBytes,
    tsaList: [{ url: KNOWN_TSA_URLS.FREETSA }, { url: "https://another-tsa-server" }],
    enableLTV: true,
});

console.log(`Added ${result.timestamps.length} timestamps`);
```

### RFC 3161 Document-Timestamp Renewal

Use `archiveTimestamp` to renew RFC 3161 document timestamps. It verifies existing timestamp
tokens, collects certificate and revocation candidates only from verified tokens, additively
updates the global DSS once, and adds a final document timestamp. Network OCSP and CRL bytes are
structural candidates only; caller-supplied revocation data remains the caller's responsibility.
This is not a general PAdES-LTA upgrader or an indefinite-validity guarantee:

```typescript
import { archiveTimestamp, KNOWN_TSA_URLS } from "pdf-rfc3161";
// `timestampPdfLTA` is a deprecated alias for `archiveTimestamp` kept for back-compat.

const result = await archiveTimestamp({
    pdf: signedPdfBytes,
    tsa: { url: KNOWN_TSA_URLS.FREETSA },
    includeExistingRevocationData: true,
});
```

### Extract and Verify Timestamps

Extract timestamps from an existing PDF:

```typescript
import { extractTimestamps, verifyTimestamp } from "pdf-rfc3161";

const timestamps = await extractTimestamps(pdfBytes);

for (const ts of timestamps) {
    console.log(`Timestamp: ${ts.info.genTime}`);
    console.log(`Policy: ${ts.info.policy}`);

    const verified = await verifyTimestamp(ts, { pdf: pdfBytes });
    console.log(`Verified: ${verified.verified}`);
}
```

### Cloudflare Workers

```typescript
import { timestampPdf, KNOWN_TSA_URLS } from "pdf-rfc3161";

export default {
    async fetch(request: Request): Promise<Response> {
        const formData = await request.formData();
        const file = formData.get("pdf") as File;
        const pdfBytes = new Uint8Array(await file.arrayBuffer());

        const result = await timestampPdf({
            pdf: pdfBytes,
            tsa: { url: KNOWN_TSA_URLS.FREETSA },
            enableLTV: true,
        });

        return new Response(result.pdf, {
            headers: {
                "Content-Type": "application/pdf",
                "Content-Disposition": 'attachment; filename="timestamped.pdf"',
            },
        });
    },
};
```

## API Reference

### `timestampPdf(options)`

Adds an RFC 3161 timestamp to a PDF document.

Options:

| Name                        | Type         | Required | Description                                                                                                    |
| --------------------------- | ------------ | -------- | -------------------------------------------------------------------------------------------------------------- |
| `pdf`                       | `Uint8Array` | Yes      | PDF document bytes                                                                                             |
| `tsa.url`                   | `string`     | Yes      | TSA server URL                                                                                                 |
| `tsa.hashAlgorithm`         | `string`     | No       | SHA-256, SHA-384, or SHA-512 (default: SHA-256)                                                                |
| `tsa.timeout`               | `number`     | No       | Request timeout in ms (default: 30000)                                                                         |
| `tsa.retry`                 | `number`     | No       | Retry attempts (default: 3)                                                                                    |
| `tsa.retryDelay`            | `number`     | No       | Base retry delay in ms (default: 1000)                                                                         |
| `enableLTV`                 | `boolean`    | No       | Embed candidate DSS material (default: `true` in the unreleased next major); not a trust or validity guarantee |
| `maxSize`                   | `number`     | No       | Maximum PDF size in bytes (default: 250MB)                                                                     |
| `signatureSize`             | `number`     | No       | Size reserved for token (default: 8192). Set to `0` for automatic.                                             |
| `signatureFieldName`        | `string`     | No       | Requested field-name base; deterministic suffixes avoid collisions (default: "Timestamp")                      |
| `reason`                    | `string`     | No       | Reason for timestamping                                                                                        |
| `location`                  | `string`     | No       | Location metadata                                                                                              |
| `contactInfo`               | `string`     | No       | Contact information                                                                                            |
| `omitModificationTime`      | `boolean`    | No       | `undefined` and `true` omit `/M`; explicit `false` restores legacy metadata                                    |
| `optimizePlaceholder`       | `boolean`    | No       | Optimize signature size (default: false)                                                                       |
| `rejectOnRevocationWarning` | `boolean`    | No       | Deprecated no-op retained for source compatibility; TSA statuses 4/5 are always fatal                          |
| `ignoreEncryption`          | `boolean`    | No       | Process encrypted PDFs (default: false; recommend leaving false)                                               |
| `revocationData`            | `LTVData`    | No       | Caller-provided candidate material; caller is responsible for trust                                            |

Returns a `TimestampResult` with the timestamped PDF, timestamp info, and optional candidate
`ltvData`. The deprecated `tsaRevocationWarning` field is never set: TSA statuses 4/5 are always
fatal.

Note: When using LTV, `signatureSize: 0` uses a 16KB default. Specify larger value manually if you encounter "token larger than placeholder" errors.

### `timestampPdfMultiple(options)`

Adds timestamps from multiple TSAs. Takes a `tsaList` array and supports `enableLTV`.

### `extractTimestamps(pdfBytes)`

Returns an array of `ExtractedTimestamp` objects from the PDF.

### `verifyTimestamp(timestamp, options?)`

Verifies the cryptographic signature of an extracted timestamp.

Options:

| Name                        | Type                 | Required | Description                                                                                |
| --------------------------- | -------------------- | -------- | ------------------------------------------------------------------------------------------ |
| `pdf`                       | `Uint8Array`         | No       | Original PDF bytes for hash verification                                                   |
| `trustStore`                | `TrustStore \| null` | No       | Trust store for chain validation. `null` skips chain check.                                |
| `strictESSValidation`       | `boolean`            | No       | Enforce PAdES ESS-cert-id compliance (default: `false`)                                    |
| `requireTimestampingEKU`    | `boolean`            | No       | Require id-kp-timeStamping EKU on TSA cert (default: `true` in the unreleased next major)  |
| `requireCertValidAtGenTime` | `boolean`            | No       | Require TSA cert valid at timestamp instant (default: `true` in the unreleased next major) |

## TSA Servers

The library includes `KNOWN_TSA_URLS` - a list of known TSA URLs for convenience.

Note: Usage is governed by providers' Terms and Conditions. FreeTSA uses a self-signed CA requiring manual root certificate installation.

## Demo

A client-side demo lives in `packages/demo/`. The repo is a pnpm workspace; run it with:

```bash
pnpm install
pnpm --filter pdf-rfc3161-demo dev
```

## Error Handling

```typescript
import { timestampPdf, TimestampError, TimestampErrorCode } from "pdf-rfc3161";

try {
    const result = await timestampPdf({/* ... */});
} catch (error) {
    if (error instanceof TimestampError) {
        switch (error.code) {
            case TimestampErrorCode.NETWORK_ERROR:
                // Handle network issues
                break;
            case TimestampErrorCode.TSA_ERROR:
                // TSA rejected the request
                break;
            case TimestampErrorCode.TIMEOUT:
                // Request timed out
                break;
        }
    }
}
```

## Scope & Design Philosophy

This library focuses on generating RFC 3161 timestamps for PDFs with candidate validation-material
support for LTV workflows.

**Primary use cases:**

- Adding timestamps to fresh documents
- Renewing RFC 3161 document timestamps with aggregate global DSS candidate material
- Extracting and verifying timestamp structures

**Verification scope:**

The `verifyTimestamp()` function checks cryptographic self-consistency and configured profile
requirements:

- The timestamp token is properly signed by the TSA
- The document hash matches what was timestamped
- The timestamp structure is valid

Those checks do not by themselves trust the TSA, validate a certificate path, or establish
revocation freshness. Supply a caller-owned `TrustStore` to apply a trust policy.

**Modular Network Architecture:**

The library is designed with pluggable network interfaces to support various deployment scenarios:

- **Edge Runtimes**: Cloudflare Workers, Vercel Edge, Deno Deploy (uses Web Fetch API)
- **Node.js**: Can use HTTP client of choice (fetch, axios, node-fetch, curl via child_process)
- **Testing**: Deterministic mock responses without network calls
- **Air-Gapped Environments**: Supply pre-fetched revocation data directly

All network operations use the Fetcher pattern. The fetcher classes live on
the `/advanced` subpath, available via tree-shakable deep import:

```typescript
import { MockFetcher, DefaultFetcher } from "pdf-rfc3161/advanced";

// Use custom fetcher for testing
const mockFetcher = new MockFetcher();
mockFetcher.setOCSPResponse("http://ocsp.example.com", mockResponse);

// Use DefaultFetcher with custom settings
const customFetcher = new DefaultFetcher({ timeout: 10000 });

// Supply pre-fetched LTV data (no network needed)
const result = await timestampPdf({
    pdf: pdfBytes,
    tsa: { url: "https://tsa.example.com" },
    enableLTV: true,
    // Pre-fetched revocation data
    revocationData: {
        certificates: [issuerCert, rootCert],
        ocspResponses: [preFetchedOCSP],
        crls: [preFetchedCRL],
    },
});
```

**Session Pattern for Complex Workflows:**

For advanced use cases, use the Session API for step-by-step control:

```typescript
const session = new TimestampSession(pdfBytes, {
    // enableLTV defaults to true. Set to false for manual/no-network scenarios.
    enableLTV: true,
});

// Step 1: Generate request (can send to external TSA)
const request = await session.createTimestampRequest();

// Step 2: Send request via your preferred method
const response = await myCustomTSAFetch(request);

// Step 3: Validate the request-bound response, then embed candidate LTV material
const finalPdf = await session.embedTimestampToken(response);
```

The session rejects a malformed, ambiguous, unbound, or cryptographically
invalid response before writing the PDF. A `certReq=false` manual response
requires external signer-certificate candidates through the session validation
options; the one-call `timestampPdf` API rejects that shape.

**RFC Compliance:**

The library implements or aims to support the following standards:

| RFC                          | Description                                                                                          |
| :--------------------------- | :--------------------------------------------------------------------------------------------------- |
| **RFC 3161**                 | Time-Stamp Protocol (Core implementation)                                                            |
| **RFC 5816**                 | ESSCertIDv2 (Supported via dependencies)                                                             |
| **RFC 6960**                 | OCSP (Implemented for LTV)                                                                           |
| **RFC 5544**                 | TimeStampedData envelope (Implemented; see `pdf-rfc3161/rfcs/rfc5544`)                               |
| **RFC 8933**                 | CMS Algorithm Identifier Protection (Implemented; see `pdf-rfc3161/rfcs/rfc8933`)                    |
| **ETSI EN 319 142-1 V1.2.1** | DocTimeStamp and DSS/VRI structural interoperability baseline; not a general PAdES conformance claim |

**Revocation & Chain Handling:**

- **OCSP/CRL**: The library can collect structurally parsed Online Certificate Status Protocol (OCSP) and Certificate Revocation List (CRL) candidate bytes. It does not verify responder signatures, certificate paths, CertIDs, freshness, scope, or revocation trust for those network candidates.
- **AIA**: Authority Information Access (AIA) extensions can discover and fetch intermediate certificate candidates. Fetching them does not construct or trust a certificate chain on its own.

**TrustStore validation:**

For production chain validation, pass a caller-owned `TrustStore` with the roots you accept to
`verifyTimestamp()`. The library's default trust store is empty, so it does not provide an
implicit TSA trust anchor or full chain-validation policy:

```typescript
import { verifyTimestamp, SimpleTrustStore } from "pdf-rfc3161";

const trustStore = new SimpleTrustStore();
trustStore.addCertificate(rootCaCert);

const verified = await verifyTimestamp(ts, {
    trustStore,
    strictESSValidation: true,
});
```

## Limitations

- Encrypted/password-protected PDFs are not supported (pdf-lib limitation)
- The library creates document timestamps, not signature timestamps on existing signatures
- The signer expects a clean, structurally valid input PDF. It preserves existing bytes and
  is not a PDF sanitizer, repair tool, or hostile-file validation gateway.
- The official `pdf-lib-incremental-save@1.17.4` loader has separate hostile-PDF
  resource and parsing limitations. Read
  [pdf-lib-incremental-save limitations](./docs/pdf-lib-incremental-save-limitations.md)
  before broadening a deployment to untrusted input; use a resource-limited sandbox when
  hostile inputs are in scope.

## Maintainer validation

The offline interoperability and packed-consumer gates complement unit tests. They
use a local TSA/root and do not require a public TSA, Acrobat Reader, or a
default trust anchor. On a clean Ubuntu 24.04 AMD64 runner, first install the
locked Python and binary tools using
[the clean-run recipe](./docs/pades-oracle-tools.md#run-from-a-clean-checkout),
then run:

```bash
corepack pnpm@10.30.3 build
PYTHON=/tmp/pdf-rfc3161-pades-python/bin/python \
  corepack pnpm@10.30.3 --filter pdf-rfc3161-tests test:interoperability
corepack pnpm@10.30.3 --filter pdf-rfc3161-tests test:package
```

For the tool-role boundaries and license cautions, see
[validation-tools.md](./docs/validation-tools.md). For a later, reproducible
Reader observation, use [manual-acrobat-validation.md](./docs/manual-acrobat-validation.md).

## Requirements

- Node.js 20.0.0 or later
- Modern browsers with Web Crypto API support
- Edge runtimes: Cloudflare Workers, Vercel Edge, Deno Deploy

## Upgrading

See [MIGRATION.md](./MIGRATION.md) for breaking-change guidance between
major and minor releases. The [CHANGELOG](./CHANGELOG.md) tracks every release.

## License

MIT
