# pdf-rfc3161

A pure JavaScript/TypeScript library for adding RFC 3161 trusted timestamps to PDF documents. Works in Node.js, Cloudflare Workers, Deno, and modern browsers without native dependencies.

## About RFC 3161

RFC 3161 defines the Time-Stamp Protocol (TSP). It allows proving that data existed at a specific time by having a trusted third party (Time Stamping Authority) cryptographically sign the hash of the data along with a timestamp.

When embedded in a PDF as a Document Timestamp (DocTimeStamp):

- It proves the document existed at the timestamp time
- It can be verified by PDF readers like Adobe Acrobat
- It does not require a signing certificate from the user
- With LTV, it remains valid even after the TSA certificate expires

## Features

- RFC 3161 compliant implementation of the Time-Stamp Protocol
- Document timestamps using the DocTimeStamp (ETSI.RFC3161) format
- LTV (Long-Term Validation) support with certificate chain embedding
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
    reason: "Document archival",
    location: "Server",
});
```

### LTV (Long-Term Validation)

Enable LTV to embed certificate chains. This allows timestamp validation even after the TSA certificates expire:

```typescript
import { timestampPdf } from "pdf-rfc3161";

const result = await timestampPdf({
    pdf: pdfBytes,
    tsa: { url: "https://freetsa.org/tsr" },
    enableLTV: true,
});
```

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

### PAdES-LTA Archive Timestamp

For long-term preservation of signed documents, use `timestampPdfLTA`. This fetches fresh revocation data and adds a final document timestamp:

```typescript
import { timestampPdfLTA, KNOWN_TSA_URLS } from "pdf-rfc3161";

const result = await timestampPdfLTA({
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

    const verified = await verifyTimestamp(ts);
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

| Name                   | Type         | Required | Description                                                        |
| ---------------------- | ------------ | -------- | ------------------------------------------------------------------ |
| `pdf`                  | `Uint8Array` | Yes      | PDF document bytes                                                 |
| `tsa.url`              | `string`     | Yes      | TSA server URL                                                     |
| `tsa.hashAlgorithm`    | `string`     | No       | SHA-256, SHA-384, or SHA-512 (default: SHA-256)                    |
| `tsa.timeout`          | `number`     | No       | Request timeout in ms (default: 30000)                             |
| `tsa.retry`            | `number`     | No       | Retry attempts (default: 3)                                        |
| `tsa.retryDelay`       | `number`     | No       | Base retry delay in ms (default: 1000)                             |
| `enableLTV`            | `boolean`    | No       | Enable Long-Term Validation (default: false)                       |
| `maxSize`              | `number`     | No       | Maximum PDF size in bytes (default: 250MB)                         |
| `signatureSize`        | `number`     | No       | Size reserved for token (default: 8192). Set to `0` for automatic. |
| `signatureFieldName`   | `string`     | No       | Custom field name (default: "Timestamp")                           |
| `reason`               | `string`     | No       | Reason for timestamping                                            |
| `location`             | `string`     | No       | Location metadata                                                  |
| `contactInfo`          | `string`     | No       | Contact information                                                |
| `omitModificationTime` | `boolean`    | No       | Omit /M from signature dictionary                                  |
| `optimizePlaceholder`  | `boolean`    | No       | Optimize signature size (default: false)                           |

Returns a `TimestampResult` with the timestamped PDF, timestamp info, and optional `ltvData`.

Note: When using LTV, `signatureSize: 0` uses a 16KB default. Specify larger value manually if you encounter "token larger than placeholder" errors.

### `timestampPdfMultiple(options)`

Adds timestamps from multiple TSAs. Takes a `tsaList` array and supports `enableLTV`.

### `extractTimestamps(pdfBytes)`

Returns an array of `ExtractedTimestamp` objects from the PDF.

### `verifyTimestamp(timestamp, options?)`

Verifies the cryptographic signature of an extracted timestamp.

Options:

| Name                  | Type         | Required | Description                                  |
| --------------------- | ------------ | -------- | -------------------------------------------- |
| `pdf`                 | `Uint8Array` | No       | Original PDF bytes for hash verification     |
| `trustStore`          | `TrustStore` | No       | Trust store for certificate chain validation |
| `strictESSValidation` | `boolean`    | No       | Enforce PAdES compliance                     |

## TSA Servers

The library includes `KNOWN_TSA_URLS` - a list of known TSA URLs for convenience.

Note: Usage is governed by providers' Terms and Conditions. FreeTSA uses a self-signed CA requiring manual root certificate installation.

## Demo

A client-side demo is included in the `demo/` folder. Run it with:

```bash
npm install
npm run demo:dev
```

## Error Handling

```typescript
import { timestampPdf, TimestampError, TimestampErrorCode } from "pdf-rfc3161";

try {
    const result = await timestampPdf({
        /* ... */
    });
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

This library focuses on generating RFC 3161 timestamps for PDFs with full LTV support.

**Primary use cases:**

- Adding timestamps to fresh documents
- Archiving documents with PAdES-LTA for indefinite validity
- Extracting and verifying timestamp structures

**Verification scope:**

The `verifyTimestamp()` function performs cryptographic integrity verification:

- The timestamp token is properly signed by the TSA
- The document hash matches what was timestamped
- The timestamp structure is valid

**Modular Network Architecture:**

The library is designed with pluggable network interfaces to support various deployment scenarios:

- **Edge Runtimes**: Cloudflare Workers, Vercel Edge, Deno Deploy (uses Web Fetch API)
- **Node.js**: Can use HTTP client of choice (fetch, axios, node-fetch, curl via child_process)
- **Testing**: Deterministic mock responses without network calls
- **Air-Gapped Environments**: Supply pre-fetched revocation data directly

All network operations use the Fetcher pattern:

```typescript
// Use custom fetcher for testing
const mockFetcher = new MockFetcher();
mockFetcher.setOCSPResponse("http://ocsp.example.com", mockResponse);

// Use custom curl-based fetcher
import { CurlFetcher } from "pdf-rfc3161/pki/fetchers";

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
const session = new TimestampSession(pdfBytes, { enableLTV: true });

// Step 1: Generate request (can send to external TSA)
const request = await session.createTimestampRequest();

// Step 2: Send request via your preferred method
const response = await myCustomTSAFetch(request);

// Step 3: Embed response with full LTV
const finalPdf = await session.embedTimestampToken(response);
```

**RFC Compliance:**

The library aims to support relevant RFCs for timestamp and validation workflows:

| RFC            | Status        | Description                |
| -------------- | ------------- | -------------------------- |
| RFC 3161       | [Full]        | Time-Stamp Protocol (core) |
| RFC 5816       | [Transparent] | ESSCertIDv2 for SHA-256+   |
| RFC 5544       | [Planned]     | TimeStampedData envelope   |
| RFC 6960       | [Implemented] | OCSP certificate status    |
| ETSI 319 142-1 | [Planned]     | PAdES baseline signatures  |
| RFC 6211       | [Low Prio]    | CMS Algorithm Protect      |

**Key:**

- [Full] = Complete implementation
- [Transparent] = Works via dependencies (no code needed)
- [Implemented] = Core functionality exists
- [Planned] = On roadmap for near-term
- [Low Prio] = Lower priority, future consideration

**OCSP/CRL handling:**

For LTV support, the library includes OCSP and CRL fetching via pluggable fetchers. Provide custom fetchers or pre-fetched data for:

- Controlled network access
- Air-gapped environments
- Deterministic testing
- Custom caching strategies

**TrustStore validation:**

For production chain validation, pass a `TrustStore` to `verifyTimestamp()`:

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

## Requirements

- Node.js 18.0.0 or later
- Modern browsers with Web Crypto API support
- Edge runtimes: Cloudflare Workers, Vercel Edge, Deno Deploy

## License

MIT
