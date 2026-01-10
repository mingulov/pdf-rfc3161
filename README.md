# pdf-rfc3161

A pure JavaScript/TypeScript library for adding RFC 3161 trusted timestamps to PDF documents. Works in Node.js, Cloudflare Workers, Deno, and modern browsers without native dependencies.

## Features

- RFC 3161 compliant implementation of the Time-Stamp Protocol
- Document timestamps using the DocTimeStamp (ETSI.RFC3161) format
- LTV (Long-Term Validation) support with certificate chain embedding
- Support for multiple timestamps from different TSAs
- Extraction and verification of timestamps from existing PDFs
- Edge runtime compatible (Cloudflare Workers, Vercel Edge, Deno Deploy)
- Browser support via the Web Crypto API
- Full TypeScript type definitions
- No native dependencies

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

### Quick Start

```typescript
import { timestampPdf, KNOWN_TSA_URLS } from 'pdf-rfc3161';
import { readFile, writeFile } from 'fs/promises';

const pdfBytes = await readFile('document.pdf');

const result = await timestampPdf({
  pdf: new Uint8Array(pdfBytes),
  tsa: {
    url: KNOWN_TSA_URLS.FREETSA,
  },
});

await writeFile('document-timestamped.pdf', result.pdf);

console.log('Timestamp added at:', result.timestamp.genTime);
```

## Usage

### Basic Timestamping

```typescript
import { timestampPdf } from 'pdf-rfc3161';

const result = await timestampPdf({
  pdf: pdfBytes,
  tsa: {
    url: 'https://freetsa.org/tsr',
    hashAlgorithm: 'SHA-256', // or SHA-384, SHA-512
    timeout: 30000,
  },
  reason: 'Document archival',
  location: 'Server',
});
```

### LTV (Long-Term Validation)

Enable LTV to embed certificate chains. This allows timestamp validation even after the TSA certificates expire:

```typescript
import { timestampPdf } from 'pdf-rfc3161';

const result = await timestampPdf({
  pdf: pdfBytes,
  tsa: { url: 'https://freetsa.org/tsr' },
  enableLTV: true,
});
```

### Multiple Timestamps

Add timestamps from multiple Time Stamping Authorities for redundancy:

```typescript
import { timestampPdfMultiple, KNOWN_TSA_URLS } from 'pdf-rfc3161';

const result = await timestampPdfMultiple({
  pdf: pdfBytes,
  tsaList: [
    { url: KNOWN_TSA_URLS.FREETSA },
    { url: 'https://another-tsa-server' }, // Example of another TSA server
  ],
  enableLTV: true, // Optional: enable LTV for all timestamps
});

console.log(`Added ${result.timestamps.length} timestamps`);
```

### Extract Timestamps

Extract timestamps from an existing PDF:

```typescript
import { extractTimestamps, verifyTimestamp } from 'pdf-rfc3161';

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
import { timestampPdf, KNOWN_TSA_URLS } from 'pdf-rfc3161';

export default {
  async fetch(request: Request): Promise<Response> {
    const formData = await request.formData();
    const file = formData.get('pdf') as File;
    const pdfBytes = new Uint8Array(await file.arrayBuffer());

    const result = await timestampPdf({
      pdf: pdfBytes,
      tsa: { url: KNOWN_TSA_URLS.FREETSA },
      enableLTV: true, // Recommended for production
    });

    return new Response(result.pdf, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename="timestamped.pdf"',
      },
    });
  },
};
```

## API

### `timestampPdf(options)`

Adds an RFC 3161 timestamp to a PDF document.

Options:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `pdf` | `Uint8Array` | Yes | PDF document bytes |
| `tsa.url` | `string` | Yes | TSA server URL |
| `tsa.hashAlgorithm` | `string` | No | SHA-256, SHA-384, or SHA-512 (default: SHA-256) |
| `tsa.timeout` | `number` | No | Request timeout in milliseconds (default: 30000) |
| `tsa.retry` | `number` | No | Retry attempts for network errors (default: 3) |
| `tsa.retryDelay` | `number` | No | Base retry delay in ms (default: 1000) |
| `enableLTV` | `boolean` | No | Enable Long-Term Validation by embedding certificate chain (default: false) |
| `maxSize` | `number` | No | Maximum PDF size in bytes (default: 250MB) |
| `signatureSize` | `number` | No | Size reserved for timestamp token (default: 8192). Set to `0` for automatic sizing. |
| `signatureFieldName` | `string` | No | Custom field name (default: "Timestamp") |
| `reason` | `string` | No | Reason for timestamping |
| `location` | `string` | No | Location metadata |
| `contactInfo` | `string` | No | Contact information |
| `omitModificationTime` | `boolean` | No | Omit the modification time (/M) from signature dictionary |
| `optimizePlaceholder` | `boolean` | No | Optimize signature size by making specific request (default: false) |

Returns a `TimestampResult` with the timestamped PDF, timestamp information, and optional `ltvData`.

**Note on `signatureSize: 0` with LTV:** When using LTV, automatic signature sizing (setting `signatureSize: 0`) does not perform retry logic. Instead, it uses a generous default size (16KB) to accommodate the timestamp token. Ideally, if you encounter "token larger than placeholder" errors with LTV, specify a larger `signatureSize` value manually.

### `timestampPdfMultiple(options)`

Adds timestamps from multiple TSAs using the unified `timestampPdf` logic. Takes a `tsaList` array. Supports `enableLTV` option which is applied to all timestamps.


### `extractTimestamps(pdfBytes)`

Returns an array of `ExtractedTimestamp` objects from the PDF.

### `verifyTimestamp(timestamp)`

Verifies the cryptographic signature of an extracted timestamp.

## TSA Servers

The library include `KNOWN_TSA_URLS` - a list of some known TSA URLs for convenience (e.g., FreeTSA: `https://freetsa.org/tsr`).

**Note:** Usage of these services is governed by the respective providers' Terms and Conditions. Be sure to check them before using in production. FreeTSA uses a self-signed CA which requires manual installation of their root certificate.


## Error Handling

```typescript
import { timestampPdf, TimestampError, TimestampErrorCode } from 'pdf-rfc3161';

try {
  const result = await timestampPdf({ /* ... */ });
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

## Limitations

- Encrypted/password-protected PDFs are not supported (pdf-lib limitation)
- The library creates document timestamps, not signature timestamps on existing signatures

## About RFC 3161

RFC 3161 defines the Time-Stamp Protocol (TSP). It allows proving that data existed at a specific time by having a trusted third party (Time Stamping Authority) cryptographically sign the hash of the data along with a timestamp.

When embedded in a PDF as a Document Timestamp (DocTimeStamp):

- It proves the document existed at the timestamp time
- It can be verified by PDF readers like Adobe Acrobat
- It does not require a signing certificate from the user
- With LTV, it remains valid even after the TSA certificate expires

## Requirements

- Node.js 18.0.0 or later
- Modern browsers with Web Crypto API support
- Edge runtimes: Cloudflare Workers, Vercel Edge, Deno Deploy

## License

MIT
