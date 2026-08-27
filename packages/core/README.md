# pdf-rfc3161

`pdf-rfc3161` adds RFC 3161 document timestamps to PDFs in JavaScript and TypeScript. It has no native dependencies and supports Node.js, edge runtimes, and browsers with Web Crypto support.

## Install

```bash
npm install pdf-rfc3161
```

## Timestamp a PDF

```ts
import { readFile, writeFile } from "node:fs/promises";
import { KNOWN_TSA_URLS, timestampPdf } from "pdf-rfc3161";

const result = await timestampPdf({
    pdf: await readFile("document.pdf"),
    tsa: { url: KNOWN_TSA_URLS.FREETSA },
});

await writeFile("document-timestamped.pdf", result.pdf);
```

FreeTSA is used here only as a testing/development endpoint. Selecting a TSA URL does not trust
its timestamps; choose a production TSA and verification roots according to your policy.

LTV is enabled by default. The library collects and embeds certificates, CRLs, and OCSP responses as DSS candidate material. This is validation input only: it does not establish TSA trust, validate revocation freshness, or guarantee long-term validity. Set `enableLTV: false` to skip automatic candidate-material collection.

`timestampPdf()` initially reserves 8 KB for the timestamp token and retries with a larger
placeholder if needed. A directly constructed `TimestampSession` defaults to 16 KB with LTV
enabled and 8 KB otherwise. Omit `signatureSize` or set it to `0` to use the selected API path's
default.

## Trust is caller-owned

Cryptographic consistency is not TSA trust. Supply roots that match your policy when verifying, for example with `SimpleTrustStore`. The bundled-root list is currently empty, so `getDefaultTrustStore()` throws `STATE_ERROR`; do not treat it as a usable default. You may pass `{ trustStore: null }` to skip chain validation explicitly, but that reports cryptographic consistency only.

See the [full documentation](https://github.com/mingulov/pdf-rfc3161#readme), [trust-store maintenance guidance](https://github.com/mingulov/pdf-rfc3161/blob/main/docs/maintain-trust-store.md), and [API source](https://github.com/mingulov/pdf-rfc3161/tree/main/packages/core/src).
