# TSA Test Fixtures

This directory contains real TSA responses for comprehensive offline testing.

## Structure

- `tsa-responses.ts` - Main fixture file with real TSA responses
- `index.ts` - Export module
- `capture-scripts/` - Scripts for capturing new fixtures

## Adding New Fixtures

To capture a new TSA response:

### Using curl (recommended)

```bash
# Generate a test hash
TEST_HASH=$(echo -n "test" | sha256sum | cut -d' ' -f1)
echo "$TEST_HASH"

# Create timestamp request using openssl
openssl ts -query -data /dev/stdin -sha256 -cert <<< "test" > request.tsq

# Send request and save response
curl -s -H "Content-Type: application/timestamp-query" \
     --data-binary @request.tsq \
     http://timestamp.digicert.com > response.tsr

# Convert to base64 for fixture
base64 -w 0 response.tsr
```

### Using the capture script

```bash
npm run fixtures:capture -- --url http://timestamp.digicert.com --name DIGICERT
```

## Fixture Format

Each fixture contains:

```typescript
{
  name: string;           // Human-readable name
  sourceUrl: string;      // TSA server URL
  capturedAt: string;     // ISO timestamp
  trustStatus: "QUALIFIED" | "TRUSTED" | "UNTRUSTED";
  buffer: Uint8Array;     // DER-encoded TimeStampResp
  expectedStatus: string; // GRANTED, GRANTED_WITH_MODS, REJECTION
  hashAlgorithm: string;  // SHA-256, SHA-384, SHA-512
  includesCertificate: boolean;
  certificateChain?: {    // Certificate info if included
    count: number;
    tsaSubject: string;
    tsaIssuer: string;
    serialNumber: string;
    notBefore: string;
    notAfter: string;
  };
  sizeInfo: {
    totalBytes: number;
    tokenBytes: number;
    certificateBytes: number;
  };
  quirks: string[];       // Known quirks or special behaviors
}
```

## Using Fixtures in Tests

```typescript
import { TSA_FIXTURES, getFixturesByTrustStatus } from "./fixtures";

describe("TSA Response Parsing", () => {
    it("should parse qualified TSA responses", () => {
        const qualified = getFixturesByTrustStatus("QUALIFIED");
        for (const fixture of qualified) {
            const result = parseTimestampResponse(fixture.buffer);
            expect(result.status).toBe(fixture.expectedStatus);
        }
    });

    it("should handle DigiCert responses", () => {
        const digicert = TSA_FIXTURES.DIGICERT_GRANTED;
        const result = parseTimestampResponse(digicert.buffer);
        expect(result.info).toBeDefined();
        expect(result.token).toBeDefined();
    });
});
```

## Supported Hash Algorithms

- SHA-256
- SHA-384
- SHA-512

## Trust Status Categories

- **QUALIFIED** - EU eIDAS compliant, on EU Trust List
- **TRUSTED** - On Adobe Approved Trust List
- **UNTRUSTED** - Not on any trust list (may still work)

## Error Response Types

- GRANTED (0) - Success
- GRANTED_WITH_MODS (1) - Success with modifications
- REJECTION (2) - Request rejected
- WAITING (3) - Request queued (rare)
