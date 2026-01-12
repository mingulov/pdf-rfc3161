# Timestamp Fixtures

This directory contains pre-recorded timestamp tokens from various TSA servers for testing timestamp validation without requiring live TSA connections.

## Files

### By Algorithm

- `sha256-token.der` - Timestamp token with SHA-256
- `sha384-token.der` - Timestamp token with SHA-384
- `sha512-token.der` - Timestamp token with SHA-512

### By Content

- `minimal-token.der` - Smallest valid timestamp token
- `long-chain.der` - Token with long certificate chain
- `esSCertIDv2-token.der` - Token using ESSCertIDv2 format

### Special Cases

- `expired-token.der` - Token past validity period
- `invalid-token.der` - Malformed token for error handling

## Generation

Timestamp tokens are captured from real TSA servers:

```bash
# Create timestamp request
echo -n "test data" | openssl ts -query -data - -sha256 -cert -out request.tsq

# Send to TSA and capture response
curl -H "Content-Type: application/timestamp-query" \
     --data-binary @request.tsq \
     https://freetsa.org/tsr > response.tsr

# Extract the token (it's inside a TimeStampResp structure)
# Save as .der file
```

## Usage in Tests

```typescript
import { readFileSync } from "fs";
import { validateTimestampTokenRFC8933Compliance } from "../../src/rfcs/rfc8933";

const token = new Uint8Array(readFileSync("test/fixtures/timestamps/sha256-token.der"));
const result = validateTimestampTokenRFC8933Compliance(token);
expect(result.compliant).toBe(true);
```
