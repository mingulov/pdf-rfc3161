# OCSP Response Fixtures

This directory contains pre-recorded OCSP responses for testing certificate status validation without requiring live OCSP responders.

## Files

### Status Responses

- `good.der` - OCSP response with "good" status
- `revoked.der` - OCSP response with "revoked" status
- `unknown.der` - OCSP response with "unknown" status

### Special Cases

- `with-nonce.der` - Response with nonce extension for replay protection
- `expired.der` - Response past nextUpdate time
- `malformed.der` - Invalid OCSP response for error handling tests

## Generation

OCSP responses are generated using OpenSSL:

```bash
# Create OCSP request
openssl ocsp -issuer intermediate-ca.pem -cert leaf.pem -reqout ocsp.req

# Generate good response
openssl ocsp -index ca-index.txt -rsigner intermediate-ca.pem -rkey intermediate-ca.key \
  -CA root-ca.pem -respout good.der -reqin ocsp.req

# Generate revoked response (after revoking certificate)
openssl ca -revoke leaf.pem -keyfile root-ca.key -cert root-ca.pem
openssl ocsp -index ca-index.txt -rsigner intermediate-ca.pem -rkey intermediate-ca.key \
  -CA root-ca.pem -respout revoked.der -reqin ocsp.req
```

## Usage in Tests

```typescript
import { readFileSync } from "fs";
import { MockFetcher } from "../mocks/mock-fetcher";

const goodResponse = new Uint8Array(readFileSync("test/fixtures/ocsp/good.der"));
const mockFetcher = new MockFetcher();
mockFetcher.setOCSPResponse("http://ocsp.example.com", goodResponse);

// Use in validation session tests
```
