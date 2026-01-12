# CRL Fixtures

This directory contains Certificate Revocation Lists for testing revocation checking without requiring live CRL distribution points.

## Files

### Standard CRLs

- `empty.crl` - CRL with no revoked certificates
- `with-revoked.crl` - CRL containing revoked certificates
- `delta.crl` - Delta CRL (contains only changes since base CRL)

### Special Cases

- `expired.crl` - CRL past nextUpdate time
- `malformed.crl` - Invalid CRL for error handling tests
- `large.crl` - CRL with many entries for performance testing

## Generation

CRLs are generated using OpenSSL:

```bash
# Create empty CRL
openssl ca -gencrl -keyfile root-ca.key -cert root-ca.pem -out empty.crl

# Revoke a certificate and regenerate CRL
openssl ca -revoke leaf.pem -keyfile root-ca.key -cert root-ca.pem
openssl ca -gencrl -keyfile root-ca.key -cert root-ca.pem -out with-revoked.crl

# Create delta CRL (requires CRL number extension setup)
openssl ca -gencrl -keyfile root-ca.key -cert root-ca.pem -crl_days 30 \
  -crl_compact -out delta.crl
```

## Usage in Tests

```typescript
import { readFileSync } from "fs";
import { MockFetcher } from "../mocks/mock-fetcher";

const crlData = new Uint8Array(readFileSync("test/fixtures/crl/with-revoked.crl"));
const mockFetcher = new MockFetcher();
mockFetcher.setCRLResponse("http://crl.example.com/ca.crl", crlData);

// Use in validation session tests
```
