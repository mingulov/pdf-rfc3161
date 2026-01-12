# Test Fixtures

This directory contains pre-generated test data for comprehensive testing without requiring live network connections.

## Directory Structure

```
fixtures/
|-- certs/          # X.509 certificates in PEM format
|-- ocsp/           # OCSP responses in DER format
|-- crl/            # Certificate Revocation Lists
|-- timestamps/     # Timestamp tokens from TSAs
`-- pdfs/           # Test PDF documents
```

## Philosophy

- **Real Data**: All fixtures contain actual cryptographic data from real servers
- **Deterministic**: Tests run the same way every time
- **Comprehensive**: Cover success cases, error cases, and edge cases
- **Minimal**: Only include what's needed for testing

## Generation Process

1. **Certificates**: Generated using OpenSSL with proper chains
2. **OCSP/CRL**: Captured from real certificate authorities
3. **Timestamps**: Recorded from live TSA servers
4. **PDFs**: Created using standard PDF generation tools

## Usage in Tests

```typescript
// Example: Testing with real OCSP response
import { readFileSync } from "fs";
import { MockFetcher } from "../mocks/mock-fetcher";

const realOCSPResponse = new Uint8Array(readFileSync("test/fixtures/ocsp/good.der"));

const mockFetcher = new MockFetcher();
mockFetcher.setOCSPResponse("http://ocsp.example.com", realOCSPResponse);

// Test passes with real cryptographic data
```

## Updating Fixtures

When real servers change their responses:

```bash
# Update OCSP fixtures
npm run test:update-fixtures

# Or manually capture new responses
curl -H "Content-Type: application/ocsp-request" \
     --data-binary @ocsp-request.der \
     http://ocsp.example.com > new-response.der
```

## Coverage Goals

- **100% unit test coverage** using these fixtures
- **Real cryptographic operations** (not mocked crypto)
- **Edge case handling** (expired certs, malformed responses, etc.)
- **Performance testing** with large fixtures
