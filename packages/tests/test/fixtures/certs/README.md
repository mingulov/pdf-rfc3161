# Certificate Fixtures

This directory contains test certificates in various formats for testing certificate validation, chain building, and revocation checking.

## Files

### Root CA Certificates

- `root-ca.pem` - Self-signed root CA certificate
- `intermediate-ca.pem` - Intermediate CA signed by root

### Leaf Certificates

- `leaf.pem` - End-entity certificate signed by intermediate CA
- `chain.pem` - Full certificate chain (root + intermediate + leaf)

### Special Cases

- `expired.pem` - Expired certificate for expiry testing
- `revoked.pem` - Certificate that should be in revocation lists
- `self-signed.pem` - Self-signed certificate for trust testing

## Generation

Certificates are generated using OpenSSL:

```bash
# Root CA
openssl req -x509 -newkey rsa:2048 -keyout root-ca.key -out root-ca.pem -days 3650 -subj "/CN=Test Root CA"

# Intermediate CA
openssl req -new -newkey rsa:2048 -keyout intermediate-ca.key -out intermediate-ca.csr -subj "/CN=Test Intermediate CA"
openssl x509 -req -in intermediate-ca.csr -CA root-ca.pem -CAkey root-ca.key -out intermediate-ca.pem -days 3650

# Leaf certificate
openssl req -new -newkey rsa:2048 -keyout leaf.key -out leaf.csr -subj "/CN=test.example.com"
openssl x509 -req -in leaf.csr -CA intermediate-ca.pem -CAkey intermediate-ca.key -out leaf.pem -days 365

# Create chain
cat leaf.pem intermediate-ca.pem root-ca.pem > chain.pem
```

## Usage in Tests

```typescript
import { readFileSync } from "fs";
import { createCertificateFromPem } from "../utils/cert-helpers";

const certPem = readFileSync("test/fixtures/certs/leaf.pem", "utf-8");
const cert = createCertificateFromPem(certPem);
```
