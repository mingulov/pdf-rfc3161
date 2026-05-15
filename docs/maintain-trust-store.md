# Maintaining the bundled trust store

`getDefaultTrustStore()` returns a `TrustStore` preloaded with curated root
CAs for the TSAs in `KNOWN_TSA_URLS`. The bundle lives in
`packages/core/src/pki/default-trust-store.ts` (`BUNDLED_ROOT_CERTS_BASE64`).
This document is the maintainer-facing procedure for keeping it correct and
fresh.

## What goes in the bundle

Each entry is the **root** CA cert -- not the TSA-signing leaf, and not an
intermediate. The root is what `verifyTimestamp` checks the chain anchors
against.

```typescript
{
    name: "DigiCert Global Root G2",
    source: "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt",
    fingerprint: "<sha256-of-the-DER-bytes>",
    derBase64: "<base64-encoded DER>",
}
```

## When to update

- A new TSA is added to `KNOWN_TSA_URLS` whose root is not yet in the bundle.
- A CA rotates its root (rare; CAs publish notice well in advance).
- A bundled root is revoked or distrusted by Mozilla / Apple / Microsoft.
- Quarterly review (manual until a `trust-store-freshness.yml` CI workflow lands as a follow-up; tracked as an open item).

## Procedure

1. **Identify the root** for the TSA you're adding. Connect to the TSA, capture
   the timestamp response, parse it with `parseTimestampResponse`, and walk
   `signedData.certificates` to the self-signed certificate. That's the root
   the chain anchors at -- save its Issuer DN.

2. **Fetch the canonical PEM** from the CA's repository (DigiCert, GlobalSign,
   Sectigo, Entrust all publish their roots at well-known URLs). Prefer
   `https://`. Record the URL in the `source` field.

3. **Cross-verify** the SHA-256 fingerprint against an independent source:
   - Mozilla's CA bundle at <https://wiki.mozilla.org/CA/Included_Certificates>
   - The OS trust store (`/etc/ssl/certs` on Linux, Keychain on macOS).

   If the two sources disagree, **do not commit** -- something is wrong.

4. **Decode PEM to DER**:

   ```bash
   openssl x509 -in root.pem -outform DER | base64
   ```

5. **Add the entry** to `BUNDLED_ROOT_CERTS_BASE64` in
   `default-trust-store.ts`. Include the `name`, `source`, `fingerprint`, and
   `derBase64`. Cross-link to the CA's PEM page in a comment if helpful.

6. **Run the test suite** -- `pnpm test` covers the bundle-parses-correctly
   assertions.

7. **Update `CHANGELOG.md`** under the next-version "Added" or "Changed"
   section, listing the new root by name.

## Removing a root

If a root is distrusted (Mozilla removes it from the CA list, a CA revokes
it, etc.):

1. Remove the entry from `BUNDLED_ROOT_CERTS_BASE64`.
2. Add a CHANGELOG note explaining why -- include the CA's notice URL.
3. Bump the package MAJOR if this would invalidate existing tokens for
   relying-party code (effectively a breaking change of verify semantics).

## Why we don't auto-fetch on first call

Fetching roots at runtime defeats the threat model. A compromised network
path between the application and the CA's published cert page could swap a
malicious root in. The bundle must be reviewed by a human at commit time,
signed off, and shipped with the package -- the audit trail lives in git.
