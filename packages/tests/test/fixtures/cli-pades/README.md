# CLI PAdES deterministic response fixture

This is a project-generated test fixture, not a response copied from a public
TSA. It contains a disposable local root, a TSA certificate, and an RFC 3161
response signed with the matching disposable TSA key. The input PDF and response
are base64-encoded in `cli-pades-response-fixture.ts`; no binary artifact is
checked in.

`deterministic-webcrypto.cjs` replaces only the child CLI process's
`crypto.getRandomValues` with the fixed RFC 3161 nonce `0102030405060708`.
That lets the local JS HTTP replay server return one response while the real CLI
still prepares, sends, validates, embeds, and verifies a timestamp. It is never
loaded by production code.

OpenSSL is not required to run this fixture. The ordinary Vitest suite uses the
checked-in response. The separate offline PAdES conformance gate remains the
only test path that creates or independently verifies timestamp material with
the hash-pinned Ubuntu OpenSSL oracle.

The fixture's TSA certificate has approximately 100-year disposable test
validity around its fixed token generation time. The test asserts that fixed
`genTime` after CLI embedding. The production verifier's certificate-time rule
is anchored to RFC 3161 `genTime`; this fixture never depends on the test
runner's wall-clock date.

## Regeneration

Regenerate only when the timestamp-preparation wire format intentionally changes:

1. Use the pinned PAdES OpenSSL oracle on Ubuntu 24.04, not an ambient system
   OpenSSL, to create a disposable root and TSA certificate with the same
   critical exclusive time-stamping EKU used by `local-tsa-fixture.ts`.
2. Save a fixed one-page input PDF, preload the fixed nonce above into the CLI
   child, and produce the response for that exact request with LTV disabled.
3. Replace all three exported values together: input PDF, response, and root
   certificate. Confirm `cli-pades-safety.test.ts` passes without `openssl` on
   `PATH`, then run the dedicated offline conformance gate.

The generated key material is disposable test data and is project-owned. It has
no third-party content or license obligation beyond this repository's license.
